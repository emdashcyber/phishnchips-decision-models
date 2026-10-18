#!/usr/bin/env python3
"""Download, normalize, deduplicate, and audit the fresh evaluation corpus.

Raw and prepared email text is kept under eval/ and git-ignored. No
message text is printed, written to the preparation manifest, or sent to a
provider by this script.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import sys
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SOURCE_DIR = HERE / "source_data"
DATA_DIR = HERE / "data"
PREPARED_PATH = DATA_DIR / "prepared_emails.csv"
MANIFEST_PATH = DATA_DIR / "preparation_manifest.csv"
SUMMARY_PATH = DATA_DIR / "preparation_summary.json"

PHISHNCHIPS_REPO = "AreLit/PhishNChips"
PHISHNCHIPS_REVISION = "89afcc39610084298c4679159cb2e27d9ffffa46"

SOURCES: tuple[dict[str, Any], ...] = tuple(
    {
        "dataset": "PhishNChips",
        "repo": PHISHNCHIPS_REPO,
        "revision": PHISHNCHIPS_REVISION,
        "file": name,
        "parser": "phishnchips",
        "expected_sha256": checksum,
        "expected_rows": rows,
    }
    for name, checksum, rows in (
        (
            "core_emails.csv",
            "cebb407ff8630491a97400e37464b8db8dfc4299164fca51fcb4ac7eec8204ef",
            2000,
        ),
        (
            "cross_domain_legitimate_v5.csv",
            "66df80e116bbb431b5374b381eba490df858be785a00d5e1fdf91e22bd34393c",
            333,
        ),
        (
            "infrastructure_phishing_expanded.csv",
            "839c02c0daf5e78724416b42ba95d3962cb483a01b7df13af3de1e5590a1ce71",
            54,
        ),
        (
            "real_phishing_validation.csv",
            "60131198553e6346496af955937dddeb7c7592e31dd56c0579542017d48ce196",
            1000,
        ),
    )
)

LOCAL_CACHES = {
    ("PhishNChips", "core_emails.csv"): REPO_ROOT
    / "data"
    / "PhishNChips_v5.2_core_emails.csv",
}
LOCAL_CACHE_SHA256 = {
    ("PhishNChips", "core_emails.csv"): "cebb407ff8630491a97400e37464b8db8dfc4299164fca51fcb4ac7eec8204ef",
}

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"'\]\[{}]+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"
REQUIRED_FIELDS = ("sender", "subject", "body")
PREPARED_FIELDS = (
    "email_id",
    "email_sha256",
    "source_dataset",
    "source_file",
    "source_row",
    "label",
    "sender",
    "subject",
    "body",
    "link_display_text",
    "link_urls",
    "source_memberships",
)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def set_csv_field_limit() -> None:
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(100_000_000)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_source(spec: dict[str, Any], *, refresh: bool) -> Path:
    dataset_dir = SOURCE_DIR / spec["dataset"]
    dataset_dir.mkdir(parents=True, exist_ok=True)
    destination = dataset_dir / spec["file"]
    if destination.exists() and not refresh:
        return destination

    cache_key = (spec["dataset"], spec["file"])
    cached = LOCAL_CACHES.get(cache_key)
    if cached and cached.is_file() and not refresh:
        actual = sha256_file(cached)
        expected = LOCAL_CACHE_SHA256[cache_key]
        if actual != expected:
            raise ValueError(f"Local cached source checksum mismatch for {cached.name}")
        shutil.copyfile(cached, destination)
        return destination

    url = (
        f"https://huggingface.co/datasets/{spec['repo']}/resolve/"
        f"{spec['revision']}/{spec['file']}?download=true"
    )
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "fresh-email-classification-evaluation/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as out:
            shutil.copyfileobj(response, out, length=1024 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(
            f"Could not download pinned source {spec['dataset']}/{spec['file']}; "
            "check network access to huggingface.co."
        ) from exc
    temporary.replace(destination)
    return destination


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def parse_label(value: Any) -> str | None:
    label = normalize_text(value).casefold()
    if label in {"1", "phish", "phishing"}:
        return "PHISHING"
    if label in {"0", "legitimate", "legit", "benign"}:
        return "LEGITIMATE"
    return None


def extract_urls(value: Any) -> list[str]:
    """Extract literal URL strings; never resolve, request, or open a URL."""
    found: list[str] = []
    if value is None:
        return found
    if isinstance(value, dict):
        for nested in value.values():
            found.extend(extract_urls(nested))
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            found.extend(extract_urls(nested))
    else:
        raw = normalize_text(value)
        if not raw or re.fullmatch(r"[01]", raw):
            return found
        # AURA sometimes serializes its URL lists as JSON or Python-looking
        # text. Extract only literal URL strings; never parse or execute cells.
        for match in URL_PATTERN.findall(raw):
            found.append(match.rstrip(TRAILING_URL_PUNCTUATION))
    # Preserve source order while removing exact repeated strings.
    return list(dict.fromkeys(url for url in found if url))


def canonical_sender(name: Any, address: Any = "") -> str:
    display = normalize_text(name)
    email_address = normalize_text(address)
    if not display:
        return email_address
    if not email_address or email_address.casefold() in display.casefold():
        return display
    return f"{display} <{email_address}>"


def parse_email(spec: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    normalized = {str(key).strip().lower(): value for key, value in row.items() if key}
    content_value = normalized.get("email_content")
    try:
        content = content_value if isinstance(content_value, dict) else json.loads(content_value or "")
    except (json.JSONDecodeError, TypeError):
        content = {}
    if not isinstance(content, dict):
        content = {}
    email = {str(key).strip().lower(): value for key, value in content.items()}
    sender = canonical_sender(email.get("sender"), email.get("from"))
    subject = normalize_text(email.get("subject"))
    body = normalize_text(email.get("body"))
    link_display_text = normalize_text(email.get("link_display_text"))
    link_urls = extract_urls(email.get("link_url"))

    link_urls = list(dict.fromkeys(extract_urls(body) + link_urls))
    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "link_display_text": link_display_text,
        "link_urls": link_urls,
    }


def hash_text(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\s+", " ", value).strip().casefold()


def content_hash(email: dict[str, Any]) -> str:
    canonical = {
        "sender": hash_text(email["sender"]),
        "subject": hash_text(email["subject"]),
        "body": hash_text(email["body"]),
        "link_display_text": hash_text(email["link_display_text"]),
        "link_urls": sorted(hash_text(url) for url in email["link_urls"]),
    }
    serialized = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def open_csv(path: Path) -> tuple[Any, csv.DictReader]:
    stream = path.open("r", newline="", encoding="utf-8-sig")
    reader = csv.DictReader(stream)
    return stream, reader


def build_database(source_paths: list[tuple[dict[str, Any], Path]], database_path: Path) -> dict[str, Any]:
    set_csv_field_limit()
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute(
        """CREATE TABLE rows (
            row_id INTEGER PRIMARY KEY,
            source_dataset TEXT NOT NULL,
            source_file TEXT NOT NULL,
            source_row INTEGER NOT NULL,
            label TEXT,
            email_sha256 TEXT,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            link_display_text TEXT NOT NULL,
            link_urls_json TEXT NOT NULL,
            status TEXT NOT NULL
        )"""
    )
    sources: list[dict[str, Any]] = []

    for spec, path in source_paths:
        checksum = sha256_file(path)
        expected = spec.get("expected_sha256")
        if expected and checksum != expected:
            raise ValueError(
                f"Pinned checksum mismatch for {spec['file']}: expected {expected}, got {checksum}"
            )
        stream, reader = open_csv(path)
        source_rows = 0
        try:
            for source_row, raw_row in enumerate(reader, start=2):
                source_rows += 1
                normalized = {str(key).strip().lower(): value for key, value in raw_row.items() if key}
                raw_label = normalized.get("phish_label")
                label = parse_label(raw_label)
                email = parse_email(spec, raw_row)
                missing = [key for key in REQUIRED_FIELDS if not email[key]]
                email_digest = content_hash(email)
                status = "invalid_label" if label is None else ("blank_required_field" if missing else "included")
                connection.execute(
                    """INSERT INTO rows (
                        source_dataset, source_file, source_row, label, email_sha256,
                        sender, subject, body, link_display_text, link_urls_json, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        spec["dataset"],
                        spec["file"],
                        source_row,
                        label,
                        email_digest,
                        email["sender"],
                        email["subject"],
                        email["body"],
                        email["link_display_text"],
                        json.dumps(email["link_urls"], ensure_ascii=False, separators=(",", ":")),
                        status,
                    ),
                )
        finally:
            stream.close()
        connection.commit()
        expected_rows = spec.get("expected_rows")
        if expected_rows is not None and source_rows != expected_rows:
            raise ValueError(f"Unexpected row count for {spec['file']}: expected {expected_rows}, got {source_rows}")
        sources.append(
            {
                "dataset": spec["dataset"],
                "file": spec["file"],
                "revision": spec["revision"],
                "sha256": checksum,
                "rows": source_rows,
                "parser": spec["parser"],
            }
        )

    connection.execute("CREATE INDEX rows_by_hash ON rows(email_sha256)")
    connection.execute(
        """CREATE TEMP TABLE duplicate_groups AS
           SELECT email_sha256, MIN(row_id) AS first_row, COUNT(*) AS row_count,
                  MIN(label) AS min_label, MAX(label) AS max_label
           FROM rows WHERE status='included'
           GROUP BY email_sha256 HAVING COUNT(*) > 1"""
    )
    connection.execute(
        """UPDATE rows SET status='label_conflict'
           WHERE status='included' AND email_sha256 IN
             (SELECT email_sha256 FROM duplicate_groups WHERE min_label <> max_label)"""
    )
    connection.execute(
        """UPDATE rows SET status='exact_duplicate'
           WHERE status='included' AND row_id NOT IN
             (SELECT MIN(row_id) FROM rows WHERE status='included' GROUP BY email_sha256)"""
    )
    connection.commit()
    exact_duplicate_rows = connection.execute(
        "SELECT COUNT(*) FROM rows WHERE status='exact_duplicate'"
    ).fetchone()[0]
    label_conflict_rows = connection.execute(
        "SELECT COUNT(*) FROM rows WHERE status='label_conflict'"
    ).fetchone()[0]

    grouped = connection.execute(
        """SELECT source_dataset, source_file, status, COALESCE(label, 'UNKNOWN'), COUNT(*)
           FROM rows GROUP BY source_dataset, source_file, status, COALESCE(label, 'UNKNOWN')
           ORDER BY source_dataset, source_file, status, label"""
    ).fetchall()
    per_source: dict[str, dict[str, Any]] = {}
    for dataset, file, status, label, count in grouped:
        key = f"{dataset}/{file}"
        item = per_source.setdefault(key, {"dataset": dataset, "file": file, "counts": Counter()})
        item["counts"][f"{status}:{label}"] += count

    memberships_by_hash: dict[str, list[dict[str, Any]]] = {}
    membership_hashes_by_source: dict[tuple[str, str], set[str]] = {}
    for digest, dataset, file, source_row, label in connection.execute(
        """SELECT email_sha256, source_dataset, source_file, source_row, label
           FROM rows WHERE status IN ('included', 'exact_duplicate')
           ORDER BY email_sha256, row_id"""
    ):
        source_key = (dataset, file)
        seen_sources = {member["dataset_file"] for member in memberships_by_hash.get(digest, [])}
        dataset_file = f"{dataset}/{file}"
        membership_hashes_by_source.setdefault(source_key, set()).add(digest)
        if dataset_file not in seen_sources:
            memberships_by_hash.setdefault(digest, []).append(
                {
                    "dataset": dataset,
                    "file": file,
                    "row": source_row,
                    "label": label,
                    "dataset_file": dataset_file,
                }
            )
    for item in per_source.values():
        item["unique_message_memberships"] = len(
            membership_hashes_by_source.get((item["dataset"], item["file"]), set())
        )
        item["counts"] = dict(item["counts"])

    manifest_fields = (
        "source_dataset",
        "source_file",
        "source_row",
        "email_id",
        "email_sha256",
        "label",
        "status",
    )
    with MANIFEST_PATH.open("w", newline="", encoding="utf-8") as manifest_file:
        writer = csv.DictWriter(manifest_file, fieldnames=manifest_fields)
        writer.writeheader()
        for row in connection.execute(
            "SELECT source_dataset, source_file, source_row, email_sha256, label, status FROM rows ORDER BY row_id"
        ):
            dataset, file, source_row, digest, label, status = row
            writer.writerow(
                {
                    "source_dataset": dataset,
                    "source_file": file,
                    "source_row": source_row,
                    "email_id": digest[:24] if digest else "",
                    "email_sha256": digest or "",
                    "label": label or "",
                    "status": status,
                }
            )

    with PREPARED_PATH.open("w", newline="", encoding="utf-8") as prepared_file:
        writer = csv.DictWriter(prepared_file, fieldnames=PREPARED_FIELDS)
        writer.writeheader()
        for row in connection.execute(
            """SELECT email_sha256, source_dataset, source_file, source_row, label,
                      sender, subject, body, link_display_text, link_urls_json
               FROM rows WHERE status='included' ORDER BY row_id"""
        ):
            digest, dataset, file, source_row, label, sender, subject, body, link_text, link_urls = row
            writer.writerow(
                {
                    "email_id": digest[:24],
                    "email_sha256": digest,
                    "source_dataset": dataset,
                    "source_file": file,
                    "source_row": source_row,
                    "label": label,
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "link_display_text": link_text,
                    "link_urls": link_urls,
                    "source_memberships": json.dumps(
                        [
                            {key: value for key, value in member.items() if key != "dataset_file"}
                            for member in memberships_by_hash.get(digest, [])
                        ],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                }
            )

    global_counts = Counter()
    label_counts = Counter()
    for status, label, count in connection.execute(
        "SELECT status, COALESCE(label, 'UNKNOWN'), COUNT(*) FROM rows GROUP BY status, COALESCE(label, 'UNKNOWN')"
    ):
        global_counts[status] += count
        if status == "included":
            label_counts[label] += count

    connection.close()
    return {
        "created_at_utc": now_utc(),
        "sources": sources,
        "source_summary": list(per_source.values()),
        "total_source_rows": sum(source["rows"] for source in sources),
        "included_rows": global_counts["included"],
        "included_label_counts": dict(label_counts),
        "unique_email_memberships_by_source": {
            f"{item['dataset']}/{item['file']}": item["unique_message_memberships"]
            for item in per_source.values()
        },
        "excluded_blank_required_field": global_counts["blank_required_field"],
        "excluded_invalid_label": global_counts["invalid_label"],
        "excluded_exact_duplicates": exact_duplicate_rows,
        "excluded_label_conflict_duplicates": label_conflict_rows,
        "prepared_file_sha256": sha256_file(PREPARED_PATH),
        "prepared_file": str(PREPARED_PATH.relative_to(HERE)),
        "input_fields_sent": ["sender", "subject", "body", "link_display_text", "link_urls"],
        "input_fields_excluded": ["phish_label", "id", "source_dataset", "source_file", "source_row", "url_raw", "strategy", "url_category", "datasource", "model_used"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="redownload pinned sources even when cached")
    args = parser.parse_args()
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    source_paths: list[tuple[dict[str, Any], Path]] = []
    for spec in SOURCES:
        path = download_source(spec, refresh=args.refresh)
        source_paths.append((spec, path))
        print(f"Source ready: {spec['dataset']}/{spec['file']}")

    database_path = DATA_DIR / ".prepare_work.sqlite"
    database_path.unlink(missing_ok=True)
    try:
        summary = build_database(source_paths, database_path)
    finally:
        database_path.unlink(missing_ok=True)
        Path(str(database_path) + "-journal").unlink(missing_ok=True)

    SUMMARY_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "source_summary"}, indent=2))
    print(f"Preparation manifest: {MANIFEST_PATH}")
    print(f"Source summary: {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
