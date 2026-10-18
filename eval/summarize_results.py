#!/usr/bin/env python3
"""Recompute the per-model summary from recorded predictions, with no API calls.

Reads the recorded run (or any predictions.jsonl[.gz] written by run_models.py),
rebuilds the summary with the same code run_models.py uses, and optionally
checks it against the summary the website is built from.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import sys
from pathlib import Path

import run_models

HERE = Path(__file__).resolve().parent
DEFAULT_PREDICTIONS = HERE / "published" / "predictions.jsonl.gz"
DEFAULT_OUTPUT = HERE / "results" / "model_summary_recomputed.csv"
DEFAULT_REFERENCE = HERE.parent / "data" / "results.csv"
KEY_FIELDS = ("dataset", "source_file", "model_id")


def read_records(path: Path) -> list[dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def emails_from_records(records: list[dict]) -> list[dict[str, str]]:
    """One entry per email, carrying only the fields the summary needs."""
    emails: dict[str, dict[str, str]] = {}
    for record in records:
        emails.setdefault(
            record["email_id"],
            {"email_id": record["email_id"], "source_memberships": json.dumps(record["source_memberships"])},
        )
    return list(emails.values())


def same(left: str, right: str) -> bool:
    if left == right:
        return True
    try:
        return math.isclose(float(left), float(right), rel_tol=1e-9, abs_tol=1e-12)
    except ValueError:
        return False


def compare(produced: Path, reference: Path) -> list[str]:
    def load(path: Path) -> dict[tuple, dict[str, str]]:
        with path.open(newline="", encoding="utf-8") as stream:
            return {tuple(row[k] for k in KEY_FIELDS): row for row in csv.DictReader(stream)}

    mine, theirs = load(produced), load(reference)
    problems = [f"missing row {key}" for key in theirs.keys() - mine.keys()]
    problems += [f"unexpected row {key}" for key in mine.keys() - theirs.keys()]
    for key in mine.keys() & theirs.keys():
        for column, value in theirs[key].items():
            if not same(mine[key].get(column, ""), value):
                problems.append(f"{key} {column}: recomputed {mine[key].get(column)!r}, reference {value!r}")
    return sorted(problems)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS, help="predictions.jsonl or .jsonl.gz")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the recomputed summary")
    parser.add_argument("--check", type=Path, nargs="?", const=DEFAULT_REFERENCE, help="compare with this summary CSV (default: ../data/results.csv)")
    args = parser.parse_args()

    records = read_records(args.predictions)
    emails = emails_from_records(records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    summaries = run_models.write_summaries(emails, records, args.output)
    print(f"{len(records):,} prediction records, {len(emails):,} emails, {len(summaries)} summary rows -> {args.output}")

    if args.check is None:
        return 0
    problems = compare(args.output, args.check)
    if problems:
        print(f"MISMATCH against {args.check}:")
        print("\n".join(f"  {line}" for line in problems[:20]))
        return 1
    print(f"OK: every row matches {args.check}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
