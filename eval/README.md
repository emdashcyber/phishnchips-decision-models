# Reproducing the PhishNChips decision-model results

Everything needed to check, or repeat, the run behind the dashboard. Python 3.10 or later and the standard library are enough; nothing needs installing.

These scripts were written for the original evaluation run. Changes made when they were added to this repository:

- The model name "OpenAI Decisions (GPT-6 Luna Decisions)" is shortened to "GPT-6 Luna Decisions" in the scripts and recorded files. The model ID is unchanged.
- `write_summaries()` in `run_models.py` takes an optional output path, so `summarize_results.py` can reuse it.
- `summarize_results.py` is new.

## Three levels of reproduction

### 1. Check the numbers (no key, no network)

`published/predictions.jsonl.gz` holds every decision from the recorded run: one record per email and model, with the label, probability, latency, cost, retries and errors, but no email text. The summary is rebuilt from it with the same code the runner uses, and compared with `data/results.csv`, which the website is built from:

```sh
python3 eval/summarize_results.py --check
```

Expected: `OK: every row matches ../data/results.csv`. The recomputed file is written to `eval/results/model_summary_recomputed.csv`.

### 2. Rebuild the email corpus (network, no key)

```sh
python3 eval/prepare_data.py
```

This downloads four pinned files from the [PhishNChips dataset](https://huggingface.co/datasets/AreLit/PhishNChips) (revision `89afcc39610084298c4679159cb2e27d9ffffa46`), verifies their SHA-256 checksums and row counts, and builds `eval/data/prepared_emails.csv`. That file contains raw email text and is git-ignored. The run it produces should match `published/preparation_summary.json`, including `prepared_file_sha256`.

| Source file | Rows | Role |
| --- | ---: | --- |
| `core_emails.csv` | 2,000 | Primary benchmark: 1,000 phishing, 1,000 legitimate |
| `cross_domain_legitimate_v5.csv` | 333 | Legitimate only. All 333 also appear in the core set |
| `infrastructure_phishing_expanded.csv` | 54 | Phishing only |
| `real_phishing_validation.csv` | 1,000 | Phishing only. 2 blank rows and 41 duplicates are dropped |

Of 3,387 source rows, 2 are dropped for a blank required field and 374 as exact duplicates, leaving 3,011 unique emails: 1,000 legitimate and 2,011 phishing. Duplicates are found after normalising Unicode, case and whitespace across sender, subject, body, link text and URLs. If duplicates disagree on the label, every copy is dropped (none did). Each email is sent once, and it keeps a record of every source file it came from, which is how the per-set results in the dashboard come from one set of decisions.

Because the extra sets add phishing-only rows, the combined set is not balanced. The core set is the balanced comparison.

### 3. Repeat the model run (network, API key, costs money)

The runner calls the OpenRouter decisions endpoint (`https://openrouter.ai/api/alpha/decisions`). Set `OPENROUTER_API_KEY` first. The recorded cost of the original run was about US$1.33 across 36,131 decisions.

```sh
python3 eval/run_models.py                                   # preflight: counts only, no requests
python3 eval/run_models.py --limit 20 --run-models --confirm-send    # small pilot
python3 eval/run_models.py --run-models --confirm-send       # full run, resumable
```

Both flags are required to send anything, because email text goes to the model providers. Pairs that already succeeded are skipped on a re-run and failed pairs are retried. `--workers` sets concurrency (default 6).

Output goes to `eval/results/`: `predictions.jsonl`, `model_summary.csv` and `run_metadata.json`. To rebuild the dashboard from a new run, replace `data/results.csv` with the new `model_summary.csv` and run `npm run check` in `site/`.

## What the models were asked

Each model got one question with two choices, `PHISHING` or `LEGITIMATE`, and the same definitions every time. The full wording is in `published/run_metadata.json` under `classification_question`. In short:

- **Phishing:** evidence of a deceptive, fraudulent or malicious attempt to get the recipient to disclose credentials or information, transfer money or assets, run malicious content, or grant access.
- **Legitimate:** anything where the evidence is not enough to establish malicious or fraudulent intent.
- Urgency, links, attachments, payment requests, sensitive wording or poor grammar are not proof on their own.
- The email is treated as untrusted, and instructions inside it are to be ignored.

This is not the PhishNChips baseline prompt, which asks whether to click a link. Only the sender, subject, body, link text and literal URL strings are sent. Labels and source metadata are not, and no link is ever visited.

## How the run was made

- **Date:** 2026-10-18 (UTC). A single run with one prompt.
- **Models:** 12, requested through OpenRouter. The three Clef models are pinned to the Cloudflare provider with fallback disabled. The others use the default routing. The provider that actually answered is recorded in each prediction.
- **Retries:** up to 3 attempts. HTTP 429 and 5xx errors and timeouts are retried, honouring `Retry-After` up to 20 seconds, otherwise backing off 1 then 2 seconds.
- **Result:** 36,131 of 36,132 decisions completed. One Decider Flash V1.2 decision stayed rate-limited (HTTP 429) after retries.
- **Latency:** wall-clock time per decision as seen by the client, including retries.
- **Cost:** the `cost` OpenRouter returns in the response usage when present, otherwise tokens times the live price from a snapshot taken at the start of the run.

## Summary columns

`model_summary.csv` has one row per dataset, source file and model. `ALL_DEDUPED` is the combined unique set. The `PhishNChips` rows cover the four source files, plus one `all_unique_emails` block that repeats `ALL_DEDUPED` exactly.

| Column | Meaning |
| --- | --- |
| `expected_rows`, `completed_rows`, `failed_rows`, `coverage` | Decisions asked for, answered and missing |
| `true_positive`, `false_positive`, `true_negative`, `false_negative` | Phishing is the positive class |
| `accuracy`, `phishing_precision`, `phishing_recall`, `specificity`, `false_positive_rate`, `f1` | Computed from the counts. Blank when a class is absent from the set |
| `brier_score` | Mean squared error of the model's phishing probability against the label. Lower is better |
| `mean_latency_ms` | Mean client-observed latency of the completed decisions |
| `total_cost_usd`, `cost_available_rows` | Summed cost and the number of decisions that reported one |

## Limits of reproduction

- Hosted models change. Providers can update, re-route or retire a model, so a new run can differ from the recorded one even with the same prompt and data.
- The decisions endpoint is an alpha API and may change.
- Labels are the dataset's own and were not independently checked.
- Latency and cost depend on routing, region, load and pricing on the day.
