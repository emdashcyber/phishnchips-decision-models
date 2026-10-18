# PhishNChips decision models

A static dashboard comparing 12 AI decision models on phishing detection with the PhishNChips email sets. It shows a leaderboard, accuracy against cost and speed, precision against recall, the split of correct and incorrect decisions, and accuracy across every source set.

The run completed 36,131 of 36,132 decisions (12 models on 3,011 unique emails). One Decider Flash V1.2 decision remained rate-limited with HTTP 429 after retries.

## Data

`data/results.csv` is the raw per-model, per-dataset export. `scripts/prepare-data.mjs` turns it into `site/src/data/results.json` (git-ignored) before every dev, build and test run. It:

- drops the repeated `PhishNChips / all_unique_emails` rows after checking they match `ALL_DEDUPED`;
- recomputes rates from the confusion counts, so single-class sets give n/a instead of 0 or NaN;
- scales cost to 1,000 decisions.

To update the results, replace `data/results.csv` with the same columns.

## Reproduce the results

The `eval/` folder has the scripts and the recorded run. See [eval/README.md](eval/README.md) for the full steps.

```sh
python3 eval/summarize_results.py --check     # rebuild the summary from the recorded predictions and compare
python3 eval/prepare_data.py                  # rebuild the 3,011-email corpus from the pinned dataset files
python3 eval/run_models.py --run-models --confirm-send    # repeat the model run (needs OPENROUTER_API_KEY, costs money)
```

Layout:

- `eval/prepare_data.py` downloads, checks and deduplicates the PhishNChips source files.
- `eval/run_models.py` asks each model to label every email and writes predictions and a summary.
- `eval/summarize_results.py` recomputes the summary from predictions without any API calls.
- `eval/published/` holds the recorded run: predictions without email text (gzipped), run metadata and the corpus preparation summary.

## Local development

Requires Node 22.12 or later.

```sh
cd site
npm install
npm run dev      # http://localhost:4321/phishnchips-decision-models/
npm run check    # tests, build and build verification
```

## Publishing

`.github/workflows/publish-pages.yml` builds and deploys `site/dist` to GitHub Pages. Set Pages to deploy from GitHub Actions in the repository settings. The page is served at `https://emdashcyber.com/phishnchips-decision-models/`.
