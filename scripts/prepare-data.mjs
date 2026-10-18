// Turns the PhishNChips results CSV into the JSON bundled by the dashboard.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = new URL("../", import.meta.url);

const DATASETS = [
  { id: "all", dataset: "ALL_DEDUPED", file: "all_unique_emails", label: "All unique emails" },
  { id: "core", dataset: "PhishNChips", file: "core_emails.csv", label: "Core emails" },
  { id: "cross-domain-legitimate", dataset: "PhishNChips", file: "cross_domain_legitimate_v5.csv", label: "Cross-domain legitimate (v5)" },
  { id: "infrastructure-phishing", dataset: "PhishNChips", file: "infrastructure_phishing_expanded.csv", label: "Infrastructure phishing (expanded)" },
  { id: "real-phishing", dataset: "PhishNChips", file: "real_phishing_validation.csv", label: "Real phishing validation" },
];

// The PhishNChips/all_unique_emails rows repeat ALL_DEDUPED, so they are checked and dropped.
const DUPLICATE = { dataset: "PhishNChips", file: "all_unique_emails" };

const COLUMNS = [
  "dataset", "source_file", "model_name", "model_id", "expected_rows", "completed_rows", "failed_rows", "coverage",
  "accuracy", "phishing_precision", "phishing_recall", "specificity", "false_positive_rate", "f1",
  "true_positive", "false_positive", "true_negative", "false_negative", "brier_score", "mean_latency_ms",
  "total_cost_usd", "cost_available_rows",
];

const fail = (message) => {
  throw new Error(`PhishNChips results: ${message}`);
};

export function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
  const header = lines.shift()?.split(",") ?? [];
  if (header.join() !== COLUMNS.join()) fail("unexpected CSV header");
  return lines.map((line, i) => {
    const cells = line.split(",");
    if (cells.length !== COLUMNS.length) fail(`row ${i + 2} has ${cells.length} columns`);
    return Object.fromEntries(COLUMNS.map((name, c) => [name, cells[c]]));
  });
}

const ratio = (top, bottom) => (bottom > 0 ? top / bottom : null);

// Rates come from the confusion counts so single-class sets report n/a, not 0 or NaN.
function toResult(row) {
  const tp = Number(row.true_positive);
  const fp = Number(row.false_positive);
  const tn = Number(row.true_negative);
  const fn = Number(row.false_negative);
  const completed = Number(row.completed_rows);
  if (tp + fp + tn + fn !== completed) fail(`${row.model_name} / ${row.source_file}: counts do not sum to completed rows`);
  // Precision and F1 only mean something when the set holds both classes.
  const mixed = tp + fn > 0 && fp + tn > 0;
  const precision = mixed ? ratio(tp, tp + fp) : null;
  const recall = ratio(tp, tp + fn);
  const costRows = Number(row.cost_available_rows);
  const costUsd = Number(row.total_cost_usd);
  return {
    model: row.model_name,
    expected: Number(row.expected_rows),
    completed,
    failed: Number(row.failed_rows),
    tp, fp, tn, fn,
    accuracy: ratio(tp + tn, completed),
    precision,
    recall,
    specificity: ratio(tn, tn + fp),
    fpr: ratio(fp, fp + tn),
    f1: precision === null || recall === null ? null : precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0,
    brier: Number(row.brier_score),
    latencyMs: Number(row.mean_latency_ms),
    costUsd,
    costPer1k: costRows > 0 ? (costUsd / costRows) * 1000 : null,
  };
}

const kindOf = (positives, negatives) => (positives > 0 && negatives > 0 ? "mixed" : positives > 0 ? "phishing" : "legitimate");

// Method facts come from the recorded run files so the page cannot drift from them.
export function methodFrom({ preparation, metadata }) {
  const revisions = [...new Set(preparation.sources.map((s) => s.revision))];
  if (revisions.length !== 1) fail("sources are not pinned to one dataset revision");
  return {
    revision: revisions[0],
    sourceRows: preparation.total_source_rows,
    included: preparation.included_rows,
    blank: preparation.excluded_blank_required_field,
    duplicates: preparation.excluded_exact_duplicates,
    phishing: preparation.included_label_counts.PHISHING,
    legitimate: preparation.included_label_counts.LEGITIMATE,
    runDate: metadata.run_date_utc.slice(0, 10),
    expectedDecisions: metadata.expected_model_decisions,
    emails: metadata.emails_in_run_scope,
  };
}

export function buildData(csvText, recorded = null) {
  const rows = parseCsv(csvText);
  const byDataset = new Map(DATASETS.map((d) => [d.id, rows.filter((r) => r.dataset === d.dataset && r.source_file === d.file)]));
  const duplicates = rows.filter((r) => r.dataset === DUPLICATE.dataset && r.source_file === DUPLICATE.file);
  const all = byDataset.get("all");
  for (const row of duplicates) {
    const twin = all.find((r) => r.model_name === row.model_name);
    if (!twin || COLUMNS.some((c) => c !== "dataset" && twin[c] !== row[c])) fail(`${row.model_name}: duplicate all_unique_emails row differs from ALL_DEDUPED`);
  }
  const listed = new Set([...byDataset.values()].flat());
  const unknown = rows.filter((r) => !listed.has(r) && !duplicates.includes(r));
  if (unknown.length) fail(`unrecognised dataset ${unknown[0].dataset}/${unknown[0].source_file}`);

  const results = {};
  const datasets = [];
  for (const d of DATASETS) {
    const sourceRows = byDataset.get(d.id);
    if (!sourceRows.length) fail(`no rows for ${d.id}`);
    results[d.id] = sourceRows.map(toResult);
    const first = results[d.id][0];
    const positives = first.tp + first.fn;
    const negatives = first.fp + first.tn;
    const emails = first.expected;
    datasets.push({ id: d.id, label: d.label, source: d.file, emails, positives, negatives, kind: kindOf(positives, negatives) });
  }

  const names = results.all.map((r) => r.model);
  for (const d of DATASETS) {
    const got = results[d.id].map((r) => r.model);
    if (got.length !== names.length || got.some((n) => !names.includes(n))) fail(`${d.id}: model list differs from the main set`);
  }
  const models = all.map((r) => ({ name: r.model_name, id: r.model_id, vendor: r.model_id.split("/")[0] }));
  const expected = results.all.reduce((sum, r) => sum + r.expected, 0);
  const completed = results.all.reduce((sum, r) => sum + r.completed, 0);
  const failures = results.all.filter((r) => r.failed > 0).map((r) => ({ model: r.model, failed: r.failed }));
  const method = recorded ? methodFrom(recorded) : null;
  if (method && (method.expectedDecisions !== expected || method.emails !== results.all[0].expected || method.included !== method.emails)) {
    fail("recorded run metadata does not match the results CSV");
  }

  return {
    run: { models: models.length, emails: results.all[0].expected, expected, completed, failed: expected - completed, failures },
    method,
    datasets,
    models,
    results,
  };
}

export function readRecorded() {
  const read = (name) => JSON.parse(readFileSync(new URL(`eval/published/${name}`, root), "utf8"));
  return { preparation: read("preparation_summary.json"), metadata: read("run_metadata.json") };
}

export function prepare() {
  const csv = readFileSync(new URL("data/results.csv", root), "utf8");
  const out = fileURLToPath(new URL("site/src/data/results.json", root));
  mkdirSync(dirname(out), { recursive: true });
  const data = buildData(csv, readRecorded());
  writeFileSync(out, `${JSON.stringify(data)}\n`);
  return data;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const data = prepare();
  console.log(`Prepared ${data.run.models} models, ${data.run.completed}/${data.run.expected} decisions.`);
}
