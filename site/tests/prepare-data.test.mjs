import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildData, parseCsv } from "../../scripts/prepare-data.mjs";

const csv = readFileSync(new URL("../../data/results.csv", import.meta.url), "utf8");
const data = buildData(csv);
const find = (id, model) => data.results[id].find((r) => r.model === model);

test("reports 12 models and the 36,131 of 36,132 run total", () => {
  assert.equal(data.models.length, 12);
  assert.equal(data.run.emails, 3011);
  assert.equal(data.run.expected, 36132);
  assert.equal(data.run.completed, 36131);
  assert.equal(data.run.failed, 1);
  assert.deepEqual(data.run.failures, [{ model: "Decider Flash V1.2", failed: 1 }]);
});

test("the duplicate PhishNChips all-emails rows are dropped", () => {
  assert.equal(parseCsv(csv).length, 12 * 6);
  assert.deepEqual(data.datasets.map((d) => d.id), ["all", "core", "cross-domain-legitimate", "infrastructure-phishing", "real-phishing"]);
  for (const id of Object.keys(data.results)) assert.equal(data.results[id].length, 12, id);
});

test("a differing duplicate row is rejected", () => {
  const tampered = csv.replace(/^PhishNChips,all_unique_emails,Clef,cloudflare\/clef,3011,3011,0,1\.0,0\.884/m, "PhishNChips,all_unique_emails,Clef,cloudflare/clef,3011,3011,0,1.0,0.5");
  assert.notEqual(tampered, csv);
  assert.throws(() => buildData(tampered), /differs from ALL_DEDUPED/);
});

test("dataset class mix is derived from the confusion counts", () => {
  const kinds = Object.fromEntries(data.datasets.map((d) => [d.id, d.kind]));
  assert.deepEqual(kinds, { all: "mixed", core: "mixed", "cross-domain-legitimate": "legitimate", "infrastructure-phishing": "phishing", "real-phishing": "phishing" });
  const all = data.datasets[0];
  assert.equal(all.positives + all.negatives, all.emails);
  assert.equal(all.positives, 2011);
});

test("rates recomputed from counts match the CSV on mixed sets", () => {
  const rows = parseCsv(csv).filter((r) => r.dataset === "ALL_DEDUPED" || r.source_file === "core_emails.csv");
  for (const row of rows) {
    const id = row.dataset === "ALL_DEDUPED" ? "all" : "core";
    const r = find(id, row.model_name);
    for (const [csvKey, key] of [["accuracy", "accuracy"], ["phishing_precision", "precision"], ["phishing_recall", "recall"], ["specificity", "specificity"], ["false_positive_rate", "fpr"], ["f1", "f1"]]) {
      assert.ok(Math.abs(Number(row[csvKey]) - r[key]) < 1e-9, `${id} ${row.model_name} ${key}`);
    }
  }
});

test("metrics undefined for a single-class set are null, not zero or NaN", () => {
  const legit = find("cross-domain-legitimate", "Clef");
  assert.equal(legit.recall, null);
  assert.equal(legit.precision, null);
  assert.equal(legit.f1, null);
  assert.ok(Math.abs(legit.fpr - 11 / 333) < 1e-12);
  const phishing = find("real-phishing", "Clef");
  assert.equal(phishing.fpr, null);
  assert.equal(phishing.specificity, null);
  assert.equal(phishing.precision, null);
  assert.ok(Math.abs(phishing.recall - 990 / 998) < 1e-12);
});

test("failed rows keep their completed count and cost is scaled to 1,000 decisions", () => {
  const flash = find("all", "Decider Flash V1.2");
  assert.equal(flash.completed, 3010);
  assert.equal(flash.failed, 1);
  assert.equal(flash.tp + flash.fp + flash.tn + flash.fn, 3010);
  assert.ok(Math.abs(flash.costPer1k - (0.01626536 / 3010) * 1000) < 1e-12);
});

test("every number in the output is finite or null", () => {
  for (const rows of Object.values(data.results)) {
    for (const row of rows) for (const value of Object.values(row)) assert.ok(value === null || typeof value === "string" || Number.isFinite(value));
  }
});

test("method facts come from the recorded run files and agree with the results", async () => {
  const { readRecorded } = await import("../../scripts/prepare-data.mjs");
  const withMethod = buildData(csv, readRecorded());
  assert.equal(withMethod.method.included, 3011);
  assert.equal(withMethod.method.sourceRows, 3387);
  assert.equal(withMethod.method.blank + withMethod.method.duplicates, 3387 - 3011);
  assert.equal(withMethod.method.phishing, 2011);
  assert.equal(withMethod.method.legitimate, 1000);
  assert.equal(withMethod.method.revision, "89afcc39610084298c4679159cb2e27d9ffffa46");
  assert.equal(withMethod.method.runDate, "2026-10-18");
});

test("run metadata that disagrees with the CSV is rejected", async () => {
  const { readRecorded } = await import("../../scripts/prepare-data.mjs");
  const recorded = readRecorded();
  recorded.metadata.expected_model_decisions = 1;
  assert.throws(() => buildData(csv, recorded), /does not match/);
});
