import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { accuracyInterval, availableMetrics, best, highlights, indistinguishable, inboxOutcome, int, logTicks, niceDomain, paretoFront, pct, placeLabels, rankInbox, shortlist, sortByErrors, sortRows, ticks, usd, wilson } from "../src/lib/model.mjs";

const data = JSON.parse(readFileSync(new URL("../src/data/results.json", import.meta.url), "utf8"));
const rows = data.results.all;

test("formatters render n/a for missing values", () => {
  assert.equal(pct(null), "n/a");
  assert.equal(pct(0.88442, 1), "88.4%");
  assert.equal(int(36131), "36,131");
  assert.equal(usd(0.0054), "$0.0054");
  assert.equal(usd(0.1376), "$0.138");
});

test("sortRows puts missing values last in either direction", () => {
  const sample = [{ model: "a", f1: null, accuracy: 0.5 }, { model: "b", f1: 0.2, accuracy: 0.4 }, { model: "c", f1: 0.9, accuracy: 0.3 }];
  assert.deepEqual(sortRows(sample, "f1", "desc").map((r) => r.model), ["c", "b", "a"]);
  assert.deepEqual(sortRows(sample, "f1", "asc").map((r) => r.model), ["b", "c", "a"]);
  assert.deepEqual(sortRows(sample, "model", "asc").map((r) => r.model), ["a", "b", "c"]);
});

test("best keeps every tied model", () => {
  const zeroFp = best(rows, "fpr");
  assert.equal(zeroFp.value, 0);
  assert.deepEqual(zeroFp.rows.map((r) => r.model).sort(), ["Drex v2.0", "GPT-6 Luna Decisions", "Jev 1.14", "Mercury Decide", "Microsoft Decision-1"]);
  assert.equal(best(rows, "accuracy").rows[0].model, "Clef");
});

test("highlights describe the main set", () => {
  const items = highlights(rows, data.datasets[0]);
  const byLabel = Object.fromEntries(items.map((i) => [i.label, i]));
  assert.equal(byLabel["Best accuracy"].foot, "Clef");
  assert.equal(byLabel["Zero false positives"].value, "5 of 12");
  assert.ok(!("Best F1" in byLabel));
  assert.ok(!("Decisions completed" in byLabel));
});

test("single-class sets drop metrics that need both classes", () => {
  assert.ok(!availableMetrics("phishing").includes("fpr"));
  assert.ok(!availableMetrics("phishing").includes("precision"));
  assert.ok(!availableMetrics("legitimate").includes("recall"));
  assert.ok(availableMetrics("mixed").includes("f1"));
  const legit = data.datasets.find((d) => d.kind === "legitimate");
  assert.ok(!highlights(data.results[legit.id], legit).some((i) => i.label === "Best F1"));
});

test("paretoFront keeps points not beaten on both axes", () => {
  const front = paretoFront([{ x: 1, y: 1, label: "a" }, { x: 2, y: 3, label: "b" }, { x: 3, y: 2, label: "c" }, { x: 4, y: 5, label: "d" }]);
  assert.deepEqual(front.map((p) => p.label), ["a", "b", "d"]);
});

test("niceDomain and ticks land on round numbers", () => {
  const d = niceDomain(0.53, 0.97);
  assert.ok(d.min <= 0.53 && d.max >= 0.97);
  assert.deepEqual(ticks({ min: 0, max: 0.3, step: 0.1 }), [0, 0.1, 0.2, 0.3]);
});

test("logTicks gives 1-2-5 steps inside the range", () => {
  assert.deepEqual(logTicks({ min: 0.004, max: 0.2 }), [0.005, 0.01, 0.02, 0.05, 0.1, 0.2]);
});

test("ticks start on a round number when the domain has headroom", () => {
  assert.deepEqual(ticks({ min: -0.0025, max: 0.0125, step: 0.005 }), [0, 0.005, 0.01]);
});

test("placeLabels keeps labels inside the chart and apart", () => {
  const bounds = { minX: 0, maxX: 300, minY: 0, maxY: 200 };
  const placed = placeLabels([{ label: "Alpha", x: 50, y: 50 }, { label: "Beta", x: 54, y: 52 }, { label: "Gamma", x: 295, y: 100 }], bounds);
  assert.equal(placed.length, 3);
  assert.notDeepEqual([placed[0].labelX, placed[0].labelY], [placed[1].labelX, placed[1].labelY]);
  assert.equal(placed[2].anchor, "end");
  for (const p of placed) assert.ok(p.labelX >= 0 && p.labelX <= 300 + 1);
});

test("wilson interval matches known values and stays within 0..1", () => {
  const half = wilson(5, 10);
  assert.ok(Math.abs(half.low - 0.2366) < 1e-3 && Math.abs(half.high - 0.7634) < 1e-3);
  const none = wilson(0, 1000);
  assert.equal(none.low, 0);
  assert.ok(none.high > 0.003 && none.high < 0.005);
  assert.equal(wilson(1000, 1000).high, 1);
  assert.deepEqual(wilson(0, 0), { low: null, high: null });
});

test("accuracy intervals bracket the point estimate", () => {
  for (const row of rows) {
    const ci = accuracyInterval(row);
    assert.ok(ci.low <= row.accuracy && row.accuracy <= ci.high, row.model);
  }
});

test("indistinguishable finds models overlapping the leader", () => {
  const { leader, close } = indistinguishable(rows);
  assert.equal(leader.model, "Clef");
  assert.ok(!close.some((r) => r.model === "Mercury Decide"));
  const tight = [{ model: "a", tp: 990, tn: 990, completed: 2000, accuracy: 0.99 }, { model: "b", tp: 988, tn: 990, completed: 2000, accuracy: 0.989 }];
  assert.deepEqual(indistinguishable(tight).close.map((r) => r.model), ["b"]);
});

test("inboxOutcome scales precision to a rarer phishing share", () => {
  const clef = rows.find((r) => r.model === "Clef");
  const one = inboxOutcome(clef, 0.01);
  assert.ok(Math.abs(one.precision - (0.01 * clef.recall) / (0.01 * clef.recall + 0.99 * clef.fpr)) < 1e-12);
  assert.ok(one.precision < 0.1);
  assert.ok(Math.abs(one.falseAlarms - 9900 * clef.fpr) < 1e-9);
  assert.ok(Math.abs(one.missed - 100 * (1 - clef.recall)) < 1e-9);
  const clean = inboxOutcome(rows.find((r) => r.model === "Jev 1.14"), 0.01);
  assert.equal(clean.precision, 1);
  assert.ok(clean.worst < 1 && clean.worst > 0.5);
  assert.equal(inboxOutcome(data.results["real-phishing"][0], 0.01), null);
});

test("shortlist names one winner per need and reports ties", () => {
  const items = shortlist(rows, "mixed");
  const needs = items.map((i) => i.need);
  const list = Object.fromEntries(items.map((i) => [i.need, i]));
  assert.deepEqual(needs, ["Trusted alerts", "Catching phishing", "Speed", "Lowest cost", "Probability quality"]);
  assert.ok(!needs.includes("Fewest errors"));
  assert.ok(!needs.includes("Avoiding false alarms"));
  assert.equal(list["Catching phishing"].model, "Clef");
  assert.equal(list["Trusted alerts"].tied, 4);
  assert.equal(list["Lowest cost"].model, "Decider Flash V1.2");
  assert.equal(shortlist(data.results["real-phishing"], "phishing").some((i) => i.need === "Avoiding false alarms"), false);
});

test("rankInbox splits models tied at 100% precision by their worst case", () => {
  const ranked = rankInbox(rows, 0.01).map((s) => s.r.model);
  assert.deepEqual(ranked.slice(0, 5), ["Jev 1.14", "GPT-6 Luna Decisions", "Drex v2.0", "Microsoft Decision-1", "Mercury Decide"]);
  assert.equal(ranked.at(-1), "Clef");
});

test("precision comes before accuracy in cards and metric order", () => {
  const labels = highlights(rows, data.datasets[0]).map((i) => i.label);
  assert.ok(labels.indexOf("Best precision") !== -1 && labels.indexOf("Best precision") < labels.indexOf("Best accuracy"));
  const card = highlights(rows, data.datasets[0]).find((i) => i.label === "Best precision");
  assert.equal(card.value, "100.0%");
  assert.equal(card.foot, "Jev 1.14 and 4 tied");
  const needs = shortlist(rows, "mixed").map((i) => i.need);
  assert.equal(needs[0], "Trusted alerts");
  assert.ok(availableMetrics("mixed").indexOf("precision") < availableMetrics("mixed").indexOf("accuracy"));
  const single = data.datasets.find((d) => d.kind === "phishing");
  assert.ok(!highlights(data.results[single.id], single).some((i) => i.label === "Best precision"));
});

test("sortByErrors orders by total errors, missed or false alarms", () => {
  const total = sortByErrors(rows, "total").map((r) => r.model);
  assert.deepEqual(total.slice(0, 5), ["Clef", "d1-ultra", "Clef Omni", "Jev 1.14", "Clef Flash"]);
  const missed = sortByErrors(rows, "fn").map((r) => r.model);
  assert.deepEqual(missed.slice(0, 5), ["Clef", "d1-ultra", "Clef Flash", "Clef Omni", "Jev 1.14"]);
  const alarms = sortByErrors(rows, "fp").map((r) => r.model);
  assert.equal(alarms.at(-1), "Clef");
  assert.equal(alarms[0], "Jev 1.14");
});
