// Pure helpers shared by the dashboard script and its tests.

export const pct = (value, digits = 1) => (value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(digits)}%`);
export const int = (value) => (value === null || value === undefined ? "n/a" : Math.round(value).toLocaleString("en-AU"));
export const usd = (value) => (value === null || value === undefined ? "n/a" : `$${value.toFixed(value < 0.01 ? 4 : value < 1 ? 3 : 2)}`);
export const ms = (value) => (value === null || value === undefined ? "n/a" : `${Math.round(value)} ms`);
export const decimal = (value) => (value === null || value === undefined ? "n/a" : value.toFixed(3));

export const METRICS = {
  precision: { label: "Precision", better: "high", format: pct },
  accuracy: { label: "Accuracy", better: "high", format: pct },
  recall: { label: "Recall", better: "high", format: pct },
  f1: { label: "F1", better: "high", format: pct },
  fpr: { label: "False-positive rate", better: "low", format: pct },
  brier: { label: "Brier score", better: "low", format: decimal },
  latencyMs: { label: "Mean latency", better: "low", format: ms },
  costPer1k: { label: "Cost per 1,000 decisions", better: "low", format: usd },
};

export const defaultDirection = (key) => (METRICS[key]?.better === "low" ? "asc" : "desc");

// Missing values always sort last so n/a never outranks a real score.
export function sortRows(rows, key, direction = defaultDirection(key)) {
  const sign = direction === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = key === "model" ? a.model : a[key];
    const y = key === "model" ? b.model : b[key];
    if ((x === null) !== (y === null)) return x === null ? 1 : -1;
    if (x !== null && x !== y) return (typeof x === "string" ? x.localeCompare(y) : x - y) * sign;
    return (b.accuracy ?? 0) - (a.accuracy ?? 0) || a.model.localeCompare(b.model);
  });
}

// Returns every row tied for best, so ties (such as zero false positives) are not hidden.
export function best(rows, key) {
  const better = METRICS[key].better;
  const scored = rows.filter((r) => r[key] !== null && r[key] !== undefined);
  if (!scored.length) return { value: null, rows: [] };
  const value = (better === "low" ? Math.min : Math.max)(...scored.map((r) => r[key]));
  return { value, rows: scored.filter((r) => r[key] === value) };
}

export const names = (rows, limit = 2) => (rows.length > limit ? `${rows.length} models tied` : rows.map((r) => r.model).join(", "));

// Metrics that carry meaning for a dataset: precision and F1 need both classes.
export function availableMetrics(kind) {
  const all = Object.keys(METRICS);
  if (kind === "mixed") return all;
  const bothClasses = ["precision", "f1"];
  if (kind === "phishing") return all.filter((k) => k !== "fpr" && !bothClasses.includes(k));
  return all.filter((k) => k !== "recall" && !bothClasses.includes(k));
}

export function highlights(rows, dataset) {
  const items = [];
  const accuracy = best(rows, "accuracy");
  const cost = best(rows, "costPer1k");
  const speed = best(rows, "latencyMs");
  items.push({ label: "Models compared", value: String(rows.length), foot: `${int(dataset.emails)} emails each`, tone: "accent" });
  if (dataset.kind === "mixed") {
    const precision = best(rows, "precision");
    const lead = sortRows(precision.rows, "accuracy", "desc")[0];
    items.push({
      label: "Best precision",
      value: pct(precision.value),
      foot: precision.rows.length > 1 ? `${lead.model} and ${precision.rows.length - 1} tied` : lead.model,
      tone: "good",
    });
  }
  items.push({
    label: dataset.kind === "phishing" ? "Best detection rate" : dataset.kind === "legitimate" ? "Best legitimate pass rate" : "Best accuracy",
    value: pct(accuracy.value),
    foot: names(accuracy.rows),
    tone: "good",
  });
  if (dataset.kind === "mixed") {
    const f1 = best(rows, "f1");
    items.push({ label: "Best F1", value: pct(f1.value), foot: names(f1.rows), tone: "good" });
  }
  if (dataset.kind !== "phishing") {
    const clean = rows.filter((r) => r.fp === 0);
    items.push({
      label: "Zero false positives",
      value: `${clean.length} of ${rows.length}`,
      foot: clean.length ? "observed, which is not proof of a 0% rate" : "every model flagged a legitimate email",
      tone: clean.length ? "good" : "warn",
    });
  }
  items.push({ label: "Lowest cost per 1,000", value: usd(cost.value), foot: names(cost.rows), tone: "" });
  items.push({ label: "Fastest mean latency", value: ms(speed.value), foot: names(speed.rows), tone: "" });
  const completed = rows.reduce((sum, r) => sum + r.completed, 0);
  const expected = rows.reduce((sum, r) => sum + r.expected, 0);
  items.push({
    label: "Decisions completed",
    value: `${int(completed)} / ${int(expected)}`,
    foot: completed === expected ? "no failed decisions" : `${int(expected - completed)} failed after retries`,
    tone: completed === expected ? "" : "warn",
  });
  return items;
}

// Points not beaten on both axes: lower x and higher y.
export function paretoFront(points) {
  const sorted = [...points].sort((a, b) => a.x - b.x || b.y - a.y);
  const front = [];
  let top = -Infinity;
  for (const point of sorted) {
    if (point.y > top) {
      front.push(point);
      top = point.y;
    }
  }
  return front;
}

// Rounds a padded range outward to a tidy step so axis ticks land on round numbers.
export function niceDomain(min, max, steps = 5) {
  if (min === max) return { min: min - 0.5, max: max + 0.5, step: 0.1 };
  const raw = (max - min) / steps;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((s) => s >= raw);
  return { min: Math.floor(min / step) * step, max: Math.ceil(max / step) * step, step };
}

export function ticks({ min, max, step }) {
  const out = [];
  for (let v = Math.ceil(min / step - 1e-9) * step; v <= max + step / 1e6; v += step) out.push(Number(v.toPrecision(12)));
  return out;
}

// Round-number ticks (1, 2, 5 per decade) for a log axis.
export function logTicks({ min, max }) {
  const out = [];
  for (let exp = Math.floor(Math.log10(min)); exp <= Math.ceil(Math.log10(max)); exp += 1) {
    for (const m of [1, 2, 5]) {
      const v = Number((m * 10 ** exp).toPrecision(12));
      if (v >= min && v <= max) out.push(v);
    }
  }
  return out;
}

// Crowded points choose first; each label takes the nearest free spot clear of other labels and dots.
export function placeLabels(points, bounds, charWidth = 7.2, height = 16) {
  const dots = points.map((p) => ({ x: p.x - 8, y: p.y - 8, w: 16, h: 16 }));
  const placed = [];
  const overlap = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
  const inside = (b) => b.x >= bounds.minX && b.x + b.w <= bounds.maxX && b.y >= bounds.minY && b.y + b.h <= bounds.maxY;
  const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);
  const crowd = points.map((p) => points.filter((q) => q !== p && Math.hypot(q.x - p.x, q.y - p.y) < 60).length);
  const order = points.map((_, i) => i).sort((a, b) => crowd[b] - crowd[a] || a - b);
  const out = new Array(points.length);
  for (const index of order) {
    const p = points[index];
    const w = p.label.length * charWidth;
    const h = height;
    let chosen = null;
    for (const r of crowd[index] >= 2 ? [32, 46, 62, 82, 106, 134] : [10, 22, 36, 52, 72, 96, 124]) {
      const d = r * 0.7;
      const spots = [
        { anchor: "start", x: p.x + r, y: p.y - h / 2 },
        { anchor: "end", x: p.x - r - w, y: p.y - h / 2 },
        { anchor: "middle", x: p.x - w / 2, y: p.y - r - h },
        { anchor: "middle", x: p.x - w / 2, y: p.y + r },
        { anchor: "start", x: p.x + d, y: p.y - d - h },
        { anchor: "start", x: p.x + d, y: p.y + d },
        { anchor: "end", x: p.x - d - w, y: p.y - d - h },
        { anchor: "end", x: p.x - d - w, y: p.y + d },
        { anchor: "start", x: p.x + r, y: p.y - h * 1.5 },
        { anchor: "start", x: p.x + r, y: p.y + h * 0.5 },
        { anchor: "end", x: p.x - r - w, y: p.y - h * 1.5 },
        { anchor: "end", x: p.x - r - w, y: p.y + h * 0.5 },
      ].map((s) => ({ ...s, box: { x: s.x, y: s.y, w, h }, leader: r > 10 }));
      chosen = spots.find((s) => inside(s.box) && !placed.some((o) => overlap(o, s.box)) && !dots.some((o) => overlap(o, s.box)));
      if (chosen) break;
    }
    const spot = chosen ?? { anchor: "start", box: { x: p.x + 10, y: p.y - h / 2, w, h }, leader: false };
    placed.push(spot.box);
    const { box } = spot;
    out[index] = {
      ...p,
      labelX: spot.anchor === "start" ? box.x : spot.anchor === "end" ? box.x + w : box.x + w / 2,
      labelY: box.y + h - 4,
      anchor: spot.anchor,
      leader: spot.leader ? { x: clamp(p.x, box.x, box.x + w), y: clamp(p.y, box.y, box.y + h) } : null,
    };
  }
  return out;
}

// 95% Wilson score interval for a proportion.
export function wilson(successes, n, z = 1.96) {
  if (!(n > 0)) return { low: null, high: null };
  const p = successes / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { low: Math.max(0, centre - half), high: Math.min(1, centre + half) };
}

export const accuracyInterval = (row) => wilson(row.tp + row.tn, row.completed);

// Models whose accuracy interval overlaps the leader's cannot be separated on this sample.
export function indistinguishable(rows) {
  const scored = rows.map((row) => ({ row, ci: accuracyInterval(row) }));
  const lead = scored.reduce((a, b) => (b.row.accuracy > a.row.accuracy ? b : a));
  return { leader: lead.row, band: lead.ci, close: scored.filter((s) => s !== lead && s.ci.high >= lead.ci.low).map((s) => s.row) };
}

export const PREVALENCES = [0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5];

// Scales a model's recall and false-positive rate to a mailbox with the given share of phishing.
export function inboxOutcome(row, prevalence, mailbox = 10000) {
  if (row.recall === null || row.fpr === null) return null;
  const precisionAt = (fpr) => {
    const caught = prevalence * row.recall;
    const wrong = (1 - prevalence) * fpr;
    return caught + wrong > 0 ? caught / (caught + wrong) : null;
  };
  // Zero observed false positives still allows a small true rate, so the worst case uses the upper bound.
  const worstFpr = wilson(row.fp, row.fp + row.tn).high;
  return {
    precision: precisionAt(row.fpr),
    worst: precisionAt(worstFpr),
    falseAlarms: mailbox * (1 - prevalence) * row.fpr,
    missed: mailbox * prevalence * (1 - row.recall),
  };
}

// Best first by estimated precision; ties (such as several at 100%) are split by the worst case.
export function rankInbox(rows, prevalence) {
  return rows
    .map((r) => ({ r, o: inboxOutcome(r, prevalence) }))
    .filter((s) => s.o)
    .sort((a, b) => (b.o.precision ?? -1) - (a.o.precision ?? -1) || (b.o.worst ?? -1) - (a.o.worst ?? -1) || a.r.model.localeCompare(b.r.model));
}

// Best first on one kind of error, with total errors then name as tie-breaks.
export function sortByErrors(rows, key = "total") {
  const count = (r, k) => (k === "total" ? r.fn + r.fp : r[k]);
  return [...rows].sort((a, b) => count(a, key) - count(b, key) || count(a, "total") - count(b, "total") || a.model.localeCompare(b.model));
}

const NEEDS = [
  ["Trusted alerts", "precision"],
  ["Fewest errors", "accuracy"],
  ["Catching phishing", "recall"],
  ["Avoiding false alarms", "fpr"],
  ["Speed", "latencyMs"],
  ["Lowest cost", "costPer1k"],
  ["Probability quality", "brier"],
];

// One winner per need; ties go to the more accurate model and the tie count is reported.
export function shortlist(rows, kind) {
  const usable = availableMetrics(kind);
  return NEEDS.filter(([, key]) => usable.includes(key)).map(([need, key]) => {
    const { value, rows: tied } = best(rows, key);
    return { need, key, model: sortRows(tied, "accuracy", "desc")[0].model, value: METRICS[key].format(value), tied: tied.length - 1 };
  });
}
