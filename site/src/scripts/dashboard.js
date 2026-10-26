import data from "../data/results.json";
import { METRICS, PREVALENCES, accuracyInterval, availableMetrics, defaultDirection, highlights, indistinguishable, int, logTicks, niceDomain, paretoFront, pct, placeLabels, rankInbox, shortlist, sortByErrors, sortRows, ticks } from "../lib/model.mjs";

const SVG_NS = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);
const datasets = new Map(data.datasets.map((d) => [d.id, d]));
const modelId = new Map(data.models.map((m) => [m.name, m.id]));
const state = { dataset: "all", sort: "precision", direction: "desc", x: "costPer1k", y: "precision", prevalence: 2, errors: "total" };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function svgEl(tag, attrs = {}, className) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
  if (className) node.setAttribute("class", className);
  return node;
}

const current = () => datasets.get(state.dataset);
const rows = () => data.results[state.dataset];
const columnLabel = (key, kind) => {
  if (key === "accuracy") return kind === "phishing" ? "Detection rate" : kind === "legitimate" ? "Pass rate" : "Accuracy";
  return key === "model" ? "Model" : METRICS[key].label;
};
// Short headings keep the table inside the page width; the full name stays in the tooltip.
const SHORT_HEADINGS = { fpr: "FP rate", brier: "Brier", latencyMs: "Latency", costPer1k: "Cost / 1,000" };
const TABLE_KEYS = ["precision", "accuracy", "recall", "f1", "fpr", "brier", "latencyMs", "costPer1k"];
const Y_KEYS = ["precision", "accuracy", "recall", "f1", "fpr", "brier"];

function renderSummary() {
  const d = current();
  const mix = d.kind === "mixed" ? `${int(d.positives)} phishing, ${int(d.negatives)} legitimate` : d.kind === "phishing" ? "all phishing" : "all legitimate";
  const note = d.kind === "mixed" ? "" : " Single-class set, so metrics that need both classes are hidden.";
  $("dataset-summary").textContent = `${int(d.emails)} emails (${mix}) from ${d.source}.${note}`;
}

function renderMetrics() {
  const target = $("metrics");
  target.replaceChildren();
  for (const item of highlights(rows(), current())) {
    const card = el("article", `metric-card ${item.tone}`.trim());
    card.append(el("span", "metric-label", item.label), el("strong", "metric-value", item.value), el("span", "metric-foot", item.foot));
    target.append(card);
  }
}

function valueCell(row, key, label) {
  const td = el("td", "num");
  td.dataset.label = label;
  const value = row[key];
  if (value === null || value === undefined) td.append(el("span", "na", "n/a"));
  else td.textContent = METRICS[key].format(value);
  return td;
}

function renderLeaderboard() {
  const d = current();
  const keys = TABLE_KEYS.filter((k) => availableMetrics(d.kind).includes(k));
  if (!keys.includes(state.sort) && state.sort !== "model") {
    state.sort = "accuracy";
    state.direction = defaultDirection("accuracy");
  }

  const select = $("sort-select");
  select.replaceChildren();
  for (const key of ["model", ...keys]) select.append(new Option(`Sort by ${columnLabel(key, d.kind).toLowerCase()}`, key, false, key === state.sort));

  const head = $("leaderboard-head");
  head.replaceChildren(Object.assign(el("th", "rank", "#"), { scope: "col" }));
  for (const key of ["model", ...keys]) {
    const th = el("th", key === "model" ? "" : "num");
    th.scope = "col";
    if (state.sort === key) th.setAttribute("aria-sort", state.direction === "asc" ? "ascending" : "descending");
    const button = el("button", "", SHORT_HEADINGS[key] ?? columnLabel(key, d.kind));
    button.type = "button";
    button.title = columnLabel(key, d.kind);
    button.setAttribute("aria-label", `Sort by ${columnLabel(key, d.kind).toLowerCase()}`);
    button.addEventListener("click", () => {
      state.direction = state.sort === key ? (state.direction === "asc" ? "desc" : "asc") : key === "model" ? "asc" : defaultDirection(key);
      state.sort = key;
      renderLeaderboard();
    });
    th.append(button);
    head.append(th);
  }

  const sorted = sortRows(rows(), state.sort, state.direction);
  const body = $("leaderboard-body");
  body.replaceChildren();
  sorted.forEach((row, index) => {
    const tr = el("tr");
    tr.append(el("td", "rank", String(index + 1)));
    const nameCell = el("td");
    nameCell.dataset.label = "Model";
    nameCell.append(el("span", "model-name", row.model), el("span", "model-id", modelId.get(row.model)));
    if (row.failed > 0) {
      const failure = el("span", "status-pill warn", `${row.failed} failed after retries`);
      const explanation = "The failed decision had 3 attempts: the initial request plus 2 retries. All 3 returned HTTP 429, so it was marked failed.";
      failure.title = explanation;
      failure.tabIndex = 0;
      failure.setAttribute("aria-label", `${row.failed} failed after retries. ${explanation}`);
      nameCell.append(failure);
    }
    tr.append(nameCell);
    for (const key of keys) {
      if (key !== keys[0]) {
        tr.append(valueCell(row, key, columnLabel(key, d.kind)));
        continue;
      }
      const td = el("td");
      td.dataset.label = columnLabel(key, d.kind);
      const cell = el("div", "bar-cell");
      const track = el("div", "bar-track");
      const fill = el("div", "bar-fill");
      fill.style.width = `${Math.max(1, (row[key] ?? 0) * 100)}%`;
      track.append(fill);
      cell.append(track, el("span", "bar-value", pct(row[key])));
      td.append(cell);
      tr.append(td);
    }
    body.append(tr);
  });
}

// Models nobody beats on both axes, where the direction of each axis is "better".
function frontNames(points, xBetter, yBetter) {
  const flipped = points.map((p) => ({ ...p, x: xBetter === "low" ? p.x : -p.x, y: yBetter === "low" ? -p.y : p.y }));
  return new Set(paretoFront(flipped).map((p) => p.label));
}

function formatTicks(metric, domain) {
  const fmt = METRICS[metric].format;
  if (fmt !== pct) return fmt;
  const digits = (domain.step * 100) % 1 > 1e-6 ? 1 : 0;
  return (v) => pct(v, digits);
}

function drawScatter(host, readout, { points, xMetric, yMetric }) {
  host.replaceChildren();
  readout.textContent = "";
  const usable = points.filter((p) => p.x !== null && p.y !== null);
  if (usable.length < 2) {
    host.append(el("p", "message-state", "Not enough data for this view on the selected dataset."));
    return;
  }
  const width = Math.max(300, Math.floor(host.clientWidth || 600));
  const height = Math.round(Math.min(540, Math.max(360, width * 0.72)));
  const m = { l: 62, r: 24, t: 30, b: 52 };
  const plotW = width - m.l - m.r;
  const plotH = height - m.t - m.b;

  const domainFor = (key, values) => {
    const lo = Math.min(...values);
    const hi = Math.max(...values);
    const pad = (hi - lo || Math.abs(hi) || 1) * 0.08;
    const d = niceDomain(lo - pad, hi + pad);
    // Keep headroom past 0% and 100% so dots on the limit are not drawn on the axis; ticks stop at the limit.
    d.floor = lo >= 0 ? 0 : -Infinity;
    d.ceil = METRICS[key].format === pct ? 1 : Infinity;
    if (d.min <= d.floor) d.min = d.floor - d.step * 0.4;
    if (d.max > d.ceil) d.max = d.ceil + d.step * 0.4;
    return d;
  };
  const logX = xMetric === "costPer1k";
  const xd = logX ? { min: Math.min(...usable.map((p) => p.x)) / 1.35, max: Math.max(...usable.map((p) => p.x)) * 1.35 } : domainFor(xMetric, usable.map((p) => p.x));
  const yd = domainFor(yMetric, usable.map((p) => p.y));
  const tx = logX ? Math.log10 : (v) => v;
  const sx = (v) => m.l + ((tx(v) - tx(xd.min)) / (tx(xd.max) - tx(xd.min))) * plotW;
  const sy = (v) => m.t + plotH - ((v - yd.min) / (yd.max - yd.min)) * plotH;
  const xFmt = logX ? (v) => `$${Number(v.toPrecision(2))}` : formatTicks(xMetric, xd);
  const yFmt = formatTicks(yMetric, yd);
  const inRange = (d) => (v) => v >= (d.floor ?? -Infinity) - 1e-9 && v <= (d.ceil ?? Infinity) + 1e-9;

  const root = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "group", "aria-label": `${METRICS[yMetric].label} against ${METRICS[xMetric].label.toLowerCase()} for each model` }, "scatter");
  for (const v of ticks(yd).filter(inRange(yd))) {
    root.append(svgEl("line", { x1: m.l, x2: m.l + plotW, y1: sy(v), y2: sy(v) }, "grid"));
    const t = svgEl("text", { x: m.l - 8, y: sy(v) + 4, "text-anchor": "end" });
    t.textContent = yFmt(v);
    root.append(t);
  }
  for (const v of (logX ? logTicks(xd) : ticks(xd).filter(inRange(xd)))) {
    root.append(svgEl("line", { x1: sx(v), x2: sx(v), y1: m.t, y2: m.t + plotH }, "grid"));
    const t = svgEl("text", { x: sx(v), y: m.t + plotH + 18, "text-anchor": "middle" });
    t.textContent = xFmt(v);
    root.append(t);
  }
  root.append(svgEl("line", { x1: m.l, x2: m.l + plotW, y1: m.t + plotH, y2: m.t + plotH }, "axis"));
  root.append(svgEl("line", { x1: m.l, x2: m.l, y1: m.t, y2: m.t + plotH }, "axis"));
  const xTitle = svgEl("text", { x: m.l + plotW / 2, y: height - 8, "text-anchor": "middle" }, "axis-title");
  xTitle.textContent = logX ? `${columnLabel(xMetric, "mixed")} (log scale)` : columnLabel(xMetric, "mixed");
  const yTitle = svgEl("text", { x: 14, y: m.t + plotH / 2, "text-anchor": "middle", transform: `rotate(-90 14 ${m.t + plotH / 2})` }, "axis-title");
  yTitle.textContent = columnLabel(yMetric, "mixed");
  root.append(xTitle, yTitle);

  const onFront = frontNames(usable, METRICS[xMetric].better, METRICS[yMetric].better);
  const line = usable.filter((p) => onFront.has(p.label)).sort((a, b) => a.x - b.x);
  if (line.length > 1) root.append(svgEl("polyline", { points: line.map((p) => `${sx(p.x)},${sy(p.y)}`).join(" ") }, "front"));

  const bounds = { minX: m.l + 2, maxX: width - 2, minY: 2, maxY: m.t + plotH - 2 };
  const placed = placeLabels(usable.map((p) => ({ ...p, x: sx(p.x), y: sy(p.y), source: p })), bounds);
  for (const p of placed) if (p.leader) root.append(svgEl("line", { x1: p.x, y1: p.y, x2: p.leader.x, y2: p.leader.y }, "leader"));
  for (const p of placed) {
    const detail = `${p.label}: ${columnLabel(xMetric, "mixed").toLowerCase()} ${METRICS[xMetric].format(p.source.x)}, ${columnLabel(yMetric, "mixed").toLowerCase()} ${METRICS[yMetric].format(p.source.y)}`;
    const group = svgEl("g", {}, "pt");
    const dot = svgEl("circle", { cx: p.x, cy: p.y, r: 6.5, tabindex: 0, role: "img", "aria-label": detail }, onFront.has(p.label) ? "dot on-front" : "dot");
    const show = () => { readout.textContent = detail; };
    dot.addEventListener("pointerenter", show);
    dot.addEventListener("focus", show);
    dot.addEventListener("click", show);
    const text = svgEl("text", { x: p.labelX, y: p.labelY, "text-anchor": p.anchor }, "point-label");
    text.textContent = p.label;
    group.append(dot, text);
    root.append(group);
  }
  host.append(root);
}

function renderTradeoff() {
  const d = current();
  const yKeys = Y_KEYS.filter((k) => availableMetrics(d.kind).includes(k));
  if (!yKeys.includes(state.y)) state.y = yKeys[0];
  const select = $("y-axis");
  select.replaceChildren();
  for (const key of yKeys) select.append(new Option(columnLabel(key, d.kind), key, false, key === state.y));
  $("x-axis").value = state.x;
  const lowerBetter = METRICS[state.y].better === "low";
  $("tradeoff-hint").textContent = `${lowerBetter ? "Down" : "Up"} and to the left is better.`;
  drawScatter($("tradeoff-chart"), $("tradeoff-readout"), {
    xMetric: state.x,
    yMetric: state.y,
    points: rows().map((r) => ({ label: r.model, x: r[state.x], y: r[state.y] })),
  });
}

function renderPrecisionRecall() {
  const host = $("pr-chart");
  if (current().kind !== "mixed") {
    host.replaceChildren(el("p", "message-state", "Precision and recall need both phishing and legitimate emails. Pick a dataset that has both."));
    $("pr-readout").textContent = "";
    return;
  }
  drawScatter(host, $("pr-readout"), {
    xMetric: "recall",
    yMetric: "precision",
    points: rows().map((r) => ({ label: r.model, x: r.recall, y: r.precision })),
  });
}

function renderStacks() {
  const d = current();
  const target = $("stack-chart");
  target.replaceChildren();
  const options = [["total", "Fewest total errors"]];
  if (d.kind !== "legitimate") options.push(["fn", "Fewest missed phishing"]);
  if (d.kind !== "phishing") options.push(["fp", "Fewest false alarms"]);
  if (!options.some(([key]) => key === state.errors)) state.errors = "total";
  const select = $("stack-sort");
  select.replaceChildren();
  for (const [key, label] of options) select.append(new Option(label, key, false, key === state.errors));
  for (const r of sortByErrors(rows(), state.errors)) {
    const row = el("div", "stack-row");
    const track = el("div", "stack-track");
    track.setAttribute("role", "img");
    track.setAttribute("aria-label", `${r.model}: ${int(r.tp)} phishing caught, ${int(r.tn)} legitimate passed, ${int(r.fp)} false alarms, ${int(r.fn)} phishing missed`);
    for (const [cls, count] of [["seg-tp", r.tp], ["seg-tn", r.tn], ["seg-fp", r.fp], ["seg-fn", r.fn]]) {
      if (!count) continue;
      const seg = el("span", `seg ${cls}`);
      seg.style.width = `${(count / r.completed) * 100}%`;
      track.append(seg);
    }
    const notes = [];
    if (d.kind !== "legitimate") notes.push(`missed ${int(r.fn)}`);
    if (d.kind !== "phishing") notes.push(`false alarms ${int(r.fp)}`);
    if (d.kind === "mixed") notes.push(`total ${int(r.fn + r.fp)}`);
    row.append(el("span", "stack-label", r.model), track, el("span", "stack-note", notes.join(" · ")));
    target.append(row);
  }
}

function renderShortlist() {
  const body = $("shortlist-body");
  body.replaceChildren();
  for (const item of shortlist(rows(), current().kind)) {
    const tr = el("tr");
    const need = el("th", "", item.need);
    need.scope = "row";
    need.dataset.label = "Need";
    const model = el("td", "model-name", item.model);
    model.dataset.label = "Model";
    const result = el("td", "num", item.value);
    result.dataset.label = columnLabel(item.key, current().kind);
    const ties = el("td", "", item.tied ? `+${item.tied} tied` : "");
    ties.dataset.label = "Ties";
    tr.append(need, model, result, ties);
    body.append(tr);
  }
}

function drawIntervals() {
  const host = $("interval-chart");
  const readout = $("interval-readout");
  host.replaceChildren();
  readout.textContent = "";
  const items = sortRows(rows(), "accuracy").map((r) => ({ r, ci: accuracyInterval(r) }));
  const { leader, band, close } = indistinguishable(rows());
  const width = Math.max(300, Math.floor(host.clientWidth || 600));
  const labelW = Math.min(190, Math.round(width * 0.34));
  const m = { l: labelW + 10, r: 22, t: 10, b: 44 };
  const rowH = 30;
  const plotW = width - m.l - m.r;
  const plotH = rowH * items.length;
  const height = m.t + plotH + m.b;
  const lo = Math.min(...items.map((i) => i.ci.low));
  const hi = Math.max(...items.map((i) => i.ci.high));
  const d = niceDomain(lo - (hi - lo) * 0.05, hi + (hi - lo) * 0.05, 4);
  if (d.max > 1) d.max = 1 + d.step * 0.3;
  const sx = (v) => m.l + ((v - d.min) / (d.max - d.min)) * plotW;
  const digits = (d.step * 100) % 1 > 1e-6 ? 1 : 0;

  const root = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "group", "aria-label": "Accuracy with 95% interval for each model" }, "scatter");
  root.append(svgEl("rect", { x: sx(band.low), y: m.t, width: sx(band.high) - sx(band.low), height: plotH }, "leader-band"));
  for (const v of ticks(d).filter((t) => t <= 1 + 1e-9)) {
    root.append(svgEl("line", { x1: sx(v), x2: sx(v), y1: m.t, y2: m.t + plotH }, "grid"));
    const t = svgEl("text", { x: sx(v), y: m.t + plotH + 18, "text-anchor": "middle" });
    t.textContent = pct(v, digits);
    root.append(t);
  }
  root.append(svgEl("line", { x1: m.l, x2: m.l + plotW, y1: m.t + plotH, y2: m.t + plotH }, "axis"));
  const title = svgEl("text", { x: m.l + plotW / 2, y: height - 6, "text-anchor": "middle" }, "axis-title");
  title.textContent = `${columnLabel("accuracy", current().kind)} with 95% interval`;
  root.append(title);

  const maxChars = Math.floor(labelW / 7);
  items.forEach(({ r, ci }, index) => {
    const y = m.t + index * rowH + rowH / 2;
    const overlaps = r === leader || close.includes(r);
    const detail = `${r.model}: ${pct(r.accuracy)}, 95% interval ${pct(ci.low)} to ${pct(ci.high)}`;
    const group = svgEl("g", {}, "pt");
    const label = svgEl("text", { x: m.l - 10, y: y + 4, "text-anchor": "end" }, "row-label");
    label.textContent = r.model.length > maxChars ? `${r.model.slice(0, maxChars - 1)}\u2026` : r.model;
    const whisker = svgEl("line", { x1: sx(ci.low), x2: sx(ci.high), y1: y, y2: y }, "whisker");
    const capLow = svgEl("line", { x1: sx(ci.low), x2: sx(ci.low), y1: y - 5, y2: y + 5 }, "whisker");
    const capHigh = svgEl("line", { x1: sx(ci.high), x2: sx(ci.high), y1: y - 5, y2: y + 5 }, "whisker");
    const dot = svgEl("circle", { cx: sx(r.accuracy), cy: y, r: 6, tabindex: 0, role: "img", "aria-label": detail }, overlaps ? "dot on-front" : "dot");
    const show = () => { readout.textContent = detail; };
    dot.addEventListener("pointerenter", show);
    dot.addEventListener("focus", show);
    dot.addEventListener("click", show);
    group.append(label, whisker, capLow, capHigh, dot);
    root.append(group);
  });
  host.append(root);

  $("interval-note").textContent = close.length
    ? `The shaded band is ${leader.model}'s interval. ${close.length === 1 ? "One model overlaps" : `${close.length} models overlap`} it (green: ${close.map((r) => r.model).join(", ")}), so on this sample they cannot be separated from the leader.`
    : `The shaded band is ${leader.model}'s interval. No other model overlaps it, so the lead is clear on this sample.`;
}

function renderInbox() {
  const prevalence = PREVALENCES[state.prevalence];
  $("prevalence-value").textContent = pct(prevalence, prevalence < 0.01 ? 1 : 0);
  const target = $("inbox-chart");
  target.replaceChildren();
  if (current().kind !== "mixed") {
    target.append(el("p", "message-state", "This needs recall and the false-positive rate, so pick a dataset with both phishing and legitimate emails."));
    return;
  }
  const scored = rankInbox(rows(), prevalence);
  for (const { r, o } of scored) {
    const row = el("div", "stack-row inbox-row");
    const track = el("div", "stack-track");
    track.setAttribute("role", "img");
    track.setAttribute("aria-label", `${r.model}: estimated precision ${pct(o.precision)}, worst case ${pct(o.worst)}`);
    const estimate = el("span", "seg seg-estimate");
    estimate.style.width = `${(o.precision ?? 0) * 100}%`;
    const worst = el("span", "seg seg-worst");
    worst.style.width = `${(o.worst ?? 0) * 100}%`;
    track.append(estimate, worst);
    const note = el("span", "stack-note");
    note.append(
      el("strong", "", `${pct(o.precision)} (worst ${pct(o.worst)})`),
      el("span", "", `${int(o.falseAlarms)} false alarms, ${int(o.missed)} missed per 10,000`),
    );
    row.append(el("span", "stack-label", r.model), track, note);
    target.append(row);
  }
}

function render() {
  renderSummary();
  renderMetrics();
  renderShortlist();
  renderLeaderboard();
  drawIntervals();
  renderTradeoff();
  renderPrecisionRecall();
  renderStacks();
  renderInbox();
}

$("dataset-select").addEventListener("change", (event) => {
  state.dataset = event.target.value;
  render();
});
$("sort-select").addEventListener("change", (event) => {
  state.sort = event.target.value;
  state.direction = state.sort === "model" ? "asc" : defaultDirection(state.sort);
  renderLeaderboard();
});
$("x-axis").addEventListener("change", (event) => {
  state.x = event.target.value;
  renderTradeoff();
});
$("y-axis").addEventListener("change", (event) => {
  state.y = event.target.value;
  renderTradeoff();
});
$("prevalence-range").addEventListener("input", (event) => {
  state.prevalence = Number(event.target.value);
  renderInbox();
});
$("stack-sort").addEventListener("change", (event) => {
  state.errors = event.target.value;
  renderStacks();
});

// Charts are drawn at the container's pixel width, so redraw when it changes.
const widths = new Map();
const observer = new ResizeObserver((entries) => {
  for (const entry of entries) {
    const width = Math.round(entry.contentRect.width);
    if (widths.get(entry.target) === width) continue;
    const first = !widths.has(entry.target);
    widths.set(entry.target, width);
    if (first) continue;
    if (entry.target.id === "tradeoff-chart") renderTradeoff();
    else if (entry.target.id === "interval-chart") drawIntervals();
    else renderPrecisionRecall();
  }
});
observer.observe($("tradeoff-chart"));
observer.observe($("pr-chart"));
observer.observe($("interval-chart"));

render();
