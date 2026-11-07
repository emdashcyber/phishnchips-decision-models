import { PREVALENCES, availableMetrics, defaultDirection } from "./model.mjs";
export const TABLE_KEYS = ["precision", "accuracy", "recall", "f1", "fpr", "brier", "latencyMs", "costPer1k"];
export const Y_KEYS = ["precision", "accuracy", "recall", "f1", "fpr", "brier"];
export const defaults = { dataset: "all", sort: "precision", direction: "desc", x: "costPer1k", y: "precision", prevalence: 0.01, errors: "total" };
export function normalizeView(input, datasets) {
  const view = { ...defaults, ...input };
  const dataset = datasets.find(d => d.id === view.dataset) || datasets.find(d => d.id === defaults.dataset);
  view.dataset = dataset.id;
  const metrics = availableMetrics(dataset.kind);
  if (!["model", ...TABLE_KEYS.filter(key => metrics.includes(key))].includes(view.sort)) {
    view.sort = "accuracy"; view.direction = defaultDirection("accuracy");
  }
  if (!["asc", "desc"].includes(view.direction)) view.direction = view.sort === "model" ? "asc" : defaultDirection(view.sort);
  if (!["costPer1k", "latencyMs"].includes(view.x)) view.x = defaults.x;
  if (!Y_KEYS.filter(key => metrics.includes(key)).includes(view.y)) view.y = Y_KEYS.find(key => metrics.includes(key));
  view.prevalence = Number(view.prevalence);
  if (!PREVALENCES.includes(view.prevalence)) view.prevalence = defaults.prevalence;
  if (!["total", ...(dataset.kind !== "legitimate" ? ["fn"] : []), ...(dataset.kind !== "phishing" ? ["fp"] : [])].includes(view.errors)) view.errors = "total";
  return view;
}
export function parseView(params, datasets) {
  return normalizeView(Object.fromEntries(Object.keys(defaults).filter(key => params.has(key)).map(key => [key, params.get(key)])), datasets);
}
export function viewURL(input, view) {
  const url = new URL(input);
  for (const key of Object.keys(defaults)) {
    url.searchParams.delete(key);
    if (view[key] !== defaults[key]) url.searchParams.set(key, String(view[key]));
  }
  return url.pathname + url.search + url.hash;
}
