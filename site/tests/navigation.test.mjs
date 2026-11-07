import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import * as model from '../src/lib/model.mjs';
import * as view from '../src/lib/view-state.mjs';
import { browser } from './browser.mjs';
const data = JSON.parse(fs.readFileSync(new URL('../src/data/results.json', import.meta.url)));
const source = fs.readFileSync(new URL('../src/scripts/dashboard.js', import.meta.url), 'utf8').replace(/^import .*;\n/gm, '');
function setup(url) {
  const b = browser(url); let observer;
  class ResizeObserver { constructor(callback) { this.callback = callback; observer = this; } observe(target) { this.callback([{ target, contentRect: { width: target.clientWidth } }]); } }
  vm.runInNewContext(source, { ...model, ...view, ...b, data, ResizeObserver, URL, console });
  return { ...b, resize(id, width) { const target = b.el(id); target.clientWidth = width; observer.callback([{ target, contentRect: { width } }]); } };
}

test('round trips, defaults and invalid or dataset-dependent values', () => {
  const url = new URL('https://example.test/nested/?dataset=core&sort=costPer1k&direction=asc&x=latencyMs&y=fpr&prevalence=0.005&errors=fp&utm=x#errors');
  const state = view.parseView(url.searchParams, data.datasets);
  assert.equal(state.prevalence, 0.005);
  assert.deepEqual(view.parseView(new URL(view.viewURL(url, state), url).searchParams, data.datasets), state);
  assert.equal(view.viewURL(url, view.defaults), '/nested/?utm=x#errors');
  const invalid = view.parseView(new URLSearchParams('dataset=bad&sort=bad&direction=sideways&x=bad&y=bad&prevalence=2&errors=bad'), data.datasets);
  assert.equal(invalid.dataset, 'all'); assert.equal(invalid.sort, 'accuracy'); assert.equal(invalid.direction, 'desc');
  assert.equal(invalid.x, 'costPer1k'); assert.equal(invalid.y, 'precision'); assert.equal(invalid.prevalence, 0.01); assert.equal(invalid.errors, 'total');
  const phishing = view.normalizeView({ dataset: 'real-phishing', sort: 'precision', y: 'fpr', errors: 'fp' }, data.datasets);
  assert.equal(phishing.sort, 'accuracy'); assert.equal(phishing.y, 'accuracy'); assert.equal(phishing.errors, 'total');
  const legit = view.normalizeView({ dataset: 'cross-domain-legitimate', sort: 'recall', y: 'recall', errors: 'fn' }, data.datasets);
  assert.equal(legit.sort, 'accuracy'); assert.equal(legit.y, 'accuracy'); assert.equal(legit.errors, 'total');
  for (const prevalence of model.PREVALENCES) assert.equal(view.parseView(new URLSearchParams({ prevalence }), data.datasets).prevalence, prevalence);
});
test('sort direction preserves controls and focus, mobile exposes only visible sorting controls', () => {
  const h = setup();
  const head = h.el('leaderboard-head'); const button = head.children[2].children[0];
  const options = h.el('sort-select').children;
  button.focus(); button.click();
  assert.equal(h.document.activeElement, button); assert.equal(head.children[2].children[0], button);
  assert.equal(h.el('sort-select').children, options);
  assert.equal(h.el('sort-direction').value, 'asc');
  assert.equal(head.children[2].getAttribute('aria-sort'), 'ascending');
  assert.match(h.window.location.search, /direction=asc/);
  h.media.matches = true; h.media.change();
  assert.equal(h.document.activeElement, h.el('sort-select'));
  assert.ok(head.querySelectorAll('button').every(b => b.tabIndex === -1));
  h.el('sort-direction').focus(); h.el('sort-direction').value = 'desc'; h.el('sort-direction').dispatch('change');
  assert.equal(h.document.activeElement, h.el('sort-direction'));
  assert.equal(head.children[2].getAttribute('aria-sort'), 'descending');
  assert.doesNotMatch(h.window.location.search, /direction=/);
});
test('copied URL, reload, history, dataset normalization, slider replacement and reset', () => {
  const url = 'https://example.test/phishnchips-decision-models/?dataset=core&sort=fpr&direction=asc&x=latencyMs&y=fpr&prevalence=0.005&errors=fp&utm=x#tradeoff';
  const h = setup(url);
  assert.equal(h.el('dataset-select').value, 'core'); assert.equal(h.el('x-axis').value, 'latencyMs');
  assert.equal(h.el('y-axis').value, 'fpr'); assert.equal(h.el('stack-sort').value, 'fp');
  assert.equal(Number(h.el('prevalence-range').value), 1); assert.match(h.el('prevalence-range').getAttribute('aria-valuetext'), /0.5%/);
  assert.match(h.el('view-status').textContent, /Chart: mean latency versus false-positive rate.*Errors: false alarms/);
  const initialHistory = h.history.length;
  h.el('prevalence-range').value = '6'; h.el('prevalence-range').dispatch('input');
  assert.equal(h.history.length, initialHistory); assert.match(h.window.location.search, /prevalence=0.25/);
  assert.match(h.el('prevalence-value').textContent, /25%/);
  h.el('dataset-select').value = 'real-phishing'; h.el('dataset-select').dispatch('change');
  assert.equal(h.history.length, initialHistory + 1);
  assert.equal(h.el('sort-select').value, 'accuracy'); assert.equal(h.el('y-axis').value, 'accuracy'); assert.equal(h.el('stack-sort').value, 'total');
  assert.match(h.window.location.search, /sort=accuracy/); assert.doesNotMatch(h.window.location.search, /errors=fp/);
  assert.match(h.el('pr-chart').textContent, /need both/);
  const reloaded = setup(h.window.location.href);
  assert.equal(reloaded.el('sort-select').value, 'accuracy'); assert.equal(reloaded.el('dataset-select').value, 'real-phishing');
  h.go(-1); assert.equal(h.el('dataset-select').value, 'core'); assert.equal(h.el('y-axis').value, 'fpr');
  h.go(1); assert.equal(h.el('dataset-select').value, 'real-phishing');
  h.el('reset-view').click();
  assert.equal(h.window.location.href, 'https://example.test/phishnchips-decision-models/?utm=x#tradeoff');
  assert.equal(h.el('dataset-select').value, 'all'); assert.equal(h.el('sort-select').value, 'precision'); assert.equal(h.el('sort-direction').value, 'desc');
  assert.equal(h.el('x-axis').value, 'costPer1k'); assert.equal(h.el('y-axis').value, 'precision'); assert.equal(h.el('stack-sort').value, 'total');
  assert.equal(Number(h.el('prevalence-range').value), 2); assert.match(h.el('view-status').textContent, /1% phishing prevalence/);
  assert.equal(h.document.activeElement, h.el('dataset-select'));
});
test('chart focus survives redraw by chart and model, with pointer, keyboard and touch readouts', () => {
  for (const [id, readout] of [['tradeoff-chart', 'tradeoff-readout'], ['pr-chart', 'pr-readout'], ['interval-chart', 'interval-readout']]) {
    const h = setup(); const original = h.el(id).querySelectorAll('[data-model]')[3];
    original.focus(); const detail = h.el(readout).textContent; assert.ok(detail);
    const identity = original.dataset.model;
    h.resize(id, 360);
    assert.notEqual(h.document.activeElement, original);
    assert.equal(h.document.activeElement.dataset.model, identity);
    assert.ok(h.el(id).contains(h.document.activeElement));
    assert.equal(h.el(readout).textContent, detail);
    const another = h.el(id).querySelectorAll('[data-model]')[0];
    another.dispatch('pointerenter'); const pointer = h.el(readout).textContent;
    another.click(); assert.equal(h.el(readout).textContent, pointer);
    another.focus(); assert.equal(h.el(readout).textContent, pointer);
    h.el('sort-direction').focus(); h.resize(id, 800); assert.equal(h.document.activeElement, h.el('sort-direction'));
  }
});
