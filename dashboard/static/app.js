// Chokidaar admin dashboard.
//
// Everything shown here that comes from the request log (paths, queries, IPs,
// reasons, rule patterns) is attacker-controlled. It is only ever put on the
// page with textContent or setAttribute on safe attributes, never as markup.
"use strict";

const TOKEN_KEY = "chokidaar-admin-token";
const REFRESH_MS = 5000;
const SVG_NS = "http://www.w3.org/2000/svg";

let refreshTimer = null;
let refreshing = false;
let refreshAgain = false;

// ---- small DOM helpers ----

const $ = (id) => document.getElementById(id);

// Create an element; `text` is always set as plain text.
function el(tag, { cls, text, attrs } = {}, children = []) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (attrs) for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  for (const child of children) node.append(child);
  return node;
}

function svg(tag, attrs = {}, text) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function emptyRow(columns, message) {
  return el("tr", { cls: "empty" }, [el("td", { text: message, attrs: { colspan: columns } })]);
}

const fmtInt = (n) => Number(n || 0).toLocaleString();

function fmtTime(ts) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

// ---- token and API ----

function getToken() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

function setToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage blocked: the token lives only for this page load */ }
  memoryToken = token;
}

let memoryToken = getToken();

class Unauthorized extends Error {}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { Authorization: `Bearer ${memoryToken}`, Accept: "application/json" },
    cache: "no-store",
  });
  if (response.status === 401) throw new Unauthorized();
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

// ---- login ----

function showLogin(message = "") {
  stopRefresh();
  $("app").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = message;
  $("token").value = "";
  $("token").focus();
}

function showApp() {
  $("login").hidden = true;
  $("app").hidden = false;
  startRefresh();
}

async function signIn(event) {
  event.preventDefault();
  const token = $("token").value.trim();
  if (!token) return;
  memoryToken = token;
  try {
    await api("/api/summary");
  } catch (err) {
    memoryToken = null;
    $("login-error").textContent = err instanceof Unauthorized
      ? "That token is not right." : `Could not reach the dashboard: ${err.message}`;
    return;
  }
  setToken(token);
  showApp();
}

function signOut() {
  setToken(null);
  showLogin();
}

// ---- rendering ----

function renderSummary(s) {
  $("c-total").textContent = fmtInt(s.total);
  $("c-allow").textContent = fmtInt(s.counts.allow);
  $("c-block").textContent = fmtInt(s.counts.block);
  $("c-flagged").textContent = fmtInt(s.counts.flagged);
  $("c-share").textContent = `${(Number(s.blocked_share) * 100).toFixed(1)}%`;
}

function renderTimeline(hours) {
  const W = 720, H = 200, left = 36, right = 8, top = 10, bottom = 24;
  const plotW = W - left - right, plotH = H - top - bottom;
  const max = Math.max(1, ...hours.map((h) => h.requests));
  const slot = plotW / Math.max(1, hours.length);
  const barW = Math.max(2, slot * 0.7);
  const y = (v) => top + plotH - (v / max) * plotH;

  const nodes = [
    svg("line", { class: "axis", x1: left, y1: top + plotH, x2: W - right, y2: top + plotH }),
    svg("text", { x: left - 6, y: top + 4, "text-anchor": "end", "dominant-baseline": "hanging" }, fmtInt(max)),
    svg("text", { x: left - 6, y: top + plotH, "text-anchor": "end" }, "0"),
  ];
  hours.forEach((h, i) => {
    const x = left + i * slot + (slot - barW) / 2;
    const when = new Date(h.hour);
    const label = when.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const group = svg("g");
    group.append(svg("title", {}, `${label}: ${h.requests} requests, ${h.blocks} blocked`));
    group.append(svg("rect", { class: "bar-requests", x, y: y(h.requests), width: barW, height: top + plotH - y(h.requests) }));
    if (h.blocks > 0) {
      group.append(svg("rect", { class: "bar-blocks", x, y: y(h.blocks), width: barW, height: top + plotH - y(h.blocks) }));
    }
    // An invisible full-height target so empty hours still show their tooltip.
    group.append(svg("rect", { x: left + i * slot, y: top, width: slot, height: plotH, fill: "transparent" }));
    nodes.push(group);
    if (i % 6 === 0 || i === hours.length - 1) {
      nodes.push(svg("text", { x: x + barW / 2, y: H - 6, "text-anchor": "middle" }, label));
    }
  });
  $("timeline").replaceChildren(...nodes);
}

function renderTopIps(rows) {
  const body = $("top-ips");
  if (!rows.length) { body.replaceChildren(emptyRow(2, "No blocked requests yet")); return; }
  body.replaceChildren(...rows.map((r) => {
    const link = el("button", { cls: "ip-link", text: r.ip, attrs: { type: "button", title: "Show this IP's requests" } });
    link.addEventListener("click", () => { $("ip").value = r.ip; refresh(); });
    return el("tr", {}, [el("td", {}, [link]), el("td", { cls: "num", text: fmtInt(r.blocks) })]);
  }));
}

function renderRequests(rows) {
  const body = $("requests");
  if (!rows.length) { body.replaceChildren(emptyRow(8, "No requests match")); return; }
  body.replaceChildren(...rows.map((r) => {
    const target = r.query ? `${r.path}?${r.query}` : r.path;
    return el("tr", {}, [
      el("td", { cls: "nowrap", text: fmtTime(r.ts) }),
      el("td", { cls: "nowrap", text: r.ip ?? "" }),
      el("td", { text: r.method }),
      el("td", { cls: "path", text: target }),
      el("td", {}, [el("span", { cls: `badge ${badgeClass(r.decision)}`, text: r.decision })]),
      el("td", { cls: "nowrap", text: r.rule_id ?? "" }),
      el("td", { cls: "num", text: r.ml_score == null ? "" : Number(r.ml_score).toFixed(2) }),
      el("td", { cls: "reason", text: r.reason }),
    ]);
  }));
}

// Only known values become class names.
function badgeClass(value) {
  return ["allow", "block", "flagged", "pending", "approved", "rejected"].includes(value) ? value : "";
}

function renderSuggestions(rows) {
  const list = $("suggestions");
  if (!rows.length) { list.replaceChildren(el("li", { cls: "empty", text: "No suggestions" })); return; }
  list.replaceChildren(...rows.map((p) => {
    const item = el("li", {}, [
      el("div", { cls: "meta" }, [
        el("span", { cls: `badge ${badgeClass(p.status)}`, text: p.status }),
        el("strong", { text: p.attack_type }),
        el("span", { cls: "muted", text: `#${p.id}` }),
      ]),
      el("code", { text: p.pattern }),
    ]);
    if (p.rationale) item.append(el("span", { cls: "muted", text: p.rationale }));
    if (p.status === "pending") {
      const approve = el("button", { text: "Approve", attrs: { type: "button" } });
      const reject = el("button", { cls: "danger", text: "Reject", attrs: { type: "button" } });
      approve.addEventListener("click", () => decide(p.id, "approve", [approve, reject]));
      reject.addEventListener("click", () => decide(p.id, "reject", [approve, reject]));
      item.append(el("div", { cls: "actions" }, [approve, reject]));
    }
    return item;
  }));
}

async function decide(id, action, buttons) {
  buttons.forEach((b) => { b.disabled = true; });
  try {
    await api(`/api/suggestions/${encodeURIComponent(id)}/${action}`, { method: "POST" });
    await refresh();
  } catch (err) {
    if (err instanceof Unauthorized) { signOut(); return; }
    buttons.forEach((b) => { b.disabled = false; });
    $("status").textContent = `Could not ${action} suggestion #${id}: ${err.message}`;
  }
}

// ---- refresh loop ----

async function refresh() {
  if (refreshing) { refreshAgain = true; return; }
  refreshing = true;
  const params = new URLSearchParams({ limit: "100" });
  if ($("decision").value) params.set("decision", $("decision").value);
  const ip = $("ip").value.trim();
  if (ip) params.set("ip", ip);
  const status = $("suggestion-status").value;
  try {
    const [summary, timeline, topIps, requests, suggestions] = await Promise.all([
      api("/api/summary"),
      api("/api/timeline"),
      api("/api/top-ips"),
      api(`/api/requests?${params}`),
      api(status ? `/api/suggestions?status=${encodeURIComponent(status)}` : "/api/suggestions"),
    ]);
    renderSummary(summary);
    renderTimeline(timeline);
    renderTopIps(topIps);
    renderRequests(requests);
    renderSuggestions(suggestions);
    $("status").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    if (err instanceof Unauthorized) { setToken(null); showLogin("Your session has ended; sign in again."); }
    else $("status").textContent = `Update failed: ${err.message}`;
  } finally {
    refreshing = false;
    if (refreshAgain && refreshTimer) { refreshAgain = false; refresh(); }
  }
}

function startRefresh() {
  stopRefresh();
  refresh();
  refreshTimer = setInterval(refresh, REFRESH_MS);
}

function stopRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = null;
}

// ---- start ----

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", signIn);
  $("logout").addEventListener("click", signOut);
  $("decision").addEventListener("change", refresh);
  $("suggestion-status").addEventListener("change", refresh);
  let typing;
  $("ip").addEventListener("input", () => { clearTimeout(typing); typing = setTimeout(refresh, 400); });
  if (memoryToken) showApp(); else showLogin();
});
