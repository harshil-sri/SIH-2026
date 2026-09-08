/* ══════════════════════════════════════════════════════════════════════════
   SIH26145 — DIODE-IDS OPERATOR CONSOLE / client
   Every value is rendered through textContent and element factories; no
   innerHTML anywhere, so nothing arriving from /score or /recent_alerts can
   inject markup into the console.
   ══════════════════════════════════════════════════════════════════════════ */
"use strict";

const API = "http://127.0.0.1:8200";
const WS  = "ws://127.0.0.1:8200/ws/alerts";

const BANDS = [
  { name: "CRITICAL", min: 0.75 },
  { name: "HIGH",     min: 0.50 },
  { name: "MEDIUM",   min: 0.25 },
  { name: "OK",       min: 0.00 },
];
const BAND_COLOR = {
  OK: "#6a6a6a", MEDIUM: "#b8860b", HIGH: "#d95a00", CRITICAL: "#e61919",
};
const TREND_CAP = 120;

const $ = (id) => document.getElementById(id);
const el = {
  uptime: $("m-uptime"), clock: $("m-clock"),
  linkDot: $("link-dot"), linkText: $("link-text"),
  diodeVerdict: $("diode-verdict"), diodeProof: $("diode-proof"),
  featCount: $("d-featcount"),
  idxValue: $("idx-value"), idxVerdict: $("idx-verdict"), idxFamily: $("idx-family"),
  bandMarker: $("band-marker"),
  cClf: $("c-clf"), cAe: $("c-ae"), vClf: $("v-clf"), vAe: $("v-ae"),
  trend: $("trend"), classbars: $("classbars"),
  sScored: $("s-scored"), sAlerts: $("s-alerts"), sLat: $("s-lat"), sP95: $("s-p95"),
  sClf: $("s-clf"), sAe: $("s-ae"), sDev: $("s-dev"), sF1: $("s-f1"),
  feed: $("feed"), families: $("families"), topfeat: $("topfeat"),
  btnRefresh: $("btn-refresh"), btnPause: $("btn-pause"),
};

let trendData = [];         // recent threat scores, oldest -> newest
let paused = false;         // HOLD freezes the feed for inspection
let familyTally = new Map();
let alertCount = 0;
let ws = null;
let wsRetry = 0;

/* ── helpers ─────────────────────────────────────────────────────────────── */
const bandOf = (s) => (BANDS.find((b) => s >= b.min) || BANDS[3]).name;
const num = (v, d = 3) => (Number.isFinite(+v) ? (+v).toFixed(d) : "--");

function hhmmss(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  return [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()]
    .map((n) => String(n).padStart(2, "0")).join(":");
}

function durationShort(s) {
  if (!Number.isFinite(s)) return "--";
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}H ${m}M` : `${m}M ${Math.floor(s % 60)}S`;
}

/** Create an element with text and optional class/attrs. */
function mk(tag, text, cls, attrs) {
  const n = document.createElement(tag);
  if (text !== undefined && text !== null) n.textContent = String(text);
  if (cls) n.className = cls;
  if (attrs) for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}
function svg(tag, attrs) {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
  return n;
}

/* ── masthead clock ──────────────────────────────────────────────────────── */
setInterval(() => {
  el.clock.textContent = hhmmss(Date.now() / 1000);
}, 1000);

/* ── threat index ────────────────────────────────────────────────────────── */
function setIndex(score, verdict, family, components) {
  const s = Number.isFinite(+score) ? +score : 0;
  const band = verdict || bandOf(s);

  el.idxValue.textContent = s.toFixed(2);
  el.idxValue.className = `idx-num v-${band}`;
  el.idxVerdict.textContent = band;
  el.idxVerdict.className = `verdict v-${band}`;
  el.idxFamily.textContent = family && family !== "n/a" ? family : "NO KNOWN FAMILY MATCH";

  // marker walks the four verdict bands proportionally to the score
  el.bandMarker.style.left = `${Math.min(100, Math.max(0, s * 100))}%`;

  const clf = components ? components.classifier : 0;
  const ae  = components ? components.autoencoder : 0;
  el.cClf.style.width = `${Math.min(100, clf * 100 / 0.6)}%`;
  el.cAe.style.width  = `${Math.min(100, ae  * 100 / 0.4)}%`;
  el.vClf.textContent = num(clf);
  el.vAe.textContent  = num(ae);
}

/* ── trend sparkline (hand-rolled SVG; no chart library) ─────────────────── */
function drawTrend() {
  const W = 600, H = 190, PAD_L = 30, PAD_B = 16, PAD_T = 8;
  const plotW = W - PAD_L - 6, plotH = H - PAD_B - PAD_T;
  const y = (v) => PAD_T + plotH * (1 - Math.min(1, Math.max(0, v)));
  const frag = document.createDocumentFragment();

  // verdict band shading + gridlines, so a spike is readable without a legend
  for (const [lo, hi, col] of [[0.75, 1.0, "#e61919"], [0.5, 0.75, "#d95a00"],
                               [0.25, 0.5, "#b8860b"]]) {
    frag.appendChild(svg("rect", {
      x: PAD_L, y: y(hi), width: plotW, height: y(lo) - y(hi),
      fill: col, "fill-opacity": 0.07,
    }));
  }
  for (const v of [0, 0.25, 0.5, 0.75, 1]) {
    frag.appendChild(svg("line", {
      x1: PAD_L, x2: W - 6, y1: y(v), y2: y(v),
      stroke: "#2a2a2a", "stroke-width": 1,
      "stroke-dasharray": v === 0 || v === 1 ? "0" : "2 4",
    }));
    const t = svg("text", { x: 4, y: y(v) + 3, fill: "#5a5a5a", "font-size": 9 });
    t.textContent = v.toFixed(2);
    frag.appendChild(t);
  }

  if (trendData.length > 1) {
    const step = plotW / (TREND_CAP - 1);
    const pts = trendData.map((v, i) => {
      const x = PAD_L + (i + (TREND_CAP - trendData.length)) * step;
      return [x, y(v)];
    });
    // area under the curve, then the stroke on top
    frag.appendChild(svg("path", {
      d: `M ${pts[0][0]} ${y(0)} ` + pts.map((p) => `L ${p[0]} ${p[1]}`).join(" ") +
         ` L ${pts[pts.length - 1][0]} ${y(0)} Z`,
      fill: "#e61919", "fill-opacity": 0.1,
    }));
    frag.appendChild(svg("polyline", {
      points: pts.map((p) => p.join(",")).join(" "),
      fill: "none", stroke: "#eaeaea", "stroke-width": 1.5,
    }));
    // mark every window that cleared the alert floor
    trendData.forEach((v, i) => {
      if (v < 0.25) return;
      const [x, yy] = pts[i];
      frag.appendChild(svg("rect", {
        x: x - 1.75, y: yy - 1.75, width: 3.5, height: 3.5,
        fill: BAND_COLOR[bandOf(v)],
      }));
    });
    const last = pts[pts.length - 1];
    frag.appendChild(svg("line", {
      x1: last[0], x2: last[0], y1: PAD_T, y2: PAD_T + plotH,
      stroke: "#e61919", "stroke-width": 1, "stroke-dasharray": "2 3",
    }));
  } else {
    const t = svg("text", { x: W / 2, y: H / 2, fill: "#5a5a5a", "font-size": 10,
                            "text-anchor": "middle" });
    t.textContent = "AWAITING TELEMETRY";
    frag.appendChild(t);
  }

  el.trend.replaceChildren(frag);
}

function pushTrend(score) {
  trendData.push(Math.min(1, Math.max(0, +score || 0)));
  if (trendData.length > TREND_CAP) trendData = trendData.slice(-TREND_CAP);
  drawTrend();
}

/* ── class posterior bars ────────────────────────────────────────────────── */
function renderClassBars(probs) {
  if (!probs || !Object.keys(probs).length) return;
  const entries = Object.entries(probs).sort((a, b) => b[1] - a[1]);
  const topAttack = entries.find(([k]) => k !== "BENIGN");
  const frag = document.createDocumentFragment();

  for (const [name, p] of entries) {
    const row = mk("div", null, "cbrow" +
      (name === "BENIGN" ? " is-benign" : "") +
      (topAttack && name === topAttack[0] && p > 0.01 ? " is-top" : ""));
    row.appendChild(mk("span", name, "cbname"));
    row.appendChild(mk("span", (p * 100).toFixed(1) + "%", "cbval"));
    const track = mk("span", null, "cbtrack");
    const fill = mk("i");
    fill.style.width = `${Math.max(0, Math.min(100, p * 100))}%`;
    track.appendChild(fill);
    row.appendChild(track);
    frag.appendChild(row);
  }
  el.classbars.replaceChildren(frag);
}

/* ── alert feed ──────────────────────────────────────────────────────────── */
function feedRow(a) {
  const tr = mk("tr");
  tr.appendChild(mk("td", hhmmss(a.ts)));

  const tdv = mk("td");
  tdv.appendChild(mk("span", a.verdict, `badge ${a.verdict}`));
  tr.appendChild(tdv);

  tr.appendChild(mk("td", num(a.threat_score, 3)));
  tr.appendChild(mk("td", a.attack_family || a.predicted_label || "--"));
  tr.appendChild(mk("td", a.ae_error === null || a.ae_error === undefined
    ? "--" : num(a.ae_error, 4)));
  tr.appendChild(mk("td", (a.reasons || []).join("  //  ") || "--", "evidence"));
  tr.appendChild(mk("td", a.latency_ms !== undefined ? num(a.latency_ms, 1) : "--"));
  return tr;
}

function prependAlert(a) {
  if (paused) return;
  const empty = el.feed.querySelector(".empty-row");
  if (empty) empty.remove();
  const row = feedRow(a);
  row.classList.add("arrive");
  el.feed.insertBefore(row, el.feed.firstChild);
  while (el.feed.children.length > 120) el.feed.removeChild(el.feed.lastChild);
}

function renderFamilies() {
  const rows = [...familyTally.entries()].sort((x, y) => y[1] - x[1]);
  if (!rows.length) {
    el.families.replaceChildren(mk("p", "NONE", "empty"));
    return;
  }
  const frag = document.createDocumentFragment();
  for (const [name, n] of rows) {
    const r = mk("div", null, "famrow");
    r.appendChild(mk("b", name));
    r.appendChild(mk("samp", String(n)));
    frag.appendChild(r);
  }
  el.families.replaceChildren(frag);
}

function tallyFamily(a) {
  const fam = a.attack_family || a.predicted_label || "UNKNOWN";
  familyTally.set(fam, (familyTally.get(fam) || 0) + 1);
  renderFamilies();
}

/* ── ingest one scored window from the stream ─────────────────────────────── */
function ingest(a) {
  setIndex(a.threat_score, a.verdict, a.attack_family || a.predicted_label,
           a.components);
  renderClassBars(a.class_probs);
  pushTrend(a.threat_score);
  if (a.verdict && a.verdict !== "OK") {
    alertCount += 1;
    el.sAlerts.textContent = String(alertCount);
    prependAlert(a);
    tallyFamily(a);
  }
}

/* ── polled endpoints ────────────────────────────────────────────────────── */
async function getJSON(path) {
  const r = await fetch(API + path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

async function pollHealth() {
  try {
    const h = await getJSON("/health");
    el.sScored.textContent = String(h.windows_scored ?? 0);
    el.sLat.textContent = h.avg_latency_ms ?? "--";
    el.sP95.textContent = h.p95_latency_ms ?? "--";
    el.sDev.textContent = (h.device || "--").toUpperCase();
    el.uptime.textContent = durationShort(h.uptime_s);

    for (const [node, ok] of [[el.sClf, h.classifier], [el.sAe, h.autoencoder]]) {
      node.textContent = ok ? "LOADED" : "ABSENT";
      node.className = ok ? "good" : "bad";
    }
    setLink(true);
  } catch {
    setLink(false);
  }
}

async function loadMeta() {
  try {
    const m = await getJSON("/meta");
    el.featCount.textContent = `${m.n_features || 0} FEATURES`;
    const f1 = m.classifier_metrics && m.classifier_metrics.macro_f1;
    el.sF1.textContent = Number.isFinite(f1) ? f1.toFixed(3) : "--";

    const d = m.diode || {};
    if (d.zero_reverse_packets) {
      el.diodeVerdict.textContent = "VERIFIED";
      el.diodeVerdict.className = "pill good";
      el.diodeProof.textContent = "PROOF: 0 REVERSE PACKETS OBSERVED IN NS-MONITOR";
      el.diodeProof.className = "good";
    } else {
      el.diodeVerdict.textContent = d.proof_present ? "REVIEW" : "NO PROOF";
      el.diodeVerdict.className = "pill bad";
      el.diodeProof.textContent = d.proof_present
        ? "PROOF: PRESENT BUT NOT CONCLUSIVE — RUN make diode"
        : "PROOF: MISSING — RUN make diode";
      el.diodeProof.className = "";
    }

    const feats = (m.top_features || []).filter(Boolean);
    el.topfeat.replaceChildren(...(feats.length
      ? feats.slice(0, 8).map((f) => mk("li", f))
      : [mk("li", "NOT AVAILABLE — RETRAIN TO POPULATE", "empty")]));

    // seed the class bars with a flat prior so the panel is never blank
    if (m.classes && m.classes.length && !el.classbars.querySelector(".cbrow")) {
      const seed = {};
      for (const c of m.classes) seed[c] = 0;
      renderClassBars(seed);
    }
  } catch { /* /meta is optional; console still works without it */ }
}

async function loadHistory() {
  try {
    const t = await getJSON(`/trend?n=${TREND_CAP}`);
    trendData = t.map((r) => Math.min(1, Math.max(0, +r.threat_score || 0)));
    drawTrend();
  } catch { /* no history yet */ }

  try {
    const alerts = await getJSON("/recent_alerts?n=120");
    familyTally = new Map();
    if (alerts.length) {
      el.feed.replaceChildren(...[...alerts].reverse().map(feedRow));
      for (const a of alerts) {
        const fam = a.attack_family || a.predicted_label || "UNKNOWN";
        familyTally.set(fam, (familyTally.get(fam) || 0) + 1);
      }
      renderFamilies();
      // repaint the gauge from the newest alert without double-counting it
      const last = alerts[alerts.length - 1];
      setIndex(last.threat_score, last.verdict,
               last.attack_family || last.predicted_label, last.components);
      renderClassBars(last.class_probs);
    } else {
      renderFamilies();
    }
  } catch { /* no alerts yet */ }

  // authoritative running total: /recent_alerts is a capped tail, so counting it
  // would undercount once more than 120 alerts have fired
  try {
    const s = await getJSON("/stats");
    alertCount = s.alerts ?? alertCount;
    el.sAlerts.textContent = String(alertCount);
  } catch { /* optional */ }
}

/* ── link status ─────────────────────────────────────────────────────────── */
let linkUp = null;
function setLink(up) {
  if (up === linkUp) return;
  linkUp = up;
  el.linkDot.className = `dot ${up ? "live" : "downed"}`;
  el.linkText.textContent = up ? "API LIVE" : "API UNREACHABLE";
}

/* ── websocket stream ────────────────────────────────────────────────────── */
function connect() {
  ws = new WebSocket(WS);

  ws.onopen = () => {
    wsRetry = 0;
    el.linkText.textContent = "STREAM LIVE";
    el.linkDot.className = "dot live";
    linkUp = true;
  };
  ws.onmessage = (ev) => {
    let a;
    try { a = JSON.parse(ev.data); } catch { return; }
    ingest(a);
  };
  ws.onerror = () => ws.close();
  ws.onclose = () => {
    setLink(false);
    wsRetry = Math.min(wsRetry + 1, 6);
    setTimeout(connect, 500 * 2 ** (wsRetry - 1));   // capped backoff
  };
}

setInterval(() => {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send("ping");
}, 25000);

/* ── controls ────────────────────────────────────────────────────────────── */
el.btnRefresh.addEventListener("click", () => {
  pollHealth(); loadMeta(); loadHistory();
});
el.btnPause.addEventListener("click", () => {
  paused = !paused;
  el.btnPause.setAttribute("aria-pressed", String(paused));
  el.btnPause.textContent = paused ? "\u25B6 RESUME" : "\u2759\u2759 HOLD";
});

/* ── routing ─────────────────────────────────────────────────────────────── */
function handleRouting() {
  const hash = window.location.hash || '#telemetry';
  const navBtns = document.querySelectorAll('.nav-btn');
  const views = document.querySelectorAll('.route-view');
  
  navBtns.forEach(btn => {
    if (btn.getAttribute('href') === hash) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  views.forEach(view => {
    view.style.display = 'none';
  });

  let targetId;
  if (hash === '#telemetry') targetId = 'view-telemetry';
  else if (hash === '#alerts') targetId = 'view-alerts';
  else if (hash === '#diagnostics') targetId = 'view-diagnostics';
  else targetId = 'view-telemetry';

  const targetView = document.getElementById(targetId);
  if (targetView) targetView.style.display = 'block';
}

window.addEventListener('hashchange', handleRouting);
handleRouting();

/* ── boot ────────────────────────────────────────────────────────────────── */
drawTrend();
pollHealth();
loadMeta();
loadHistory();
connect();
setInterval(pollHealth, 3000);
setInterval(loadMeta, 30000);
