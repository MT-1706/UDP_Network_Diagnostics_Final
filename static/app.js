"use strict";
const $ = id => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
let topo = null, last = null, selectedPath = null, busy = false;

function el(name, attrs = {}, text) {
  const e = document.createElementNS(SVG, name);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  return e;
}
const fmt = (v, u = " ms") => (v === null || v === undefined) ? "–" : v + u;
const key = (a, b) => [a, b].sort().join("|");
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
function say(text, err) { $("msg").textContent = text; $("msg").className = "msg" + (err ? " err" : ""); }

/* ---------- topology drawing ---------- */
function layout(t) {
  const n = t.switches.length, pos = {};
  const chain = t.links.length <= n - 1;           // no redundant links -> straight line
  const cx = 400, cy = 160, rx = n <= 2 ? 150 : 250, ry = n <= 2 ? 0 : 100;
  t.switches.forEach((s, i) => {
    const a = n === 1 ? 0 : (2 * Math.PI * i) / n - Math.PI / 2;
    pos[s] = n <= 3 && chain ? { x: 400 + (i - (n - 1) / 2) * 250, y: 170 }
                             : { x: cx + rx * Math.cos(a), y: cy + ry * Math.sin(a) };
  });
  const per = {};
  t.hosts.forEach(h => (per[h.switch] = per[h.switch] || []).push(h));
  const hpos = {};
  for (const s in per) {
    if (!pos[s]) continue;
    per[s].forEach((h, i) => {
      const off = (i - (per[s].length - 1) / 2) * 90;
      hpos[h.ip] = { x: pos[s].x + off, y: pos[s].y + (pos[s].y < 200 ? 110 : -110) };
    });
  }
  return { pos, hpos };
}

function draw() {
  const svg = $("topo");
  svg.replaceChildren();
  if (!topo) return;
  const { pos, hpos } = layout(topo);
  const cls = !last ? "" : last.status === "healthy" ? "ok" : last.status === "degraded" ? "warn" : "bad";
  const prim = new Set(), alt = new Set();
  const addPath = (p, set) => { for (let i = 0; i + 1 < p.length; i++) set.add(key(p[i], p[i + 1])); };
  if (last && last.primary) addPath(last.primary, prim);
  if (selectedPath) addPath(selectedPath, alt);

  topo.links.forEach(([a, b, state]) => {
    if (!pos[a] || !pos[b]) return;
    const k = key(a, b);
    let c = "edge";
    if (state === "down") c += " down";
    else if (alt.has(k) && !prim.has(k)) c += " alt";
    else if (prim.has(k)) c += " " + cls;
    svg.append(el("line", { class: c, x1: pos[a].x, y1: pos[a].y, x2: pos[b].x, y2: pos[b].y }));
    if (state === "down")
      svg.append(el("text", { class: "x", x: (pos[a].x + pos[b].x) / 2, y: (pos[a].y + pos[b].y) / 2 }, "✕"));
  });
  topo.hosts.forEach(h => {
    const hp = hpos[h.ip], sp = pos[h.switch];
    if (hp && sp) svg.append(el("line", { class: "hedge", x1: hp.x, y1: hp.y, x2: sp.x, y2: sp.y }));
  });
  topo.switches.forEach(s => {
    const p = pos[s];
    svg.append(el("circle", { class: "node", cx: p.x, cy: p.y, r: 26 }));
    svg.append(el("text", { x: p.x, y: p.y }, s));
  });
  topo.hosts.forEach(h => {
    const p = hpos[h.ip]; if (!p) return;
    const isEnd = last && (h.ip === last.src || h.ip === last.dst);
    svg.append(el("rect", { class: "host" + (isEnd ? " end" : ""), x: p.x - 38, y: p.y - 16, width: 76, height: 32, rx: 6 }));
    svg.append(el("text", { class: "small", x: p.x, y: p.y }, h.ip));
  });
}

/* ---------- failure-testing panel ---------- */
function renderLinkCtl() {
  const box = $("linkCtl");
  if (!topo || !topo.links.length) { box.innerHTML = '<span class="empty">No links known.</span>'; return; }
  box.replaceChildren();
  topo.links.forEach(([a, b, state]) => {
    const d = document.createElement("div");
    d.className = "lk " + state;
    d.innerHTML = `<span>${esc(a)} – ${esc(b)} (${state})</span>`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = state === "down" ? "Restore" : "Fail link";
    btn.disabled = busy;
    btn.onclick = () => toggleLink(a, b, state === "down" ? "up" : "down");
    d.append(btn); box.append(d);
  });
}

async function toggleLink(a, b, action) {
  if (busy) return;
  setBusy(true);
  try {
    say(`Setting link ${a}–${b} ${action}…`);
    const r = await fetch("/api/link", { method: "POST", headers: { "Content-Type": "application/json" },
                                         body: JSON.stringify({ a, b, action }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "Failed to change link");
    // wait until the controller's topology reflects the change (max ~20 s)
    const want = action === "down" ? "down" : "up";
    const t0 = Date.now();
    while (Date.now() - t0 < 20000) {
      say(`Waiting for the controller to notice (${Math.round((Date.now() - t0) / 1000)} s)…`);
      await sleep(1000);
      const t = await (await fetch("/api/topology")).json();
      const l = t.links.find(x => x[0] === a && x[1] === b);
      topo = { ...topo, ...t }; draw(); renderLinkCtl();
      if (l && l[2] === want) break;
    }
    await runDiagnosis(true);
  } catch (e) { say("Error: " + e.message, true); }
  finally { setBusy(false); }
}

function setBusy(v) {
  busy = v; $("runBtn").disabled = v;
  document.querySelectorAll(".lk button").forEach(b => b.disabled = v);
}

/* ---------- render results ---------- */
function setStat(id, text, cls) { const e = $(id); e.textContent = text; e.className = "v " + (cls || ""); }

function render(r) {
  last = r; selectedPath = null;
  const p = r.probe;
  setStat("sMin", fmt(p.rtt_min_ms)); setStat("sAvg", fmt(p.rtt_avg_ms)); setStat("sMax", fmt(p.rtt_max_ms));
  setStat("sJit", fmt(p.jitter_ms));
  setStat("sLoss", p.loss_pct + " %", p.loss_pct === 0 ? "ok" : p.loss_pct === 100 ? "bad" : "warn");
  setStat("sCnt", p.sent + " / " + p.received);

  const d = $("diag"); d.textContent = r.diagnosis; d.className = "diag " + r.status;
  $("route").textContent = r.primary ? r.primary.join(" → ") : "NO PATH";
  $("hops").textContent = r.primary ? r.primary.length : "n/a";
  $("cause").textContent = r.cause || "–";
  $("downLinks").textContent = r.down_links.length ? r.down_links.map(l => l.join("–")).join(", ") : "none";
  $("suspects").textContent = r.suspect_links.length ? r.suspect_links.map(l => l.join("–")).join(", ") : "none";
  $("recommend").textContent = r.recommend || "not needed";
  $("lostSeq").textContent = p.lost_seq.length ? p.lost_seq.join(", ") : "none";

  const notes = [...r.warnings];
  if (r.topology.note) notes.push(r.topology.note);
  const b = $("banner");
  b.classList.toggle("hidden", notes.length === 0);
  b.textContent = notes.join(" ");

  topo = { ...topo, ...r.topology };
  badge(r.topology.source);
  renderPaths(r); renderLinkCtl(); draw();
}

function renderPaths(r) {
  const tb = document.querySelector("#pathTable tbody");
  tb.replaceChildren();
  if (!r.paths.length) {
    tb.innerHTML = '<tr><td colspan="5" class="empty">No path found between these hosts.</td></tr>';
    return;
  }
  r.paths.forEach(pt => {
    const tr = document.createElement("tr");
    tr.className = "pick";
    const why = pt.down_links.length ? ` title="down: ${esc(pt.down_links.map(l => l.join("–")).join(", "))}"` : "";
    tr.innerHTML = `<td>${pt.names.join(" → ")}${pt.primary ? '<span class="tag">active</span>' : ""}</td>
      <td>${pt.hops}</td>
      <td><span class="pill ${pt.status}"${why}>${pt.status}${pt.down_links.length ? " (" + esc(pt.down_links.map(l => l.join("–")).join(", ")) + " down)" : ""}</span></td>
      <td>${fmt(pt.measured_rtt_ms)}</td><td>${fmt(pt.est_rtt_ms)}</td>`;
    tr.onclick = () => {
      selectedPath = pt.primary ? null : pt.names;
      tb.querySelectorAll("tr").forEach(x => x.classList.remove("sel"));
      if (!pt.primary) tr.classList.add("sel");
      draw();
    };
    tb.append(tr);
  });
}

async function loadHistory() {
  const rows = await (await fetch("/api/history")).json();
  const tb = document.querySelector("#histTable tbody");
  tb.replaceChildren();
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="7" class="empty">No runs yet.</td></tr>'; return; }
  rows.slice().reverse().forEach(h => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${h.time}</td><td>${h.dst}</td><td>${h.path}</td><td>${fmt(h.rtt_avg_ms)}</td>
      <td>${fmt(h.jitter_ms)}</td><td>${h.loss_pct} %</td><td><span class="pill ${h.status}">${h.status}</span></td>`;
    tb.append(tr);
  });
}

function badge(src) {
  const b = $("topoBadge");
  b.textContent = src === "ryu" ? "topology: live (Ryu)" : "topology: demo (Ryu offline)";
  b.className = "badge " + (src === "ryu" ? "live" : "demo");
}

/* ---------- actions ---------- */
async function loadTopology() {
  try {
    const t = await (await fetch("/api/topology")).json();
    topo = t; $("srcIp").value = t.src_ip; badge(t.source);
    $("hostList").innerHTML = t.hosts.filter(h => h.ip !== t.src_ip)
      .map(h => `<option value="${esc(h.ip)}">`).join("");
    if (t.note) { $("banner").textContent = t.note; $("banner").classList.remove("hidden"); }
    draw(); renderLinkCtl();
  } catch (e) { say("Could not reach the dashboard server.", true); }
}

async function runDiagnosis(keepBusy) {
  const count = +$("count").value;
  if (!keepBusy) setBusy(true);
  say(`Sending ${count} UDP probes… (up to ~${Math.ceil(count * 0.1 + 1)} s, longer if packets are lost)`);
  try {
    const res = await fetch("/api/diagnose", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dst: $("dstIp").value.trim(), count }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    render(data); loadHistory();
    say(`Done at ${data.time} (probes sent from ${data.probe.probe_origin}).`);
  } catch (e) { say("Error: " + e.message, true); }
  finally { if (!keepBusy) setBusy(false); }
}

$("probeForm").addEventListener("submit", ev => { ev.preventDefault(); runDiagnosis(false); });
$("resetBtn").addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST", body: "{}" });
  last = null; loadTopology(); loadHistory(); say("Remembered topology and history cleared.");
});

loadTopology(); loadHistory();
