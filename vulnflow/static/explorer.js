(function () {
'use strict';
const D = JSON.parse(document.getElementById('vf-data').textContent);
const telemetryOnly = D.vulnerability_data_available === false;
if (telemetryOnly) document.getElementById('hint').textContent =
  'Click a host to inspect recorded endpoints, ports, protocols, and direction.';
const cv = document.getElementById('stage'), ctx = cv.getContext('2d');
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const iocIds = new Set((D.ioc_matches || []).map(item => item.id));
const iocCounts = D.ioc_counts || {};
const iocButton = (type, value, label = value) => {
  const key = type + ':' + (type === 'cve' ? String(value).toUpperCase() : value);
  return iocIds.has(key) ? `<button type="button" class="ioc-link" data-ioc-key="${esc(key)}">${esc(label)}</button>` : esc(label);
};
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
// backdrop follows the report theme picked on the vulnflow pages (same browser storage when served);
// light themes get a dark slate, since the glowing graph needs a dark canvas
const BACKDROP = {dark: ['#16223a', '#020617'], 'olive-drab': ['#263021', '#10150e'],
  'high-contrast': ['#0a0a0a', '#000000'], matrix: ['#05200c', '#020b04'],
  light: ['#3a4a60', '#283548']};
const SLATE = ['#3a4a60', '#283548'];
let themeName = 'dark';
try { themeName = localStorage.getItem('vulnflow-theme') || 'dark'; } catch (_) {}
if (!BACKDROP[themeName]) themeName = 'dark';
document.documentElement.dataset.theme = themeName;
const [BG_IN, BG_OUT] = BACKDROP[themeName] || SLATE;
document.documentElement.style.setProperty('--bg', BG_OUT);
const SEV = {Critical: '#ff3b5c', High: '#ff8a3d', Medium: '#ffd23f', Low: '#4dabf7', Info: '#8da2b5', '': '#8da2b5'};
const RETURN = '#b98cff';
const KIND = {alert: '#ff3b5c', vuln: '#ff8a3d', reached: '#ffc857', outbound: RETURN, attempt: '#8892a6', blocked: '#5b6b82'};
const KIND_TXT = {alert: 'IPS alert, not blocked', vuln: 'Reached a vulnerable service', reached: 'Reached the host',
  outbound: 'Host connected out to it', attempt: 'Tried, no completed session', blocked: 'Blocked by firewall or IPS'};
const BAND = {High: '#ff2e88', Medium: '#ffb020', Low: '#2ee6d6', None: '#5b6b82', Unknown: '#8da2b5'};

let W = 0, H = 0, DPR = 1;
const cam = {x: 0, y: 0, z: 0.25, tx: 0, ty: 0, tz: 1};
const still = /[?&#]still\b/.test(location.search + location.hash);
const state = {mode: 'overview', focus: null, hover: null, labels: true, motion: !reduced && !still, history: []};
const nodes = new Map();          // id -> render node
let edges = [];                   // focus-mode edges
let t0 = performance.now();

// ---------------------------------------------------------------- layout: overview
function overviewLayout() {
  const groups = new Map();
  D.nodes.forEach(n => { if (!groups.has(n.subnet)) groups.set(n.subnet, []); groups.get(n.subnet).push(n); });
  const subnets = [...groups.keys()].sort();
  const golden = Math.PI * (3 - Math.sqrt(5));
  const clusters = [];
  subnets.forEach((s, i) => {
    const members = groups.get(s).sort((a, b) => (b.observed - a.observed) || (b.score - a.score) || a.id.localeCompare(b.id));
    const cr = 40 + 40 * Math.sqrt(members.length);
    const r = i === 0 ? 0 : 230 * Math.sqrt(i) + cr;
    const cx = r * Math.cos(i * golden), cy = r * Math.sin(i * golden);
    clusters.push({subnet: s, x: cx, y: cy, r: cr + 18});
    members.forEach((n, k) => {
      const rr = k === 0 && members.length === 1 ? 0 : 40 * Math.sqrt(k + 0.5);
      const a = k * golden;
      const rn = node(n);
      rn.ox = cx + rr * Math.cos(a); rn.oy = cy + rr * Math.sin(a);
    });
  });
  return clusters;
}
function node(d) {
  if (nodes.has(d.id)) return nodes.get(d.id);
  const r = d.observed ? 7 + Math.min(9, (d.score || 0) / 12) : 4.5;
  const n = {d, id: d.id, x: 0, y: 0, tx: 0, ty: 0, ox: 0, oy: 0, a: 0, ta: 1, r, tr: r, color: SEV[d.sev] || SEV[''],
    ext: false, born: performance.now() + Math.random() * 900};
  nodes.set(d.id, n);
  return n;
}
const clusters = overviewLayout();
const links = D.links.map(([a, b, w]) => ({a: nodes.get(a), b: nodes.get(b), w})).filter(l => l.a && l.b);
nodes.forEach(n => { n.x = n.ox * 1.8; n.y = n.oy * 1.8; n.tx = n.ox; n.ty = n.oy; });

// ---------------------------------------------------------------- stars
const stars = Array.from({length: 260}, () => ({x: Math.random(), y: Math.random(), z: Math.random() * 0.8 + 0.2,
  p: Math.random() * Math.PI * 2}));

// ---------------------------------------------------------------- focus layout
function extNode(a) {
  const id = 'ext:' + a.ip;
  let n = nodes.get(id);
  if (!n) {
    n = {d: {id: a.ip, name: '', scanned: false, sev: ''}, id, x: 0, y: 0, tx: 0, ty: 0, ox: 0, oy: 0, a: 0, ta: 0,
      r: 6, tr: 6, color: KIND[a.kind], ext: true, born: 0, info: a};
    nodes.set(id, n);
  }
  n.info = a; n.color = KIND[a.kind];
  return n;
}
function domainNode(match) {
  const id = match.id;
  let n = nodes.get(id);
  if (!n) {
    n = {d: {id: match.value, name: '', scanned: false, sev: ''}, id, x: 0, y: 0, tx: 0, ty: 0, ox: 0, oy: 0, a: 0, ta: 0,
      r: 7, tr: 7, color: '#2ee6d6', ext: false, domain: true, born: 0, info: match};
    nodes.set(id, n);
  }
  n.info = match;
  return n;
}
const LABELED = 24;                // nodes per side drawn large and labelled; the rest are packed beyond them
const SIDE_MAX = 400;              // nodes drawn per side; the panel lists every one
function arc(list, dir) {
  // two labelled columns of up to 12, curved so both ends bend towards the selected host,
  // then a dense block of small unlabelled nodes further out (hover them for details)
  const per = 12, rows = 24;
  list.forEach((item, i) => {
    if (i < LABELED) {
      const col = Math.floor(i / per), k = i % per, cnt = Math.min(per, Math.min(LABELED, list.length) - col * per);
      const gap = Math.max(36, Math.min(95, 420 / cnt));
      const y = (k - (cnt - 1) / 2) * gap;
      item.tx = dir * (400 + col * 270 - (y * y) / 1600); item.ty = y; item.gap = gap; item.small = false;
    } else {
      const j = i - LABELED, col = Math.floor(j / rows), k = j % rows, cnt = Math.min(rows, list.length - LABELED - col * rows);
      item.tx = dir * (900 + col * 24); item.ty = (k - (cnt - 1) / 2) * 17; item.gap = 17; item.small = true;
    }
  });
}
function peerNode(ip) {
  return nodes.get(ip) || node({id: ip, name: '', scanned: false, sev: '', subnet: '', pri: '', score: 0, ev: '', os: ''});
}
function focus(id, push = true) {
  const F = D.focus[id];
  if (!F) return;
  if (push && state.focus && state.focus !== id) state.history.push(state.focus);
  state.mode = 'focus'; state.focus = id;
  document.body.classList.add('focused');
  $('hint').classList.add('gone');
  history.replaceState(null, '', '#host=' + encodeURIComponent(id));
  const center = nodes.get(id);
  const keep = new Set([id]);
  // background nodes drift outward and fade
  nodes.forEach(n => { n.gap = 0; n.small = false; if (n.ext || n.domain) { n.ta = 0; } else { n.ta = 0.05; n.tx = n.ox * 2.4; n.ty = n.oy * 2.4; n.tr = n.r; } });
  center.tx = 0; center.ty = 0; center.ta = 1; center.tr = 22;
  const atk = F.attackers.slice(0, SIDE_MAX).map(extNode);
  arc(atk, -1);
  atk.forEach(n => { n.ta = 1; n.tr = n.small ? 3.5 : 5 + Math.min(7, Math.log2(1 + n.info.sessions + n.info.out_sessions + 3 * n.info.alerts)); keep.add(n.id); });
  // DNS matches are source-linked IOCs without a corresponding outside IP node.
  // Show them separately above the host; the dashed edge means an observed query, not an IP session.
  const domains = (D.ioc_matches || []).filter(item => item.type === 'domain' && item.hosts.includes(id)).slice(0, 8).map(domainNode);
  const domainCols = domains.length <= 4 ? 2 : 3;
  const domainRows = Math.ceil(domains.length / domainCols);
  domains.forEach((n, i) => {
    const row = Math.floor(i / domainCols), inRow = Math.min(domainCols, domains.length - row * domainCols), col = i % domainCols;
    n.tx = (col - (inRow - 1) / 2) * 300;
    n.ty = -190 - (domainRows - 1) * 45 + row * 90;
    n.ta = 1; n.tr = 7; n.gap = 90; keep.add(n.id);
  });
  const peers = F.peers.slice(0, SIDE_MAX).map(p => { const n = peerNode(p.ip); n.info = p; return n; });
  arc(peers, 1);
  peers.forEach(n => { n.ta = n.info.band === 'None' ? 0.75 : 1; n.tr = n.small ? 3.5 : (n.d.observed ? 8 : 6) + n.info.p * 6; keep.add(n.id); });
  // two-hop nodes sit beyond the labelled columns; with a packed overflow block they stay in the panel only
  const shownPeers = new Set(peers.length > LABELED ? [] : peers.map(n => n.id));
  const h2 = F.hop2.filter(p => shownPeers.has(p.via) && p.p >= 0.1).slice(0, 10).map(p => { const n = peerNode(p.ip); n.info = p; return n; });
  h2.forEach((n, i) => {
    const via = nodes.get(n.info.via);
    const sib = h2.slice(0, i).filter(m => m.info.via === n.info.via).length;
    n.tx = via.tx + 260 + Math.floor(sib / 4) * 190; n.ty = via.ty + ((sib % 4) - 1.5) * 52;
    n.ta = 0.85; n.tr = 5; keep.add(n.id);
  });
  edges = [];
  F.attackers.slice(0, SIDE_MAX).forEach(a => {
    const n = nodes.get('ext:' + a.ip), sm = n.small;
    if (a.dir === 'out') {
      edges.push(mkEdge(center, n, RETURN, a.out_sessions, !a.out_established, 'atk', a, false, sm));
      return;
    }
    edges.push(mkEdge(n, center, KIND[a.kind], Math.max(a.sessions, a.alerts + a.alerts_blocked), a.kind === 'blocked' || a.kind === 'attempt', 'atk', a, false, sm));
    if (a.out_sessions) edges.push(mkEdge(center, n, RETURN, a.out_sessions, !a.out_established, 'ret', a, true, sm));
  });
  domains.forEach(n => edges.push(mkEdge(center, n, '#2ee6d6', 1, true, 'dns', n.info, false, false)));
  F.peers.slice(0, SIDE_MAX).forEach(p => {
    const n = nodes.get(p.ip), sm = n.small, c = BAND[p.band], none = p.band === 'None';
    if (p.out_tries) edges.push(mkEdge(center, n, c, none ? p.out_tries : p.out, none || !p.out, 'out', p, false, sm));
    if (p.in_tries) edges.push(mkEdge(n, center, c, none ? p.in_tries : p.in, none || !p.in, 'in', p, !!p.out_tries, sm));
  });
  h2.map(n => n.info).forEach(p => edges.push(mkEdge(nodes.get(p.via), nodes.get(p.ip), BAND[p.band], 2, true, 'hop2', p)));
  // camera: fit the focus constellation
  let minX = -60, maxX = 60, minY = -60, maxY = 60;
  keep.forEach(k => { const n = nodes.get(k); minX = Math.min(minX, n.tx); maxX = Math.max(maxX, n.tx); minY = Math.min(minY, n.ty); maxY = Math.max(maxY, n.ty); });
  minX -= 130; maxX += 110;           // room for the labels beside the outer nodes
  const drawerW = document.body.classList.contains('ai-chat-open') && W > 1100 ? $('analyst-chat').getBoundingClientRect().width : 0;
  const panelW = drawerW ? drawerW + Math.min(100, W * 0.06) : (W > 900 ? 420 : 0);
  const railW = W > 900 ? 280 : 0, mobileH = W > 900 ? 0 : H * 0.52;
  const availW = W - panelW - railW - 60, availH = H - 170 - mobileH;
  cam.tz = Math.min(1.6, Math.max(drawerW ? 0.12 : 0.25,
    Math.min(availW / (maxX - minX + 160), availH / (maxY - minY + 120))));
  cam.tx = (minX + maxX) / 2 - (railW - panelW) / 2 / cam.tz;
  cam.ty = (minY + maxY) / 2 + mobileH / 2 / cam.tz;
  if (!state.motion) snap();
  renderPanel(id); renderList();
}
function mkEdge(a, b, color, weight, dashed, kind, info, bend, small) {
  const w = small ? 0.8 : 1 + Math.min(5, Math.log2(1 + weight));
  const count = state.motion && !small && kind !== 'hop2' && !dashed ? Math.min(6, 1 + Math.floor(Math.log2(1 + weight))) : 0;
  return {a, b, color, w, dashed, kind, info, small, bend: bend ? 1 : 0,
    parts: Array.from({length: count}, () => Math.random()), speed: 0.12 + Math.random() * 0.1};
}
function overview() {
  state.mode = 'overview'; state.focus = null; state.history = [];
  document.body.classList.remove('focused');
  history.replaceState(null, '', '#');
  nodes.forEach(n => { if (n.ext || n.domain) n.ta = 0; else { n.ta = 1; n.tx = n.ox; n.ty = n.oy; n.tr = n.r; } });
  edges = [];
  fitOverview();
  $('panel').hidden = true;
  renderList();
}
function fitOverview() {
  let minX = 0, maxX = 0, minY = 0, maxY = 0;
  nodes.forEach(n => { if (!n.ext && !n.domain) { minX = Math.min(minX, n.ox); maxX = Math.max(maxX, n.ox); minY = Math.min(minY, n.oy); maxY = Math.max(maxY, n.oy); } });
  const railW = W > 900 ? 280 : 0;
  const drawerW = document.body.classList.contains('ai-chat-open') && W > 1100 ? $('analyst-chat').getBoundingClientRect().width : 0;
  const rightInset = drawerW ? drawerW + Math.min(100, W * 0.06) : 0;
  cam.tz = Math.min(1.5, Math.max(drawerW ? 0.12 : 0.2,
    Math.min((W - railW - rightInset - 80) / (maxX - minX + 200), (H - 200) / (maxY - minY + 200))));
  cam.tx = (minX + maxX) / 2 - (railW - rightInset) / 2 / cam.tz; cam.ty = (minY + maxY) / 2;
}
function snap() { nodes.forEach(n => { n.x = n.tx; n.y = n.ty; n.a = n.ta; n.r = n.tr; }); cam.x = cam.tx; cam.y = cam.ty; cam.z = cam.tz; }

// ---------------------------------------------------------------- drawing
const toS = (x, y) => [(x - cam.x) * cam.z + W / 2, (y - cam.y) * cam.z + H / 2];
const toW = (sx, sy) => [(sx - W / 2) / cam.z + cam.x, (sy - H / 2) / cam.z + cam.y];
function resize() {
  DPR = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight;
  cv.width = W * DPR; cv.height = H * DPR; ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
}
function bezier(a, b, bend) {
  const [x1, y1] = toS(a.x, a.y), [x2, y2] = toS(b.x, b.y);
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, dx = x2 - x1, dy = y2 - y1;
  const k = bend ? 0.28 : 0.1;
  return [x1, y1, mx - dy * k, my + dx * k, x2, y2];
}
const qpt = (p, t) => { const u = 1 - t; return [u * u * p[0] + 2 * u * t * p[2] + t * t * p[4], u * u * p[1] + 2 * u * t * p[3] + t * t * p[5]]; };
function frame(now) {
  const dt = Math.min(0.05, (now - t0) / 1000); t0 = now;
  const k = state.motion ? 1 - Math.pow(0.0015, dt) : 1;
  cam.x += (cam.tx - cam.x) * k; cam.y += (cam.ty - cam.y) * k; cam.z += (cam.tz - cam.z) * k;
  nodes.forEach(n => {
    const ready = now > n.born;
    n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k; n.r += (n.tr - n.r) * k;
    n.a += ((ready ? n.ta : 0) - n.a) * Math.min(1, k * 1.4);
  });
  ctx.clearRect(0, 0, W, H);
  // backdrop: deep gradient + parallax stars
  const g = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.75);
  g.addColorStop(0, BG_IN); g.addColorStop(1, BG_OUT);
  ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
  const T = now / 1000;
  stars.forEach(s => {
    const x = ((s.x * W - cam.x * cam.z * s.z * 0.15) % W + W) % W, y = ((s.y * H - cam.y * cam.z * s.z * 0.15) % H + H) % H;
    ctx.globalAlpha = 0.25 + 0.35 * s.z * (0.6 + 0.4 * Math.sin(T * 1.3 + s.p));
    ctx.fillStyle = '#9fc6ff'; ctx.fillRect(x, y, s.z * 1.6, s.z * 1.6);
  });
  ctx.globalAlpha = 1;
  drawGrid();
  const focusing = state.mode === 'focus';
  // subnet halos
  clusters.forEach(c => {
    const [x, y] = toS(c.x * (focusing ? 2.4 : 1), c.y * (focusing ? 2.4 : 1));
    ctx.globalAlpha = focusing ? 0.05 : 0.5;
    ctx.strokeStyle = 'rgba(120,170,255,.22)'; ctx.setLineDash([3, 6]); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(x, y, c.r * cam.z, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]);
    if (!focusing && cam.z > 0.35) { ctx.fillStyle = '#6f86a6'; ctx.font = '11px ui-monospace,Menlo,monospace'; ctx.textAlign = 'center';
      ctx.fillText(c.subnet, x, y - c.r * cam.z - 6); }
  });
  ctx.globalAlpha = 1;
  // overview links
  links.forEach(l => {
    const al = Math.min(l.a.a, l.b.a) * (focusing ? 0.15 : 1);
    if (al < 0.02) return;
    const [x1, y1] = toS(l.a.x, l.a.y), [x2, y2] = toS(l.b.x, l.b.y);
    ctx.globalAlpha = al * 0.22; ctx.strokeStyle = '#6ea8ff'; ctx.lineWidth = 0.6 + Math.min(2.5, Math.log10(1 + l.w));
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
  });
  ctx.globalAlpha = 1;
  // focus edges
  const hl = state.hoverEdge;
  edges.forEach(e => {
    const al = Math.min(e.a.a, e.b.a); if (al < 0.03) return;
    const p = bezier(e.a, e.b, e.bend);
    const lit = !hl || hl === e.info;
    ctx.globalAlpha = al * (lit ? (e.kind === 'hop2' ? 0.55 : e.small ? 0.35 : 0.8) : 0.12) * (e.small && hl && lit ? 2.5 : 1);
    ctx.strokeStyle = e.color; ctx.lineWidth = e.w * (lit && hl ? 1.6 : 1);
    ctx.setLineDash(e.dashed ? [5, 6] : []);
    ctx.shadowColor = e.color; ctx.shadowBlur = e.dashed || e.small ? 0 : 8;
    ctx.beginPath(); ctx.moveTo(p[0], p[1]); ctx.quadraticCurveTo(p[2], p[3], p[4], p[5]); ctx.stroke();
    ctx.setLineDash([]); ctx.shadowBlur = 0;
    if (e.kind !== 'dns' && (!e.small || (hl && lit))) arrow(p, e.color, al * (lit ? 1 : 0.2), e.b.r * cam.z);
    if (e.parts.length) {
      ctx.globalCompositeOperation = 'lighter';
      e.parts.forEach((t, i) => {
        t = (t + dt * e.speed * (e.kind === 'in' ? 0.6 : 1)) % 1; e.parts[i] = t;
        const [x, y] = qpt(p, t);
        const r = 1.6 + e.w * 0.5;
        const gr = ctx.createRadialGradient(x, y, 0, x, y, r * 3);
        gr.addColorStop(0, '#ffffff'); gr.addColorStop(0.3, e.color); gr.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.globalAlpha = al * (lit ? 0.95 : 0.15); ctx.fillStyle = gr;
        ctx.beginPath(); ctx.arc(x, y, r * 3, 0, Math.PI * 2); ctx.fill();
      });
      ctx.globalCompositeOperation = 'source-over';
    }
  });
  ctx.globalAlpha = 1;
  // nodes
  const order = [...nodes.values()].filter(n => n.a > 0.02).sort((a, b) => a.a - b.a);
  order.forEach(n => drawNode(n, T));
  // overview satellites: outside sources orbiting exposed hosts
  if (!focusing && state.motion) nodes.forEach(n => {
    if (n.ext || !n.d.ext || n.a < 0.3) return;
    const cnt = Math.min(10, Math.ceil(Math.log2(1 + n.d.ext) * 1.6));
    const [x, y] = toS(n.x, n.y);
    for (let i = 0; i < cnt; i++) {
      const ang = T * (0.4 + i * 0.03) + i * (Math.PI * 2 / cnt), rr = (n.r + 9 + (i % 3) * 4) * cam.z;
      ctx.globalAlpha = n.a * 0.8; ctx.fillStyle = n.d.alert && i === 0 ? '#ff3b5c' : '#ffc857';
      ctx.beginPath(); ctx.arc(x + rr * Math.cos(ang), y + rr * Math.sin(ang), Math.max(1.2, 1.6 * cam.z), 0, 7); ctx.fill();
    }
  });
  ctx.globalAlpha = 1;
  if (focusing) sideTitles();
  requestAnimationFrame(frame);
}
function drawGrid() {
  const step = 120 * cam.z; if (step < 24) return;
  ctx.strokeStyle = 'rgba(80,140,255,.05)'; ctx.lineWidth = 1;
  const [ox, oy] = toS(0, 0);
  ctx.beginPath();
  for (let x = ox % step; x < W; x += step) { ctx.moveTo(x, 0); ctx.lineTo(x, H); }
  for (let y = oy % step; y < H; y += step) { ctx.moveTo(0, y); ctx.lineTo(W, y); }
  ctx.stroke();
}
function arrow(p, color, al, rb) {
  const t = 0.985, [x, y] = qpt(p, t), [x0, y0] = qpt(p, 0.93);
  const ang = Math.atan2(y - y0, x - x0), back = Math.min(rb + 3, 40);
  const ax = p[4] - Math.cos(ang) * back, ay = p[5] - Math.sin(ang) * back;
  ctx.globalAlpha = al; ctx.fillStyle = color;
  ctx.beginPath(); ctx.moveTo(ax, ay);
  ctx.lineTo(ax - 9 * Math.cos(ang - 0.4), ay - 9 * Math.sin(ang - 0.4));
  ctx.lineTo(ax - 9 * Math.cos(ang + 0.4), ay - 9 * Math.sin(ang + 0.4)); ctx.closePath(); ctx.fill();
}
function nodeLabel(n) {
  if (n.domain) return n.d.id.length > 24 ? n.d.id.slice(0, 23) + '…' : n.d.id;
  return n.ext ? n.d.id : (n.d.name ? n.d.name.split('.')[0] : n.d.id);
}
function drawNode(n, T) {
  const [x, y] = toS(n.x, n.y), r = Math.max(2, n.r * cam.z);
  if (x < -80 || y < -80 || x > W + 80 || y > H + 80) return;
  const sel = state.focus === n.id, hov = state.hover === n;
  ctx.globalAlpha = n.a;
  if (sel) {   // radar rings and sweep on the selected host
    for (let i = 0; i < 3; i++) {
      const ph = ((T * 0.6 + i / 3) % 1);
      ctx.globalAlpha = n.a * (1 - ph) * 0.6; ctx.strokeStyle = n.color; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(x, y, r + ph * 90 * cam.z, 0, 7); ctx.stroke();
    }
    if (state.motion) {
      const sw = ctx.createConicGradient ? ctx.createConicGradient(T * 1.4, x, y) : null;
      if (sw) { sw.addColorStop(0, 'rgba(46,230,214,.22)'); sw.addColorStop(0.12, 'rgba(46,230,214,0)'); sw.addColorStop(1, 'rgba(46,230,214,0)');
        ctx.globalAlpha = n.a; ctx.fillStyle = sw; ctx.beginPath(); ctx.arc(x, y, 160 * cam.z, 0, 7); ctx.fill(); }
    }
    ctx.globalAlpha = n.a;
  }
  ctx.shadowColor = n.color; ctx.shadowBlur = (sel ? 30 : hov ? 22 : 12);
  if (n.domain) { // source-linked DNS observations are separate from network traffic nodes
    ctx.fillStyle = 'rgba(8,40,48,.95)'; ctx.strokeStyle = '#2ee6d6'; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
    ctx.shadowBlur = 0;
    ctx.beginPath(); ctx.arc(x, y, r + 6, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = '#2ee6d6'; ctx.font = '700 10px ui-monospace,Menlo,monospace'; ctx.textAlign = 'center';
    ctx.fillText('D', x, y + 3);
  } else if (n.ext) {   // outside sources are diamonds
    ctx.fillStyle = n.info.kind === 'blocked' ? 'rgba(20,30,46,.9)' : n.color;
    ctx.strokeStyle = n.color; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(x, y - r * 1.25); ctx.lineTo(x + r * 1.25, y); ctx.lineTo(x, y + r * 1.25); ctx.lineTo(x - r * 1.25, y); ctx.closePath();
    ctx.fill(); ctx.stroke();
    if (iocIds.has('ip:' + n.d.id)) {
      ctx.strokeStyle = '#2ee6d6'; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(x, y, r + 6, 0, Math.PI * 2); ctx.stroke();
    }
  } else if (!n.d.observed) {
    ctx.fillStyle = 'rgba(14,22,36,.9)'; ctx.strokeStyle = '#8da2b5'; ctx.lineWidth = 1.5; ctx.setLineDash([2, 2]);
    ctx.beginPath(); ctx.arc(x, y, r, 0, 7); ctx.fill(); ctx.stroke(); ctx.setLineDash([]);
  } else {
    const gr = ctx.createRadialGradient(x - r * 0.3, y - r * 0.3, r * 0.1, x, y, r);
    gr.addColorStop(0, '#ffffff'); gr.addColorStop(0.25, n.color); gr.addColorStop(1, shade(n.color));
    ctx.fillStyle = gr; ctx.beginPath(); ctx.arc(x, y, r, 0, 7); ctx.fill();
    if (n.d.ev) { ctx.shadowBlur = 0; ctx.strokeStyle = n.d.ev === 'likely' ? '#ff3b5c' : '#ffd23f'; ctx.lineWidth = 2;
      ctx.setLineDash([4, 3]); ctx.beginPath(); ctx.arc(x, y, r + 5, T % 7, T % 7 + 6.28); ctx.stroke(); ctx.setLineDash([]); }
  }
  ctx.shadowBlur = 0;
  if (hov && !sel) { ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, r + 4, 0, 7); ctx.stroke(); }
  // labels
  const show = state.labels && (sel || hov || (state.mode === 'focus' ? n.a > 0.5 && !n.small : (n.d.observed && (cam.z > 0.55 || n.d.pri === 'P1'))));
  if (show) {
    const name = nodeLabel(n);
    ctx.font = (sel ? '600 14px' : '12px') + ' system-ui,-apple-system,Segoe UI,sans-serif';
    const side = n.domain ? 'center' : n.ext ? 'right' : (state.mode === 'focus' && n.id !== state.focus && n.info) ? 'left' : 'center';
    ctx.textAlign = side;
    const lx = side === 'right' ? x - r - 8 : side === 'left' ? x + r + 8 : x, ly = side === 'center' ? y + r + 15 : y + 4;
    ctx.lineWidth = 4; ctx.strokeStyle = 'rgba(3,6,12,.85)'; ctx.strokeText(name, lx, ly);
    ctx.fillStyle = sel ? '#ffffff' : '#d6e4f5'; ctx.fillText(name, lx, ly);
    // tight columns: keep everything on one line so neighbouring rows don't collide
    const tight = state.mode === 'focus' && !sel && (n.gap || 99) * cam.z < 42;
    if (tight && n.info && n.info.band && side === 'left') {
      const nw = ctx.measureText(name).width;
      ctx.font = '600 10.5px ui-monospace,Menlo,monospace'; ctx.fillStyle = BAND[n.info.band];
      const t = n.info.band === 'None' ? 'NO SESSION' : (n.info.p * 100).toFixed(0) + '% ' + n.info.band.toUpperCase();
      ctx.strokeText(t, lx + nw + 8, ly); ctx.fillText(t, lx + nw + 8, ly);
    } else if ((sel || state.mode === 'focus') && !n.ext && n.d.name) {
      ctx.font = '10.5px ui-monospace,Menlo,monospace'; ctx.fillStyle = '#7f95b3';
      ctx.strokeText(n.d.id, lx, ly + 13); ctx.fillText(n.d.id, lx, ly + 13);
    }
    if (state.mode === 'focus' && n.info && n.info.band && !sel && !tight) {
      ctx.font = '600 10.5px ui-monospace,Menlo,monospace'; ctx.fillStyle = BAND[n.info.band];
      const t = n.info.band === 'None' ? 'NO SESSION' : (n.info.p * 100).toFixed(0) + '% ' + n.info.band.toUpperCase();
      ctx.strokeText(t, lx, ly + 26); ctx.fillText(t, lx, ly + 26);
    }
  }
  ctx.globalAlpha = 1;
}
function shade(hex) { const c = parseInt(hex.slice(1), 16); return `rgb(${(c >> 16 & 255) * 0.35 | 0},${(c >> 8 & 255) * 0.35 | 0},${(c & 255) * 0.35 | 0})`; }
function sideTitles() {
  const F = D.focus[state.focus]; if (!F) return;
  ctx.font = '600 11px ui-monospace,Menlo,monospace'; ctx.textAlign = 'center'; ctx.fillStyle = '#7f95b3';
  let top = 0;
  nodes.forEach(n => { if (n.ta > 0.5 && n.id !== state.focus) top = Math.min(top, n.ty); });
  const [cx, ly0] = toS(0, top - 46), ly = Math.max(96, ly0);
  const lx = cx - 30, rx = cx + 30;
  ctx.globalAlpha = 0.9;
  const more = (n, shown) => n > shown ? `  (+${n - shown} in panel)` : '';
  ctx.textAlign = 'right';
  const lt = `◀ NORTH / SOUTH · ${F.attackers_total} OUTSIDE ADDRESS${F.attackers_total === 1 ? '' : 'ES'}${more(F.attackers_total, Math.min(SIDE_MAX, F.attackers.length))}`;
  const minL = (W > 900 ? 290 : 10) + ctx.measureText(lt).width;
  const lxe = Math.max(lx, minL);
  ctx.fillText(lt, lxe, Math.max(90, ly));
  ctx.textAlign = 'left';
  ctx.fillText(`EAST / WEST · ${F.peers_total} INTERNAL HOST${F.peers_total === 1 ? '' : 'S'}${more(F.peers_total, Math.min(SIDE_MAX, F.peers.length))} ▶`, Math.max(rx, lxe + 28), Math.max(90, ly));
  ctx.globalAlpha = 1;
}

// ---------------------------------------------------------------- interaction
function pick(sx, sy) {
  let best = null, bd = 1e9;
  nodes.forEach(n => {
    if (n.a < 0.3) return;
    const [x, y] = toS(n.x, n.y), d = Math.hypot(x - sx, y - sy), r = Math.max(8, n.r * cam.z + 6);
    const labelRight = x - r - 8;
    const extLabelHit = n.ext && state.mode === 'focus' && state.labels && !n.small && n.a > 0.5
      && sx >= labelRight - n.d.id.length * 7.5 && sx <= labelRight
      && Math.abs(sy - (y + 4)) < 12;
    const domainWidth = nodeLabel(n).length * 7.5;
    const domainLabelHit = n.domain && state.mode === 'focus' && state.labels && n.a > 0.5
      && sx >= x - domainWidth / 2 && sx <= x + domainWidth / 2
      && Math.abs(sy - (y + Math.max(2, n.r * cam.z) + 15)) < 12;
    const labelHit = extLabelHit || domainLabelHit;
    const score = labelHit ? 0 : d;
    if ((d < r || labelHit) && score < bd) { bd = score; best = n; }
  });
  return best;
}
let drag = null;
cv.addEventListener('pointerdown', e => { drag = {x: e.clientX, y: e.clientY, cx: cam.tx, cy: cam.ty,
  node: pick(e.clientX, e.clientY), moved: false}; cv.setPointerCapture(e.pointerId); });
cv.addEventListener('pointermove', e => {
  if (drag) {
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) { drag.moved = true; cv.classList.add('dragging'); }
    if (drag.moved) { cam.tx = drag.cx - dx / cam.z; cam.ty = drag.cy - dy / cam.z; cam.x = cam.tx; cam.y = cam.ty; }
    return;
  }
  const n = pick(e.clientX, e.clientY);
  state.hover = n; cv.classList.toggle('hover', !!n);
  state.hoverEdge = n && n.info && state.mode === 'focus' ? n.info : null;
  tip(n, e.clientX, e.clientY);
});
cv.addEventListener('pointerup', e => {
  const wasDrag = drag && drag.moved, startNode = drag && drag.node;
  drag = null; cv.classList.remove('dragging');
  if (wasDrag) return;
  const n = pick(e.clientX, e.clientY) || startNode;
  if (!n) return;
  if (n.domain) {
    document.dispatchEvent(new CustomEvent('ioc:open', {detail: {id: n.id}}));
    return;
  }
  if (n.ext) {
    const key = 'ip:' + n.d.id;
    if (iocIds.has(key)) document.dispatchEvent(new CustomEvent('ioc:open', {detail: {id: key}}));
    return;
  }
  if (!n.ext && D.focus[n.id]) focus(n.id);
});
cv.addEventListener('dblclick', e => { if (!pick(e.clientX, e.clientY)) { overview(); } });
cv.addEventListener('pointerleave', () => { state.hover = null; tip(null); });
cv.addEventListener('wheel', e => {
  e.preventDefault();
  const [wx, wy] = toW(e.clientX, e.clientY);
  const z = Math.max(0.12, Math.min(4, cam.tz * Math.exp(-e.deltaY * 0.0015)));
  cam.tz = z; cam.tx = wx - (e.clientX - W / 2) / z; cam.ty = wy - (e.clientY - H / 2) / z;
}, {passive: false});
function tip(n, x, y) {
  const el = $('tip');
  if (!n) { el.hidden = true; return; }
  let h;
  if (n.domain) {
    const observed = n.info.observed && n.info.observed['dns event'];
    h = `<b>${esc(n.d.id)}</b> <span class="m">domain IOC · ${observed ? 'observed DNS query' : 'observed domain match'}</span>` +
      '<br>Exact IOC match. A DNS query alone does not prove a connection or compromise.' +
      '<br><span style="color:#2ee6d6">Click for report overview</span>';
  } else if (n.ext) {
    const a = n.info;
    h = `<b>${esc(a.ip)}</b> <span class="m">outside address · north/south</span><br>${esc(KIND_TXT[a.kind])}` +
      (a.dir !== 'out' ? `<br><span class="m">Inbound: ${a.sessions} session(s), ${a.established} completed, ${a.blocked} blocked` +
        (a.ports.length ? `; ports ${esc(a.ports.join(', '))}` : '') + '</span>' : '') +
      (a.out_sessions ? `<br><span class="m">Outbound from the host: ${a.out_sessions} session(s), ${a.out_established} completed` +
        (a.out_ports.length ? `; ports ${esc(a.out_ports.join(', '))}` : '') + '</span>' : '') +
      (a.alerts || a.alerts_blocked ? `<br>IPS: ${a.alerts} not blocked, ${a.alerts_blocked} blocked` : '') +
      (a.signatures.length ? `<br><span class="m">${esc(a.signatures.join('; '))}</span>` : '') +
      (a.returned && a.dir === 'both' ? '<br><span style="color:#b98cff">The host also connected out to this address (lead)</span>' : '') +
      (iocIds.has('ip:' + a.ip) ? '<br><span style="color:#2ee6d6">Click for IOC details</span>' : '');
  } else {
    const d = n.d, info = state.mode === 'focus' && n.info && n.id !== state.focus ? n.info : null;
    h = `<b>${esc(d.name || d.id)}</b>${d.name ? ` <span class="m">${esc(d.id)}</span>` : ''}<br>` +
      (telemetryOnly ? '<span class="m">Vulnerability data unavailable; status unknown</span>' :
        d.scanned ? `<span class="pill ${esc(d.pri)}">${esc(d.pri)}</span> worst finding ${esc(d.sev || 'none')}` : '<span class="m">Not in the vulnerability scan</span>') +
      (info && info.band === 'None' ? `<br>East/west attempts only, no completed session<br><span class="m">${esc(info.why.join('; '))}</span>` : '') +
      (info && info.band !== 'None' && !telemetryOnly ? `<br>Estimated likelihood if ${esc(state.focus)} is exploited: <b style="color:${BAND[info.band]}">${Math.round(info.p * 100)}% ${info.band}</b>` +
        `<br><span class="m">${esc(info.why.join('; '))}</span>` : '') +
      (D.focus[n.id] && n.id !== state.focus ? '<br><span class="m">Click to focus</span>' : '');
  }
  el.innerHTML = h; el.hidden = false;
  const r = el.getBoundingClientRect();
  el.style.left = Math.min(W - r.width - 10, x + 16) + 'px'; el.style.top = Math.min(H - r.height - 10, y + 16) + 'px';
}
addEventListener('keydown', e => {
  if (e.target.closest('#analyst-chat') || e.target.closest('#btn-ai')) return;
  if (e.target.tagName === 'INPUT') { if (e.key === 'Escape') e.target.blur(); return; }
  if (e.key === 'Escape') { state.history.length ? focus(state.history.pop(), false) : overview(); }
  else if (e.key === '/') { e.preventDefault(); $('search').focus(); }
  else if (e.key === 'l' || e.key === 'L') toggleLabels();
  else if (e.key === 'm' || e.key === 'M') toggleMotion();
  else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
    const ids = hostOrder(); const i = ids.indexOf(state.focus);
    focus(ids[(i + (e.key === 'ArrowRight' ? 1 : ids.length - 1)) % ids.length]);
  }
});
addEventListener('resize', () => { resize(); state.mode === 'focus' ? focus(state.focus, false) : fitOverview(); });

// ---------------------------------------------------------------- panels
function hostOrder() {
  return Object.keys(D.focus).sort((a, b) => {
    const A = nodes.get(a).d, B = nodes.get(b).d;
    return (A.pri || 'P9').localeCompare(B.pri || 'P9') || (B.score - A.score) || a.localeCompare(b);
  });
}
function renderList() {
  const q = $('search').value.trim().toLowerCase();
  const rows = hostOrder().filter(id => {
    if (iocOnly && !iocCounts[id]) return false;
    if (!q) return true;
    const d = nodes.get(id).d, F = D.focus[id];
    return (id + ' ' + d.name + ' ' + d.os + ' ' + F.findings.map(f => f.name + ' ' + f.cves.join(' ')).join(' ')).toLowerCase().includes(q);
  });
  $('hostlist').innerHTML = rows.map(id => {
    const d = nodes.get(id).d, F = D.focus[id];
    const iocCount = iocCounts[id] || 0;
  const iocHint = iocCount ? `<span class="ioc-host-badge" title="${iocCount} exact IOC match${iocCount === 1 ? '' : 'es'}; review the source and traffic" aria-label="${iocCount} IOC match${iocCount === 1 ? '' : 'es'}">IOC ${iocCount}</span>` : '';
    return `<div class="hrow${id === state.focus ? ' on' : ''}" role="listitem" tabindex="0" data-id="${esc(id)}">` +
      (telemetryOnly ? '<span class="pill">UNKNOWN</span>' : `<span class="pill ${esc(d.pri)}">${esc(d.pri)}</span>`) + `<span class="nm">${esc((d.name || id).split('.')[0])} ${iocHint}` +
      `<br><span class="ip">${esc(id)} · ${F.attackers_total} N/S · ${F.peers_total} E/W</span></span>` +
      (d.ev ? `<span class="tag ${d.ev}">${d.ev === 'likely' ? 'LIKELY' : 'LEAD'}</span>` : '') + '</div>';
  }).join('') || `<div class="hrow">${iocOnly ? 'No IOC hosts match' : 'No match'}</div>`;
}
// These are recorded source/originator -> destination/responder tuples, not
// arrows inferred from an internet/internal boundary or a vulnerability scan.
function connectionExamples(items, total) {
  if (!items || !items.length) return '';
  const endpoint = (ip, port) => `${esc(ip)}:${port == null ? '?' : esc(port)}`;
  return `<div class="conn-examples">${items.map(f =>
    `<div class="conn-line"><span class="conn-path">${endpoint(f.src_ip, f.src_port)} → ${endpoint(f.dst_ip, f.dst_port)}</span>` +
    ` · ${esc(f.proto || 'transport unknown')}${f.app ? ` · logged app/service: ${esc(f.app)}` : ''}` +
    `${f.action !== 'allow' ? ` · ${esc(f.action)}` : !f.established ? ' · not completed' : ''}` +
    `${f.source ? ` <span class="conn-source">(${esc(f.source)})</span>` : ''}</div>`).join('')}` +
    (total > items.length ? `<div class="conn-more">${total} sessions total; representative distinct tuples shown.</div>` : '') +
    '</div>';
}
function alertExamples(items) {
  if (!items || !items.length) return '';
  return `<div class="conn-examples">${items.map(a =>
    `<div class="conn-line">Alert metadata: ${esc(a.src_ip)} → ${esc(a.dst_ip)}${a.dst_port == null ? '' : ':' + esc(a.dst_port)}` +
    ` · transport and source port not logged · ${a.blocked ? 'blocked' : 'not blocked'}</div>`).join('')}</div>`;
}
function otExamples(items, total) {
  if (!items || !items.length) return '';
  return `<h3>Industrial protocol records</h3><p class="onward-note">Zeek protocol records show message operations; they are not extra connection sessions or vulnerability findings.</p>` +
    items.map(e => {
      const direction = e.src_ip && e.dst_ip ? `${esc(e.src_ip)} → ${esc(e.dst_ip)}` :
        `${esc(e.originator || '?')} ↔ ${esc(e.responder || '?')} (message direction not logged)`;
      return `<div class="ot-record"><b>${esc(e.protocol)}</b>${e.operation ? ` · ${esc(e.operation)}` : ''}<br>` +
        `<span class="conn-path">${direction}</span>` +
        `${e.message_side !== 'unknown' ? ` · sent by Zeek ${esc(e.message_side)}` : ''}` +
        `${e.source ? ` · ${esc(e.source)}` : ''}</div>`;
    }).join('') + (total > items.length ?
      `<div class="conn-more">Showing ${items.length} of ${total} industrial records. See normalized/ot_events.jsonl for all records.</div>` : '');
}
let iocOnly = false;
const iocHostTotal = Object.values(iocCounts).filter(count => count > 0).length;
if (iocHostTotal) {
  $('ioc-filter').hidden = false;
  $('ioc-host-count').textContent = `(${iocHostTotal})`;
  $('ioc-filter').title = 'Show only hosts with exact IOC matches';
  $('ioc-filter').addEventListener('click', () => {
    iocOnly = !iocOnly;
    $('ioc-filter').setAttribute('aria-pressed', String(iocOnly));
    renderList();
  });
}
$('hostlist').addEventListener('click', e => { const r = e.target.closest('.hrow[data-id]'); if (r) { focus(r.dataset.id); } });
$('hostlist').addEventListener('keydown', e => { const r = e.target.closest('.hrow[data-id]'); if (r && e.key === 'Enter') { focus(r.dataset.id); } });
$('search').addEventListener('input', renderList);
$('search').addEventListener('keydown', e => { if (e.key === 'Enter') { const r = document.querySelector('.hrow[data-id]'); if (r) focus(r.dataset.id); } });

function renderPanel(id) {
  const F = D.focus[id], d = nodes.get(id).d, p = $('panel');
  const nAlert = F.attackers.filter(a => a.kind === 'alert').length;
  const atk = F.attackers.map(a =>
    `<div class="row" data-k="atk" data-ip="${esc(a.ip)}"><span class="kind k-${a.kind}" title="${esc(KIND_TXT[a.kind])}"></span>` +
    `<span class="ip">${iocButton('ip', a.ip)}</span><span class="lk">${a.sessions ? '← ' + a.sessions : ''}${a.sessions && a.out_sessions ? '  ' : ''}${a.out_sessions ? '→ ' + a.out_sessions : ''}${a.alerts ? ' · ' + a.alerts + ' IPS' : ''}</span>` +
    `<span class="sub">${esc(KIND_TXT[a.kind])}${iocIds.has('ip:' + a.ip) ? ' · ' + iocButton('ip', a.ip, 'Report overview') : ''}${a.ports.length ? ' · ports ' + esc(a.ports.join(', ')) : ''}` +
    `${a.alerts_blocked ? ' · ' + a.alerts_blocked + ' IPS blocked' : ''}` +
    `${a.dir === 'both' && a.out_sessions ? ' · <span style="color:var(--violet)">host also connected out' + (a.out_ports.length ? ' on ' + esc(a.out_ports.join(', ')) : '') + '</span>' : ''}` +
    `${a.dir === 'out' && a.out_ports.length ? ' · ports ' + esc(a.out_ports.join(', ')) : ''}` +
    `${a.signatures.length ? '<br>' + esc(a.signatures.join('; ')) : ''}</span>` +
    connectionExamples(a.connection_examples, a.sessions + a.out_sessions) +
    (a.connection_examples && a.connection_examples.length ? '' : alertExamples(a.alert_examples)) +
    '</div>').join('') ||
    '<div class="row"><span></span><span class="sub">No north/south traffic to or from this host in the telemetry.</span></div>';
  const peers = F.peers.map(q => {
    const pd = peerNode(q.ip).d, nm = pd.name ? pd.name.split('.')[0] : q.ip, none = q.band === 'None';
    const o = none ? q.out_tries : q.out, i = none ? q.in_tries : q.in;
    const dir = (o ? `→ ${o}` : '') + (o && i ? '  ' : '') + (i ? `← ${i}` : '');
    return `<div class="row peer" data-k="peer" data-ip="${esc(q.ip)}"><div class="bar b-${q.band}"><i style="width:${Math.round(q.p * 100)}%"></i></div>` +
      `<span>${D.focus[q.ip] ? `<span class="go" data-go="${esc(q.ip)}">${esc(nm)}</span>` : esc(nm)} <span class="ip" style="color:var(--muted);font-size:11px">${esc(q.ip)}</span></span>` +
      `<span class="lk" style="color:${BAND[q.band]}">${none ? 'no session' : telemetryOnly ? 'observed' : Math.round(q.p * 100) + '% ' + q.band}</span>` +
      `<span class="sub">${esc(dir)} ${none ? 'attempts, none completed' : 'sessions'}${q.ports_out.length ? ' · ' + (none ? 'tried ' : 'uses ') + esc(q.ports_out.join(', ')) : ''}${telemetryOnly ? ' · vulnerability status unknown' : pd.scanned ? ' · worst ' + esc(pd.sev || 'none') : ' · not scanned'}</span>` +
      connectionExamples(q.connection_examples, q.out_tries + q.in_tries) +
      `<ul class="why" hidden>${q.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div>`;
  }).join('') || '<div class="row"><span></span><span class="sub">No east/west traffic to or from this host in the telemetry.</span></div>';
  const h2list = F.hop2.filter(q => q.p >= 0.05).slice(0, 12);
  const hop2 = h2list.length ? `<h3>Possible onward connections</h3>` +
    `<p class="onward-note">Each path follows observed connections through a directly connected internal host. These scores are investigation leads, not confirmed compromise.</p>` +
    h2list.map(q =>
      `<div class="row peer" data-k="peer" data-ip="${esc(q.ip)}"><div class="bar b-${q.band}"><i style="width:${Math.round(q.p * 100)}%"></i></div>` +
      `<span class="ip">${esc(q.ip)}</span><span class="lk" style="color:${BAND[q.band]}">${Math.round(q.p * 100)}%</span>` +
      `<span class="sub">via ${esc(q.via)}</span><ul class="why" hidden>${q.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div>`).join('') : '';
  const fds = F.findings.map(f =>
    `<div class="fd"><span class="pill ${esc(f.pri)}">${esc(f.pri)}</span> <b>${esc(f.name)}</b>` +
    `<div class="meta">${f.port ? esc(f.port + '/' + f.proto) : 'host-level'} · ${esc(f.sev)} · CVSS ${Number(f.cvss).toFixed(1)}` +
    `${f.exploit ? ' · public exploit' : ''} · score ${f.score}${f.cves.length ? ' · ' + f.cves.map(c => iocButton('cve', c)).join(', ') : ''}<br>${esc(f.exposure)}</div>` +
    f.evidence.map(e => `<div class="ev"><span class="tag ${e.c === 'corroborated' ? 'likely' : 'lead'}">${e.c === 'corroborated' ? 'LIKELY' : 'LEAD'}</span> ${esc(e.t)}</div>`).join('') + '</div>').join('');
  p.innerHTML =
    `<div style="display:flex;justify-content:space-between;gap:8px;align-items:start"><div><h2>${esc(d.name ? d.name.split('.')[0] : id)}</h2>` +
    `<div class="ipline">${esc(id)}${d.name ? ' · ' + esc(d.name) : ''}</div><div class="ipline">${esc(d.os)}</div></div>` +
    `<div style="text-align:right">${telemetryOnly ? '<span class="pill">UNKNOWN</span><div class="ipline">No vulnerability data</div>' : `<span class="pill ${esc(d.pri)}">${esc(d.pri)}</span><div class="ipline">score ${d.score}</div>`}` +
    (d.ev ? `<span class="tag ${d.ev}">${d.ev === 'likely' ? 'LIKELY EXPLOITATION' : 'LEAD'}</span>` : '') + `</div></div>` +
    `<div class="stats"><div class="stat red"><b>${F.attackers_total}</b><span>outside addresses (N/S)${nAlert ? `, ${nAlert} with IPS alerts` : ''}</span></div>` +
    `<div class="stat pink"><b>${F.peers_total}</b><span>internal hosts (E/W)${telemetryOnly ? '' : ` · ${F.blast.high} high, ${F.blast.medium} med`}</span></div></div>` +
    (state.history.length ? `<p style="margin:10px 0 0"><button id="btn-back">← Back to ${esc(state.history[state.history.length - 1])}</button></p>` : '') +
    `<p class="direction-note">Recorded direction: source/originator → destination/responder. Ports are source → destination; ? means the log did not provide a port. Logged application labels appear only when supplied.</p>` +
    `<h3>North / south: outside addresses</h3>${atk}` +
    (F.attackers_total > F.attackers.length ? `<div class="row"><span></span><span class="sub">${F.attackers_total - F.attackers.length} more not shown</span></div>` : '') +
    `<h3>${telemetryOnly ? 'East / west: observed internal connections' : 'East / west: internal hosts · blast radius if exploited'}</h3>${peers}${hop2}` +
    (F.peers_total > F.peers.length ? `<div class="row"><span></span><span class="sub">${F.peers_total - F.peers.length} more not shown</span></div>` : '') +
    otExamples(F.ot_events, F.ot_events_total) +
    `<h3>Vulnerabilities</h3>${telemetryOnly ? '<div class="fd">No vulnerability data available; status unknown.</div>' : fds || '<div class="fd">None at the configured severity.</div>'}` +
    (D.ioc_matches && D.ioc_matches.some(item => item.hosts.includes(id))
      ? `<h3>IOC matches</h3><div class="note">Exact IOC matches are leads for review.</div>` +
        D.ioc_matches.filter(item => item.hosts.includes(id)).map(item =>
          `<div class="fd">${iocButton(item.type, item.value)} <span class="meta">${esc(item.type)} · ${item.articles.length} source link(s)</span> · ${iocButton(item.type, item.value, 'View details')}</div>`).join('')
      : '') +
    `<div class="note">This view shows observed traffic to and from the host: outside addresses on the left, internal hosts on the right. Outside contact alone is not proof of compromise. ` +
    (telemetryOnly ? 'Vulnerability status is unknown. Review alerts and IOC matches as leads; only host evidence confirms a compromise.' :
    `Likelihood is an estimate from observed sessions, the ports in use and the scanner's findings on each peer. Use it to decide where to look first; only host evidence confirms a compromise. Click a row for the reasons.`) + '</div>';
  p.hidden = false; p.scrollTop = 0;
  const back = $('btn-back'); if (back) back.onclick = () => focus(state.history.pop(), false);
}
$('panel').addEventListener('click', e => {
  const go = e.target.closest('[data-go]'); if (go) { focus(go.dataset.go); return; }
  const row = e.target.closest('.row.peer'); if (row) { const w = row.querySelector('.why'); if (w) w.hidden = !w.hidden; }
});
$('panel').addEventListener('mouseover', e => {
  const row = e.target.closest('.row[data-ip]'); const F = D.focus[state.focus];
  if (!row || !F) { state.hoverEdge = null; return; }
  const ip = row.dataset.ip;
  state.hoverEdge = (row.dataset.k === 'atk' ? F.attackers : F.peers.concat(F.hop2)).find(x => x.ip === ip) || null;
  state.hover = nodes.get(row.dataset.k === 'atk' ? 'ext:' + ip : ip) || null;
});
$('panel').addEventListener('mouseleave', () => { state.hoverEdge = null; state.hover = null; });

// ---------------------------------------------------------------- controls
function toggleLabels() { state.labels = !state.labels; $('btn-labels').setAttribute('aria-pressed', state.labels); }
function toggleMotion() {
  state.motion = !state.motion; $('btn-motion').setAttribute('aria-pressed', state.motion);
  if (state.mode === 'focus') focus(state.focus, false);
}
$('btn-overview').onclick = () => { overview(); };
$('btn-labels').onclick = toggleLabels;
$('btn-motion').onclick = toggleMotion;
if (!state.motion) $('btn-motion').setAttribute('aria-pressed', 'false');

$('legend').innerHTML =
  `<span><i style="background:${KIND.alert}"></i>IPS alert, not blocked</span>` +
  (telemetryOnly ? '' : `<span><i style="background:${KIND.vuln}"></i>Reached a vulnerable service</span>`) +
  `<span><i style="background:${KIND.reached}"></i>Reached the host</span>` +
  `<span><i style="background:repeating-linear-gradient(90deg,#5b6b82 0 5px,transparent 5px 9px)"></i>Blocked or failed, no session</span>` +
  `<span><i style="background:${RETURN}"></i>Host connected out</span>` +
  `<span><span class="sw" style="background:transparent;border:2px solid #2ee6d6"></span>Click outlined IP or domain IOC for report overview</span>` +
  (telemetryOnly ? '' : `<span><i style="background:${BAND.High}"></i><i style="background:${BAND.Medium};width:12px"></i><i style="background:${BAND.Low};width:12px"></i>Blast-radius likelihood high / medium / low</span>` +
  `<span><span class="sw" style="background:${SEV.Critical}"></span>Critical <span class="sw" style="background:${SEV.High}"></span>High <span class="sw" style="background:${SEV.Medium}"></span>Medium <span class="sw" style="background:${SEV.Low}"></span>Low</span>`) +
  `<span class="cal">${telemetryOnly ? 'No vulnerability data; status unknown' : 'Leads and estimates, not confirmed compromise'}</span>`;

const c = D.counts, w = D.window;
$('subtitle').textContent = (telemetryOnly ? `${c.hosts} observed hosts · no vulnerability data · ${c.flows.toLocaleString()} sessions · ${c.alerts} IPS alerts` : `${c.hosts} scanned hosts · ${c.flows.toLocaleString()} sessions · ${c.p1} P1 · ${c.alerts} IPS alerts`) +
  (w[0] ? ` · ${w[0].slice(0, 10)} → ${(w[1] || '').slice(0, 10)}` : '');

// ---------------------------------------------------------------- start
resize(); renderList(); fitOverview();
const introText = telemetryOnly ? `Exploring ${c.hosts} observed hosts and ${c.flows.toLocaleString()} sessions` : `Correlating ${c.hosts} hosts against ${c.flows.toLocaleString()} sessions`;
if (state.motion) {
  let i = 0; const it = setInterval(() => { $('intro-text').textContent = introText.slice(0, ++i) + (i < introText.length ? '▌' : ''); if (i >= introText.length) clearInterval(it); }, 22);
  setTimeout(() => $('intro').classList.add('gone'), 1500);
} else { $('intro').style.display = 'none'; nodes.forEach(n => n.born = 0); snap(); }
const m = location.hash.match(/host=([^&]+)/);
if (m && D.focus[decodeURIComponent(m[1])]) {
  if (state.motion) setTimeout(() => focus(decodeURIComponent(m[1])), 900); else { focus(decodeURIComponent(m[1])); snap(); }
}
requestAnimationFrame(frame);
})();
