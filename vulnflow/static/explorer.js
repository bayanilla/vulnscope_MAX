(function () {
'use strict';
const D = JSON.parse(document.getElementById('vf-data').textContent);
const telemetryOnly = D.vulnerability_data_available === false;
if (telemetryOnly) document.getElementById('hint').textContent =
  'Click a host to inspect recorded endpoints, ports, protocols, and direction.';
const cv = document.getElementById('stage'), ctx = cv.getContext('2d');
// cinematic 3D view (explorer3d.js, Three.js); the 2D canvas stays as the fallback and draws labels on top
const cv3 = document.getElementById('stage3d');
// 3D is the default where WebGL works; choosing Flat is remembered, ?3d / ?2d force one
const KEY3D = 'vulnscope-explorer-3d-v3';
const can3d = !!(cv3 && window.VF3D && window.VF3D.supported());
let R3 = null, R3inst = null;
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
const KIND_RANK = {alert: 0, vuln: 1, reached: 2, outbound: 3, attempt: 4, blocked: 5};
const KIND_TXT = {alert: 'IPS alert, not blocked', vuln: 'Reached a vulnerable service', reached: 'Reached the host',
  outbound: 'Host connected out to it', attempt: 'Tried, no completed session', blocked: 'Blocked by firewall or IPS'};
const BAND = {High: '#ff2e88', Medium: '#ffb020', Low: '#2ee6d6', None: '#5b6b82', Unknown: '#8da2b5'};

let W = 0, H = 0, DPR = 1;
const cam = {x: 0, y: 0, z: 0.25, tx: 0, ty: 0, tz: 1, sx: 0, sy: 0, tsx: 0, tsy: 0};
const still = /[?&#]still\b/.test(location.search + location.hash);
const state = {mode: 'overview', focus: null, hover: null, labels: true, motion: !reduced && !still, history: []};
const nodes = new Map();          // id -> render node
let edges = [];                   // focus-mode edges
let t0 = performance.now();
// 3D camera. Overview: the user's own orbit (oyaw around the plane, opitch from straight above);
// host focus: small offsets (fyaw, fpitch) from a front-on view, reset on each new host.
// The overview opens on the low view, slowly turning to the left (view.spin). The turn stops for good
// as soon as the user moves the camera, picks a view or opens a host; Reset or the Spin button restart it.
const VIEWS = {top: 0, tilted: 0.82, low: 1.25};
const DEFAULT_VIEW = 'low', SPIN = Math.PI * 2 / 150;   // one full turn every 150 s
const view = {yaw: 0, pitch: VIEWS[DEFAULT_VIEW], dist: 1.6, oyaw: 0, opitch: VIEWS[DEFAULT_VIEW], fyaw: 0, fpitch: 0, idle: 0, cmix: 1, spin: true};
const hash01 = s => { let h = 2166136261; for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619); return ((h >>> 0) % 10007) / 10007; };

// ---------------------------------------------------------------- layout: overview
function overviewLayout() {
  const groups = new Map();
  D.nodes.forEach(n => { if (!groups.has(n.subnet)) groups.set(n.subnet, []); groups.get(n.subnet).push(n); });
  const subnets = [...groups.keys()].sort();
  const golden = Math.PI * (3 - Math.sqrt(5));
  const clusters = [];
  // pack subnets by their real size: largest first, each at the first spot on an outward spiral that
  // clears every placed subnet by GAP plus a share of both radii, so small subnets no longer pile up
  // in the middle and big neighbours get proportionally more room
  // big subnets pack their hosts a little tighter so one large subnet cannot crowd out the rest
  const SP = 48, GAP = 180, GAP_K = 0.3, spacing = n => SP / Math.pow(Math.max(1, n / 30), 0.25);
  const sized = subnets.map(s => {
    const members = groups.get(s).sort((a, b) => (b.observed - a.observed) || (b.score - a.score) || a.id.localeCompare(b.id));
    return {s, members, cr: 40 + spacing(members.length) * Math.sqrt(members.length)};
  }).sort((a, b) => b.members.length - a.members.length || a.s.localeCompare(b.s));
  const placed = [];
  sized.forEach(({s, members, cr}, i) => {
    let cx = 0, cy = 0;
    if (i) for (let t = 0; t < 20000; t++) {
      const a = t * 0.12, r = 6 * a;
      const x = r * Math.cos(a), y = r * Math.sin(a) * 0.8;
      if (placed.every(p => Math.hypot(p.x - x, p.y - y) >= (p.r + cr) * (1 + GAP_K) + GAP)) { cx = x; cy = y; break; }
    }
    placed.push({x: cx, y: cy, r: cr});
    clusters.push({subnet: s, x: cx, y: cy, z: 0, r: cr + 18});
    members.forEach((n, k) => {
      const rr = k === 0 && members.length === 1 ? 0 : spacing(members.length) * Math.sqrt(k + 0.5);
      const a = k * golden;
      const rn = node(n);
      rn.ox = cx + rr * Math.cos(a); rn.oy = cy + rr * Math.sin(a);
      rn.oz = pillarH(n);
    });
  });
  return clusters;
}
// pillar height in the 3D overview: risk score with a scan, outside exposure without one
function pillarH(d) {
  if (!d.observed) return 4;
  return telemetryOnly ? 14 + 26 * Math.log2(1 + (d.ext || 0)) : 12 + Math.min(100, d.score || 0) * 2.6;
}
function node(d) {
  if (nodes.has(d.id)) return nodes.get(d.id);
  const r = d.observed ? 7 + Math.min(9, (d.score || 0) / 12) : 4.5;
  const n = {d, id: d.id, x: 0, y: 0, z: 0, tx: 0, ty: 0, tz: 0, ox: 0, oy: 0, oz: 0, a: 0, ta: 1, r, tr: r, color: SEV[d.sev] || SEV[''],
    ext: false, born: performance.now() + Math.random() * 900};
  nodes.set(d.id, n);
  return n;
}
const clusters = overviewLayout();
const links = D.links.map(([a, b, w]) => ({a: nodes.get(a), b: nodes.get(b), w})).filter(l => l.a && l.b);
nodes.forEach(n => { n.x = n.ox * 1.8; n.y = n.oy * 1.8; n.tx = n.ox; n.ty = n.oy;
  n.z = -40 - hash01(n.id + '~') * 260; n.tz = n.oz; });
// 3D overview summaries (explore.py _overview_summary): complete per-subnet totals, bundled traffic
// between subnets, the risky host-to-host paths, and the most significant outside addresses
const fewP1 = D.nodes.filter(n => n.pri === 'P1').length <= 40;   // 3D overview labels every P1 only when there are few
const subnetInfo = new Map((D.subnets || []).map(x => [x.id, x]));
const clusterOf = new Map(clusters.map(c => [c.subnet, c]));
// with many subnets, label only the ones that matter most (the rest on hover)
[...clusters].sort((a, b) => {
  const A = subnetInfo.get(a.subnet) || {}, B = subnetInfo.get(b.subnet) || {};
  return (B.likely || 0) - (A.likely || 0) || (B.p1 || 0) - (A.p1 || 0) || (B.hosts || 0) - (A.hosts || 0);
}).forEach((c, i) => { c.labelled = i < 14; });
const subLinks = (D.subnet_links || []).map(([a, b, w, lw]) => ({a: clusterOf.get(a), b: clusterOf.get(b), w, lw})).filter(l => l.a && l.b);
const riskyLinks = (D.risky_links || []).map(([a, b, w, why, lvl]) => ({a: nodes.get(a), b: nodes.get(b), w, why, lvl})).filter(l => l.a && l.b);
const ring = (() => {
  let minX = 0, maxX = 0, minY = 0, maxY = 0;
  clusters.forEach(c => { minX = Math.min(minX, c.x - c.r); maxX = Math.max(maxX, c.x + c.r); minY = Math.min(minY, c.y - c.r); maxY = Math.max(maxY, c.y + c.r); });
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2, R = Math.max(260, Math.hypot(maxX - minX, maxY - minY) / 2 * 1.05);
  return {cx, cy, R, z: 200 + R * 0.4};
})();
const inetNodes = [];
// the internet arc always sits overhead on the far side of the network from the camera, so it never
// blocks the view; when the view is rotated the arc glides round to stay behind
const ARC = Math.PI - 0.6;
const arcCenter = yaw => 1.5 * Math.PI - yaw;
function placeInet(yaw) {
  const rx = Math.cos(yaw), ry = -Math.sin(yaw);   // screen-right direction on the plane
  const order = inetNodes.map(n => {
    let sx = 0, k = 0;
    n.info.targets.forEach(t => { const h = nodes.get(t[0]); if (h) { sx += (h.ox - ring.cx) * rx + (h.oy - ring.cy) * ry; k++; } });
    return {n, x: k ? sx / k : (n.hash - 0.5) * ring.R};
  }).sort((a, b) => a.x - b.x || (a.n.id < b.n.id ? -1 : 1));
  order.forEach(({n}, i) => {
    const f = order.length > 1 ? i / (order.length - 1) : 0.5;
    const ang = arcCenter(yaw) - (f - 0.5) * ARC;
    n.ox = ring.cx + ring.R * 1.08 * Math.cos(ang); n.oy = ring.cy + ring.R * 1.08 * Math.sin(ang);
    if (n.ta > 0) { n.tx = n.ox; n.ty = n.oy; }
  });
}
(D.internet || []).slice(0, 48).forEach((e, i) => {
  const id = 'inet:' + e.ip;
  const n = {d: {id: e.ip, name: '', scanned: false, sev: ''}, id, x: ring.cx, y: ring.cy, z: ring.z + 400, tx: 0, ty: 0, tz: 0,
    ox: ring.cx, oy: ring.cy, oz: ring.z + (i % 3) * 26, hash: hash01(e.ip),
    a: 0, ta: 0, r: 5 + Math.min(6, Math.log2(1 + e.hosts_total) * 2), tr: 0, color: KIND[e.kind], ext: true, inet: true,
    born: 0, info: e, labelled: false};
  n.tr = n.r; n.tz = n.oz;
  nodes.set(id, n); inetNodes.push(n);
});
placeInet(0);
inetNodes.forEach(n => { n.tx = n.ox; n.ty = n.oy; });
[...inetNodes].sort((a, b) => KIND_RANK[a.info.kind] - KIND_RANK[b.info.kind] || b.info.hosts_total - a.info.hosts_total)
  .slice(0, 6).forEach(n => { n.labelled = true; });
function showInet(on) { inetNodes.forEach(n => { n.ta = on ? 1 : 0; n.tx = n.ox; n.ty = n.oy; n.tz = n.oz; }); }
function clusterAt(sx, sy) {
  if (!R3 || state.mode !== 'overview') return null;
  let best = null, bd = 1e9;
  clusters.forEach(c => {
    const [x, y, sc] = Pw(c.x, c.y, 0), d = Math.hypot(x - sx, (y - sy) / Math.max(0.35, Math.cos(view.pitch)));
    if (d < c.r * sc && d < bd) { bd = d; best = c; }
  });
  return best;
}
function zoomCluster(c) {
  const railW = W > 900 ? 280 : 0;
  cam.tz = Math.min(1.6, Math.max(0.3, Math.min((W - railW - 80) / (c.r * 2 + 260), (H - 200) / (c.r * 2 + 360)) * 1.3));
  cam.tx = c.x; cam.ty = c.y; cam.tsx = railW / 2; cam.tsy = 0;
  view.idle = performance.now();
}

// ---------------------------------------------------------------- stars
const stars = Array.from({length: 260}, () => ({x: Math.random(), y: Math.random(), z: Math.random() * 0.8 + 0.2,
  p: Math.random() * Math.PI * 2}));

// ---------------------------------------------------------------- focus layout
function extNode(a) {
  const id = 'ext:' + a.ip;
  let n = nodes.get(id);
  if (!n) {
    n = {d: {id: a.ip, name: '', scanned: false, sev: ''}, id, x: 0, y: 0, z: 0, tx: 0, ty: 0, tz: 0, ox: 0, oy: 0, oz: 0, a: 0, ta: 0,
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
    n = {d: {id: match.value, name: '', scanned: false, sev: ''}, id, x: 0, y: 0, z: 0, tx: 0, ty: 0, tz: 0, ox: 0, oy: 0, oz: 0, a: 0, ta: 0,
      r: 7, tr: 7, color: '#2ee6d6', ext: false, domain: true, born: 0, info: match};
    nodes.set(id, n);
  }
  n.info = match;
  return n;
}
const LABELED = 24;                // nodes per side drawn large and labelled; the rest are packed beyond them
const SIDE_MAX = 400;              // graph drawing limit; the panel can reach every IP
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
      item.tz = 40 - (y * y) / 2600 - col * 25;
    } else {
      const j = i - LABELED, col = Math.floor(j / rows), k = j % rows, cnt = Math.min(rows, list.length - LABELED - col * rows);
      item.tx = dir * (900 + col * 24); item.ty = (k - (cnt - 1) / 2) * 17; item.gap = 17; item.small = true;
      item.tz = -50 - col * 3;
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
  stopSpin();
  state.mode = 'focus'; state.focus = id;
  document.body.classList.add('focused');
  $('hint').classList.add('gone');
  updateAbout();
  history.replaceState(null, '', '#host=' + encodeURIComponent(id));
  const center = nodes.get(id);
  const keep = new Set([id]);
  // background nodes drift outward and fade
  nodes.forEach(n => { n.gap = 0; n.small = false; if (n.ext || n.domain) { n.ta = 0; } else { n.ta = 0.05; n.tx = n.ox * 2.4; n.ty = n.oy * 2.4; n.tz = n.oz - 900; n.tr = n.r; } });
  center.tx = 0; center.ty = 0; center.tz = 40; center.ta = 1; center.tr = 22;
  if (push !== 'resize') { view.fyaw = 0; view.fpitch = 0; }
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
    n.tz = 50; n.ta = 1; n.tr = 7; n.gap = 90; keep.add(n.id);
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
    n.tz = via.tz - 25; n.ta = 0.85; n.tr = 5; keep.add(n.id);
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
  const phoneLayout = W <= 520;
  const panelW = drawerW ? drawerW + Math.min(100, W * 0.06) :
    phoneLayout ? 0 : (parseFloat(getComputedStyle($('panel')).width) || 400) + 20;
  const railW = W > 900 ? 280 : 0;
  const phonePanelH = phoneLayout ? H * 0.52 : 0;
  const availW = Math.max(80, W - panelW - railW - 40), availH = H - 170 - phonePanelH;
  cam.tz = Math.min(1.6, Math.max(drawerW ? 0.12 : W > 900 ? 0.25 : 0.08,
    Math.min(availW / (maxX - minX + 160), availH / (maxY - minY + 120))));
  if (R3) cam.tz *= 1.12;
  cam.tx = (minX + maxX) / 2 - (railW - panelW) / 2 / cam.tz;
  cam.ty = (minY + maxY) / 2 + phonePanelH / 2 / cam.tz;
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
  nodes.forEach(n => { if (n.ext || n.domain) n.ta = 0; else { n.ta = 1; n.tx = n.ox; n.ty = n.oy; n.tz = n.oz; n.tr = n.r; } });
  showInet(!!R3);
  edges = [];
  fitOverview();
  $('panel').hidden = true;
  renderList(); updateAbout();
}
function fitOverview() {
  let minX = 0, maxX = 0, minY = 0, maxY = 0;
  nodes.forEach(n => { if (!n.ext && !n.domain) { minX = Math.min(minX, n.ox); maxX = Math.max(maxX, n.ox); minY = Math.min(minY, n.oy); maxY = Math.max(maxY, n.oy); } });
  const railW = W > 900 ? 280 : 0;
  const drawerW = document.body.classList.contains('ai-chat-open') && W > 1100 ? $('analyst-chat').getBoundingClientRect().width : 0;
  const rightInset = drawerW ? drawerW + Math.min(100, W * 0.06) : 0;
  cam.tz = Math.min(1.5, Math.max(drawerW ? 0.12 : 0.2,
    Math.min((W - railW - rightInset - 80) / (maxX - minX + 200), (H - 200) / (maxY - minY + 200))));
  if (R3) {
    minX = ring.cx - ring.R * 1.1; maxX = ring.cx + ring.R * 1.1; minY = ring.cy - ring.R; maxY = ring.cy + ring.R;
    cam.tz = Math.min(1.5, Math.max(drawerW ? 0.1 : 0.15,
      Math.min((W - railW - rightInset - 60) / (maxX - minX + 120), (H - 170) / ((maxY - minY) * 0.75 + 120)))) * 0.85;
    // orbit pivot = the network's centre; the screen shift keeps it clear of the host list and drawer
    cam.tx = ring.cx; cam.ty = ring.cy; cam.tsx = (railW - rightInset) / 2; cam.tsy = ring.R * 0.3 * cam.tz;
    return;
  }
  cam.tx = (minX + maxX) / 2 - (railW - rightInset) / 2 / cam.tz; cam.ty = (minY + maxY) / 2;
}
function snap() { nodes.forEach(n => { n.x = n.tx; n.y = n.ty; n.z = n.tz; n.a = n.ta; n.r = n.tr; }); cam.x = cam.tx; cam.y = cam.ty; cam.z = cam.tz; cam.sx = cam.tsx; cam.sy = cam.tsy; view.dist = 1; }

// ---------------------------------------------------------------- drawing
const toS = (x, y) => [(x - cam.x) * cam.z + W / 2, (y - cam.y) * cam.z + H / 2];
const toW = (sx, sy) => [(sx - W / 2) / cam.z + cam.x, (sy - H / 2) / cam.z + cam.y];
// screen position and CSS px per world unit, through the 3D camera when it is on
const Pw = (x, y, z) => R3 ? R3.project(x, y, z || 0) : [(x - cam.x) * cam.z + W / 2, (y - cam.y) * cam.z + H / 2, cam.z];
const P = n => Pw(n.x, n.y, n.z);
function resize() {
  DPR = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight;
  cv.width = W * DPR; cv.height = H * DPR; ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  if (R3inst) R3inst.setSize(W, H, DPR);
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
  if (state.mode === 'focus' || !R3) { cam.tsx = 0; cam.tsy = 0; }
  cam.sx += (cam.tsx - cam.sx) * k; cam.sy += (cam.tsy - cam.sy) * k;
  nodes.forEach(n => {
    const ready = now > n.born;
    n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k; n.r += (n.tr - n.r) * k;
    n.z += (n.tz - n.z) * (ready ? k * 0.8 : 0);
    n.a += ((ready ? n.ta : 0) - n.a) * Math.min(1, k * 1.4);
  });
  ctx.clearRect(0, 0, W, H);
  if (R3) { draw3d(now, dt, k); requestAnimationFrame(frame); return; }
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
  const [x, y, sc] = P(n), r = Math.max(2, n.r * sc);
  if (!(x > -80 && y > -80 && x < W + 80 && y < H + 80)) return;
  const sel = state.focus === n.id, hov = state.hover === n, gl = !!R3;
  ctx.globalAlpha = n.a;
  if (sel) {   // radar rings and sweep on the selected host (3D draws its rings in the scene)
    for (let i = 0; i < 3 && !gl; i++) {
      const ph = ((T * 0.6 + i / 3) % 1);
      ctx.globalAlpha = n.a * (1 - ph) * 0.6; ctx.strokeStyle = n.color; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(x, y, r + ph * 90 * sc, 0, 7); ctx.stroke();
    }
    if (state.motion) {
      const sw = ctx.createConicGradient ? ctx.createConicGradient(T * 1.4, x, y) : null;
      if (sw) { sw.addColorStop(0, 'rgba(46,230,214,.22)'); sw.addColorStop(0.12, 'rgba(46,230,214,0)'); sw.addColorStop(1, 'rgba(46,230,214,0)');
        ctx.globalAlpha = n.a * (gl ? 0.7 : 1); ctx.fillStyle = sw; ctx.beginPath(); ctx.arc(x, y, 160 * sc, 0, 7); ctx.fill(); }
    }
    ctx.globalAlpha = n.a;
  }
  ctx.shadowColor = n.color; ctx.shadowBlur = (sel ? 30 : hov ? 22 : 12);
  if (gl) {
    ctx.shadowBlur = 0;
    if (n.domain) { ctx.strokeStyle = '#2ee6d6'; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x, y, r + 6, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = '#2ee6d6'; ctx.font = '700 10px ui-monospace,Menlo,monospace'; ctx.textAlign = 'center'; ctx.fillText('D', x, y + 3); }
    else if (n.ext) { if (iocIds.has('ip:' + n.d.id)) { ctx.strokeStyle = '#2ee6d6'; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x, y, r + 6, 0, Math.PI * 2); ctx.stroke(); } }
    else if (n.d.observed && n.d.ev) { ctx.strokeStyle = n.d.ev === 'likely' ? '#ff3b5c' : '#ffd23f'; ctx.lineWidth = 2;
      ctx.setLineDash([4, 3]); ctx.beginPath(); ctx.arc(x, y, r + 5, T % 7, T % 7 + 6.28); ctx.stroke(); ctx.setLineDash([]); }
  } else if (n.domain) { // source-linked DNS observations are separate from network traffic nodes
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
  const show = state.labels && (sel || hov || (n.inet ? n.labelled && n.a > 0.5 : state.mode === 'focus' ? n.a > 0.5 && !n.small : (n.d.observed && (sc > 0.55 || (n.d.pri === 'P1' && (!R3 || fewP1 || n.d.ev))))));
  if (show) {
    const name = nodeLabel(n);
    ctx.font = (sel ? '600 14px' : '12px') + ' system-ui,-apple-system,Segoe UI,sans-serif';
    const side = n.domain ? 'center' : n.ext ? 'right' : (state.mode === 'focus' && n.id !== state.focus && n.info) ? 'left' : 'center';
    ctx.textAlign = side;
    const lx = side === 'right' ? x - r - 8 : side === 'left' ? x + r + 8 : x, ly = side === 'center' ? y + r + 15 : y + 4;
    ctx.lineWidth = 4; ctx.strokeStyle = 'rgba(3,6,12,.85)'; ctx.strokeText(name, lx, ly);
    ctx.fillStyle = sel ? '#ffffff' : '#d6e4f5'; ctx.fillText(name, lx, ly);
    // tight columns: keep everything on one line so neighbouring rows don't collide
    const tight = state.mode === 'focus' && !sel && (n.gap || 99) * sc < 42;
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
  const [cx, ly0] = Pw(0, top - 46, 0), ly = Math.max(96, ly0);
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

// ---------------------------------------------------------------- 3D (Three.js) drawing
function rotateView(dir) { view.spin = false; view.oyaw += dir * Math.PI / 4; placeInet(view.oyaw); markView(); }
function setView(name, reset) {
  view.opitch = VIEWS[name];
  if (reset) { view.oyaw = 0; placeInet(0); fitOverview(); }
  view.spin = !!reset;
  markView();
}
function stopSpin() { if (view.spin) { view.spin = false; markView(); } }
function markView() {
  for (const name of Object.keys(VIEWS)) {
    const b = $('vc-' + name); if (b) b.setAttribute('aria-pressed', String(Math.abs(view.opitch - VIEWS[name]) < 0.02));
  }
  const sp = $('vc-spin'); if (sp) sp.setAttribute('aria-pressed', String(view.spin && state.motion));
}
function set3d(on, remember) {
  on = !!on && can3d;
  if (on && !R3inst) {
    try { R3inst = window.VF3D.create(cv3, {bgIn: BG_IN, bgOut: BG_OUT, onLost: () => set3d(false, false)}); R3inst.setSize(W, H, DPR); }
    catch (err) { console.warn('3D view unavailable, using 2D', err); R3inst = null; on = false; }
  }
  R3 = on ? R3inst : null;
  if (cv3) cv3.hidden = !on;
  document.body.classList.toggle('gl3d', on);
  markSeg();
  if (remember) { try { localStorage.setItem(KEY3D, on ? '1' : '0'); } catch (_) {} }
  if (on && remember && state.motion) view.dist = 1.6;
  if (state.mode === 'focus') focus(state.focus, 'resize'); else { showInet(on); fitOverview(); }
  if (!state.motion) snap();
}
const RGB = hex => window.VF3D.rgb(hex);
// the 2D view's curve between two nodes, lifted towards the camera in proportion to its length
function edgeCurve(e) {
  const a = e.a, b = e.b, dx = b.x - a.x, dy = b.y - a.y, k = e.bend ? 0.28 : 0.1;
  return [a.x, a.y, a.z, (a.x + b.x) / 2 - dy * k, (a.y + b.y) / 2 + dx * k, (a.z + b.z) / 2 + Math.hypot(dx, dy) * 0.12, b.x, b.y, b.z];
}
const qb = (c, t) => { const u = 1 - t, A = u * u, B = 2 * u * t, C = t * t;
  return [A * c[0] + B * c[3] + C * c[6], A * c[1] + B * c[4] + C * c[7], A * c[2] + B * c[5] + C * c[8]]; };
const HALO = RGB('#78aaff');
const RISK2 = RGB('#ff2e88'), RISK1 = RGB('#ffb020'), BUNDLE = RGB('#6ea8ff'), BUNDLE_LAT = RGB('#ff8a3d'),
  RING = RGB('#2ee6d6'), P_CRIT = RGB('#ff3b5c'), P_HIGH = RGB('#ff8a3d');
const BEAM_ALPHA = {alert: 0.85, vuln: 0.13, reached: 0.08, outbound: 0.08, attempt: 0.04, blocked: 0.035};
const OUT_BEAM = RGB(RETURN), OUT_ALPHA = 0.15;
// which way a host's traffic with an outside address went: in, out or both (older data has no 4th field)
const beamDir = t => t[3] || (t[1] === 'outbound' ? 'out' : 'in');
// Overview: subnet platforms on one plane, hosts as pillars whose height is risk, traffic between
// subnets bundled beneath the plane, only risky host paths drawn bright, and the internet as a ring
// overhead with beams down to the hosts each outside address reached, and violet beams rising from
// hosts that connected out to it.
function overviewScene(L, T, cm, cs, cdz) {
  const flows = [];
  if (cm < 0.01) return flows;
  const hc = state.hoverCluster, hn = state.hover;
  clusters.forEach(c => {
    const si = subnetInfo.get(c.subnet), col = si && si.likely ? P_CRIT : si && si.p1 ? P_HIGH : HALO;
    const on = !hc || hc === c;
    L.circle(c.x * cs, c.y * cs, cdz, c.r, 80, hc === c ? 2.2 : 1.4, col, cm * (on ? 0.5 : 0.18), false);
    L.circle(c.x * cs, c.y * cs, cdz, c.r * 0.97, 80, 0.8, HALO, cm * 0.12, true);
  });
  // bundled subnet-to-subnet traffic, sagging under the plane; orange share = admin/lateral protocols
  const maxW = subLinks.reduce((m, l) => Math.max(m, l.w), 1);
  subLinks.forEach(l => {
    const a = l.a, b = l.b, ax = a.x * cs, ay = a.y * cs, bx = b.x * cs, by = b.y * cs, len = Math.hypot(bx - ax, by - ay);
    const lat = l.lw / Math.max(1, l.w), on = !hc || hc === a || hc === b;
    const al = cm * (on ? 0.22 + 0.4 * Math.sqrt(l.w / maxW) : 0.06);
    const col = lat > 0.25 ? BUNDLE_LAT : BUNDLE, c = [ax, ay, cdz, (ax + bx) / 2, (ay + by) / 2, cdz - 60 - len * 0.32, bx, by, cdz];
    L.quad(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], 24, 1 + Math.min(7, Math.log2(1 + l.w) * 0.6), col, al, false);
    if (on) flows.push({c, col, al: al * 1.3, size: 3 + Math.min(3, Math.log10(1 + l.w)), speed: 0.05 + (l.w / maxW) * 0.08});
  });
  // risk pillars
  nodes.forEach(n => {
    if (n.ext || n.domain || n.a < 0.02) return;
    const base = n.z - n.oz, w = n.d.pri === 'P1' ? 3.2 : n.d.observed ? 2 : 1;
    L.strip(2, i => [n.x, n.y, i ? n.z : base], w, RGB(n.color), n.a * cm * (hn === n ? 0.95 : 0.5), false);
  });
  // risky host-to-host paths, from pillar base to pillar base beneath the plane
  riskyLinks.forEach((l, i) => {
    if (i >= 60 && !(hn && (hn === l.a || hn === l.b))) return;
    const a = l.a, b = l.b, al0 = Math.min(a.a, b.a) * cm; if (al0 < 0.02) return;
    const za = a.z - a.oz, zb = b.z - b.oz, len = Math.hypot(b.x - a.x, b.y - a.y);
    const on = !hn || hn === a || hn === b, col = l.lvl > 1 ? RISK2 : RISK1;
    const c = [a.x, a.y, za, (a.x + b.x) / 2, (a.y + b.y) / 2, (za + zb) / 2 - 25 - len * 0.3, b.x, b.y, zb];
    const al = al0 * (on ? (l.lvl > 1 ? 0.42 : 0.22) * (hn ? 2 : 1) : 0.04);
    L.quad(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], 16, 0.9 + Math.min(1.8, Math.log10(1 + l.w) * 0.7), col, al, false);
    if (on && al > 0.1) flows.push({c, col, al, size: 3.4, speed: 0.12 + (hash01(a.id + b.id) * 0.1)});
  });
  // the internet ring and its beams
  if (inetNodes.length) {
    const arcAt = (f, dz) => { const ang = arcCenter(view.yaw) - (f - 0.5) * ARC;
      return [ring.cx + ring.R * 1.08 * Math.cos(ang), ring.cy + ring.R * 1.08 * Math.sin(ang), ring.z + dz]; };
    L.strip(61, i => arcAt(i / 60, -14), 1.1, RING, cm * 0.25, true);
    L.strip(61, i => arcAt(i / 60, 66), 0.7, RING, cm * 0.1, false);
    inetNodes.forEach(n => {
      if (n.a < 0.02) return;
      n.info.targets.forEach(t => {
        const h = nodes.get(t[0]); if (!h || h.a < 0.02) return;
        const on = !hn || hn === n || hn === h, dir = beamDir(t), w = 0.9 + Math.min(2.2, Math.log2(1 + t[2]) * 0.3);
        if (dir !== 'out') {   // inbound: from the address down to the host
          const al = Math.min(n.a, h.a) * cm * BEAM_ALPHA[t[1]] * (on ? (hn ? 1.4 : 1) : 0.12);
          const c = [n.x, n.y, n.z, (n.x + h.x) / 2, (n.y + h.y) / 2, (n.z + h.z) / 2 + 60, h.x, h.y, h.z];
          const col = RGB(KIND[t[1]]), dashed = t[1] === 'blocked' || t[1] === 'attempt';
          L.quad(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], 14, w, col, al, dashed);
          if (!dashed && on && (t[1] === 'alert' || t[1] === 'vuln' || hn)) flows.push({c, col, al: Math.min(1, al * 1.4), size: 3.2, speed: 0.18});
        }
        if (dir !== 'in') {    // outbound: from the host up to the address, on a slightly higher curve
          const al = Math.min(n.a, h.a) * cm * (t[1] === 'alert' ? 0.6 : OUT_ALPHA) * (on ? (hn ? 1.6 : 1) : 0.12);
          const c = [h.x, h.y, h.z, (n.x + h.x) / 2, (n.y + h.y) / 2, (n.z + h.z) / 2 + 130, n.x, n.y, n.z];
          L.quad(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], 14, w, OUT_BEAM, al, false);
          if (on) flows.push({c, col: OUT_BEAM, al: Math.min(1, al * 2.2), size: 3, speed: 0.14});
        }
      });
    });
  }
  return flows;
}
function draw3d(now, dt, k) {
  const T = now / 1000, focusing = state.mode === 'focus', motion = state.motion;
  // camera: cinematic tilt over the overview, near front-on (readable labels) when focused
  const kv = motion ? 1 - Math.pow(0.02, dt) : 1;
  // slow turn to the left over the overview, until the user takes the camera
  if (view.spin && motion && !focusing && view.cmix > 0.99) { view.oyaw += SPIN * Math.min(dt, 0.1); placeInet(view.oyaw); }
  const tyaw = focusing ? view.fyaw : view.oyaw, tpitch = focusing ? 0.13 + view.fpitch : view.opitch;
  view.yaw += (tyaw - view.yaw) * kv;
  view.pitch += (tpitch - view.pitch) * kv;
  view.dist += (1 - view.dist) * (motion ? 1 - Math.pow(0.05, dt) : 1);
  view.cmix += ((focusing ? 0 : 1) - view.cmix) * k;
  // switching between orbit (overview) and front-on (focus) camera models: snap yaw so neither spins
  if (focusing !== view.wasFocus) { view.wasFocus = focusing; view.yaw = tyaw; }
  R3.setCamera(cam.x, cam.y, cam.z, view.yaw, view.pitch, view.dist, !focusing, cam.sx, cam.sy);

  // ribbons: subnet halos, overview links, focus edges, shockwaves on the selected host
  const L = R3.lines; L.begin();
  const cm = view.cmix, cs = 2.4 - 1.4 * cm, cdz = -900 * (1 - cm);
  const flows = overviewScene(L, T, cm, cs, cdz);
  const hl = state.hoverEdge;
  edges.forEach(e => {
    const al = Math.min(e.a.a, e.b.a); e.c = null; if (al < 0.03) return;
    const c = e.c = edgeCurve(e), lit = !hl || hl === e.info;
    e.al = al * (lit ? (e.kind === 'hop2' ? 0.55 : e.small ? 0.35 : 0.8) : 0.12) * (e.small && hl && lit ? 2.5 : 1);
    e.lit = lit;
    L.quad(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], e.small ? 6 : 20, e.w * (lit && hl ? 1.6 : 1), RGB(e.color), e.al, e.dashed);
  });
  const sel = state.focus && nodes.get(state.focus);
  if (sel && focusing) for (let i = 0; i < 3; i++) {
    const ph = (T * 0.45 + i / 3) % 1;
    L.circle(sel.x, sel.y, sel.z, sel.r + 6 + ph * 140, 64, 1.6, RGB(sel.color), sel.a * (1 - ph) * 0.7, false);
  }
  L.end();

  // node bodies and halos
  const N = R3.nodes; N.begin();
  nodes.forEach(n => {
    if (n.a < 0.01) return;
    const isSel = state.focus === n.id, hov = state.hover === n;
    let shape = 0, hollow = 0;
    if (n.domain) shape = 3; else if (n.ext) { shape = 1; hollow = n.info.kind === 'blocked' ? 1 : 0; } else if (!n.d.observed) shape = 2;
    const glow = isSel ? 1.6 : hov ? 1.2 : n.ext ? 0.45 : n.d.observed ? 0.75 : 0.2;
    N.add(n.x, n.y, n.z, n.r, RGB(n.color), n.a, shape, hollow, glow, 2);
  });
  N.end();

  // sparks: traffic along focus edges, flow on the busiest overview links, satellites round exposed hosts
  const S = R3.sparks; S.begin();
  edges.forEach(e => {
    if (!e.parts.length || !e.c) return;
    const col = RGB(e.color), size = (1.6 + e.w * 0.5) * 2.6;
    e.parts.forEach((t, i) => {
      t = (t + dt * e.speed * (e.kind === 'in' ? 0.6 : 1)) % 1; e.parts[i] = t;
      const p = qb(e.c, t);
      S.add(p[0], p[1], p[2], 0, col, e.al / 0.8 * (e.lit ? 0.95 : 0.15), 0, 0, 0, size);
    });
  });
  if (motion && cm > 0.05) flows.forEach((f, i) => {
    const t = (T * f.speed + i * 0.137) % 1, p = qb(f.c, t);
    S.add(p[0], p[1], p[2], 0, f.col, f.al, 0, 0, 0, f.size);
  });
  S.end();
  R3.render(T);

  // canvas overlay: subnet labels, arrowheads, rings and labels
  if (cm > 0.3 && state.labels) clusters.forEach(c => {
    const [x, y, sc] = Pw(c.x, c.y + c.r, 0);
    if (!(x > -50 && x < W + 50 && y > -50 && y < H + 50)) return;
    const si = subnetInfo.get(c.subnet);
    const hov = state.hoverCluster === c;
    if (!hov && !c.labelled) return;
    ctx.globalAlpha = cm * (hov ? 1 : 0.8); ctx.textAlign = 'center';
    ctx.font = (hov ? '600 ' : '') + '11px ui-monospace,Menlo,monospace'; ctx.fillStyle = hov ? '#e6f1ff' : '#a9bcd6';
    ctx.lineWidth = 4; ctx.strokeStyle = 'rgba(3,6,12,.8)';
    ctx.strokeText(c.subnet, x, y + 14); ctx.fillText(c.subnet, x, y + 14);
    if (si && (sc > 0.25 || hov)) {
      const bits = [`${si.hosts} host${si.hosts === 1 ? '' : 's'}`];
      if (si.p1) bits.push(`${si.p1} P1`);
      if (si.likely) bits.push(`${si.likely} likely`);
      if (si.exposed) bits.push(`${si.exposed} exposed`);
      if (si.drawn < si.hosts) bits.push(`${si.hosts - si.drawn} not drawn`);
      ctx.font = '10px ui-monospace,Menlo,monospace'; ctx.fillStyle = si.likely ? '#ff8095' : si.p1 ? '#ffb27a' : '#7f95b3';
      const t = bits.join(' · ');
      ctx.strokeText(t, x, y + 27); ctx.fillText(t, x, y + 27);
    }
  });
  if (cm > 0.3 && inetNodes.length) {
    const ac = arcCenter(view.yaw), [x, y] = Pw(ring.cx + ring.R * 1.08 * Math.cos(ac), ring.cy + ring.R * 1.08 * Math.sin(ac), ring.z + 70);
    if (y > 70) {
      ctx.globalAlpha = 0.75 * cm; ctx.font = '600 11px ui-monospace,Menlo,monospace'; ctx.textAlign = 'center'; ctx.fillStyle = '#2ee6d6';
      const tot = D.internet_total || inetNodes.length;
      ctx.fillText(`INTERNET · ${tot.toLocaleString()} OUTSIDE ADDRESS${tot === 1 ? '' : 'ES'}` + (tot > inetNodes.length ? ` · TOP ${inetNodes.length} SHOWN` : ''), x, Math.max(84, y - 18));
      if (D.internet_out_total != null) {
        ctx.font = '10px ui-monospace,Menlo,monospace'; ctx.fillStyle = '#7f95b3';
        const a = `↓ ${D.internet_in_total.toLocaleString()} REACHED IN   `, b = `↑ ${D.internet_out_total.toLocaleString()} CONTACTED BY HOSTS`;
        const wa = ctx.measureText(a).width, wb = ctx.measureText(b).width, x0 = x - (wa + wb) / 2;
        ctx.textAlign = 'left'; ctx.fillText(a, x0, Math.max(98, y - 4));
        ctx.fillStyle = RETURN; ctx.fillText(b, x0 + wa, Math.max(98, y - 4)); ctx.textAlign = 'center';
      }
    }
  }
  edges.forEach(e => {
    if (!e.c || e.kind === 'dns' || (e.small && !(hl && e.lit))) return;
    const [x0, y0] = Pw(...qb(e.c, 0.93)), [x1, y1] = Pw(...qb(e.c, 0.985)), [xe, ye, se] = P(e.b);
    if (!(xe > -50 && xe < W + 50 && ye > -50 && ye < H + 50)) return;
    const ang = Math.atan2(y1 - y0, x1 - x0), back = Math.min(e.b.r * se + 3, 40);
    const ax = xe - Math.cos(ang) * back, ay = ye - Math.sin(ang) * back;
    ctx.globalAlpha = Math.min(e.a.a, e.b.a) * (e.lit ? 1 : 0.2); ctx.fillStyle = e.color;
    ctx.beginPath(); ctx.moveTo(ax, ay);
    ctx.lineTo(ax - 9 * Math.cos(ang - 0.4), ay - 9 * Math.sin(ang - 0.4));
    ctx.lineTo(ax - 9 * Math.cos(ang + 0.4), ay - 9 * Math.sin(ang + 0.4)); ctx.closePath(); ctx.fill();
  });
  ctx.globalAlpha = 1;
  const order = [...nodes.values()].filter(n => n.a > 0.02).sort((a, b) => a.a - b.a);
  order.forEach(n => drawNode(n, T));
  if (focusing) sideTitles();
}

// ---------------------------------------------------------------- interaction
function pick(sx, sy) {
  let best = null, bd = 1e9;
  nodes.forEach(n => {
    if (n.a < 0.3) return;
    const [x, y, sc] = P(n), d = Math.hypot(x - sx, y - sy), r = Math.max(8, n.r * sc + 6);
    if (!(d < 1e9)) return;
    const labelRight = x - r - 8;
    const extLabelHit = n.ext && state.mode === 'focus' && state.labels && !n.small && n.a > 0.5
      && sx >= labelRight - n.d.id.length * 7.5 && sx <= labelRight
      && Math.abs(sy - (y + 4)) < 12;
    const domainWidth = nodeLabel(n).length * 7.5;
    const domainLabelHit = n.domain && state.mode === 'focus' && state.labels && n.a > 0.5
      && sx >= x - domainWidth / 2 && sx <= x + domainWidth / 2
      && Math.abs(sy - (y + Math.max(2, n.r * sc) + 15)) < 12;
    const labelHit = extLabelHit || domainLabelHit;
    const score = labelHit ? 0 : d;
    if ((d < r || labelHit) && score < bd) { bd = score; best = n; }
  });
  return best;
}
let drag = null;
cv.addEventListener('pointerdown', e => { drag = {x: e.clientX, y: e.clientY, cx: cam.tx, cy: cam.ty,
  node: pick(e.clientX, e.clientY), moved: false, lx: e.clientX, ly: e.clientY, orbit: !!R3 && (e.button === 2 || e.shiftKey || e.altKey),
  yaw: state.mode === 'focus' ? view.fyaw : view.oyaw, pitch: state.mode === 'focus' ? view.fpitch : view.opitch}; view.idle = performance.now(); cv.setPointerCapture(e.pointerId); });
cv.addEventListener('contextmenu', e => { if (R3) e.preventDefault(); });
cv.addEventListener('pointermove', e => {
  if (drag) {
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) { if (!drag.moved) { stopSpin(); drag.yaw = state.mode === 'focus' ? view.fyaw : view.oyaw; } drag.moved = true; cv.classList.add('dragging'); }
    view.idle = performance.now();
    if (drag.moved && drag.orbit) {
      if (state.mode === 'focus') { view.fyaw = Math.max(-0.9, Math.min(0.9, drag.yaw - dx * 0.005)); view.fpitch = Math.max(-0.5, Math.min(0.9, drag.pitch + dy * 0.004)); }
      else { view.oyaw = drag.yaw - dx * 0.006; view.opitch = Math.max(0, Math.min(1.4, drag.pitch - dy * 0.004)); placeInet(view.oyaw); markView(); }
      view.yaw = state.mode === 'focus' ? view.fyaw : view.oyaw; view.pitch = state.mode === 'focus' ? 0.13 + view.fpitch : view.opitch;
    } else if (drag.moved) {
      panBy(drag.lx, drag.ly, e.clientX, e.clientY);
    }
    drag.lx = e.clientX; drag.ly = e.clientY;
    return;
  }
  const n = pick(e.clientX, e.clientY);
  const hc = n ? null : clusterAt(e.clientX, e.clientY);
  state.hover = n; state.hoverCluster = hc; cv.classList.toggle('hover', !!(n || hc));
  if (hc) { subnetTip(hc, e.clientX, e.clientY); return; }
  state.hoverEdge = n && n.info && state.mode === 'focus' ? n.info : null;
  tip(n, e.clientX, e.clientY);
});
cv.addEventListener('pointerup', e => {
  const wasDrag = drag && drag.moved, startNode = drag && drag.node;
  drag = null; cv.classList.remove('dragging');
  if (wasDrag) return;
  const n = pick(e.clientX, e.clientY) || startNode;
  if (!n) { const c = clusterAt(e.clientX, e.clientY); if (c) zoomCluster(c); return; }
  if (n.domain) {
    document.dispatchEvent(new CustomEvent('ioc:open', {detail: {id: n.id}}));
    return;
  }
  if (n.inet) {
    const key = 'ip:' + n.d.id;
    if (iocIds.has(key)) document.dispatchEvent(new CustomEvent('ioc:open', {detail: {id: key}}));
    else if (n.info.targets.length && D.focus[n.info.targets[0][0]]) focus(n.info.targets[0][0]);
    return;
  }
  if (n.ext) {
    const key = 'ip:' + n.d.id;
    if (iocIds.has(key)) document.dispatchEvent(new CustomEvent('ioc:open', {detail: {id: key}}));
    return;
  }
  if (!n.ext && D.focus[n.id]) focus(n.id);
});
cv.addEventListener('dblclick', e => { if (!pick(e.clientX, e.clientY) && !clusterAt(e.clientX, e.clientY)) { overview(); } });
cv.addEventListener('pointerleave', () => { state.hover = null; state.hoverCluster = null; tip(null); });
// move the view so the point under (sx0, sy0) ends up under (sx1, sy1); in 3D this follows the
// camera's current yaw and tilt, so dragging left always moves the network left on screen
function panBy(sx0, sy0, sx1, sy1) {
  if (R3) {
    const a = R3.unproject(sx0, sy0), b = R3.unproject(sx1, sy1);
    if (a && b) { cam.tx += a[0] - b[0]; cam.ty += a[1] - b[1]; }
  } else { cam.tx -= (sx1 - sx0) / cam.z; cam.ty -= (sy1 - sy0) / cam.z; }
  cam.x = cam.tx; cam.y = cam.ty; view.idle = performance.now();
}
cv.addEventListener('wheel', e => {
  e.preventDefault();
  stopSpin();
  view.idle = performance.now();
  // trackpad two-finger swipe sideways pans; pinch (ctrl+wheel) and the mouse wheel zoom
  if (!e.ctrlKey && Math.abs(e.deltaX) > Math.abs(e.deltaY) * 0.5) {
    const k = e.deltaMode === 1 ? 16 : 1;
    panBy(e.clientX, e.clientY, e.clientX - e.deltaX * k, e.clientY - e.deltaY * k);
    return;
  }
  if (R3) {   // zoom towards the point under the cursor on the network plane
    const z = Math.max(0.12, Math.min(4, cam.tz * Math.exp(-e.deltaY * 0.0015)));
    const w = R3.unproject(e.clientX, e.clientY);
    if (w) { const f = cam.tz / z; cam.tx = w[0] + (cam.tx - w[0]) * f; cam.ty = w[1] + (cam.ty - w[1]) * f; }
    cam.tz = z;
    return;
  }
  const [wx, wy] = toW(e.clientX, e.clientY);
  const z = Math.max(0.12, Math.min(4, cam.tz * Math.exp(-e.deltaY * 0.0015)));
  cam.tz = z; cam.tx = wx - (e.clientX - W / 2) / z; cam.ty = wy - (e.clientY - H / 2) / z;
}, {passive: false});
function placeTip(h, x, y) {
  const el = $('tip');
  el.innerHTML = h; el.hidden = false;
  const r = el.getBoundingClientRect();
  el.style.left = Math.min(W - r.width - 10, x + 16) + 'px'; el.style.top = Math.min(H - r.height - 10, y + 16) + 'px';
}
function subnetTip(c, x, y) {
  const si = subnetInfo.get(c.subnet) || {hosts: 0};
  const out = subLinks.filter(l => l.a === c || l.b === c).sort((a, b) => b.w - a.w).slice(0, 3)
    .map(l => `${esc((l.a === c ? l.b : l.a).subnet)} · ${l.w.toLocaleString()} sessions` + (l.lw ? ` (${l.lw.toLocaleString()} admin/lateral)` : ''));
  placeTip(`<b>${esc(c.subnet)}</b> <span class="m">subnet</span><br>${si.hosts} host(s)` +
    (si.drawn < si.hosts ? `, ${si.hosts - si.drawn} not drawn` : '') +
    (telemetryOnly ? '' : `<br>${si.p1 || 0} P1 · ${si.likely || 0} likely exploitation · ${si.lead || 0} lead`) +
    `<br>${si.exposed || 0} exposed to outside addresses` + (si.alert_hosts ? `, ${si.alert_hosts} with IPS alerts` : '') +
    (out.length ? `<br><span class="m">Busiest links to other subnets:<br>${out.join('<br>')}</span>` : '') +
    '<br><span class="m">Click to zoom in</span>', x, y);
}
function tip(n, x, y) {
  const el = $('tip');
  if (!n) { el.hidden = true; return; }
  let h;
  if (n.inet) {
    const e = n.info, more = e.hosts_total - e.targets.length;
    const arrow = t => ({in: '←', out: '→', both: '⇄'})[beamDir(t)];
    h = `<b>${esc(e.ip)}</b> <span class="m">outside address</span><br>${esc(KIND_TXT[e.kind])}` +
      `<br><span class="m">${e.hosts_total} internal host(s) · ${e.sessions.toLocaleString()} session(s)` + (e.alerts ? ` · ${e.alerts} IPS alert(s) not blocked` : '') + '</span>' +
      (e.out_sessions != null ? `<br><span class="m">Inbound ${e.in_sessions.toLocaleString()} · </span><span style="color:${RETURN}">outbound ${e.out_sessions.toLocaleString()} from ${e.out_hosts} host(s)</span>` : '') +
      '<br>' + e.targets.slice(0, 5).map(t => `${esc(t[0])} ${arrow(t)} <span style="color:${KIND[t[1]]}">${esc(KIND_TXT[t[1]])}</span>` +
        (beamDir(t) === 'both' && t[1] !== 'outbound' ? ` <span style="color:${RETURN}">+ host connected out</span>` : '')).join('<br>') +
      (more > 0 ? `<br><span class="m">+${more} more host(s)</span>` : '') +
      (iocIds.has('ip:' + e.ip) ? '<br><span style="color:#2ee6d6">Click for IOC details</span>' : '<br><span class="m">Click to focus its top target</span>');
  } else if (n.domain) {
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
  else if (e.key === '?') toggleAbout();
  else if (e.key === 'l' || e.key === 'L') toggleLabels();
  else if (e.key === 'm' || e.key === 'M') toggleMotion();
  else if (e.key === '3' && can3d) set3d(!R3, true);
  else if (e.key === '2') set3d(false, true);
  else if (R3 && state.mode === 'overview' && 'qQeEtTyYuUrR'.includes(e.key)) {
    const k = e.key.toLowerCase();
    if (k === 'q') rotateView(1); else if (k === 'e') rotateView(-1);
    else if (k === 't') setView('top'); else if (k === 'y') setView('tilted'); else if (k === 'u') setView('low'); else setView(DEFAULT_VIEW, true);
  }
  else if (e.shiftKey && e.key.startsWith('Arrow')) {   // Shift+arrows pan
    const d = 80, cx = W / 2, cy = H / 2;
    panBy(cx, cy, cx + (e.key === 'ArrowLeft' ? d : e.key === 'ArrowRight' ? -d : 0), cy + (e.key === 'ArrowUp' ? d : e.key === 'ArrowDown' ? -d : 0));
  }
  else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
    const ids = hostOrder(); const i = ids.indexOf(state.focus);
    focus(ids[(i + (e.key === 'ArrowRight' ? 1 : ids.length - 1)) % ids.length]);
  }
});
addEventListener('resize', () => { resize(); placeViewctl(); state.mode === 'focus' ? focus(state.focus, 'resize') : fitOverview(); });

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
      (telemetryOnly ? '' : `<span class="pill ${esc(d.pri)}">${esc(d.pri)}</span>`) + `<span class="nm">${esc(d.name ? d.name.split('.')[0] : id)} ${iocHint}` +
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

const panelLists = {
  atk: {query: '', sort: 'priority', expanded: false, page: 0},
  peer: {query: '', sort: 'priority', expanded: false, page: 0},
};
const IP_PREVIEW = 8, IP_PAGE = 20;
function ipRow(kind, item) {
  if (kind === 'atk') {
    const a = item;
    return `<details class="ip-entry" data-k="atk" data-ip="${esc(a.ip)}"><summary class="row"><span class="kind k-${a.kind}" title="${esc(KIND_TXT[a.kind])}"></span>` +
      `<span class="ip">${esc(a.ip)}</span><span class="lk">${a.sessions ? '← ' + a.sessions : ''}${a.sessions && a.out_sessions ? '  ' : ''}${a.out_sessions ? '→ ' + a.out_sessions : ''}${a.alerts ? ' · ' + a.alerts + ' IPS' : ''}</span></summary>` +
      `<div class="ip-detail">${esc(KIND_TXT[a.kind])}${iocIds.has('ip:' + a.ip) ? ' · ' + iocButton('ip', a.ip, 'Report overview') : ''}` +
      `${a.established ? ' · ' + a.established + ' inbound completed' : ''}${a.blocked ? ' · ' + a.blocked + ' firewall blocked' : ''}` +
      `${a.ports.length ? ' · ports ' + esc(a.ports.join(', ')) : ''}${a.alerts_blocked ? ' · ' + a.alerts_blocked + ' IPS blocked' : ''}` +
      `${a.dir === 'both' && a.out_sessions ? ' · host also connected out' + (a.out_ports.length ? ' on ' + esc(a.out_ports.join(', ')) : '') : ''}` +
      `${a.dir === 'out' && a.out_ports.length ? ' · ports ' + esc(a.out_ports.join(', ')) : ''}` +
      `${a.signatures.length ? '<br>' + esc(a.signatures.join('; ')) : ''}` +
      connectionExamples(a.connection_examples, a.sessions + a.out_sessions) +
      (a.connection_examples.length ? '' : alertExamples(a.alert_examples)) + '</div></details>';
  }
  const q = item, pd = nodes.get(q.ip)?.d || {name: '', scanned: false, sev: ''};
  const nm = pd.name ? pd.name.split('.')[0] : q.ip, none = q.band === 'None';
  const o = none ? q.out_tries : q.out, i = none ? q.in_tries : q.in;
  const dir = (o ? `→ ${o}` : '') + (o && i ? '  ' : '') + (i ? `← ${i}` : '');
  return `<details class="ip-entry" data-k="peer" data-ip="${esc(q.ip)}"><summary class="row peer"><div class="bar b-${q.band}"><i style="width:${Math.round(q.p * 100)}%"></i></div>` +
    `<span>${pd.name ? `${esc(nm)} <span class="ip" style="color:var(--muted);font-size:11px">${esc(q.ip)}</span>` : `<span class="ip">${esc(q.ip)}</span>`}</span>` +
    `<span class="lk" style="color:${BAND[q.band] || 'var(--muted)'}">${none ? 'no session' : telemetryOnly ? 'observed' : Math.round(q.p * 100) + '% ' + q.band}</span></summary>` +
    `<div class="ip-detail">${D.focus[q.ip] ? `<button type="button" class="go" data-go="${esc(q.ip)}">Focus ${esc(nm)}</button> · ` : ''}` +
    `${esc(dir)} ${none ? 'attempts, none completed' : 'completed sessions'}${q.ports_out.length ? ' · ' + (none ? 'tried ' : 'uses ') + esc(q.ports_out.join(', ')) : ''}` +
    `${telemetryOnly ? ' · vulnerability status unknown' : pd.scanned ? ' · worst ' + esc(pd.sev || 'none') : ' · not scanned'}` +
    connectionExamples(q.connection_examples, q.out_tries + q.in_tries) +
    `<ul class="why">${q.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div></details>`;
}
function renderIpList(kind) {
  const F = D.focus[state.focus], s = panelLists[kind];
  if (!F) return;
  const list = kind === 'atk' ? F.attackers : F.peers;
  const query = s.query.trim().toLowerCase();
  const filtered = query ? list.filter(x => x.ip.toLowerCase().includes(query) ||
    (kind === 'peer' && (nodes.get(x.ip)?.d.name || '').toLowerCase().includes(query))) : list.slice();
  if (s.sort === 'ip') filtered.sort((a, b) => a.ip.localeCompare(b.ip, undefined, {numeric: true}));
  if (s.sort === 'activity') filtered.sort((a, b) =>
    (kind === 'atk' ? b.sessions + b.out_sessions - a.sessions - a.out_sessions :
      b.out_tries + b.in_tries - a.out_tries - a.in_tries) || a.ip.localeCompare(b.ip));
  if (s.sort === 'likelihood' && kind === 'peer') filtered.sort((a, b) => b.p - a.p || a.ip.localeCompare(b.ip));
  const expanded = s.expanded || !!query, pageSize = expanded ? IP_PAGE : IP_PREVIEW;
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  s.page = Math.min(s.page, pages - 1);
  const start = s.page * pageSize, end = Math.min(filtered.length, start + pageSize);
  const label = kind === 'atk' ? 'outside addresses' : 'internal peers';
  const rows = filtered.slice(start, end).map(x => ipRow(kind, x)).join('') ||
    `<div class="ip-empty">${query ? 'No matching ' + label + '.' : 'No ' + label + ' recorded for this host.'}</div>`;
  document.querySelector(`[data-ip-results="${kind}"]`).innerHTML =
    `<div class="ip-list-count">${filtered.length ? `Showing ${start + 1}–${end} of ${filtered.length}` : '0'} ${label}${query ? ` matching “${esc(s.query)}”` : ''}</div>` + rows +
    (!expanded && filtered.length > IP_PREVIEW ? `<button type="button" class="ip-list-action" data-ip-expand="${kind}">Show all ${filtered.length} ${label}</button>` : '') +
    (expanded && pages > 1 ? `<div class="ip-pager"><button type="button" data-ip-page="${kind}" data-step="-1" ${s.page ? '' : 'disabled'}>Previous</button>` +
      `<span>Page ${s.page + 1} of ${pages}</span><button type="button" data-ip-page="${kind}" data-step="1" ${s.page + 1 < pages ? '' : 'disabled'}>Next</button></div>` : '') +
    (s.expanded && !query && filtered.length > IP_PREVIEW ? `<button type="button" class="ip-list-action" data-ip-collapse="${kind}">Show fewer</button>` : '');
}
function renderPanel(id) {
  const F = D.focus[id], d = nodes.get(id).d, p = $('panel');
  for (const kind of ['atk', 'peer']) panelLists[kind] = {query: '', sort: 'priority', expanded: false, page: 0};
  const nAlert = F.attackers.filter(a => a.kind === 'alert').length;
  const ipSection = (kind, title) => `<section class="ip-section"><h3>${title}</h3><div class="ip-list-tools">` +
    `<input type="search" data-ip-search="${kind}" aria-label="Search ${kind === 'atk' ? 'outside addresses' : 'internal peers'}" placeholder="Search IP${kind === 'peer' ? ' or name' : ''}">` +
    `<select data-ip-sort="${kind}" aria-label="Sort ${kind === 'atk' ? 'outside addresses' : 'internal peers'}"><option value="priority">Priority</option>` +
    `<option value="ip">IP address</option><option value="activity">Activity</option>${kind === 'peer' ? '<option value="likelihood">Likelihood estimate</option>' : ''}</select></div>` +
    `<div data-ip-results="${kind}"></div></section>`;
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
    ipSection('atk', 'North / south: outside addresses') +
    ipSection('peer', telemetryOnly ? 'East / west: observed internal connections' : 'East / west: internal hosts · blast radius if exploited') + hop2 +
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
  renderIpList('atk'); renderIpList('peer');
  const back = $('btn-back'); if (back) back.onclick = () => focus(state.history.pop(), false);
}
$('panel').addEventListener('click', e => {
  const go = e.target.closest('[data-go]'); if (go) { focus(go.dataset.go); return; }
  const expand = e.target.closest('[data-ip-expand]');
  if (expand) { panelLists[expand.dataset.ipExpand].expanded = true; renderIpList(expand.dataset.ipExpand); return; }
  const collapse = e.target.closest('[data-ip-collapse]');
  if (collapse) { const s = panelLists[collapse.dataset.ipCollapse]; s.expanded = false; s.page = 0; renderIpList(collapse.dataset.ipCollapse); return; }
  const page = e.target.closest('[data-ip-page]');
  if (page) { const s = panelLists[page.dataset.ipPage]; s.page += Number(page.dataset.step); renderIpList(page.dataset.ipPage); return; }
  const row = e.target.closest('.row.peer'); if (row) { const w = row.querySelector('.why'); if (w) w.hidden = !w.hidden; }
});
$('panel').addEventListener('input', e => {
  if (!e.target.matches('[data-ip-search]')) return;
  const kind = e.target.dataset.ipSearch, s = panelLists[kind];
  s.query = e.target.value; s.page = 0; renderIpList(kind);
});
$('panel').addEventListener('change', e => {
  if (!e.target.matches('[data-ip-sort]')) return;
  const kind = e.target.dataset.ipSort, s = panelLists[kind];
  s.sort = e.target.value; s.page = 0; renderIpList(kind);
});
$('panel').addEventListener('mouseover', e => {
  const row = e.target.closest('[data-k][data-ip]'); const F = D.focus[state.focus];
  if (!row || !F) { state.hoverEdge = null; return; }
  const ip = row.dataset.ip;
  state.hoverEdge = (row.dataset.k === 'atk' ? F.attackers : F.peers.concat(F.hop2)).find(x => x.ip === ip) || null;
  state.hover = nodes.get(row.dataset.k === 'atk' ? 'ext:' + ip : ip) || null;
});
$('panel').addEventListener('mouseleave', () => { state.hoverEdge = null; state.hover = null; });

// ---------------------------------------------------------------- controls
function toggleLabels() { state.labels = !state.labels; $('btn-labels').setAttribute('aria-pressed', state.labels); }
function toggleMotion() {
  state.motion = !state.motion; $('btn-motion').setAttribute('aria-pressed', state.motion); markView();
  if (state.mode === 'focus') focus(state.focus, false);
}
$('btn-overview').onclick = () => { overview(); };
$('btn-labels').onclick = toggleLabels;
$('btn-motion').onclick = toggleMotion;
$('btn-3d').hidden = !can3d;
// one switcher for the three views: flat network, 3D network, attack paths (attackpaths.js)
function markSeg() {
  const ap = document.getElementById('attack-paths'), paths = !!ap && !ap.hidden;
  $('vw-flat').classList.toggle('on', !paths && !R3); $('btn-3d').classList.toggle('on', !paths && !!R3);
  $('btn-paths').classList.toggle('on', paths);
  for (const id of ['vw-flat', 'btn-3d', 'btn-paths']) $(id).setAttribute('aria-current', $(id).classList.contains('on') ? 'true' : 'false');
  placeViewctl(); updateAbout();
}
// a one-line "what am I looking at" caption under the heading, worded for the current view; the ? button
// hides or shows it and that choice is remembered (closed by default on narrow screens)
const ABOUT_KEY = 'vulnscope-explorer-about';
const ABOUT = telemetryOnly ? {
  flat: 'Each dot is an internal host seen in the logs, grouped by subnet; <b>bigger dots</b> had more contact with outside addresses and <b>blue lines</b> are traffic between hosts. No scan was loaded, so vulnerability status is unknown. Click a host to see who it talked to.',
  '3d': 'Each platform is a subnet and each pillar a host; <b>taller</b> means more contact with outside addresses. Outside addresses sit on the arc above: <b>beams down</b> reach a host, <b>violet beams up</b> are hosts calling out. Click a host to see who it talked to.',
  focus: h => `<b>${esc(h)}</b> in the middle. <b>Left:</b> outside addresses it exchanged traffic with (north/south). <b>Right:</b> internal hosts it talked to (east/west). Esc or ← All hosts goes back.`,
} : {
  flat: 'Each dot is a scanned host, grouped by subnet and colored by its worst finding; <b>bigger dots</b> carry a higher risk score and <b>blue lines</b> are traffic between hosts. Click a host to see who reached it and how far a compromise could spread.',
  '3d': 'Each platform is a subnet and each pillar a host; <b>taller</b> means a higher risk score. Outside addresses sit on the arc above: <b>beams down</b> reach a host, <b>violet beams up</b> are hosts calling out. Click a host for detail.',
  focus: h => `<b>${esc(h)}</b> in the middle. <b>Left:</b> outside addresses that touched it (north/south). <b>Right:</b> internal hosts it can reach, colored by how likely a compromise could spread there (east/west). Esc or ← All hosts goes back.`,
};
function aboutOpen() {
  let v = null; try { v = localStorage.getItem(ABOUT_KEY); } catch (_) {}
  return v === null ? !matchMedia('(max-width: 900px)').matches : v === '1';
}
function updateAbout() {
  const box = $('about'); if (!box) return;
  const open = aboutOpen(), d = state.mode === 'focus' && D.nodes ? (D.nodes.find(n => n.id === state.focus) || {}) : null;
  $('about-text').innerHTML = d ? ABOUT.focus(d.name ? d.name.split('.')[0] + ' (' + state.focus + ')' : state.focus) : ABOUT[R3 ? '3d' : 'flat'];
  box.classList.toggle('closed', !open);
  $('about-toggle').setAttribute('aria-expanded', String(open));
  $('about-toggle').textContent = open ? '?' : '? What am I looking at';
  $('about-toggle').title = open ? 'Hide this explanation (?)' : 'What am I looking at? (?)';
  // keep the host list clear of the heading as the caption grows or shrinks
  document.documentElement.style.setProperty('--rail-top', Math.max(78, $('hud').getBoundingClientRect().bottom + 12) + 'px');
}
function toggleAbout() { try { localStorage.setItem(ABOUT_KEY, aboutOpen() ? '0' : '1'); } catch (_) {} updateAbout(); }
$('about-toggle').onclick = toggleAbout;
const closePaths = () => { if (window.VFPaths) window.VFPaths.close(); };
$('vw-flat').onclick = () => { closePaths(); set3d(false, true); };
$('btn-3d').onclick = () => { closePaths(); set3d(true, true); };
// the 3D camera controls sit in the lower right, just above the legend
function placeViewctl() { document.documentElement.style.setProperty('--legend-h', ($('legend').offsetHeight + 24) + 'px'); }
$('vc-left').onclick = () => rotateView(1);
$('vc-right').onclick = () => rotateView(-1);
$('vc-top').onclick = () => setView('top');
$('vc-tilted').onclick = () => setView('tilted');
$('vc-low').onclick = () => setView('low');
$('vc-reset').onclick = () => setView(DEFAULT_VIEW, true);
$('vc-spin').onclick = () => { view.spin = !(view.spin && state.motion); if (view.spin && !state.motion) toggleMotion(); markView(); };
markView();
if (!state.motion) $('btn-motion').setAttribute('aria-pressed', 'false');

$('legend').innerHTML =
  `<span class="only3d m">Drag: pan · right-drag or Shift-drag: rotate and tilt · Q / E: rotate · T top · Y tilted · U low · R reset (low, turning)</span>` +
  `<span class="only3d">${telemetryOnly ? 'Pillar height: outside exposure' : 'Pillar height: risk score'}</span>` +
  `<span class="only3d"><i style="background:#2ee6d6"></i>Arc above: top outside addresses, beams down to hosts they reached, violet beams up from hosts that called out</span>` +
  `<span class="only3d"><i style="background:#6ea8ff"></i><i style="background:#ff8a3d;width:12px"></i>Traffic between subnets (orange: mostly admin protocols)</span>` +
  `<span class="only3d"><i style="background:#ff2e88"></i><i style="background:#ffb020;width:12px"></i>Risky host paths: admin protocol into P1 or flagged host / either one</span>` +
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
resize();
{
  let pref = null; try { pref = localStorage.getItem(KEY3D); } catch (_) {}
  const q = location.search + location.hash;
  set3d(can3d && !/[?&#]2d\b/.test(q) && (/[?&#]3d\b/.test(q) || pref !== '0'), false);
}
renderList(); fitOverview(); placeViewctl();
const introText = telemetryOnly ? `Exploring ${c.hosts} observed hosts and ${c.flows.toLocaleString()} sessions` : `Correlating ${c.hosts} hosts against ${c.flows.toLocaleString()} sessions`;
if (state.motion) {
  let i = 0; const it = setInterval(() => { $('intro-text').textContent = introText.slice(0, ++i) + (i < introText.length ? '▌' : ''); if (i >= introText.length) clearInterval(it); }, 22);
  setTimeout(() => $('intro').classList.add('gone'), 1500);
} else { $('intro').style.display = 'none'; nodes.forEach(n => n.born = 0); snap(); }
const m = location.hash.match(/host=([^&]+)/);
if (m && D.focus[decodeURIComponent(m[1])]) {
  if (state.motion) setTimeout(() => focus(decodeURIComponent(m[1])), 900); else { focus(decodeURIComponent(m[1])); snap(); }
}
// lets the Attack paths view (attackpaths.js) hand a host back to this view
window.VFExplorer = {focus: id => focus(id), overview: () => overview(), set3d: on => set3d(on, true), is3d: () => !!R3, can3d, markSeg};
requestAnimationFrame(frame);
})();
