// Timeline view ("time tunnel"): time runs along a tunnel, subnets are lanes around its wall and every
// flow is a chord drawn at the moment it happened, so the order of events (first contact, an exploit
// alert, the callback, repeating beacons) reads directly. Data comes from the `timeline` block that
// explore.py adds to the Explorer blob; large runs are sampled there, and the side panel says so.
(function () {
'use strict';
const D = JSON.parse(document.getElementById('vf-data').textContent);
const T = D.timeline, root = document.getElementById('timeline-view'), openBtn = document.getElementById('btn-timeline');
if (!root || !openBtn) return;
const supported = (() => { try { const c = document.createElement('canvas'); return !!(window.THREE && (c.getContext('webgl2') || c.getContext('webgl'))); } catch (_) { return false; } })();
if (!T || !T.flows || !T.flows.length || !supported) { openBtn.hidden = true; return; }
openBtn.hidden = false;
const apTimeline = document.querySelector('#attack-paths .ap-seg [data-view="timeline"]');   // the switcher inside Attack paths
if (apTimeline) apTimeline.hidden = false;
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
const COL = {crit: 0xff3b5c, pink: 0xff2e88, cyan: 0x2ee6d6, violet: 0xb98cff, orange: 0xff8a3d, internal: 0x2f5d9c, blocked: 0x55606e, guide: 0x24406a, day: 0x2b4f80};
// restrained themes (html[data-calm]): muted lines, neutral guides
if (document.documentElement.hasAttribute('data-calm')) Object.assign(COL, {crit: 0xe5534b, pink: 0xd86a8c, cyan: parseInt((getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#45b0c2').slice(1), 16), violet: 0x9088b0, orange: 0xd98845, internal: 0x5a5d62, blocked: 0x4a4c50, guide: 0x34363a, day: 0x44464b});
if (document.documentElement.dataset.theme === 'light') Object.assign(COL, {crit: 0xc62828, pink: 0xb0486a, cyan: 0x0f6f80, violet: 0x6d5fb0, orange: 0xc2570c, internal: 0xa6a8ab, blocked: 0xc4c6c8, guide: 0xd5d5d1, day: 0xbdbdb9});
const hex = c => '#' + c.toString(16).padStart(6, '0');
const T0 = new Date(T.t0), HRS = Math.max(T.hours, 1);
const when = h => new Date(T0.getTime() + h * 3600e3);
const fmt = h => when(h).toISOString().slice(5, 16).replace('T', ' ') + 'Z';
const short = n => (n || '').split('.')[0];
const N = D.nodes, X = T.ext;
const hostName = i => i >= 0 ? (short(N[i].name) || N[i].id) : X[-i - 1][0];
const telemetryOnly = !D.vulnerability_data_available;
// shared services (DNS, AD, proxy, file and print): hosts that more than 25 others talk to; traffic to them is expected
const deg = new Map(); for (const [a, b] of D.links || []) { deg.set(a, (deg.get(a) || 0) + 1); deg.set(b, (deg.get(b) || 0) + 1); }
const hub = N.map(n => (deg.get(n.id) || 0) > 25);

// ---------------------------------------------------------------- page chrome
const BRAND = (document.querySelector('meta[name="application-name"]') || {}).content || 'VulnScope';
const BRAND_IMG = document.querySelector('#hud .brand-logo');           // the analyst's logo, as the other views show it
const BRAND_LOGO = (BRAND_IMG || {}).src || '';
const BRAND_SMALL = !!(BRAND_IMG && BRAND_IMG.classList.contains('logo-small'));
const WINS = HRS > 72 ? [6, 12, 24] : HRS > 12 ? [2, 6, 12] : [0.5, 1, 3];
let WIN = WINS[1];
root.innerHTML = `<canvas id="tl-canvas" aria-label="Flows over time"></canvas><div id="tl-labels"></div>
<header class="tl-top">${BRAND_LOGO.startsWith('data:image/') ? `<img class="tl-logo${BRAND_SMALL ? ' logo-small' : ''}" src="${esc(BRAND_LOGO)}" alt="" aria-hidden="true">` : ''}<div class="tl-title"><div class="t">${esc(BRAND)} · Timeline</div><div class="s" id="tl-sub"></div></div>
  <div class="seg" role="group" aria-label="View"><button type="button" data-view="flat" title="Flat network view (2)">Flat</button><button type="button" data-view="3d" title="3D network view (3)">3D</button><button type="button" data-view="paths" title="Attack paths (P)">Attack paths</button><button type="button" class="on" aria-current="true" title="Timeline (Esc to go back)">Timeline</button></div>
  <span class="tl-qwrap"><button type="button" id="tl-about-toggle" aria-controls="tl-about" aria-expanded="false" aria-label="What am I looking at?" title="What am I looking at? (?)">?</button></span></header>
<aside class="tl-side"><h3>Time window</h3><div class="tl-winbtns" role="group" aria-label="Window length">${WINS.map(w => `<button type="button" data-w="${w}">${w < 1 ? w * 60 + ' min' : w + ' h'}</button>`).join('')}</div>
  <input id="tl-scrub" type="range" min="0" step="0.25" aria-label="Window start"><div id="tl-win"></div><div id="tl-sample"></div></aside>
<p id="tl-about" hidden>Time runs <b>left to right</b> along the tunnel. Each lane on the wall is a subnet and the <b>internet</b> is the outer band on top. Every flow is a <b>chord</b> drawn at the moment it happened, so you can read the order of events: first contact, the exploit alert, the callback out, and anything that repeats on a schedule. <b>Rings</b> are IPS alerts. Drag the window in the side panel to light up one stretch of time.</p>
<div class="tl-legend" id="tl-legend"></div>
<div class="tl-cams" role="group" aria-label="Camera"><button type="button" data-p="angled" title="Angled view">Angled</button><button type="button" data-p="side" title="Side view">Side</button><button type="button" data-p="down" title="Look down the tunnel">Down the tunnel</button><button type="button" data-p="above" title="Top-down view">Above</button><button type="button" id="tl-spin" title="Turn slowly to the left (stops when you move the camera; Space)">Spin</button></div>
<div id="tl-tip" hidden></div>`;
const $ = id => document.getElementById(id);
$('tl-sub').textContent = `${fmt(0)} → ${fmt(T.hours)} · ${T.flows.length.toLocaleString()} flows drawn` + (T.sampled ? ` (sample of ${T.total.toLocaleString()})` : '');
$('tl-legend').innerHTML = [[COL.pink, 'To/from an alert or IOC address'], [COL.cyan, 'Inbound from internet'], [COL.violet, 'Outbound to internet'],
  [COL.orange, 'Direct between subnets'], [COL.internal, 'Within a subnet or to shared services'], [COL.blocked, 'Blocked or failed'], [COL.crit, 'IPS alert', 'ring'], [COL.pink, 'IOC domain lookup', 'dot']]
  .map(([c, t, k]) => `<span><i class="${k || ''}" style="--c:${hex(c)}"></i>${t}</span>`).join('') + '<span class="cal">Drag: rotate · right-drag or Shift-drag: pan · scroll: zoom</span>';

// ---------------------------------------------------------------- scene (built on first open)
let renderer, scene, camera, built = false, raf = 0, last = 0;
const cam = {theta: -1, phi: 1.22, r: 1000, tx: 0, ty: -12, tz: 0, spin: true, preset: 'angled'};
const LEN = 900, SX = LEN / HRS, X0 = -LEN / 2, R = 70, RX = 112;
const tx = h => X0 + h * SX;
const labels = [], pick = [];
let hostA, extA, allLines, winLines, winRings = [], lanes;

function laneLayout() {
  const subs = (D.subnets || []).slice().sort((a, b) => b.hosts - a.hosts);
  const shown = subs.slice(0, 14).sort((a, b) => a.id < b.id ? -1 : 1), keep = new Set(shown.map(s => s.id));
  const list = shown.map(s => ({id: s.id, name: s.id, n: 0}));
  if (subs.length > shown.length) list.push({id: '*', name: 'other subnets', n: 0});
  const byId = Object.fromEntries(list.map(l => [l.id, l]));
  const laneOf = N.map(n => byId[keep.has(n.subnet) ? n.subnet : '*'] || list[0]);
  laneOf.forEach(l => l && l.n++);
  const INET = Math.PI * .55, gap = .05, rest = Math.PI * 2 - INET - gap * (list.length + 1);
  const wsum = list.reduce((a, l) => a + Math.sqrt(l.n + 2), 0);
  let a = INET / 2 + gap;
  list.forEach(l => { l.span = Math.sqrt(l.n + 2) / wsum * rest; l.a0 = a; a += l.span + gap; l.k = 0; });
  hostA = N.map((n, i) => { const l = laneOf[i]; return l.a0 + (l.k++ + .5) / l.n * l.span; });
  extA = X.map((e, i) => -INET / 2 + ((i * 0.618034) % 1) * INET);
  return {list, INET};
}
const ptAt = (ref, h) => { const x = tx(h); if (ref >= 0) { const a = hostA[ref]; return [x, Math.cos(a) * R, Math.sin(a) * R]; }
  const a = extA[-ref - 1]; return [x, Math.cos(a) * RX, Math.sin(a) * RX]; };
function flowColor(s, d, f) {
  if (f & 2) return COL.pink; if (f & 1) return COL.blocked;
  if (s < 0) return COL.cyan; if (d < 0) return COL.violet;
  return N[s].subnet !== N[d].subnet && !hub[s] && !hub[d] ? COL.orange : COL.internal;
}
function segs(filter, opacity) {
  const p = [], c = [], col = new THREE.Color();
  for (const fl of T.flows) { if (!filter(fl)) continue; const [h, s, d, , f] = fl; col.setHex(flowColor(s, d, f));
    p.push(...ptAt(s, h), ...ptAt(d, h)); c.push(col.r, col.g, col.b, col.r, col.g, col.b); }
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(p, 3)); g.setAttribute('color', new THREE.Float32BufferAttribute(c, 3));
  const l = new THREE.LineSegments(g, new THREE.LineBasicMaterial({vertexColors: true, transparent: true, opacity, depthWrite: false}));
  scene.add(l); return l;
}
function circle(radius, x, color, opacity) {
  const pts = []; for (let i = 0; i <= 96; i++) { const a = i / 96 * Math.PI * 2; pts.push(new THREE.Vector3(x, Math.cos(a) * radius, Math.sin(a) * radius)); }
  const l = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({color, transparent: true, opacity}));
  scene.add(l); return l;
}
function label(text, x, y, z, cls) {
  const el = document.createElement('div'); el.className = 'tl-l ' + cls; el.textContent = text; $('tl-labels').appendChild(el);
  labels.push({el, v: new THREE.Vector3(x, y, z)});
}
function build() {
  renderer = new THREE.WebGLRenderer({canvas: $('tl-canvas'), antialias: true, alpha: true});
  renderer.setClearColor(0x000000, 0);
  scene = new THREE.Scene(); camera = new THREE.PerspectiveCamera(45, 1, 1, 10000);
  const L = laneLayout(); lanes = L.list;
  // lane edges along the wall, lane names at the start, the internet band on top
  const gp = [], gc = [], g1 = new THREE.Color(COL.guide), g2 = new THREE.Color(0x147a74);
  const edge = (a, r, c) => { gp.push(X0, Math.cos(a) * r, Math.sin(a) * r, X0 + LEN, Math.cos(a) * r, Math.sin(a) * r); gc.push(c.r, c.g, c.b, c.r, c.g, c.b); };
  lanes.forEach(l => { edge(l.a0, R, g1); edge(l.a0 + l.span, R, g1); const m = l.a0 + l.span / 2;
    label(`${l.name} · ${l.n}`, X0 - 8, Math.cos(m) * (R + 8), Math.sin(m) * (R + 8), 'lane'); });
  edge(-L.INET / 2, RX, g2); edge(L.INET / 2, RX, g2); label('INTERNET', X0 - 8, RX + 10, 0, 'inet');
  const gg = new THREE.BufferGeometry(); gg.setAttribute('position', new THREE.Float32BufferAttribute(gp, 3)); gg.setAttribute('color', new THREE.Float32BufferAttribute(gc, 3));
  scene.add(new THREE.LineSegments(gg, new THREE.LineBasicMaterial({vertexColors: true, transparent: true, opacity: .55})));
  // day rings (weekly once the run is long), labelled with the UTC date
  const step = HRS > 24 * 40 ? 24 * 7 : 24, first = (24 - (T0.getUTCHours() + T0.getUTCMinutes() / 60)) % 24;
  const every = Math.max(1, Math.ceil(HRS / step / 12));
  for (let h = first, k = 0; h <= HRS; h += step, k++) { circle(R, tx(h), COL.day, .6);
    if (k % every === 0) label(when(h).toUTCString().slice(0, 11), tx(h), -R - 22, 0, 'day'); }
  allLines = segs(f => !(f[4] & 2), .16);
  segs(f => f[4] & 2, 1);
  // IPS alerts as rings around the tunnel; IOC domain lookups as dots on the host's lane
  const ringGeo = new THREE.TorusGeometry(R + 4, 1.1, 6, 96).rotateY(Math.PI / 2);
  const am = new THREE.InstancedMesh(ringGeo, new THREE.MeshBasicMaterial(), Math.max(1, T.alerts.length)); am.count = T.alerts.length;
  const m4 = new THREE.Matrix4(); let stack = 0, lastH = -1e9;
  T.alerts.forEach(([h, hi, src, name, blocked], k) => {
    m4.makeTranslation(tx(h), 0, 0); am.setMatrixAt(k, m4); am.setColorAt(k, new THREE.Color(blocked ? 0x8da2b5 : COL.crit));
    if (!blocked || k < 6) { stack = h - lastH < HRS / 25 ? stack + 1 : 0; lastH = h;
      label((blocked ? 'blocked: ' : 'ALERT: ') + name.replace(/\(.*?\)/g, '').replace(' Vulnerability', '').replace('Intel::Notice - ', '').slice(0, 52) + (hi >= 0 ? ' → ' + hostName(hi) : ''),
        tx(h), R + 18 + stack * 13, 0, blocked ? 'dim' : 'hot'); }
  });
  scene.add(am); pick.push({obj: am, info: k => { const [h, hi, src, name, blocked] = T.alerts[k];
    return `<b>${blocked ? 'Blocked' : '<span class="bad">Not blocked</span>'} IPS alert</b> · ${fmt(h)}<br>${esc(name)}<br><span class="mono">${esc(src)}</span> → ${hi >= 0 ? esc(hostName(hi)) : '?'}${hi >= 0 ? '<br>Click to open the host' : ''}`; },
    click: k => T.alerts[k][1] >= 0 && openHost(N[T.alerts[k][1]].id)});
  if (T.ioc_lookups.length) {
    const im = new THREE.InstancedMesh(new THREE.SphereGeometry(2.2, 10, 8), new THREE.MeshBasicMaterial({color: COL.pink}), T.ioc_lookups.length);
    T.ioc_lookups.forEach(([h, hi], k) => { m4.makeTranslation(...ptAt(hi, h)); im.setMatrixAt(k, m4); });
    scene.add(im); pick.push({obj: im, info: k => { const [h, hi, q] = T.ioc_lookups[k]; return `<b class="bad">IOC domain lookup</b> · ${fmt(h)}<br>${esc(hostName(hi))} asked for <span class="mono">${esc(q)}</span><br>Click to open the host`; },
      click: k => openHost(N[T.ioc_lookups[k][1]].id)});
    const [h, hi, q] = T.ioc_lookups[0]; const p = ptAt(hi, h); label(`IOC lookups: ${q}` + (T.ioc_lookups.length > 1 ? ` (${T.ioc_lookups.length}×)` : ''), p[0], p[1] - 10, p[2], 'hot');
  }
  winRings = [circle(R + 3, 0, COL.cyan, .9), circle(R + 3, 0, COL.cyan, .9)];
  controls(); built = true;
}

// ---------------------------------------------------------------- window, side panel
function setWindow(h) {
  if (winLines) { scene.remove(winLines); winLines.geometry.dispose(); }
  winLines = segs(f => f[0] >= h && f[0] < h + WIN, .9);
  allLines.material.opacity = .06; winRings[0].position.x = tx(h); winRings[1].position.x = tx(h + WIN);
  const inW = T.flows.filter(f => f[0] >= h && f[0] < h + WIN), c = k => inW.filter(k).length;
  const evs = T.alerts.map((a, k) => ({h: a[0], k, html: `<button type="button" class="ev${a[4] ? ' blk' : ''}" data-alert="${k}"><span class="tm">${fmt(a[0]).slice(6)}</span>${esc(a[3].replace(/\(.*?\)/g, ''))} → ${a[1] >= 0 ? esc(hostName(a[1])) : '?'}</button>`}))
    .concat(T.ioc_lookups.map(a => ({h: a[0], html: `<button type="button" class="ev" data-host="${esc(N[a[1]].id)}"><span class="tm">${fmt(a[0]).slice(6)}</span>${esc(hostName(a[1]))} looked up ${esc(a[2])}</button>`})))
    .filter(e => e.h >= h && e.h < h + WIN).sort((a, b) => a.h - b.h);
  $('tl-win').innerHTML = `<div class="row"><span>${fmt(h)} → +${WIN < 1 ? WIN * 60 + ' min' : WIN + ' h'}</span><b>${inW.length.toLocaleString()} flows</b></div>`
    + `<div class="row"><span>Inbound from internet</span><b>${c(f => f[1] < 0)}</b></div><div class="row"><span>Outbound to internet</span><b>${c(f => f[2] < 0)}</b></div>`
    + `<div class="row"><span>Blocked or failed</span><b>${c(f => f[4] & 1)}</b></div><div class="row"><span>Alert or IOC address</span><b style="color:var(--pink)">${c(f => f[4] & 2)}</b></div>`
    + (telemetryOnly ? '' : `<div class="row"><span>Onto a vulnerable port</span><b>${c(f => f[4] & 4)}</b></div>`)
    + (evs.length ? `<h3 style="margin-top:10px">Events</h3>${evs.slice(0, 12).map(e => e.html).join('')}` : '<p>No alerts or IOC lookups in this window.</p>');
  $('tl-win').querySelectorAll('[data-alert]').forEach(b => b.onclick = () => { const a = T.alerts[+b.dataset.alert]; if (a[1] >= 0) openHost(N[a[1]].id); });
  $('tl-win').querySelectorAll('[data-host]').forEach(b => b.onclick = () => openHost(b.dataset.host));
}
function setupSide() {
  const sc = $('tl-scrub'); sc.max = Math.max(0, HRS - WIN);
  const firstLive = T.alerts.find(a => !a[4]) || T.alerts[0] || T.ioc_lookups[0];
  sc.value = firstLive ? Math.max(0, Math.min(HRS - WIN, firstLive[0] - WIN / 4)) : 0;
  sc.oninput = () => setWindow(+sc.value);
  const markW = () => root.querySelectorAll('.tl-winbtns button').forEach(b => b.classList.toggle('on', +b.dataset.w === WIN));
  root.querySelectorAll('.tl-winbtns button').forEach(b => b.onclick = () => { WIN = +b.dataset.w; sc.max = Math.max(0, HRS - WIN); markW(); setWindow(Math.min(+sc.value, +sc.max)); });
  markW(); setWindow(+sc.value);
  $('tl-sample').innerHTML = T.sampled ? `<p>This run has ${T.total.toLocaleString()} flows. Every blocked flow and every flow to or from an alert or IOC address is kept (up to half the budget); the rest is a fixed random sample.</p>` : '';
}

// ---------------------------------------------------------------- camera: moves only when you drag or zoom, or while Spin is on
const PRESETS = {angled: {theta: -1, phi: 1.22, r: LEN * 1.05, t: [-LEN * .08, -12, 0]}, side: {theta: 0, phi: 1.42, r: LEN * .95, t: [0, 0, 0]},
  down: {theta: -Math.PI / 2 + .25, phi: 1.3, r: LEN / 2 + 160, t: [LEN * .12, 0, 0]}, above: {theta: 0, phi: .25, r: LEN * .95, t: [0, 0, 0]}};
function applyCam() {
  cam.phi = Math.max(.05, Math.min(Math.PI - .05, cam.phi)); const sp = Math.sin(cam.phi);
  camera.position.set(cam.tx + cam.r * sp * Math.sin(cam.theta), cam.ty + cam.r * Math.cos(cam.phi), cam.tz + cam.r * sp * Math.cos(cam.theta));
  camera.lookAt(cam.tx, cam.ty, cam.tz);
}
function setPreset(name) { const p = PRESETS[name]; cam.preset = name; Object.assign(cam, {theta: p.theta, phi: p.phi, r: p.r, tx: p.t[0], ty: p.t[1], tz: p.t[2]}); applyCam(); markCam(); }
function setSpin(on) { cam.spin = on; markCam(); }
function markCam() { root.querySelectorAll('.tl-cams [data-p]').forEach(b => b.setAttribute('aria-pressed', b.dataset.p === cam.preset)); $('tl-spin').setAttribute('aria-pressed', cam.spin); }
root.querySelectorAll('.tl-cams [data-p]').forEach(b => b.onclick = () => setPreset(b.dataset.p));
$('tl-spin').onclick = () => setSpin(!cam.spin);
const ray = new THREE.Raycaster(), mouse = new THREE.Vector2();
function hit(e) {
  const r = renderer.domElement.getBoundingClientRect(); mouse.set((e.clientX - r.left) / r.width * 2 - 1, -(e.clientY - r.top) / r.height * 2 + 1);
  ray.setFromCamera(mouse, camera); let best = null;
  for (const p of pick) { const h = ray.intersectObject(p.obj, false)[0]; if (h && (!best || h.distance < best.h.distance)) best = {p, h}; }
  return best;
}
function controls() {
  const el = renderer.domElement, pts = new Map(); let drag = null;
  el.addEventListener('contextmenu', e => e.preventDefault());
  el.addEventListener('pointerdown', e => { el.setPointerCapture(e.pointerId); pts.set(e.pointerId, {x: e.clientX, y: e.clientY});
    drag = {pan: e.button === 2 || e.shiftKey, moved: 0}; el.classList.add('drag'); });
  el.addEventListener('pointermove', e => {
    if (!drag) { const b = hit(e), tip = $('tl-tip');
      if (b) { tip.innerHTML = b.p.info(b.h.instanceId); tip.hidden = false; el.classList.add('hover');
        tip.style.left = Math.min(innerWidth - tip.offsetWidth - 8, e.clientX + 14) + 'px'; tip.style.top = Math.min(innerHeight - tip.offsetHeight - 8, e.clientY + 14) + 'px'; }
      else { tip.hidden = true; el.classList.remove('hover'); }
      return; }
    const prev = pts.get(e.pointerId); if (!prev) return;
    if (pts.size === 2) { const [a, b] = [...pts.values()], d0 = Math.hypot(a.x - b.x, a.y - b.y); pts.set(e.pointerId, {x: e.clientX, y: e.clientY});
      const [c, d] = [...pts.values()], d1 = Math.hypot(c.x - d.x, c.y - d.y); if (d0 && d1) { cam.r *= d0 / d1; applyCam(); } setSpin(false); return; }
    const dx = e.clientX - prev.x, dy = e.clientY - prev.y; pts.set(e.pointerId, {x: e.clientX, y: e.clientY}); drag.moved += Math.abs(dx) + Math.abs(dy);
    if (drag.moved > 3) { setSpin(false); cam.preset = ''; markCam(); $('tl-tip').hidden = true; }
    if (drag.pan) { const s = cam.r * .0016, right = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 0), up = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 1);
      cam.tx += -dx * s * right.x + dy * s * up.x; cam.ty += -dx * s * right.y + dy * s * up.y; cam.tz += -dx * s * right.z + dy * s * up.z; }
    else { cam.theta -= dx * .005; cam.phi -= dy * .005; }
    applyCam();
  });
  const end = e => { pts.delete(e.pointerId); if (drag && drag.moved < 4 && !pts.size) { const b = hit(e); if (b && b.p.click) b.p.click(b.h.instanceId); }
    if (!pts.size) { drag = null; el.classList.remove('drag'); } };
  el.addEventListener('pointerup', end); el.addEventListener('pointercancel', end);
  el.addEventListener('wheel', e => { e.preventDefault(); cam.r = Math.max(40, Math.min(5000, cam.r * Math.exp(e.deltaY * .0012))); applyCam(); setSpin(false); cam.preset = ''; markCam(); }, {passive: false});
}
const _v = new THREE.Vector3();
function frame(now) {
  raf = requestAnimationFrame(frame);
  const dt = Math.min(.05, (now - (last || now)) / 1000); last = now;
  if (cam.spin) { cam.theta -= dt * .06; applyCam(); }
  renderer.render(scene, camera);
  const W = innerWidth, Hh = innerHeight;
  for (const l of labels) { _v.copy(l.v).project(camera); const vis = _v.z < 1 && Math.abs(_v.x) < 1.1 && Math.abs(_v.y) < 1.1;
    l.el.style.display = vis ? '' : 'none'; if (vis) l.el.style.transform = `translate(${(_v.x + 1) / 2 * W}px,${(1 - _v.y) / 2 * Hh}px) translate(-50%,-50%)`; }
}
function resize() { if (!renderer) return; renderer.setPixelRatio(Math.min(2, devicePixelRatio || 1)); renderer.setSize(innerWidth, innerHeight, false); camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix(); }
addEventListener('resize', () => { if (!root.hidden) resize(); });

// ---------------------------------------------------------------- note, open and close, switching views
const ABOUT_MS = 15000; let aboutTimer = 0;
function closeAbout() { clearTimeout(aboutTimer); $('tl-about').hidden = true; $('tl-about-toggle').setAttribute('aria-expanded', 'false'); }
// the note sits centered under the tunnel: above the legend, left of the side panel and camera buttons
function placeAbout() {
  const box = el => { if (!el) return null; const cs = getComputedStyle(el); if (cs.display === 'none') return null;
    const b = el.getBoundingClientRect(); return b.width && b.height ? b : null; };
  const v = root.getBoundingClientRect(); let l = v.left + 18, r = v.right - 18, bottom = v.bottom - 14;
  for (const el of [root.querySelector('.tl-side'), root.querySelector('.tl-cams')]) { const b = box(el); if (b) r = Math.min(r, b.left - 14); }
  const lg = box($('tl-legend')); if (lg) bottom = Math.min(bottom, lg.top - 10);
  const cams = box(root.querySelector('.tl-cams')); if (cams && lg && cams.bottom > lg.top) bottom = Math.min(bottom, cams.top - 10);
  if (r - l < 280) { l = v.left + 18; r = v.right - 18; }
  const st = $('tl-about').style;
  st.left = Math.round(l - v.left) + 'px'; st.right = Math.round(v.right - r) + 'px'; st.bottom = Math.round(v.bottom - bottom) + 'px';
  st.maxWidth = Math.round(Math.min(620, r - l)) + 'px';
}
function openAbout(ms = ABOUT_MS) { $('tl-about').hidden = false; placeAbout(); requestAnimationFrame(placeAbout); $('tl-about-toggle').setAttribute('aria-expanded', 'true'); clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, ms); }
addEventListener('resize', () => { if (!$('tl-about').hidden) placeAbout(); });
function toggleAbout() { if ($('tl-about').hidden) openAbout(); else closeAbout(); }
$('tl-about-toggle').onclick = toggleAbout;
$('tl-about').addEventListener('mouseenter', () => clearTimeout(aboutTimer));
$('tl-about').addEventListener('mouseleave', () => { clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, 3000); });
let isOpen = false;
function open() {
  if (window.VFPaths) window.VFPaths.close();
  isOpen = true; root.hidden = false; openBtn.setAttribute('aria-expanded', 'true');
  if (!built) { build(); setupSide(); setPreset('angled'); setSpin(true); }
  resize(); last = 0; cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); openAbout();
  if (!/[?&#]timeline\b/.test(location.hash)) history.replaceState(null, '', '#timeline');
  if (window.VFExplorer) window.VFExplorer.markSeg();
}
function close() {
  if (!isOpen) return;
  isOpen = false; root.hidden = true; cancelAnimationFrame(raf); closeAbout(); $('tl-tip').hidden = true; openBtn.setAttribute('aria-expanded', 'false');
  if (/[?&#]timeline\b/.test(location.hash)) history.replaceState(null, '', location.pathname + location.search);
  if (window.VFExplorer) window.VFExplorer.markSeg();
}
function showView(v) { close(); if (v === 'paths') { if (window.VFPaths) window.VFPaths.open(); } else if (window.VFExplorer) window.VFExplorer.set3d(v === '3d'); }
function openHost(ip) { close(); if (window.VFExplorer) window.VFExplorer.focus(ip); }
openBtn.onclick = () => { if (!isOpen) open(); };
root.querySelectorAll('.seg [data-view]').forEach(b => { b.onclick = () => showView(b.dataset.view);
  if (b.dataset.view === '3d' && !(window.VFExplorer && window.VFExplorer.can3d)) b.hidden = true;
  if (b.dataset.view === 'paths' && document.getElementById('btn-paths').hidden) b.hidden = true; });
// while open, keys belong to this view so the network view underneath does not react
addEventListener('keydown', e => {
  const typing = e.target.tagName === 'INPUT' && e.target.type !== 'range' || e.target.tagName === 'TEXTAREA' || (e.target.closest && e.target.closest('#analyst-chat'));
  if (!isOpen) { if ((e.key === 'i' || e.key === 'I') && !e.metaKey && !e.ctrlKey && !typing) open(); return; }
  if (typing) return;
  e.stopImmediatePropagation();
  if (e.key === 'Escape' || e.key === 'i' || e.key === 'I') close();
  else if (e.key === '?') toggleAbout();
  else if (e.key === ' ') { e.preventDefault(); setSpin(!cam.spin); }
  else if (e.key === '2') showView('flat');
  else if (e.key === '3' && window.VFExplorer && window.VFExplorer.can3d) showView('3d');
  else if ((e.key === 'p' || e.key === 'P') && !document.getElementById('btn-paths').hidden) showView('paths');
}, true);
if (/[?&#]timeline\b/.test(location.search + location.hash)) open();
window.VFTimeline = {open, close, isOpen: () => isOpen};
})();
