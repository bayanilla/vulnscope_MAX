// Attack paths view ("Breach Lines"): the most likely ways in, drawn like a transit map.
// Columns are attack steps (internet origin, entry, first pivot, second pivot), rows are subnets, and
// each colored line is one ranked chain built from the Explorer data already on the page. Chains rank
// where to look; they are estimates, never a confirmed compromise.
(function () {
'use strict';
const D = JSON.parse(document.getElementById('vf-data').textContent);
const root = document.getElementById('attack-paths'), openBtn = document.getElementById('btn-paths');
if (!root || !openBtn) return;
const q = id => document.getElementById('ap-' + id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
const NS = 'http://www.w3.org/2000/svg';
const PAL = ['#e8372e', '#2f8ff0', '#13b07a', '#f39a1d', '#9b5de5', '#11b5b5', '#c2683a', '#e2589f', '#86b818', '#5468d4'];
const SEVC = {Critical: 'var(--ap-crit)', High: 'var(--ap-high)', Medium: 'var(--ap-med)', Low: 'var(--ap-low)'};
const MAX_LINES = 9;
const BRAND = (document.querySelector('meta[name="application-name"]') || {}).content || 'VulnScope';
const BRAND_LOGO = (document.querySelector('#hud .brand-logo') || {}).src || '';

// ---------------------------------------------------------------- data from the Explorer blob
const H = {}, IOC = {}, inports = {};
for (const F of Object.values(D.focus || {})) for (const p of F.peers || []) {
  const c = inports[p.ip] = inports[p.ip] || {};
  for (const port of p.ports_out || []) c[port] = (c[port] || 0) + 1;
}
for (const n of D.nodes || []) {
  const F = (D.focus || {})[n.id] || {}, att = F.attackers || [], kinds = {};
  for (const a of att) kinds[a.kind] = (kinds[a.kind] || 0) + 1;
  H[n.id] = {
    n: n.name ? n.name.split('.')[0] : '', sub: n.subnet || 'other', pri: n.pri, sev: n.sev, score: n.score || 0,
    os: n.os, ext: n.ext || 0, ev: n.ev, kinds,
    alerts: att.filter(a => a.kind === 'alert').map(a => ({ip: a.ip, first: a.first, sig: (a.signatures || [''])[0], blocked: (a.alerts_blocked || 0) > 0, out: a.out_ports || []})),
    vports: [...new Set(att.filter(a => a.kind === 'vuln').flatMap(a => a.vuln_ports || []))].sort((a, b) => a - b),
    inports: Object.entries(inports[n.id] || {}).sort((a, b) => b[1] - a[1]).slice(0, 4).map(e => +e[0]),
    times: att.filter(a => a.first).map(a => [a.kind[0], a.first]),
    find: (F.findings || []).slice(0, 4), nfind: (F.findings || []).length,
    peers: F.peers || [], hop2: F.hop2 || [], ot: F.ot_events_total || 0,
  };
}
for (const m of D.ioc_matches || []) {
  const url = (m.articles || [''])[0], slug = url.replace(/\/+$/, '').split('/').pop();
  for (const ip of m.hosts || []) (IOC[ip] = IOC[ip] || []).push({v: m.value, t: m.type, src: (m.sources || [''])[0], slug});
}
const zoneOf = ip => (H[ip] && H[ip].sub) || 'other';
const label = ip => (H[ip] && H[ip].n) || ip;

// subnets: name from the most common host-name prefixes; OT when any host has OT protocol events
const ZINFO = {};
for (const [ip, h] of Object.entries(H)) {
  const z = ZINFO[h.sub] = ZINFO[h.sub] || {id: h.sub, n: 0, pre: {}, ot: false};
  z.n++; if (h.ot) z.ot = true;
  const p = (h.n || '').replace(/[-_]?\d+[a-z]?$/i, '').replace(/[-_]$/, '');
  if (p) z.pre[p] = (z.pre[p] || 0) + 1;
}
const zname = z => { const p = Object.entries(z.pre).sort((a, b) => b[1] - a[1]).slice(0, 4).map(e => e[0]); return (z.ot ? 'OT · ' : '') + (p.length ? p.join(' · ') : 'unnamed hosts'); };

// what a host is worth to an attacker, from its name, the services others use on it, and OT activity
function role(ip) {
  const h = H[ip] || {}, n = h.n || '', ports = h.inports || [];
  if (h.ot || (ZINFO[zoneOf(ip)] || {}).ot) return {r: 'OT segment', v: 1};
  if (ports.includes(88) || ports.includes(389) || /^dc\d|^ad\d/.test(n)) return {r: 'directory (Kerberos/LDAP)', v: .95};
  if (/backup|veeam/.test(n)) return {r: 'backup server', v: .95};
  if (/^(db|sql|pg|mysql|ora)/.test(n) || ports.includes(5432) || ports.includes(1433) || ports.includes(3306)) return {r: 'database', v: .9};
  if (/git|jenkins|build|ci\d/.test(n)) return {r: 'source & build', v: .88};
  if (/^(fs|nas|file)/.test(n)) return {r: 'file server', v: .8};
  if (/vpn/.test(n)) return {r: 'VPN gateway', v: .8};
  if (/mail|exch/.test(n)) return {r: 'mail server', v: .7};
  if (ports.includes(53)) return {r: 'DNS resolver', v: .6};
  if (/^app/.test(n)) return {r: 'app server', v: .7};
  return {r: '', v: Math.max(.3, (h.score || 0) / 100 * .8)};
}
function campaign(slug) {
  const s = (slug || '').replace(/[-_]+/g, ' ');
  for (const [re, t] of [[/stylesmuggler/i, 'StyleSmuggler'], [/redflick/i, 'RedFlick'], [/antino/i, 'Antino'], [/rmm/i, 'RMM abuse'], [/linux/i, 'Linux campaign']]) if (re.test(s)) return t;
  return s.split(' ').slice(0, 3).join(' ');
}
// how a line starts: the strongest thing the internet did to the entry host
function entry(ip) {
  const h = H[ip], k = h.kinds, io = IOC[ip] || [], cand = [];
  const live = h.alerts.filter(a => !a.blocked);
  if (live.length) cand.push({w: 1, src: live[0].ip, how: 'IPS alert · not blocked', kind: 'alert', detail: live[0]});
  else if (h.alerts.length) cand.push({w: .5, src: h.alerts[0].ip, how: 'IPS alert · blocked', kind: 'alert', detail: h.alerts[0]});
  if (io.length) cand.push({w: .85, src: 'IOC · ' + io[0].v, how: io.length + ' indicator' + (io.length > 1 ? 's' : '') + ' · ' + campaign(io[0].slug), kind: 'ioc'});
  if (k.vuln) cand.push({w: h.find.some(f => f.exploit) ? .6 : .45, src: k.vuln + ' internet sources', how: 'reached vulnerable :' + h.vports.slice(0, 3).join(' :'), kind: 'vuln'});
  if (k.outbound) cand.push({w: .3, src: k.outbound + ' outside addresses', how: 'host called out', kind: 'outbound'});
  if (!cand.length) return null;
  cand.sort((a, b) => b.w - a.w);
  const e = cand[0];
  if (h.ev === 'likely') e.w = Math.max(e.w, .97);
  return e;
}

// every chain: internet -> entry -> pivot (-> second pivot)
const CHAINS = [];
for (const ip of Object.keys(H)) {
  const h = H[ip];
  if (!(h.ext > 0 || IOC[ip])) continue;
  const e = entry(ip); if (!e || e.w < .2) continue;
  for (const p of h.peers) {
    if (!(p.p >= .1) || !H[p.ip]) continue;
    CHAINS.push({e, hops: [ip, p.ip], ps: [p.p], risk: e.w * p.p * (.35 + .65 * role(p.ip).v), why: [p.why || []]});
    for (const t of h.hop2) {
      if (t.via !== p.ip || !(t.p >= .1) || !H[t.ip] || t.ip === ip) continue;
      CHAINS.push({e, hops: [ip, p.ip, t.ip], ps: [p.p, t.p], risk: e.w * t.p * (.35 + .65 * role(t.ip).v), why: [p.why || [], t.why || []]});
    }
  }
}
CHAINS.sort((a, b) => b.risk - a.risk);
if (!CHAINS.length) { openBtn.hidden = true; return; }
openBtn.hidden = false;
const TOTAL = CHAINS.reduce((s, c) => s + c.risk, 0);

// drawn lines: diverse entries and first pivots, then each extended to its best deeper target
const LINES = [];
const kindKey = ip => zoneOf(ip) + '|' + role(ip).r + '|' + label(ip).replace(/[\d.-]+$/, '');
for (const c of CHAINS) {
  if (LINES.length >= MAX_LINES) break;
  if (c.hops.length !== 2) continue;
  if (LINES.filter(l => l.hops[0] === c.hops[0]).length >= 3) continue;
  if (LINES.some(l => l.hops[0] === c.hops[0] && kindKey(l.hops[1]) === kindKey(c.hops[1]))) continue;
  LINES.push(c);
}
for (let i = 0; i < LINES.length; i++) {
  const l = LINES[i], used = new Set(LINES.flatMap(x => x.hops));
  const ext = CHAINS.find(c => c.hops.length === 3 && c.hops[0] === l.hops[0] && c.hops[1] === l.hops[1] && !used.has(c.hops[2]));
  if (ext && ext.risk >= .45 * l.risk) LINES[i] = Object.assign({}, ext, {risk: Math.max(ext.risk, l.risk)});
}
LINES.sort((a, b) => b.risk - a.risk).forEach((l, i) => { l.id = i; l.color = PAL[i % PAL.length]; });
const MAXR = LINES[0].risk;

// chokepoints across ALL scored chains, not only the drawn ones
const through = {};
for (const c of CHAINS) for (const ip of new Set(c.hops)) through[ip] = (through[ip] || 0) + c.risk;
const CHOKE = Object.entries(through).sort((a, b) => b[1] - a[1]).slice(0, 7).map(([ip, v]) => ({ip, v}));

const state = {sel: {type: 'line', id: 0}, cut: new Set(), hover: null, open: false, built: false};
const cutBy = c => c.hops.find(ip => state.cut.has(ip));

// ---------------------------------------------------------------- page skeleton
root.innerHTML = `<div class="ap-app">
  <header class="ap-top">${BRAND_LOGO.startsWith('data:image/') ? `<img class="ap-logo" src="${esc(BRAND_LOGO)}" alt="" aria-hidden="true">` : ''}<div class="ap-brand"><b>Attack <em>paths</em></b><span>${esc(BRAND)} · most likely ways in</span></div>
    <div class="ap-kpis" id="ap-kpis"></div>
    <div class="ap-seg" role="group" aria-label="View"><button type="button" data-view="flat" title="Flat network view (2)">Flat</button><button type="button" data-view="3d" title="3D network view (3)">3D</button><button type="button" class="on" aria-current="true" title="Attack paths (Esc to go back)">Attack paths</button><button type="button" data-view="timeline" title="Flows over time (I)" hidden>Timeline</button></div><span class="ap-qwrap"><button type="button" class="ap-qbtn" id="ap-about-toggle" aria-controls="ap-about" aria-expanded="false" aria-label="What am I looking at?" title="What am I looking at? (?)">?</button><p class="ap-about" id="ap-about" hidden>Each colored line is one likely way in, read left to right: an internet origin (◆), the entry host, then up to two pivots inside. Rows are subnets; line 1 is the most likely. Ranked estimates of where to look first, not confirmed compromise.</p></span></header>
  <div class="ap-brief" id="ap-brief"></div>
  <main class="ap-main">
    <section class="ap-col ap-lines"><h3>Most likely ways in</h3><div id="ap-lines"></div></section>
    <section class="ap-mapwrap" id="ap-mapwrap"><svg id="ap-map"></svg>
      <div class="ap-legend"><span><i style="width:18px;height:5px;border-radius:3px;background:var(--ap-crit)"></i>attack line</span><span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="6" fill="var(--ap-card)" stroke="var(--ap-ink)" stroke-width="2.4"/></svg>host · capsule = shared by lines</span><span><svg width="14" height="14"><path d="M7 1 13 7 7 13 1 7Z" fill="var(--ap-ink)"/></svg>internet origin</span><span>dots per row: every host in the subnet, by priority</span></div>
    </section>
    <section class="ap-col ap-detail" id="ap-detail"></section>
  </main>
  <footer class="ap-foot">
    <div class="ap-contain"><div class="ap-hd"><h3>Simulate fixes</h3><span class="ap-sub">what-if only, nothing on the network changes. Assumes the host is fully fixed or isolated, so no path can pass through it</span></div>
      <div class="ap-meter"><div class="ap-big" id="ap-mbig">100%</div><div class="ap-track"><i id="ap-mbar" style="width:100%"></i></div><div class="ap-cap" id="ap-mcap"></div></div>
      <div class="ap-chips" id="ap-chips"></div></div>
    <div class="ap-timeline"><div class="ap-hd"><h3>When the internet touched the entry hosts</h3><span class="ap-sub" id="ap-tlsub"></span></div><svg id="ap-tl" height="112"></svg></div>
  </footer></div>`;

// the short explanation under the heading opens for 20 s when this view opens, then folds back into the ?
let aboutTimer = 0;
function setAbout(o) { clearTimeout(aboutTimer); q('about').hidden = !o; q('about-toggle').setAttribute('aria-expanded', String(o)); if (o) aboutTimer = setTimeout(() => setAbout(false), 20000); }
function toggleAbout() { setAbout(q('about').hidden); }
q('about-toggle').onclick = toggleAbout;
q('about').addEventListener('mouseenter', () => clearTimeout(aboutTimer));
q('about').addEventListener('mouseleave', () => { clearTimeout(aboutTimer); aboutTimer = setTimeout(() => setAbout(false), 3000); });

// ---------------------------------------------------------------- header and brief
function shortFind(ip) { const f = H[ip].find[0]; return f ? f.name.replace(/\s*\(.*?\)\s*/g, ' ').replace(/ Multiple Vulnerabilities.*/, '').split(/ < | Remote| Path| Request/)[0].trim() : ''; }
function header() {
  const p1 = Object.values(H).filter(h => h.pri === 'P1').length, c = D.counts || {};
  q('kpis').innerHTML = [[c.hosts, 'hosts'], [p1, 'P1 hosts', 'red'], [Object.keys(IOC).length, 'hosts with IOCs', 'red'], [CHAINS.length, 'paths scored']]
    .map(([b, s, k]) => `<div class="ap-kpi ${k || ''}"><b>${esc(b)}</b><span>${s}</span></div>`).join('');
  const l = LINES[0], a = l.hops[0], f = H[a].find[0] || {}, rest = l.hops.slice(1), r = role(rest.at(-1)).r;
  q('brief').innerHTML = `<span class="ap-tag">Line 1</span><span>The most likely breach starts at <em class="mono">${esc(l.e.src)}</em> (${esc(l.e.how)}), lands on <em>${esc(label(a))}</em>${f.name ? ` through <em>${esc(shortFind(a))}</em>${f.cves && f.cves[0] ? ' (' + esc(f.cves[0]) + ')' : ''}` : ''}, then moves ${rest.map(ip => `to <em>${esc(label(ip))}</em>`).join(' and on ')}${r ? ', a ' + esc(r) : ''}. Fixing <em>${esc(label(CHOKE[0].ip))}</em> alone would remove ${Math.round(CHOKE[0].v / TOTAL * 100)}% of all scored path risk.</span>`;
}

// ---------------------------------------------------------------- left: the lines
function renderLines() {
  q('lines').innerHTML = LINES.map(l => {
    const c = cutBy(l), sel = state.sel.type === 'line' && state.sel.id === l.id, r = role(l.hops.at(-1)).r;
    return `<div class="ap-lcard ${sel ? 'sel' : ''} ${c ? 'cut' : ''}" data-line="${l.id}" tabindex="0">
      <div class="ap-lbadge" style="background:${c ? 'var(--ap-cut)' : l.color}">${l.id + 1}</div>
      <div><div class="t">${l.hops.map(label).map(esc).join(' → ')}</div>
      <div class="s">${esc(l.e.how)}${r ? ' · ends at ' + esc(r) : ''}</div>
      <div class="ap-rbar"><i style="width:${Math.round(l.risk / MAXR * 100)}%;background:${c ? 'var(--ap-cut)' : l.color}"></i></div>
      ${c ? `<div class="ap-cutnote">cut by simulated fix on ${esc(label(c))}</div>` : ''}</div></div>`;
  }).join('') + `<div class="ap-note">Lines are ranked by entry evidence × reach estimate × what the last host is worth. ${CHAINS.length} internet-to-target paths were scored; the top ${LINES.length} distinct ones are drawn. Reach estimates rank where to look; they are not compromise probabilities.</div>`;
  q('lines').querySelectorAll('.ap-lcard').forEach(el => {
    el.onclick = () => select({type: 'line', id: +el.dataset.line});
    el.onkeydown = e => { if (e.key === 'Enter') el.click(); };
    el.onmouseenter = () => hot({line: +el.dataset.line}); el.onmouseleave = () => hot(null);
  });
}

// ---------------------------------------------------------------- center: the transit map
let GEO = null;
const LANE = 7.5, GAP = 46;
function layout(W) {
  const COLS = [{t: 'Internet', s: 'origin'}, {t: 'Entry', s: 'reachable from outside'}, {t: 'First pivot', s: 'reached from entry'}, {t: 'Second pivot', s: 'two hops in'}];
  const right = 170, c0 = 310;
  const colX = [c0, c0 + (W - c0 - right) * .30, c0 + (W - c0 - right) * .64, W - right];
  const depth = {}, at = {};
  for (const l of LINES) l.hops.forEach((ip, i) => { depth[ip] = Math.min(depth[ip] ?? 9, i + 1); (at[ip] = at[ip] || []).push(l.id); });
  const cells = {};
  for (const ip of Object.keys(depth)) { const k = zoneOf(ip) + '|' + depth[ip]; (cells[k] = cells[k] || []).push(ip); }
  for (const k in cells) cells[k].sort((a, b) => Math.min(...at[a]) - Math.min(...at[b]));
  // rows: subnets that carry a line, in address order; quiet subnets fold into one row
  const busy = [...new Set(Object.keys(depth).map(zoneOf))];
  const cmp = (a, b) => a.localeCompare(b, undefined, {numeric: true});
  busy.sort(cmp);
  const quiet = Object.keys(ZINFO).filter(z => !busy.includes(z)).sort(cmp);
  let y = 58; const rows = [];
  for (const z of busy) {
    let need = 0;
    for (let d = 1; d <= 3; d++) need = Math.max(need, (cells[z + '|' + d] || []).reduce((s, ip) => s + at[ip].length * LANE + GAP, 0));
    const h = Math.max(72, need + 24); rows.push({z, y, h}); y += h;
  }
  if (quiet.length) { rows.push({quiet, y, h: 34}); y += 34; }
  const pos = {};
  for (const r of rows) if (r.z) for (let d = 1; d <= 3; d++) {
    const c = cells[r.z + '|' + d] || []; if (!c.length) continue;
    const tot = c.reduce((s, ip) => s + at[ip].length * LANE + GAP, 0) - GAP;
    let yy = r.y + (r.h - tot) / 2;
    for (const ip of c) { const hh = at[ip].length * LANE; pos[ip] = {x: colX[d], y: yy + hh / 2, h: hh, lines: at[ip]}; yy += hh + GAP; }
  }
  const origins = {};
  for (const l of LINES) {
    const k = l.e.src + '|' + l.hops[0];
    if (!origins[k]) origins[k] = {k, src: l.e.src, how: l.e.how, kind: l.e.kind, entry: l.hops[0], lines: []};
    origins[k].lines.push(l.id); l.okey = k;
  }
  const byEntry = {};
  Object.values(origins).forEach(o => (byEntry[o.entry] = byEntry[o.entry] || []).push(o));
  for (const e in byEntry) byEntry[e].forEach((o, i, arr) => { const p = pos[e]; o.x = colX[0]; o.y = p.y + (i - (arr.length - 1) / 2) * Math.max(36, p.h / arr.length); o.h = o.lines.length * LANE; });
  return {W, H: y + 20, colX, COLS, rows, pos, origins, at};
}
function rounded(pts, r) {
  pts = pts.filter((p, i) => i === 0 || Math.hypot(p[0] - pts[i - 1][0], p[1] - pts[i - 1][1]) > .5);
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], [x2, y2] = pts[i + 1];
    const l1 = Math.hypot(x1 - x0, y1 - y0), l2 = Math.hypot(x2 - x1, y2 - y1), rr = Math.min(r, l1 / 2, l2 / 2);
    const a = [x1 - (x1 - x0) / l1 * rr, y1 - (y1 - y0) / l1 * rr], b = [x1 + (x2 - x1) / l2 * rr, y1 + (y2 - y1) / l2 * rr];
    d += ` L${a[0].toFixed(1)},${a[1].toFixed(1)} Q${x1},${y1} ${b[0].toFixed(1)},${b[1].toFixed(1)}`;
  }
  const z = pts.at(-1); return d + ` L${z[0]},${z[1]}`;
}
function seg(x1, y1, x2, y2, k) {
  // octilinear: horizontal, 45-degree run, horizontal; k shifts the bend so parallel lanes stay parallel
  const dx = x2 - x1, dy = y2 - y1, ady = Math.abs(dy);
  if (dx > ady + 24) { const xm = x1 + (dx - ady) * .55 + k; return [[x1, y1], [xm, y1], [xm + ady, y2], [x2, y2]]; }
  if (dx > 20) { const s = 16; return [[x1, y1], [x1 + s, y1], [x1 + s + (dx - 2 * s) / 2, y1 + dy / 2], [x2 - s, y2], [x2, y2]]; }
  return [[x1, y1], [x1 + 40, y1], [x1 + 40, y2], [x2, y2]];
}
function laneY(p, lid) { return p.y + (p.lines.indexOf(lid) - (p.lines.length - 1) / 2) * LANE; }
function linePts(l) {
  const o = GEO.origins[l.okey], oy = o.y + (o.lines.indexOf(l.id) - (o.lines.length - 1) / 2) * LANE;
  const pts = [[o.x, oy]]; let prev = [o.x + 8, oy];
  for (const ip of l.hops) {
    const p = GEO.pos[ip], y = laneY(p, l.id), dir = y > prev[1] ? 1 : -1;
    const k = -(p.lines.indexOf(l.id) - (p.lines.length - 1) / 2) * LANE * .41 * dir;
    const s = seg(prev[0], prev[1], p.x - 7, y, k); s.shift(); pts.push(...s, [p.x + 7, y]);
    prev = [p.x + 7, y];
  }
  return pts;
}
function el(tag, attrs, parent, text) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text != null) e.textContent = text;
  if (parent) parent.appendChild(e); return e;
}
const priC = p => p === 'P1' ? 'var(--ap-crit)' : p === 'P2' ? 'var(--ap-high)' : p === 'P3' ? 'var(--ap-med)' : 'var(--ap-none)';
function renderMap() {
  const W = Math.max(860, q('mapwrap').clientWidth);
  GEO = layout(W);
  const svg = q('map'); svg.innerHTML = '';
  svg.setAttribute('width', W); svg.setAttribute('height', GEO.H); svg.setAttribute('viewBox', `0 0 ${W} ${GEO.H}`);
  const g0 = el('g', {}, svg);
  GEO.rows.forEach((r, i) => {
    el('rect', {x: 0, y: r.y, width: W, height: r.h, fill: i % 2 ? 'var(--ap-band2)' : 'var(--ap-band)'}, g0);
    el('line', {x1: 0, x2: W, y1: r.y, y2: r.y, stroke: 'var(--ap-rule)'}, g0);
    if (r.quiet) {
      el('text', {x: 16, y: r.y + 21, 'font-size': 12, 'font-weight': 700, fill: 'var(--ap-ink)'}, g0, 'Other subnets');
      const n = r.quiet.reduce((s, z) => s + ZINFO[z].n, 0);
      el('text', {x: 120, y: r.y + 21, 'font-size': 10.5, fill: 'var(--ap-ink3)'}, g0,
        `${r.quiet.length} subnet${r.quiet.length > 1 ? 's' : ''}, ${n} host${n > 1 ? 's' : ''}, no drawn line: ` + r.quiet.slice(0, 6).map(z => z.replace('/24', '') + ' (' + ZINFO[z].n + ')').join(', ') + (r.quiet.length > 6 ? ', …' : ''));
      return;
    }
    const z = ZINFO[r.z] || {id: r.z, pre: {}, n: 0};
    el('text', {x: 16, y: r.y + 22, 'font-size': 12, 'font-weight': 700, fill: 'var(--ap-ink)', class: 'mono'}, g0, r.z);
    const nm = zname(z);
    el('text', {x: 16, y: r.y + 36, 'font-size': 10.5, fill: 'var(--ap-ink3)'}, g0, nm.length > 34 ? nm.slice(0, 33) + '…' : nm);
    // population: one dot per host, colored by priority
    const hs = Object.values(H).filter(h => h.sub === r.z).sort((a, b) => b.score - a.score);
    const per = 18, rowsMax = Math.max(1, Math.floor((r.h - 52) / 6.2));
    hs.slice(0, per * rowsMax).forEach((h, j) => el('circle', {cx: 18 + (j % per) * 6.2, cy: r.y + 47 + Math.floor(j / per) * 6.2, r: 2.2, fill: priC(h.pri)}, g0));
    if (hs.length > per * rowsMax) el('text', {x: 18 + per * 6.2, y: r.y + 50 + (rowsMax - 1) * 6.2, 'font-size': 9.5, fill: 'var(--ap-ink3)'}, g0, '+' + (hs.length - per * rowsMax));
  });
  el('line', {x1: 0, x2: W, y1: GEO.H - 20, y2: GEO.H - 20, stroke: 'var(--ap-rule)'}, g0);
  GEO.COLS.forEach((c, i) => {
    const x = GEO.colX[i];
    el('line', {x1: x, x2: x, y1: 46, y2: GEO.H - 20, stroke: 'var(--ap-rule)', 'stroke-dasharray': '2 5'}, g0);
    el('text', {x, y: 22, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 800, 'letter-spacing': '.12em', fill: 'var(--ap-ink)'}, g0, c.t.toUpperCase());
    el('text', {x, y: 37, 'text-anchor': 'middle', 'font-size': 10.5, fill: 'var(--ap-ink3)'}, g0, c.s);
  });
  const gl = el('g', {}, svg), sid = state.sel.type === 'line' ? state.sel.id : -1;
  for (const l of LINES.slice().reverse().sort((a, b) => (a.id === sid) - (b.id === sid))) {
    const c = cutBy(l), d = rounded(linePts(l), 14);
    const g = el('g', {class: 'ap-ln', 'data-line': l.id}, gl);
    el('path', {d, fill: 'none', stroke: 'var(--ap-halo)', 'stroke-width': 8.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round'}, g);
    el('path', {d, fill: 'none', id: 'ap-lp' + l.id, stroke: c ? 'var(--ap-cut)' : l.color, 'stroke-width': l.id === sid ? 6.5 : 5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-dasharray': c ? '2 7' : 'none', opacity: c ? .7 : 1}, g);
    g.onclick = () => select({type: 'line', id: l.id}); g.onmouseenter = () => hot({line: l.id}); g.onmouseleave = () => hot(null);
  }
  const gs = el('g', {}, svg);
  for (const o of Object.values(GEO.origins)) {
    const g = el('g', {class: 'ap-stn', 'data-lines': o.lines.join(',')}, gs), hh = Math.max(14, o.h + 6), loud = o.kind === 'alert' || o.kind === 'ioc';
    el('path', {d: `M${o.x} ${o.y - hh / 2 - 3} L${o.x + 9} ${o.y} L${o.x} ${o.y + hh / 2 + 3} L${o.x - 9} ${o.y}Z`, fill: 'var(--ap-ink)'}, g);
    el('text', {x: o.x - 16, y: o.y - 2, 'text-anchor': 'end', 'font-size': 11.5, 'font-weight': 700, fill: 'var(--ap-ink)', class: 'ap-lbl' + (o.kind === 'alert' ? ' mono' : '')}, g, o.src.length > 28 ? o.src.slice(0, 27) + '…' : o.src);
    el('text', {x: o.x - 16, y: o.y + 12, 'text-anchor': 'end', 'font-size': 10, fill: loud ? 'var(--ap-crit)' : 'var(--ap-ink2)', 'font-weight': loud ? 700 : 400, class: 'ap-lbl'}, g, o.how.length > 34 ? o.how.slice(0, 33) + '…' : o.how);
    g.onclick = () => select({type: 'host', ip: o.entry});
  }
  for (const [ip, p] of Object.entries(GEO.pos)) {
    const h = H[ip], cut = state.cut.has(ip), hh = Math.max(14, p.h + 6), pc = priC(h.pri);
    const g = el('g', {class: 'ap-stn', 'data-lines': p.lines.join(',')}, gs);
    if (state.sel.type === 'host' && state.sel.ip === ip) el('rect', {x: p.x - 13, y: p.y - hh / 2 - 6, width: 26, height: hh + 12, rx: 13, fill: 'none', stroke: 'var(--ap-ink)', 'stroke-width': 1.5, 'stroke-dasharray': '3 3'}, g);
    el('rect', {x: p.x - 8, y: p.y - hh / 2, width: 16, height: hh, rx: 8, fill: 'var(--ap-card)', stroke: cut ? 'var(--ap-crit)' : 'var(--ap-ink)', 'stroke-width': 2.6}, g);
    if (cut) el('path', {d: `M${p.x - 11} ${p.y - hh / 2 - 4} L${p.x + 11} ${p.y + hh / 2 + 4}`, stroke: 'var(--ap-crit)', 'stroke-width': 3.2, 'stroke-linecap': 'round'}, g);
    el('circle', {cx: p.x, cy: p.y, r: 3.2, fill: pc}, g);
    const lx = p.x - 7, t = el('text', {x: lx, y: p.y - hh / 2 - 6, 'font-size': 12.5, 'font-weight': 800, fill: 'var(--ap-ink)', class: 'ap-lbl'}, g, label(ip));
    el('text', {x: lx, y: p.y + hh / 2 + 13, 'font-size': 10, fill: 'var(--ap-ink2)', class: 'ap-lbl'}, g, [h.n ? ip : '', role(ip).r].filter(Boolean).join(' · '));
    if (h.pri) el('text', {x: lx + t.getComputedTextLength() + 6, y: p.y - hh / 2 - 6, 'font-size': 9.5, 'font-weight': 800, fill: pc, class: 'ap-lbl'}, g, h.pri + (IOC[ip] ? ' · IOC' : ''));
    g.onclick = () => select({type: 'host', ip}); g.onmouseenter = () => hot({ip}); g.onmouseleave = () => hot(null);
  }
  el('g', {id: 'ap-train'}, svg);
  hot(state.hover);
}
function hot(h) {
  state.hover = h;
  const svg = q('map'); if (!GEO) return;
  const on = id => !!h && (h.line === id || (h.ip && (GEO.at[h.ip] || []).includes(id)));
  svg.classList.toggle('ap-dim', !!h);
  svg.querySelectorAll('.ap-ln').forEach(g => g.classList.toggle('hot', on(+g.dataset.line)));
  svg.querySelectorAll('.ap-stn').forEach(g => g.classList.toggle('hot', g.dataset.lines.split(',').map(Number).some(on)));
}

// ---------------------------------------------------------------- right: detail
function select(s) { state.sel = s; stopTrain(); renderLines(); renderMap(); renderDetail(); renderTimeline(); }
const pill = h => h.pri ? `<span class="ap-pill" style="background:${priC(h.pri)}">${h.pri}</span>` : '';
const ipSpan = ip => `<span class="mono" style="font-weight:400;color:var(--ap-ink3);font-size:11px">${esc(ip)}</span>`;
function renderDetail() {
  const box = q('detail');
  if (state.sel.type === 'line') {
    const l = LINES[state.sel.id], c = cutBy(l), a = l.hops[0], f = H[a].find[0], al = l.e.detail;
    const steps = [{k: 'Internet origin', h: esc(l.e.src), body: `<div class="ap-mut">${esc(l.e.how)}</div>` +
      (al ? `<ul><li>${esc(al.sig)}</li>${al.first ? `<li>first contact ${esc(al.first.replace('T', ' ').replace('Z', ' UTC'))}</li>` : ''}${al.out.length ? `<li>host connected back out on :${al.out.join(' :')}</li>` : ''}</ul>` : '') +
      ((IOC[a] || []).length ? `<ul>${IOC[a].slice(0, 3).map(i => `<li><span class="mono">${esc(i.v)}</span> · ${esc(campaign(i.slug))} (${esc(i.src)})</li>`).join('')}</ul>` : '')}];
    steps.push({k: 'Entry', ip: a, p: l.e.w, h: `${esc(label(a))} ${ipSpan(a)}`,
      body: f ? `<div class="ap-fx"><b>${esc(f.name)}</b>${f.cvss ? ` · CVSS ${f.cvss}` : ''}${f.cves && f.cves.length ? ' · ' + esc(f.cves.slice(0, 3).join(', ')) : ''}${f.exploit ? ' · <b style="color:var(--ap-crit)">exploit available</b>' : ''}</div><ul>${(f.evidence || []).slice(0, 2).map(e => `<li>${esc(e.t)}</li>`).join('')}</ul>` : ''});
    l.hops.slice(1).forEach((ip, i) => {
      const r = role(ip).r;
      steps.push({k: i ? 'Second pivot' : 'First pivot', ip, p: l.ps[i], h: `${esc(label(ip))} ${ipSpan(ip)}${r ? ` <span class="ap-mut" style="font-weight:400">· ${esc(r)}</span>` : ''}`,
        body: `<ul>${(l.why[i] || []).slice(0, 4).map(t => `<li>${esc(t)}</li>`).join('')}</ul>`});
    });
    box.innerHTML = `<div class="ap-dhead"><div class="ap-lbadge big" style="background:${c ? 'var(--ap-cut)' : l.color}">${l.id + 1}</div>
      <div><div class="t">${l.hops.map(label).map(esc).join(' → ')}</div><div class="s">path score ${(l.risk * 100).toFixed(0)} · #${l.id + 1} of ${CHAINS.length} scored paths${c ? ` · <b style="color:var(--ap-crit)">cut by simulated fix on ${esc(label(c))}</b>` : ''}</div></div></div>
      <div class="ap-btnrow"><button class="ap-btn" type="button" id="ap-replay">▶ Walk the line</button>${l.hops.slice(0, 2).map(ip => `<button type="button" class="ap-btn ${state.cut.has(ip) ? 'ghost' : 'danger'}" data-cut="${ip}" title="What-if: assumes the host is fully fixed or isolated, so no scored path can pass through it. Patching one CVE may cut fewer paths.">${state.cut.has(ip) ? 'Undo fix on' : 'Simulate fix on'} ${esc(label(ip))}</button>`).join('')}</div>
      <div class="ap-steps" style="--lc:${c ? 'var(--ap-cut)' : l.color}">${steps.map((s, i) => `<div class="ap-step"><div class="dot">${i ? i : '◆'}</div><div class="k">${s.k}${s.p != null ? `<span class="p">${s.k === 'Entry' ? 'entry evidence' : 'reach'} ${s.p.toFixed(2)}</span>` : ''}</div><div class="h" ${s.ip ? `data-host="${s.ip}"` : ''}>${s.h}</div>${s.body}</div>`).join('')}</div>
      <div class="ap-note">Entry evidence comes from IPS/IDS alerts, IOC matches and scanned exposure. Reach is the Explorer's traffic-based estimate of how likely the next host falls if this one is exploited. Both rank where to look; neither confirms a compromise.</div>`;
    q('replay').onclick = () => walk(l);
  } else {
    const ip = state.sel.ip, h = H[ip], r = role(ip).r, ls = LINES.filter(l => l.hops.includes(ip)), k = h.kinds;
    box.innerHTML = `<div class="ap-dhead"><div><div class="t">${esc(label(ip))} ${pill(h)}</div><div class="s"><span class="mono">${esc(ip)}</span> · ${esc(h.sub)}${r ? ' · ' + esc(r) : ''}</div></div></div>
      <div class="ap-btnrow"><button type="button" class="ap-btn" data-open="${ip}">Open in Explorer</button><button type="button" class="ap-btn ${state.cut.has(ip) ? 'ghost' : 'danger'}" data-cut="${ip}" title="What-if: assumes the host is fully fixed or isolated, so no scored path can pass through it. Patching one CVE may cut fewer paths.">${state.cut.has(ip) ? 'Undo simulated fix' : 'Simulate fix'}</button><span class="ap-mut" style="align-self:center">would remove ${Math.round((through[ip] || 0) / TOTAL * 100)}% of path risk</span></div>
      <dl class="ap-kv"><dt>Score</dt><dd>${h.score || '—'} ${h.sev ? '· ' + esc(h.sev) : ''}</dd><dt>OS</dt><dd>${esc(h.os || 'not scanned')}</dd>
      <dt>Internet</dt><dd>${[k.alert ? `<b style="color:var(--ap-crit)">${k.alert} alerting</b>` : '', k.vuln ? k.vuln + ' hit a vulnerable port' : '', k.outbound ? k.outbound + ' contacted by host' : '', k.blocked ? k.blocked + ' blocked' : ''].filter(Boolean).join(' · ') || 'none observed'}</dd>
      <dt>Lines</dt><dd>${ls.length ? ls.map(l => `<span class="ap-pill" style="background:${l.color};cursor:pointer" data-line="${l.id}">${l.id + 1}</span>`).join(' ') : 'none drawn'}</dd></dl>
      ${(IOC[ip] || []).length ? `<h3>Indicator matches</h3>${IOC[ip].slice(0, 6).map(i => `<div class="ap-ioc"><code>${esc(i.v)}</code> · ${esc(i.t)} · ${esc(campaign(i.slug))}</div>`).join('')}` : ''}
      <h3>Top findings (${h.nfind})</h3>${h.find.map(f => `<div class="ap-find" style="--sevc:${SEVC[f.sev] || 'var(--ap-none)'}"><b>${esc(f.name)}</b><div class="m">${esc(f.sev)}${f.cvss ? ' · CVSS ' + f.cvss : ''}${f.port ? ' · :' + f.port : ''}${f.cves && f.cves.length ? ' · ' + esc(f.cves.slice(0, 3).join(', ')) : ''}</div>${f.exposure ? `<div class="m" style="color:var(--ap-ink)">${esc(f.exposure)}</div>` : ''}</div>`).join('') || '<div class="ap-mut">No scan findings for this host.</div>'}
      <h3>Who it can reach next</h3>${h.peers.slice(0, 5).map(p => `<div class="ap-ioc" style="cursor:pointer" data-host="${p.ip}"><b style="color:var(--ap-ink)">${(p.p || 0).toFixed(2)}</b> · ${esc(label(p.ip))} <span class="mono">:${esc((p.ports_out || []).slice(0, 4).join(' :'))}</span></div>`).join('') || '<div class="ap-mut">No internal peers observed.</div>'}`;
  }
  box.querySelectorAll('[data-cut]').forEach(b => b.onclick = () => toggleCut(b.dataset.cut));
  box.querySelectorAll('[data-open]').forEach(b => b.onclick = () => openInExplorer(b.dataset.open));
  box.querySelectorAll('[data-host]').forEach(b => b.onclick = () => H[b.dataset.host] && select({type: 'host', ip: b.dataset.host}));
  box.querySelectorAll('.ap-pill[data-line]').forEach(b => b.onclick = () => select({type: 'line', id: +b.dataset.line}));
}

// ---------------------------------------------------------------- walk the line (user-started only)
let RAF = 0;
function stopTrain() { cancelAnimationFrame(RAF); const t = q('train'); if (t) t.innerHTML = ''; }
function walk(l) {
  stopTrain();
  const path = q('lp' + l.id); if (!path) return;
  const len = path.getTotalLength(), xs = [GEO.origins[l.okey].x, ...l.hops.map(ip => GEO.pos[ip].x)];
  const stops = xs.map(x => { let lo = 0, hi = len; for (let i = 0; i < 30; i++) { const m = (lo + hi) / 2; if (path.getPointAtLength(m).x < x) lo = m; else hi = m; } return lo; });
  const train = q('train'), ring = el('circle', {r: 12, fill: 'none', stroke: l.color, 'stroke-width': 3, opacity: .5}, train);
  const dot = el('circle', {r: 7.5, fill: '#fff', stroke: l.color, 'stroke-width': 4}, train);
  hot({line: l.id});
  const T = 1100, start = performance.now(), n = stops.length, steps = [...q('detail').querySelectorAll('.ap-step')];
  const tick = now => {
    const t = Math.max(0, (now - start) / T), i = Math.min(n - 1, Math.floor(t)), f = Math.min(1, t - i);
    const ease = f < .5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2;
    const p = path.getPointAtLength(i >= n - 1 ? stops[n - 1] : stops[i] + (stops[i + 1] - stops[i]) * ease);
    for (const c of [dot, ring]) { c.setAttribute('cx', p.x); c.setAttribute('cy', p.y); }
    ring.setAttribute('r', 10 + 6 * Math.abs(Math.sin(now / 220)));
    const lit = i + (f > .85 ? 1 : 0);
    steps.forEach((s, j) => s.classList.toggle('lit', j <= lit));
    if (t < n - .2) RAF = requestAnimationFrame(tick); else { steps.forEach(s => s.classList.add('lit')); setTimeout(() => hot(null), 900); }
  };
  RAF = requestAnimationFrame(tick);
}

// ---------------------------------------------------------------- bottom: simulated fixes (what-if only) and timeline
function toggleCut(ip) { state.cut.has(ip) ? state.cut.delete(ip) : state.cut.add(ip); renderContain(); renderLines(); renderMap(); renderDetail(); }
function renderContain() {
  const left = CHAINS.reduce((s, c) => s + (cutBy(c) ? 0 : c.risk), 0), pct = Math.round(left / TOTAL * 100);
  q('mbig').textContent = pct + '%'; q('mbar').style.width = pct + '%';
  q('mcap').textContent = state.cut.size ? `of path risk remains with simulated fixes on ${state.cut.size} host${state.cut.size > 1 ? 's' : ''} · ${LINES.filter(cutBy).length} of ${LINES.length} lines cut` : 'of scored path risk is live. Fixing these hosts would cut the most paths:';
  q('chips').innerHTML = CHOKE.map(c => `<button type="button" class="ap-chip ${state.cut.has(c.ip) ? 'on' : ''}" data-ip="${c.ip}" title="Simulate a fix on this host (what-if; assumes it is fully fixed or isolated)"><span class="box">${state.cut.has(c.ip) ? '✕' : ''}</span><span><b>${esc(label(c.ip))}</b><small>${esc(role(c.ip).r || H[c.ip].pri || c.ip)}</small></span><span class="pct">−${Math.round(c.v / TOTAL * 100)}%</span></button>`).join('');
  q('chips').querySelectorAll('.ap-chip').forEach(b => { b.onclick = () => toggleCut(b.dataset.ip); b.onmouseenter = () => hot({ip: b.dataset.ip}); b.onmouseleave = () => hot(null); });
}
function renderTimeline() {
  const svg = q('tl'), W = svg.clientWidth || 600, Hh = 112; svg.setAttribute('viewBox', `0 0 ${W} ${Hh}`); svg.innerHTML = '';
  const w = D.window || [], t0 = new Date(w[0]).getTime(), t1 = new Date(w[1]).getTime();
  if (!(t1 > t0)) { q('tlsub').textContent = 'no time window in this run'; return; }
  const BIN = Math.max(3600e3, Math.ceil((t1 - t0) / 56 / 3600e3) * 3600e3), nb = Math.ceil((t1 - t0) / BIN), bins = Array.from({length: nb}, () => ({v: 0, b: 0, o: 0}));
  const entries = new Set(CHAINS.map(c => c.hops[0])); let tot = 0;
  for (const ip of entries) for (const [k, ts] of H[ip].times) { const i = Math.floor((new Date(ts) - t0) / BIN); if (i >= 0 && i < nb && bins[i][k] != null) { bins[i][k]++; tot++; } }
  const max = Math.max(1, ...bins.map(b => b.v + b.b + b.o));
  const x = t => 8 + (t - t0) / (t1 - t0) * (W - 16), base = 78, bh = 58, bw = Math.max(2, (W - 16) / nb - 1.5);
  bins.forEach((b, i) => { let y = base; for (const k of ['b', 'v', 'o']) { const h = b[k] / max * bh; if (h > 0) { el('rect', {x: x(t0 + i * BIN), y: y - h, width: bw, height: h, fill: `var(--ap-bar-${k})`}, svg); y -= h; } } });
  el('line', {x1: 8, x2: W - 8, y1: base, y2: base, stroke: 'var(--ap-ink)', 'stroke-width': 1.2}, svg);
  const step = (t1 - t0) > 20 * 864e5 ? 7 * 864e5 : 864e5;
  for (let t = Math.ceil(t0 / 864e5) * 864e5; t < t1; t += step) {
    if (x(t) > W - 44) continue;
    el('line', {x1: x(t), x2: x(t), y1: base, y2: base + 5, stroke: 'var(--ap-ink)'}, svg);
    el('text', {x: x(t) + 3, y: base + 16, 'font-size': 10, fill: 'var(--ap-ink2)'}, svg, new Date(t).toLocaleDateString('en-US', {month: 'short', day: 'numeric', timeZone: 'UTC'}));
  }
  const sel = state.sel.type === 'line' ? state.sel.id : -1, seen = new Set();
  for (const l of LINES) {
    const a = l.e.detail; if (!a || !a.first || seen.has(a.ip + a.first)) continue; seen.add(a.ip + a.first);
    const xx = x(new Date(a.first).getTime()), on = sel === l.id;
    el('line', {x1: xx, x2: xx, y1: 8, y2: base, stroke: l.color, 'stroke-width': on ? 2.5 : 1.5, 'stroke-dasharray': on ? 'none' : '3 3'}, svg);
    el('circle', {cx: xx, cy: 12, r: on ? 8 : 7, fill: l.color, stroke: 'var(--ap-paper)', 'stroke-width': 2}, svg);
    el('text', {x: xx, y: 15.5, 'text-anchor': 'middle', 'font-size': 9.5, 'font-weight': 800, fill: '#fff'}, svg, l.id + 1);
    el('text', {x: xx + 12, y: 16, 'font-size': 10.5, 'font-weight': 700, fill: 'var(--ap-ink)', class: 'ap-lbl'}, svg, label(l.hops[0]) + ' alert');
  }
  let lx = W - 8;
  for (const [k, t] of [['o', 'host called out'], ['v', 'hit vulnerable port'], ['b', 'blocked']]) {
    const tx = el('text', {x: lx, y: Hh - 4, 'text-anchor': 'end', 'font-size': 10, fill: 'var(--ap-ink2)'}, svg, t);
    lx -= tx.getComputedTextLength() + 4; el('rect', {x: lx - 9, y: Hh - 12, width: 9, height: 9, fill: `var(--ap-bar-${k})`}, svg); lx -= 22;
  }
  q('tlsub').textContent = `${tot.toLocaleString()} first contacts on ${entries.size} entry hosts · ${BIN / 3600e3}-hour bins (UTC)`;
}

// ---------------------------------------------------------------- open and close (colors follow the Múcaro theme on <html>)
function render() { header(); renderLines(); renderMap(); renderDetail(); renderContain(); renderTimeline(); }
function open() {
  if (window.VFTimeline) window.VFTimeline.close();
  state.open = true; root.hidden = false; openBtn.setAttribute('aria-expanded', 'true');
  render(); setAbout(true);
  if (!/[?&#]paths\b/.test(location.hash)) history.replaceState(null, '', '#paths');
  if (window.VFExplorer) window.VFExplorer.markSeg();
}
function close() {
  state.open = false; stopTrain(); root.hidden = true; openBtn.setAttribute('aria-expanded', 'false');
  if (/[?&#]paths\b/.test(location.hash)) history.replaceState(null, '', location.pathname + location.search);
  if (window.VFExplorer) window.VFExplorer.markSeg();
}
function showView(v) { close(); if (v === 'timeline') { if (window.VFTimeline) window.VFTimeline.open(); } else if (window.VFExplorer) window.VFExplorer.set3d(v === '3d'); }
function openInExplorer(ip) { close(); if (window.VFExplorer) window.VFExplorer.focus(ip); }
openBtn.onclick = () => { if (!state.open) open(); };
root.querySelectorAll('.ap-seg [data-view]').forEach(b => { b.onclick = () => showView(b.dataset.view); if (b.dataset.view === '3d' && !(window.VFExplorer && window.VFExplorer.can3d)) b.hidden = true; });
// while open, keys belong to this view so the network view underneath does not react
addEventListener('keydown', e => {
  if (!state.open) { if ((e.key === 'p' || e.key === 'P') && !e.metaKey && !e.ctrlKey && e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA' && !e.target.closest('#analyst-chat')) open(); return; }
  if (e.target.closest && e.target.closest('#analyst-chat')) return;
  e.stopImmediatePropagation();
  if (e.key === 'Escape' || e.key === 'p' || e.key === 'P') close();
  else if (e.key === '?') toggleAbout();
  else if (e.key === '2') showView('flat');
  else if (e.key === '3' && window.VFExplorer && window.VFExplorer.can3d) showView('3d');
  else if ((e.key === 'i' || e.key === 'I') && !document.getElementById('btn-timeline').hidden) showView('timeline');
}, true);
addEventListener('resize', () => { if (state.open) { renderMap(); renderTimeline(); } });
if (/[?&#]paths\b/.test(location.search + location.hash)) open();
window.VFPaths = {open, close, select, toggleCut, walk, LINES, CHAINS};
})();
