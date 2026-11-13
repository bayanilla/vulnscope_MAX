"""HTML-only visual layer for the reports: priority badges, evidence tags, number tiles, the
priority bar, score breakdowns, the interactive findings table and the diagrams.

The Markdown reports stay plain. report.md_to_html() calls in here through `inserts`, which places
blocks of HTML next to named headings, and `decorate`, which turns plain labels into badges.
"""
from __future__ import annotations

import re
from html import escape

from .correlate import PRIORITY_LABELS
from .diagram import DIAGRAM_CSS, blast_svg, hostile_activity_svg

PRI_WORD = {"P1": "act now", "P2": "this cycle", "P3": "scheduled", "P4": "routine"}

VISUAL_CSS = """
:root,[data-theme]{--p1:#ef4444;--p2:#f97316;--p3:#eab308;--p4:#64748b;--p-tx:#0b1020;
--sev-critical:#f87171;--sev-high:#fb923c;--sev-medium:#facc15;--sev-low:#60a5fa;--sev-none:#94a3b8;
--e-return:#c084fc;--e-ips:#ef4444;--e-spread:#fb923c;--e-internet:#94a3b8}
[data-theme="light"]{
--p1:#b91c1c;--p2:#c2410c;--p3:#a16207;--p4:#475569;--p-tx:#fff;
--sev-critical:#b91c1c;--sev-high:#c2410c;--sev-medium:#a16207;--sev-low:#1d4ed8;--sev-none:#64748b;
--e-return:#7c3aed;--e-ips:#dc2626;--e-spread:#c2410c;--e-internet:#64748b}
[data-theme="high-contrast"]{--p1:#ff5c5c;--p2:#ffa040;--p3:#fde047;--p4:#e5e7eb;--sev-critical:#ff5c5c;
--sev-high:#ffa040;--sev-medium:#fde047;--sev-low:#7cc4ff;--e-return:#e879f9;--e-ips:#ff5c5c}
[data-calm]{--p1:#c93c3c;--p2:#bd6222;--p3:#9a7a16;--p4:#55585c;--p-tx:#fff;
--sev-critical:#e5534b;--sev-high:#d98845;--sev-medium:#c9a544;--sev-low:#7c9fd4;--sev-none:#8e8f8b;
--e-return:#9088b0;--e-ips:#e5534b;--e-spread:#d98845;--e-internet:#8e8f8b}
[data-theme="light"][data-calm]{--p1:#b91c1c;--p2:#c2410c;--p3:#a16207;--p4:#5c5e62;--p-tx:#fff;
--sev-critical:#b91c1c;--sev-high:#c2410c;--sev-medium:#a16207;--sev-low:#1d4ed8;--sev-none:#6b6d71;
--e-return:#7c3aed;--e-ips:#dc2626;--e-spread:#c2410c;--e-internet:#6b6d71}
[data-theme="high-contrast"][data-calm]{--p1:#ff5c5c;--p2:#ffa040;--p3:#fde047;--p4:#e5e7eb;--p-tx:#000;--sev-critical:#ff5c5c;
--sev-high:#ffa040;--sev-medium:#fde047;--sev-low:#7cc4ff;--sev-none:#e0e0e0;--e-return:#e879f9;--e-ips:#ff5c5c;--e-spread:#ffa040;--e-internet:#e0e0e0}
[data-calm] .pri{border-radius:3px;font-weight:600}
[data-calm] .ev{border-width:1px;border-radius:3px;font-weight:600}
[data-calm] .tiles{display:flex;flex-wrap:wrap;gap:20px 0;margin:16px 0 20px;padding:0}
[data-calm] .tile{flex:1 1 150px;background:none;border:0;border-left:1px solid var(--line);border-radius:0;padding:2px 20px}
[data-calm] .tile.t-p1,[data-calm] .tile.t-warn,[data-calm] .tile.t-lead{border-left-color:var(--line)}
[data-calm] .tile:first-child{border-left:0;padding-left:0}
[data-calm] .tile b{font-size:30px;font-weight:600;line-height:1.15;letter-spacing:-.01em;color:var(--fg);font-variant-numeric:tabular-nums}
[data-calm] .tile.t-p1 b{color:var(--sev-critical)}[data-calm] .tile.t-ok b{color:var(--fg)}
[data-calm] .tile span{display:block;font-size:12.5px;line-height:1.4;margin-top:4px;max-width:18ch}
[data-calm] .panel{background:none;border:0;border-top:1px solid var(--line);border-radius:0;padding:14px 0 0}
[data-calm] .pbar{height:20px}[data-calm] .pbar div{font-size:12px;font-weight:600}
[data-calm] .why .f{border-radius:3px}
[data-calm] .tbl-wrap tr.sel td{box-shadow:inset 2px 0 0 var(--accent)}
.pri{display:inline-block;min-width:2.2em;padding:.05em .5em;border-radius:999px;font-weight:700;font-size:.82em;
text-align:center;color:var(--p-tx);background:var(--p4);white-space:nowrap;vertical-align:.08em}
.pri-P1{background:var(--p1)}.pri-P2{background:var(--p2)}.pri-P3{background:var(--p3)}
.pri small{font-weight:600;opacity:.9;margin-left:.35em;font-size:.95em}
.ev{display:inline-block;padding:.05em .55em;border-radius:4px;font-size:.8em;font-weight:700;letter-spacing:.02em;
border:1.5px solid currentColor;white-space:nowrap;vertical-align:.08em}
.ev-likely{color:var(--p1)}.ev-lead{color:var(--p3)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:14px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--line);
border-radius:var(--radius);padding:12px 14px}
.tile b{display:block;font-size:2rem;line-height:1.1}.tile span{color:var(--muted);font-size:.86rem}
.tile.t-p1{border-left-color:var(--p1)}.tile.t-p1 b{color:var(--p1)}.tile.t-warn{border-left-color:var(--p2)}
.tile.t-lead{border-left-color:var(--p3)}.tile.t-ok b{color:var(--muted)}
.pbar{display:flex;height:26px;border-radius:var(--radius);overflow:hidden;margin:6px 0 4px;border:1px solid var(--line)}
.pbar div{display:flex;align-items:center;justify-content:center;color:var(--p-tx);font-weight:700;font-size:.82rem;min-width:28px}
.pbar .b-P1{background:var(--p1)}.pbar .b-P2{background:var(--p2)}.pbar .b-P3{background:var(--p3)}.pbar .b-P4{background:var(--p4)}
.pbar-legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:.85rem;color:var(--muted);margin-bottom:10px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px;margin:14px 0}
.panel>p.hint{margin:0 0 10px;color:var(--muted);font-size:.9rem}
.dg-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}.dg-wrap svg{display:block;max-width:none}
.focus-note{font-size:.88rem;color:var(--muted);min-height:1.4em}.focus-note button{margin:0 0 0 8px;padding:2px 10px;font-size:.82rem}
.meter{display:inline-block;width:64px;height:8px;border-radius:4px;background:var(--line);vertical-align:middle;margin-left:6px;overflow:hidden}
.meter i{display:block;height:100%;background:var(--p4)}.meter.m-P1 i{background:var(--p1)}.meter.m-P2 i{background:var(--p2)}.meter.m-P3 i{background:var(--p3)}
.why{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:.3rem 0 .6rem;font-size:.86rem}
.why .f{border:1px solid var(--line);border-radius:999px;padding:1px 9px;background:var(--code);white-space:nowrap}
.why .f.up{border-color:var(--p2)}.why .f.down{border-color:var(--sev-low)}.why .op{color:var(--muted)}
.why .res{font-weight:700}
.ftools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.ftools button{margin:0;padding:3px 12px;font-size:.85rem;background:var(--panel);color:var(--fg);border:1px solid var(--line)}
.ftools button[aria-pressed="true"]{background:var(--accent);color:var(--accent-text);border-color:var(--accent)}
.ftools input{flex:1;min-width:160px;max-width:300px;padding:4px 8px}
.ftools .count{color:var(--muted);font-size:.85rem}
.tbl-wrap{max-height:75vh;overflow:auto;border:1px solid var(--line);border-radius:var(--radius)}
.tbl-wrap table{display:table;margin:0;border:0}.tbl-wrap th{position:sticky;top:0;z-index:1;cursor:pointer;user-select:none}
.tbl-wrap th[aria-sort="ascending"]::after{content:" \\25B2";font-size:.7em}.tbl-wrap th[aria-sort="descending"]::after{content:" \\25BC";font-size:.7em}
.tbl-wrap tbody tr{cursor:pointer}.tbl-wrap tbody tr:hover td{background:var(--head)}
.tbl-wrap tr.sel td{background:var(--code);box-shadow:inset 0 2px 0 var(--accent),inset 0 -2px 0 var(--accent)}
.tbl-wrap td.num{text-align:right;white-space:nowrap}
details.blast{margin:.4rem 0 1rem}details.blast summary{cursor:pointer;color:var(--accent);font-weight:600}
.host-tags{display:flex;flex-wrap:wrap;gap:6px;margin:-.4rem 0 .6rem}
@media print{:root,[data-theme]{--bg:#fff;--fg:#000;--muted:#333;--line:#bbb;--head:#eee;--panel:#fff;--code:#f3f3f3;
--p1:#b91c1c;--p2:#c2410c;--p3:#a16207;--p4:#475569;--p-tx:#fff;--sev-critical:#b91c1c;--sev-high:#c2410c;
--sev-medium:#a16207;--sev-low:#1d4ed8;--e-return:#7c3aed;--e-ips:#dc2626;--e-spread:#c2410c;--e-internet:#64748b}
.ftools,.focus-note,.panel>p.hint{display:none}.tbl-wrap{max-height:none;overflow:visible;border:0}
.tbl-wrap th{position:static}.tile,.panel,.why,svg,tr{break-inside:avoid}
.dg-wrap{overflow:visible}.dg-wrap svg{max-width:100%;height:auto}
.pri,.ev,.pbar div,.tile{-webkit-print-color-adjust:exact;print-color-adjust:exact}
h2,h3{break-after:avoid}}
""" + DIAGRAM_CSS

SCRIPT = """<script>
(function(){
const table=document.querySelector('table.findings');
const svg=document.querySelector('svg.dg:not(.blast)');
const note=document.querySelector('.focus-note');
let filterPri='all', filterHost='', query='';
function apply(){
  if(!table)return;let n=0;
  table.querySelectorAll('tbody tr').forEach(tr=>{
    const ok=(filterPri==='all'||tr.dataset.pri===filterPri)&&(!filterHost||tr.dataset.host===filterHost)
      &&(!query||tr.textContent.toLowerCase().includes(query));
    tr.hidden=!ok;if(ok)n++;});
  const c=document.querySelector('.ftools .count');if(c)c.textContent=n+' shown';
}
function focusHost(host,fid){
  if(svg){
    const nodes=svg.querySelectorAll('.node'),edges=svg.querySelectorAll('.edge');
    if(!host){nodes.forEach(x=>x.classList.remove('dg-dim','dg-focus'));edges.forEach(x=>x.classList.remove('dg-dim'));}
    else{
      const linked=new Set([host]);
      edges.forEach(e=>{const on=fid?(e.dataset.findings||'').split(' ').includes(fid)
          :(e.dataset.src===host||e.dataset.dst===host);
        e.classList.toggle('dg-dim',!on);if(on){linked.add(e.dataset.src);linked.add(e.dataset.dst);}});
      nodes.forEach(nd=>{nd.classList.toggle('dg-dim',!linked.has(nd.dataset.host));
        nd.classList.toggle('dg-focus',nd.dataset.host===host);});
    }
  }
  if(note){note.innerHTML='';if(host){note.append('Focused on '+host+'. ');
    const b=document.createElement('button');b.type='button';b.textContent='Clear focus';
    b.onclick=()=>{filterHost='';focusHost('');apply();table&&table.querySelectorAll('tr.sel').forEach(r=>r.classList.remove('sel'));};
    note.append(b);}}
}
if(svg)svg.querySelectorAll('.node').forEach(nd=>{
  const go=()=>{const h=nd.dataset.host;if(h==='internet')return;
    filterHost=(filterHost===h)?'':h;focusHost(filterHost);apply();};
  nd.addEventListener('click',go);nd.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}});
});
if(table){
  table.querySelectorAll('tbody tr').forEach(tr=>tr.addEventListener('click',()=>{
    const was=tr.classList.contains('sel');
    table.querySelectorAll('tr.sel').forEach(r=>r.classList.remove('sel'));
    if(was){focusHost('');return;}
    tr.classList.add('sel');focusHost(tr.dataset.host,tr.dataset.fid);
    if(svg){const r=svg.getBoundingClientRect();if(r.bottom<0||r.top>innerHeight)svg.scrollIntoView({behavior:'smooth',block:'center'});}
  }));
  document.querySelectorAll('.ftools button[data-pri]').forEach(b=>b.addEventListener('click',()=>{
    filterPri=b.dataset.pri;document.querySelectorAll('.ftools button[data-pri]').forEach(x=>x.setAttribute('aria-pressed',x===b));apply();}));
  const q=document.querySelector('.ftools input');if(q)q.addEventListener('input',()=>{query=q.value.trim().toLowerCase();apply();});
  table.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{
    const dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';
    table.querySelectorAll('th').forEach(x=>x.removeAttribute('aria-sort'));th.setAttribute('aria-sort',dir);
    const rows=[...table.tBodies[0].rows];
    const key=r=>{const c=r.cells[i];return c.dataset.sort!==undefined?c.dataset.sort:c.textContent.trim().toLowerCase();};
    rows.sort((a,b)=>{const x=key(a),y=key(b),nx=parseFloat(x),ny=parseFloat(y);
      const d=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return dir==='ascending'?d:-d;});
    rows.forEach(r=>table.tBodies[0].append(r));}));
  apply();
}
window.addEventListener('beforeprint',()=>document.querySelectorAll('details').forEach(d=>d.open=true));
})();
</script>"""


# ------------------------------------------------------------- decoration
def badge(pri: str, long: bool = False) -> str:
    word = f"<small>{PRI_WORD[pri]}</small>" if long else ""
    return f'<span class="pri pri-{pri}" title="{pri}: {PRI_WORD[pri]}">{pri}{word}</span>'


EV_TAGS = {"likely": '<span class="ev ev-likely">Likely exploitation</span>',
           "lead": '<span class="ev ev-lead">Lead, not confirmed</span>'}


def decorate(h: str) -> str:
    """Turn plain-text priority labels and evidence markers into badges and tags."""
    for p, label in PRIORITY_LABELS.items():
        h = h.replace(escape(label, quote=False), badge(p, long=True))
    h = re.sub(r"<td>(P[1-4])</td>", lambda m: f"<td>{badge(m[1])}</td>", h)
    h = re.sub(r"<h4>(P[1-4]) \((\d+)\) ", lambda m: f"<h4>{badge(m[1])} <span class=\"score\">{m[2]}</span> ", h)
    h = h.replace("<li>[corroborated] ", "<li>" + EV_TAGS["likely"] + " ")
    h = h.replace("<li>[lead] ", "<li>" + EV_TAGS["lead"] + " ")
    h = re.sub(r"<strong>IPS alert and host traffic both point to exploitation</strong>", EV_TAGS["likely"], h, flags=re.I)
    h = re.sub(r"<strong>traffic pattern worth investigating \(not confirmed\)</strong>", EV_TAGS["lead"], h, flags=re.I)
    return h


def _evidence(r: dict) -> str:
    if any(i["confidence"] == "corroborated" for i in r["indicators"]):
        return "likely"
    return "lead" if r["indicators"] else ""


def _fid(r: dict) -> str:
    return f"{r['host']}|{r['plugin_id']}|{r['port']}"


# ------------------------------------------------------------- blocks
def tiles(res: dict) -> str:
    s, cov, F = res["summary"], res["coverage"], res["findings"]
    pc = s["priority_counts"]
    exposed = [r for r in F if r["exposure"]["scope"] == "port" and r["exposure"]["external_sources"]]
    corr, inv = s["hosts_corroborated"], s["hosts_to_investigate"]
    gaps = cov["active_servers_not_scanned"]
    t = [("t-p1" if pc["P1"] else "t-ok", pc["P1"], "Priority 1 findings (act now)"),
         ("t-p1" if corr else "t-ok", len(corr), "Systems with likely exploitation"),
         ("t-lead" if inv else "t-ok", len(inv), "Systems to investigate (leads)"),
         ("t-warn" if exposed else "t-ok", len(exposed), "Vulnerable services reached from the internet"),
         ("t-warn" if gaps else "t-ok", len(gaps), "Active servers missing from the scan"),
         ("", f"{s['flows']:,}", f"Network sessions analysed across {cov['scanned_hosts']} scanned systems")]
    return ('<div class="tiles">' + "".join(f'<div class="tile {c}"><b>{v}</b><span>{escape(lab)}</span></div>'
                                           for c, v, lab in t) + "</div>" + priority_bar(res))


def priority_bar(res: dict) -> str:
    pc = res["summary"]["priority_counts"]
    total = sum(pc.values()) or 1
    segs = "".join(f'<div class="b-{p}" style="flex:{pc[p]}" title="{pc[p]} {p} findings ({PRI_WORD[p]})">{pc[p]}</div>'
                   for p in ("P1", "P2", "P3", "P4") if pc[p])
    legend = "".join(f'<span>{badge(p)} {PRI_WORD[p]}: {pc[p]} ({pc[p] * 100 // total}%)</span>'
                     for p in ("P1", "P2", "P3", "P4"))
    return (f'<div class="pbar" role="img" aria-label="Findings by priority">{segs}</div>'
            f'<div class="pbar-legend">{legend}</div>')


def diagram_panel(res: dict, title: str | None = "Hostile activity diagram") -> str:
    head = f"<h3>{escape(title)}</h3>" if title else ""
    return (f'{head}<div class="panel"><p class="hint">Click a host to focus the report on it. Click a finding in the '
            'table below to highlight it here.</p><div class="focus-note" aria-live="polite"></div>'
            f'<div class="dg-wrap">{hostile_activity_svg(res)}</div></div>')


def findings_table(res: dict) -> str:
    F = res["findings"]
    names = lambda r: f"{r['hostname']} ({r['host']})" if r["hostname"] else r["host"]
    rows = []
    for r in F:
        e = r["exposure"]
        ev = _evidence(r)
        svc = "host-level" if r["port"] == 0 else f"{r['port']}/{r['proto']}" + (f" ({r['service']})" if r["service"] else "")
        rows.append(
            f'<tr data-pri="{r["priority"]}" data-host="{escape(r["host"])}" data-fid="{escape(_fid(r))}">'
            f'<td data-sort="{r["priority"]}">{badge(r["priority"])}</td>'
            f'<td class="num" data-sort="{r["score"]:03d}">{r["score"]}<span class="meter m-{r["priority"]}">'
            f'<i style="width:{r["score"]}%"></i></span></td>'
            f'<td>{escape(names(r))}</td><td>{escape(r["plugin_name"])} ({escape(r["plugin_id"])})</td>'
            f'<td>{escape(svc)}</td><td class="num">{r["cvss"]:.1f}</td>'
            f'<td>{"Yes" if r["exploit_available"] else "No"}</td><td>{escape(e["label"])}</td>'
            f'<td class="num">x{r["blast_factor"]}</td>'
            f'<td data-sort="{ {"likely": 0, "lead": 1}.get(ev, 2)}">{EV_TAGS[ev] if ev else ""}</td></tr>')
    btns = "".join(f'<button type="button" data-pri="{p}" aria-pressed="{str(p == "all").lower()}">'
                   f'{"All" if p == "all" else p}</button>' for p in ("all", "P1", "P2", "P3", "P4"))
    return ('<div class="ftools" role="group" aria-label="Filter findings">' + btns +
            '<input type="search" placeholder="Search host, CVE, service" aria-label="Search findings">'
            '<span class="count"></span></div><div class="tbl-wrap"><table class="findings"><thead><tr>'
            "<th>Pri</th><th>Score</th><th>Host</th><th>Vulnerability</th><th>Port</th><th>CVSS</th>"
            "<th>Exploit</th><th>Exposure</th><th>Blast</th><th>Evidence</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div>")


def score_breakdown(r: dict) -> str:
    """The score's multiplication written out, so readers see which factor drove it."""
    base = r["cvss"] * 10
    ev = _evidence(r)
    ev_f = 1.25 if ev == "likely" else 1.1 if ev == "lead" else 1.0
    exp_f = r["exposure"]["factor"]
    parts = [(f"CVSS {r['cvss']:.1f} × 10 = {base:.0f}", "")]
    for val, name in ((r["exploit_factor"], "exploit"), (exp_f, "exposure"), (r["blast_factor"], "blast radius"),
                      (ev_f, "evidence")):
        if name == "evidence" and ev_f == 1.0:
            continue
        cls = "up" if val > 1 else "down" if val < 1 else ""
        parts.append((f"×{val:g} {name}", cls))
    raw = base * r["exploit_factor"] * exp_f * r["blast_factor"] * ev_f
    out = '<div class="why" aria-label="Score breakdown">'
    out += '<span class="op"></span>'.join(f'<span class="f {c}">{escape(t)}</span>' for t, c in parts)
    capped = " (capped)" if raw > 100 else ""
    out += (f'<span class="op">=</span><span class="res">{r["score"]}{capped}</span>'
            f'<span class="meter m-{r["priority"]}"><i style="width:{r["score"]}%"></i></span>{badge(r["priority"])}</div>')
    return out


def host_block(h: dict, res: dict) -> str:
    rows = [r for r in res["findings"] if r["host"] == h["host"]]
    evs = {_evidence(r) for r in rows}
    tags = []
    if "likely" in evs:
        tags.append(EV_TAGS["likely"])
    elif "lead" in evs:
        tags.append(EV_TAGS["lead"])
    if h["internet_exposed"]:
        tags.append('<span class="ev" style="color:var(--p2)">Internet-exposed</span>')
    out = f'<div class="host-tags">{" ".join(tags)}</div>'
    bl = h["blast"]
    if bl["reachable_count"]:
        spread = {t["ip"] for r in rows for i in r["indicators"] if i["type"] == "new_lateral"
                  for t in i.get("targets", [])}
        open_ = " open" if h["priority"] in ("P1", "P2") else ""
        out += (f'<details class="blast"{open_}><summary>Blast radius map ({bl["direct_count"]} direct, '
                f'{bl["reachable_count"]} within reach)</summary><div class="dg-wrap">{blast_svg(h, res, spread)}'
                "</div></details>")
    return out


def executive_inserts(res: dict) -> dict:
    return {"Key numbers": [{"replace_table": tiles(res)}],
            "Recommended actions": [{"before": diagram_panel(res, "Where the hostile activity is")}]}


def technical_inserts(res: dict) -> dict:
    ins: dict[str, list] = {"3. Prioritized findings": [{"after": diagram_panel(res), "replace_table": findings_table(res)}]}
    for h in res["hosts"]:
        title = f"{_name(h)} - {PRIORITY_LABELS[h['priority']]}"
        ins.setdefault(title, []).append({"after": host_block(h, res)})
    by_host = {}
    for r in res["findings"]:
        by_host.setdefault(r["host"], []).append(r)
    for h in res["hosts"]:                    # same order as the technical report writes them
        for r in by_host.get(h["host"], []):
            ins.setdefault(f"{r['priority']} ({r['score']}) {r['plugin_name']}", []).append({"after": score_breakdown(r)})
    return ins


def _name(h: dict) -> str:
    return f"{h['hostname']} ({h['host']})" if h["hostname"] else h["host"]
