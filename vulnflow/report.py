"""Render the correlation result as an executive summary, a technical report
(Markdown + HTML each) and machine-readable CSV/JSON."""
from __future__ import annotations

import csv
import html
import json
import os
import re
import tempfile

from .correlate import PRIORITY_LABELS
from .branding import PRODUCT_NAME, icon_data_uri
from .theme_backgrounds import texture_data


def _c(v) -> str:
    """Make a value safe for a Markdown table cell."""
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def _name(host: str, hostname: str) -> str:
    return f"{hostname} ({host})" if hostname else host


def _plural(n, word, plural=None):
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _short(text: str, n=140) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "..."


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _svc(r) -> str:
    return "host-level" if r["port"] == 0 else f"{r['port']}/{r['proto']}" + (f" ({r['service']})" if r["service"] else "")


# ---------------------------------------------------------------- executive
def executive_summary(res: dict) -> str:
    s, cov, F, H = res["summary"], res["coverage"], res["findings"], res["hosts"]
    pc = s["priority_counts"]
    p1_hosts = sorted({r["host"] for r in F if r["priority"] == "P1"})
    exposed = [r for r in F if r["exposure"]["scope"] == "port" and r["exposure"]["external_sources"]]
    exposed_expl = [r for r in exposed if r["exploit_available"]]
    ind_hosts = s["hosts_with_indicators"]
    corr, inv, spread = s["hosts_corroborated"], s["hosts_to_investigate"], s["hosts_possible_spread"]
    flagged = corr + inv
    names = {h["host"]: _name(h["host"], h["hostname"]) for h in H}
    nm = lambda ips: ", ".join(names.get(ip, ip) for ip in ips)
    gaps = cov["active_servers_not_scanned"]

    L = [f"# {PRODUCT_NAME}: Executive Summary", "",
         f"Prepared {res['generated'][:10]}. Network activity analysed from "
         f"{s['window_start'] or 'n/a'} to {s['window_end'] or 'n/a'}.", "",
         "## Bottom line", ""]
    bottom = []
    if corr:
        bottom.append(f"**Likely exploitation on {nm(corr)}.** An IPS/IDS alert on a vulnerable service and the "
                      f"host's own traffic afterwards point the same way. Start incident response; host forensics "
                      f"is needed to confirm a compromise.")
    if inv:
        bottom.append(f"**Investigate {nm(inv)}.** Network traffic shows a pattern associated with exploitation, "
                      f"but nothing in the supplied logs confirms it. Check IPS/threat logs, application logs and "
                      f"the host before treating it as an incident.")
    if spread:
        bottom.append(f"{'A flagged system' if flagged else 'A system'} later made new connections to vulnerable "
                      f"services on {_plural(len(spread), 'other system')} ({nm(spread)}). If the first system "
                      f"is compromised, these are the likely next targets.")
    if pc["P1"]:
        bottom.append(f"{_plural(pc['P1'], 'vulnerability', 'vulnerabilities')} on "
                      f"{_plural(len(p1_hosts), 'system')} need action now (Priority 1).")
    else:
        bottom.append("No vulnerability reached Priority 1 (act now).")
    if exposed:
        n = len(exposed)
        bottom.append(f"{_plural(n, 'vulnerable service')} on "
                      f"{_plural(len({r['host'] for r in exposed}), 'system')} "
                      f"{'is' if n == 1 else 'are'} being reached from the internet"
                      + (f"; {'it has' if n == 1 else f'{len(exposed_expl)} of them have'} a publicly available exploit."
                         if exposed_expl else ", none with a known public exploit."))
    quiet = [r for r in F if r["exposure"]["label"] == "Service not observed in use"]
    if F:
        bottom.append(f"Of {_plural(s['findings_scored'], 'vulnerability', 'vulnerabilities')} reported by the "
                      f"scanner, {len(quiet)} {'sits' if len(quiet) == 1 else 'sit'} on services with no observed traffic and can be scheduled "
                      f"rather than rushed.")
    if gaps:
        bottom.append(f"{_plural(len(gaps), 'active server')} seen on the network "
                      f"{'was' if len(gaps) == 1 else 'were'} not in the scan, so their risk is unknown.")
    if res.get("ioc_matches"):
        bottom.append(f"{_plural(len(res['ioc_matches']), 'observed indicator')} matched the imported "
                      "IOC CSV. Review the source information and surrounding telemetry; "
                      "a match alone does not confirm malicious activity.")
    L += ["\n\n".join(bottom), "", "## Key numbers", "",
          "| Measure | Value |", "|---|---|",
          f"| Systems scanned | {cov['scanned_hosts']} |",
          f"| Systems with vulnerabilities (Low and above) | {s['hosts_with_findings']} |",
          f"| Network sessions analysed | {s['flows']:,} |",
          f"| Priority 1 / 2 / 3 / 4 findings | {pc['P1']} / {pc['P2']} / {pc['P3']} / {pc['P4']} |",
          f"| Vulnerable services reached from the internet | {len(exposed)} |",
          f"| Exploitable vulnerabilities with observed traffic | {s['exploitable_and_exposed']} |",
          f"| Systems with corroborated evidence / to investigate / possible next targets | {len(corr)} / {len(inv)} / {len(spread)} |",
          f"| Active servers missing from the scan | {len(gaps)} |"]
    if "ioc_matches" in res:
        L.append(f"| IOC CSV matches | {len(res['ioc_matches'])} |")
    L += ["", "## Top risks", ""]
    top = [r for r in F if r["priority"] in ("P1", "P2")][:5] or F[:3]
    if not top:
        L.append("No vulnerabilities at or above the configured severity were found.")
    for i, r in enumerate(top, 1):
        exp = r["exposure"]
        bits = [exp["label"].lower()]
        if r["exploit_available"]:
            bits.append("public exploit exists")
        bl = next((h["blast"] for h in H if h["host"] == r["host"]), {})
        if bl.get("reachable_count"):
            bits.append(f"compromise could spread to {_plural(bl['reachable_count'], 'connected system')}")
        if any(i["confidence"] == "corroborated" for i in r["indicators"]):
            bits.append("**IPS alert and host traffic both point to exploitation**")
        elif r["indicators"]:
            bits.append("**traffic pattern worth investigating (not confirmed)**")
        cves = [c for c in r["cves"][:2] if c not in r["plugin_name"]]
        cve = f" ({', '.join(cves)})" if cves else ""
        L.append(f"{i}. **{_name(r['host'], r['hostname'])}**: {r['plugin_name']}{cve}. "
                 f"{_cap('; '.join(bits))}. Risk score {r['score']}/100, {PRIORITY_LABELS[r['priority']]}.")
    L += ["", "## Recommended actions", ""]
    recs = []
    if corr:
        recs.append(f"**Start incident response for {nm(corr)}.** Preserve logs and memory, confirm on the host, "
                    f"contain, then patch. Patching alone will not remove an attacker."
                    + (f" Include {nm(spread)} in the scope." if spread else ""))
    if inv:
        recs.append(f"**Triage {nm(inv)} today.** Pull IPS/threat logs, web or application logs and EDR data for "
                    f"the flagged connections to confirm or rule out exploitation."
                    + (f" If confirmed, extend the check to {nm(spread)}." if spread and not corr else ""))
    elif spread and not corr:
        recs.append(f"**Check {nm(spread)}** for unexpected connections and signs of compromise.")
    exposed_urgent = [r for r in exposed if r["exploit_available"] or r["host"] in corr]
    if exposed_urgent:
        hs = sorted({_name(r['host'], r['hostname']) for r in exposed_urgent})
        recs.append(f"**Patch or shield high-risk internet-facing services within 48 hours**: {', '.join(hs)}. "
                    f"If a patch cannot go in, restrict access at the firewall.")
    wide = [h for h in H if h["blast"]["vulnerable_pivots"] and h["priority"] in ("P1", "P2")]
    if wide:
        recs.append(f"**Limit how far a breach can spread.** {_plural(len(wide), 'high-priority system')} can reach "
                    f"other vulnerable systems directly; restrict admin protocols (SMB, RDP, SSH) between "
                    f"these segments.")
    internal_p = [r for r in F if r["priority"] in ("P1", "P2") and not r["exposure"]["external_sources"]]
    if internal_p:
        recs.append(f"**Fix {_plural(len(internal_p), 'internally reachable high-priority vulnerability', 'internally reachable high-priority vulnerabilities')}** "
                    f"in the current patch cycle; they are the next step for an attacker already inside.")
    if gaps:
        recs.append(f"**Close the scan gap.** Add the {_plural(len(gaps), 'unscanned active server')} to the "
                    f"scan scope so their exposure can be assessed.")
    if quiet:
        recs.append("**Schedule the remaining findings** through normal patching, and switch off services "
                    "that no one is using.")
    L += [f"{i}. {t}" for i, t in enumerate(recs, 1)] or ["No action required beyond routine patching."]
    L += ["", "## How confident is this?", "",
          f"The assessment combines the vulnerability scan with {s['flows']:,} observed network sessions. "
          f"{cov['scanned_and_seen']} of {cov['scanned_hosts']} scanned systems appeared in the network data. "
          "A system with no observed traffic is scored as \"unknown\" rather than safe. Telemetry only shows "
          "what the sensors could see, so absence of traffic is not proof that a service is unreachable.",
          "", "Full evidence for every finding is in the technical report."]
    report = "\n".join(L) + "\n"
    if "ioc_matches" in res:
        from .ioc_archive import markdown_section
        report += "\n" + markdown_section(res["ioc_matches"])
    return report


# ---------------------------------------------------------------- technical
def technical_report(res: dict) -> str:
    s, cov, F, H, cfg = res["summary"], res["coverage"], res["findings"], res["hosts"], res["config"]
    L = [f"# {PRODUCT_NAME}: Technical Analysis", "",
         f"Generated {res['generated']}. Telemetry window {s['window_start'] or 'n/a'} to {s['window_end'] or 'n/a'}.",
         "", "## 1. Inputs and data quality", "",
         "| File | Format | Records read | Kept | Dropped | Notes |", "|---|---|---|---|---|---|"]
    for i in res["inputs"]:
        dropped = ", ".join(f"{n} {k}" for k, n in i["dropped"].items()) or "0"
        L.append(f"| {_c(i['file'])} | {i['format']} | {i['read']} | {i['kept']} | {_c(dropped)} | {_c('; '.join(i['notes']))} |")
    L += ["", f"Exact duplicate sessions removed: {s['duplicate_flows_removed']}. "
              f"Duplicate findings merged across scans: {s['duplicate_findings_merged']}. "
              f"IPS/IDS alerts loaded: {s.get('threat_alerts', 0)}. "
          f"Internal address space: {', '.join(cfg['internal_nets'])}.",
          ""]
    if s.get("zeek_event_counts"):
        L += ["Zeek stream events preserved (separate from connection sessions and alerts): "
              + ", ".join(f"{stream} {count}" for stream, count in s["zeek_event_counts"].items()) + ".", ""]
    if s.get("ot_protocol_counts"):
        L += ["Industrial protocol records: "
              + ", ".join(f"{protocol} {count}" for protocol, count in s["ot_protocol_counts"].items())
              + ". These records show observed activity; they do not, by themselves, change risk scores.", ""]
    L += ["## 2. Method", "",
          "Each finding is scored 0-100 as `CVSS x 10 x Exploit x Exposure x BlastRadius`, capped at 100, "
          "then multiplied by 1.25 with corroborated exploitation evidence or 1.1 with investigation leads.", "",
          "- **Exploit**: 1.0 if a public exploit exists (1.1 if in Metasploit/CANVAS/Core), otherwise 0.65.",
          "- **Exposure** (from telemetry): 1.0 service reached from the internet; 0.85 reached internally by 5+ hosts; "
          "0.75 reached internally; 0.45 attempts only; 0.35 blocked by firewall; 0.3 service not observed in use; "
          "0.5 host absent from telemetry (unknown). Host-level findings (port 0, e.g. missing patches or client "
          "software) use 0.7 / 0.5 / 0.35 for internet-facing / active / quiet hosts.",
          f"- **Blast radius**: 1.0 to 1.5 from the number of internal hosts this host has completed sessions with "
          f"(walked {cfg['hops']} hops), how many of those carry High/Critical findings, and use of lateral-movement "
          f"protocols (SMB, RDP, SSH, WinRM, database ports).",
          "- **Indicators** are leads, not proof. *Lead*: the host connects back to an outside address that reached "
          "the vulnerable service; new lateral connections or >20 MB uploaded to the internet after that contact; an "
          "IPS/IDS alert on the service that was not blocked; a flagged host newly connecting to this vulnerable service. "
          "*Corroborated*: an unblocked IPS/IDS alert on the service plus post-contact behaviour from the host. "
          "Confirming a compromise still needs host evidence (EDR, logs, forensics), which this tool does not see.",
          "- **Priority**: P1 score >= 75 or corroborated evidence; P2 >= 50 or any lead; P3 >= 25; P4 below.",
          "", "## 3. Prioritized findings", "",
          "| Pri | Score | Host | Vulnerability | Port | CVSS | Exploit | Exposure | Blast | Likelihood |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in F:
        L.append(f"| {r['priority']} | {r['score']} | {_c(_name(r['host'], r['hostname']))} | "
                 f"{_c(r['plugin_name'])} ({r['plugin_id']}) | {_c(_svc(r))} | {r['cvss']:.1f} | "
                 f"{'Yes' if r['exploit_available'] else 'No'} | {_c(r['exposure']['label'])} | "
                 f"x{r['blast_factor']} | {r['likelihood']} |")
    L += ["", "## 4. Host details", ""]
    by_host = {}
    for r in F:
        by_host.setdefault(r["host"], []).append(r)
    for h in H:
        bl = h["blast"]
        L += [f"### {_name(h['host'], h['hostname'])} - {PRIORITY_LABELS[h['priority']]}", "",
              f"- Operating system: {h['os'] or 'unknown'}",
              f"- Findings: " + ", ".join(f"{n} {k}" for k, n in h["by_severity"].items()),
              f"- Seen in telemetry: {'yes' if h['telemetry_seen'] else 'no'} "
              f"({h['inbound_flows']} inbound, {h['outbound_flows']} outbound sessions)",
              f"- Internet-exposed vulnerable service: {'yes' if h['internet_exposed'] else 'no'}", ""]
        inds = [i for r in by_host[h["host"]] for i in r["indicators"]]
        if inds:
            L += ["**Exploitation indicators** (leads unless marked corroborated)", ""]
            seen = set()
            for i in inds:
                if i["text"] not in seen:
                    seen.add(i["text"])
                    L.append(f"- [{i['confidence']}] {i['text']}")
            L.append("")
        L += ["**Findings and exposure evidence**", ""]
        for r in by_host[h["host"]]:
            e = r["exposure"]
            cves = ", ".join(r["cves"][:6]) + (" ..." if len(r["cves"]) > 6 else "")
            L += [f"#### {r['priority']} ({r['score']}) {r['plugin_name']}", "",
                  f"- Plugin {r['plugin_id']}, {r['severity_name']}, CVSS {r['cvss']:.1f}, port {_svc(r)}"
                  + (f", {cves}" if cves else ""),
                  f"- Why this score: {' '.join(r['rationale'])}"]
            if e["inbound_total"]:
                srcs = ", ".join(f"{ip}{' (ext)' if ext else ''} x{n}" for ip, n, ext in e["top_sources"])
                L.append(f"- Traffic to {'host' if e['scope'] == 'host' else 'service'}: {e['established']} completed, "
                         f"{e['attempts']} attempts, {e['denied']} blocked; first {e['first_seen']}, last {e['last_seen']}"
                         + (f"; top sources: {srcs}" if srcs else ""))
            if r["synopsis"]:
                L.append(f"- Synopsis: {_short(r['synopsis'], 300)}")
            if r["solution"]:
                L.append(f"- Remediation: {_short(r['solution'], 300)}")
            L.append("")
        L += ["**Blast radius**", ""]
        if bl["reachable_count"]:
            L.append(f"Completed sessions to {bl['direct_count']} internal host(s) directly, "
                     f"{bl['reachable_count']} within {cfg['hops']} hops.")
            if bl["lateral_protocols"]:
                L.append("Lateral-movement protocols used: "
                         + ", ".join(f"{k} ({n})" for k, n in bl["lateral_protocols"].items()) + ".")
            if bl["vulnerable_pivots"]:
                L.append(f"Reachable hosts with High/Critical findings: {', '.join(bl['vulnerable_pivots'])}.")
            L += ["", "| Reachable host | Hops | Ports used | Worst finding |", "|---|---|---|---|"]
            for rr in bl["reachable"][:15]:
                L.append(f"| {rr['ip']} | {rr['hop']} | {_c(', '.join(rr['ports']))} | {rr['max_severity'] or '-'} |")
            if bl["reachable_count"] > 15:
                L.append(f"| ... {bl['reachable_count'] - 15} more | | | |")
        else:
            L.append("No completed internal sessions from this host were observed.")
        if bl["external_destinations"]:
            L += ["", f"Outbound to {bl['external_destinations']} external address(es); top: "
                  + ", ".join(f"{ip} x{n}" for ip, n in bl["top_external_destinations"]) + "."]
        L.append("")
    L += ["## 5. Coverage gaps", "",
          f"{cov['scanned_and_seen']} of {cov['scanned_hosts']} scanned hosts appear in telemetry; "
          f"{cov['telemetry_internal_hosts']} internal addresses were seen in total.", ""]
    if cov["scanned_not_seen"]:
        L += ["**Scanned but not seen in telemetry** (exposure unknown; check sensor placement): "
              + ", ".join(cov["scanned_not_seen"]), ""]
    if cov["active_servers_not_scanned"]:
        L += ["**Active internal servers not in the scan** (add to scan scope):", "",
              "| Host | Services observed | Sessions |", "|---|---|---|"]
        for g in cov["active_servers_not_scanned"][:25]:
            L.append(f"| {g['ip']} | {_c(', '.join(g['services']))} | {g['sessions']} |")
        L.append("")
    L += ["## 6. Output files", "",
          "- `executive_summary.md/.html`: leadership summary",
          "- `technical_report.md/.html`: this report",
          "- `correlated_findings.csv`: one row per finding with scores, for ticketing or spreadsheets",
          "- `results.json`: full machine-readable result",
          "- `hostile_activity.svg`: the hostile activity diagram as a standalone image",
          "- `explorer.html`: interactive host explorer (who targets each host, and its internal blast radius)",
          "- `normalized/flows.csv`, `normalized/findings.csv`: cleaned inputs in the common schema",
          "- `normalized/zeek_events.jsonl`: other Zeek streams with stream identity and source fields",
          "- `normalized/ot_events.jsonl`: industrial protocol records with operation and message direction"]
    report = "\n".join(L) + "\n"
    if "ioc_matches" in res:
        from .ioc_archive import markdown_section
        report += "\n" + markdown_section(res["ioc_matches"])
    return report


# ---------------------------------------------------------------- HTML
THEMES = (
    ("dark", "SOC Dark"), ("olive-drab", "Olive Drab"),
    ("matrix", "Matrix"), ("high-contrast", "High Contrast"), ("light", "Light"),
)

THEME_INIT = """<script>
const supportedThemes = new Set(__THEMES__);
let savedTheme = 'dark';
try { savedTheme = localStorage.getItem('vulnflow-theme') || 'dark'; } catch (_) {}
document.documentElement.dataset.theme = supportedThemes.has(savedTheme) ? savedTheme : 'dark';
</script>""".replace("__THEMES__", json.dumps([value for value, _ in THEMES]))


def theme_control() -> str:
    options = "".join(f'<option value="{value}">{label}</option>' for value, label in THEMES)
    return (f'<div class="theme-bar"><span class="theme-brand">{PRODUCT_NAME}</span>'
            f'<label for="theme-choice">Theme</label><select id="theme-choice" aria-label="Theme">{options}</select></div>'
            '<script>(function(){const s=document.getElementById("theme-choice");'
            'const root=document.documentElement;'
            's.value=[...s.options].some(o=>o.value===root.dataset.theme)?root.dataset.theme:"dark";'
            's.addEventListener("change",()=>{root.dataset.theme=s.value;'
            'try{localStorage.setItem("vulnflow-theme",s.value)}catch(_){}})})();</script>')


CSS = """
:root,[data-theme="dark"]{--desktop:#020617;--bg:#020617;--fg:#f1f5f9;--muted:#cbd5e1;--line:#334155;--head:#1e293b;--accent:#22d3ee;--accent-text:#082f49;--code:#1e293b;--panel:#0f172a;--radius:10px;--bar:#020617;--shadow:none;--background-art:url('__DARK_TEXTURE__');--background-overlay:linear-gradient(#02061755,#020617aa);--body-tint:#020617dd}
[data-theme="olive-drab"]{--desktop:#10150e;--bg:#10150e;--fg:#f0f0e9;--muted:#b7bcab;--line:#62613e;--head:#192017;--accent:#d2c681;--accent-text:#10150e;--code:#1d261b;--panel:#192017;--radius:4px;--bar:#10150e;--shadow:none;--background-art:url('__WORLD_TEXTURE__');--background-overlay:linear-gradient(#10150e33,#10150e99);--body-tint:#10150ed1}
[data-theme="light"]{--desktop:#b9c4d1;--bg:#cfd8e3;--fg:#0f172a;--muted:#334155;--line:#a3b1c2;--head:#bfcad7;--accent:#1d4ed8;--accent-text:#fff;--code:#c2ccd8;--panel:#dbe2ea;--radius:10px;--bar:#c2ccd8;--shadow:0 12px 34px #47556922;--background-art:radial-gradient(at 8% 0%,#2f4b7c1a,transparent 48%),radial-gradient(at 95% 65%,#2f4b7c0b,transparent 50%),linear-gradient(115deg,transparent 38%,#2f4b7c06 49%,transparent 60%);--background-overlay:linear-gradient(#cfd8e355,#cfd8e355);--body-tint:#cfd8e3d9}
[data-theme="high-contrast"]{--desktop:#000;--bg:#000;--fg:#fff;--muted:#f1f5f9;--line:#fff;--head:#111;--accent:#fde047;--accent-text:#000;--code:#111;--panel:#000;--radius:0;--bar:#000;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#000}
[data-theme="matrix"]{--desktop:#020b04;--bg:#020b04;--fg:#86efac;--muted:#4ade80;--line:#166534;--head:#052e16;--accent:#22c55e;--accent-text:#000;--code:#052e16;--panel:#031508;--radius:4px;--bar:#001a08;--shadow:none;--background-art:url('__MATRIX_TEXTURE__');--background-overlay:linear-gradient(#020b0455,#020b04bb);--body-tint:#020b04d9}
html{background-color:var(--desktop);background-image:var(--background-overlay),var(--background-art);background-position:center;background-size:cover;background-attachment:fixed;color-scheme:dark}
[data-theme="light"]{color-scheme:light}
*{box-sizing:border-box}
body{background:var(--body-tint);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;max-width:1100px;min-height:100vh;margin:0 auto;padding:24px 22px;box-shadow:var(--shadow)}
h1{font-size:1.65rem;margin-top:.8rem}h2{margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
h3{margin-top:1.8rem;color:var(--accent)}h4{margin-bottom:.3rem}
a{color:var(--accent)}a:focus-visible,button:focus-visible,select:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.theme-bar{display:flex;align-items:center;gap:.65rem;padding:.55rem .8rem;margin:-24px -22px 24px;background:var(--bar);border-bottom:1px solid var(--line);color:var(--fg)}
.theme-brand{display:inline-flex;align-items:center;gap:.45rem;font-weight:800;letter-spacing:.02em;margin-right:auto}.theme-bar label{font-size:.82rem;margin:0}.theme-bar select{max-width:180px;padding:.25rem .4rem;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--fg);font:inherit}
form,.msg{background:var(--panel)}button{background:var(--accent);color:var(--accent-text);border:1px solid var(--accent);border-radius:var(--radius);cursor:pointer}button:hover{filter:brightness(1.08)}
input,textarea,select{accent-color:var(--accent)}input[type=text],input[type=password],textarea,select{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:var(--radius)}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.9rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--head)}
code{background:var(--code);padding:1px 4px;border-radius:3px}li{margin:.2rem 0}
pre{background:var(--code);padding:10px;border-radius:var(--radius);overflow-x:auto}pre code{padding:0}
blockquote{margin:.8rem 0;padding:.4rem .9rem;border-left:3px solid var(--accent);color:var(--muted)}
[data-theme="matrix"] body{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
[data-theme="high-contrast"] a{text-decoration:underline}
@media(max-width:600px){body{padding:16px}.theme-bar{margin:-16px -16px 20px}.theme-brand{font-size:.9rem}.theme-bar select{max-width:145px}}
@media print{html{background:#fff;color-scheme:light}body{box-shadow:none;max-width:none;padding:0;background:#fff;color:#000}.theme-bar{display:none}a{color:#000}}
"""
CSS = (CSS.replace("__DARK_TEXTURE__", texture_data("signal"))
          .replace("__WORLD_TEXTURE__", texture_data("world"))
          .replace("__MATRIX_TEXTURE__", texture_data("matrix")))


def _inline(t: str) -> str:
    t = html.escape(t, quote=False)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])", r"<em>\1</em>", t)
    return re.sub(r"(?<![\w*])_([^_]+)_(?![\w*])", r"<em>\1</em>", t)


def md_body(md: str, inserts: dict | None = None) -> str:
    """Minimal Markdown to HTML for the reports and model answers. All text is escaped.

    `inserts` maps a heading's text to a list of {"before", "after", "replace_table"} HTML blocks,
    used in order for repeated headings; "replace_table" swaps out the first table after the heading.
    """
    inserts = {k: list(v) for k, v in (inserts or {}).items()}
    out, lines, i, swap = [], md.splitlines(), 0, None
    block_start = r"(#{1,6} |\||- |\* |\d+\. |```|> )"
    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            i += 1
        elif ln.startswith("```"):
            code = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
        elif m := re.match(r"(#{1,6}) (.*)", ln):
            n = min(len(m[1]), 4)
            ins = inserts[m[2]].pop(0) if inserts.get(m[2]) else {}
            out += [ins.get("before", ""), f"<h{n}>{_inline(m[2])}</h{n}>", ins.get("after", "")]
            swap = ins.get("replace_table", swap)
            i += 1
        elif ln.startswith("> "):
            quote = []
            while i < len(lines) and lines[i].startswith("> "):
                quote.append(lines[i][2:])
                i += 1
            out.append(f"<blockquote>{_inline(' '.join(quote))}</blockquote>")
        elif ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", lines[i].strip())[1:-1]])
                i += 1
            if swap is not None:
                out.append(swap)
                swap = None
                continue
            out.append("<table><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in rows[0]) + "</tr>")
            for r in rows[2:]:
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            out.append("</table>")
        elif re.match(r"\s*(- |\* |\d+\. )", ln):
            tag = "ol" if re.match(r"\s*\d+\. ", ln) else "ul"
            out.append(f"<{tag}>")
            while i < len(lines) and re.match(r"\s*(- |\* |\d+\. )", lines[i]):
                item = re.sub(r"^\s*(- |\* |\d+\. )", "", lines[i])
                out.append(f"<li>{_inline(item)}</li>")
                i += 1
            out.append(f"</{tag}>")
        else:
            para = []
            while i < len(lines) and lines[i].strip() and not re.match(block_start, lines[i]):
                para.append(lines[i])
                i += 1
            out.append(f"<p>{_inline(' '.join(para))}</p>")
    return "\n".join(o for o in out if o)


def md_to_html(md: str, title: str, inserts: dict | None = None,
               ioc_matches: list[dict] | None = None,
               article_briefs: dict | None = None) -> str:
    """Standalone HTML page. With `inserts` (the reports) the visual layer is added: badges,
    tiles, diagrams and the interactive findings table."""
    from . import visual
    from . import ioc_archive
    if inserts is not None and ioc_matches:
        inserts = {**inserts, "IOC matches": [{"replace_table": ioc_archive.table_html(ioc_matches)}]}
    body = md_body(md, inserts)
    script = ""
    if inserts is not None:
        body, script = visual.decorate(body), visual.SCRIPT
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)} · {PRODUCT_NAME}</title><link rel=\"icon\" href=\"{icon_data_uri()}\">{THEME_INIT}<style>{CSS}{visual.VISUAL_CSS}"
            f"{ioc_archive.CSS if ioc_matches else ''}</style></head><body>"
            + theme_control()
            + body + script + ioc_archive.drawer_html(ioc_matches or [], article_briefs) + "</body></html>\n")


# ---------------------------------------------------------------- write all
FINDING_COLUMNS = ["priority", "score", "likelihood", "host", "hostname", "port", "proto", "service",
                   "plugin_id", "plugin_name", "severity_name", "cvss", "cves", "exploit_available",
                   "exposure", "external_sources", "internal_sources", "established_sessions",
                   "blocked_sessions", "blast_factor", "reachable_hosts", "vulnerable_pivots",
                   "indicators", "solution"]


def write_all(res: dict, ds, outdir: str) -> dict[str, str]:
    os.makedirs(os.path.join(outdir, "normalized"), exist_ok=True)
    paths = {}

    def w(name, text):
        p = os.path.join(outdir, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        paths[name] = p

    ex, tech = executive_summary(res), technical_report(res)
    w("executive_summary.md", ex)
    from . import visual
    from .diagram import hostile_activity_svg
    w("executive_summary.html", md_to_html(ex, "Executive Summary", visual.executive_inserts(res),
                                           res.get("ioc_matches"), res.get("article_briefs")))
    w("technical_report.md", tech)
    w("technical_report.html", md_to_html(tech, "Technical Analysis", visual.technical_inserts(res),
                                         res.get("ioc_matches"), res.get("article_briefs")))
    w("hostile_activity.svg", hostile_activity_svg(res, standalone=True))
    from . import explore
    w("explorer.html", explore.html(explore.build(res, ds)))
    w("results.json", json.dumps(res, indent=2, default=str))

    blast = {h["host"]: h["blast"] for h in res["hosts"]}
    p = os.path.join(outdir, "correlated_findings.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cw.writerow(FINDING_COLUMNS)
        for r in res["findings"]:
            e, b = r["exposure"], blast[r["host"]]
            cw.writerow([r["priority"], r["score"], r["likelihood"], r["host"], r["hostname"], r["port"],
                         r["proto"], r["service"], r["plugin_id"], r["plugin_name"], r["severity_name"],
                         r["cvss"], " ".join(r["cves"]), r["exploit_available"], e["label"],
                         e["external_sources"], e["internal_sources"], e["established"], e["denied"],
                         r["blast_factor"], b["reachable_count"], " ".join(b["vulnerable_pivots"]),
                         " | ".join(i["text"] for i in r["indicators"]), _short(r["solution"], 500)])
    paths["correlated_findings.csv"] = p

    p = os.path.join(outdir, "normalized", "flows.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cols = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "action", "established",
                "bytes_out", "bytes_in", "app", "src_zone", "dst_zone", "source"]
        cw.writerow(cols)
        for f in ds.flows:
            cw.writerow([(f.ts.isoformat() if f.ts else "") if c == "ts" else getattr(f, c) for c in cols])
    paths["normalized/flows.csv"] = p

    p = os.path.join(outdir, "normalized", "findings.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cols = ["host_ip", "hostname", "os", "port", "proto", "service", "plugin_id", "plugin_name",
                "severity", "cvss", "cvss_version", "cves", "exploit_available", "exploit_frameworks", "source"]
        cw.writerow(cols)
        for f in ds.findings:
            row = [getattr(f, c) for c in cols]
            row[cols.index("cves")] = " ".join(f.cves)
            row[cols.index("exploit_frameworks")] = " ".join(f.exploit_frameworks)
            cw.writerow(row)
    paths["normalized/findings.csv"] = p
    for name, events in (("zeek_events.jsonl", ds.zeek_events), ("ot_events.jsonl", ds.ot_events)):
        p = os.path.join(outdir, "normalized", name)
        with open(p, "w", encoding="utf-8") as fh:
            for e in events:
                row = {"ts": e.ts.isoformat() if e.ts else None,
                       "stream": e.stream, "uid": e.uid, "src_ip": e.src_ip,
                       "dst_ip": e.dst_ip, "source": e.source, "fields": e.fields}
                if name == "ot_events.jsonl":
                    row.update(protocol=e.protocol, operation=e.operation, direction=e.direction)
                fh.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
        paths["normalized/" + name] = p
    return paths


def save_article_briefs(res: dict, outdir: str) -> None:
    """Refresh standalone pages after briefs are generated for an existing run."""
    from . import explore, visual

    pages = {}
    for name, title, inserts in (
        ("executive_summary", "Executive Summary", visual.executive_inserts(res)),
        ("technical_report", "Technical Analysis", visual.technical_inserts(res)),
    ):
        with open(os.path.join(outdir, name + ".md"), encoding="utf-8") as fh:
            markdown = fh.read()
        pages[name + ".html"] = md_to_html(markdown, title, inserts,
                                            res.get("ioc_matches"), res.get("article_briefs"))

    with open(os.path.join(outdir, "explorer.html"), encoding="utf-8") as fh:
        previous = fh.read()
    match = re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', previous, re.S)
    if not match:
        raise ValueError("Cannot find the saved Explorer data for this run.")
    explorer_data = json.loads(match.group(1))
    explorer_data["article_briefs"] = res.get("article_briefs", {})
    explorer_data["ioc_matches"] = res.get("ioc_matches", [])
    pages["explorer.html"] = explore.html(explorer_data)
    pages["results.json"] = json.dumps(res, indent=2, default=str)

    for name, content in pages.items():
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=outdir, delete=False) as fh:
            fh.write(content)
            temporary = fh.name
        os.replace(temporary, os.path.join(outdir, name))
