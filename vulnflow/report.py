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
from .branding import brand_html, icon_data_uri, product_name
from .theme_backgrounds import texture_data


def _c(v) -> str:
    """Make a value safe for a Markdown table cell."""
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def _name(host: str, hostname: str) -> str:
    return f"{hostname} ({host})" if hostname else host


def _networks_table(res: dict) -> list[str]:
    """Per-network host counts; only present when a network map was supplied."""
    nets = res.get("networks")
    if not nets:
        return []
    L = ["", "## Networks", "", "From the supplied network map.", "",
         "| Network | Type | Ranges | Hosts scanned | With findings | P1 hosts |", "|---|---|---|---|---|---|"]
    for n in nets:
        L.append(f"| {_c(n['name'])} | {_c(n['type'] or '-')} | {_c(', '.join(n['ranges']) or '-')} | "
                 f"{n['scanned']} | {n['with_findings']} | {n['p1']} |")
    return L


def _net(r) -> str:
    return f" [{r['network']}]" if r.get("network") else ""


def _plural(n, word, plural=None):
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _short(text: str, n=140) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "..."


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _svc(r) -> str:
    return "host-level" if r["port"] == 0 else f"{r['port']}/{r['proto']}" + (f" ({r['service']})" if r["service"] else "")


def _hosts_seen(cov: dict) -> str:
    """'N internal hosts sent or answered traffic', plus the addresses that were only probed."""
    n, dead = cov["telemetry_internal_hosts"], cov.get("probed_only_addresses", 0)
    text = f"{n:,} internal {'host' if n == 1 else 'hosts'} sent or answered traffic."
    if dead:
        text += (f" {dead:,} more internal {'address was' if dead == 1 else 'addresses were'} only probed "
                 "and never answered; they are not counted as hosts and are listed in "
                 "`normalized/probed_addresses.csv`.")
        blocked = cov.get("probed_blocked_addresses", 0)
        if blocked:
            text += (f" For {blocked:,} of them a firewall log shows the traffic was blocked, so a host "
                     "may exist behind the firewall.")
        top = cov.get("probed_only_subnets") or []
        if top:
            text += (" Most probed: " + ", ".join(f"{sn} ({n})" for sn, n in top[:5])
                     + (f" and {len(top) - 5} more ranges" if len(top) > 5 else "") + ".")
    if cov.get("one_way_capture_suspected"):
        text += (f" **Check the sensor:** only {cov.get('sessions_answered_pct')}% of sessions show any answer, "
                 "which usually means it sees one direction of the traffic. Hosts that exist may be "
                 "missing from this report.")
    return text


def _scanner_lines(res: dict, technical: bool, heading: str = "## Scanning hosts") -> list[str]:
    """Hosts whose traffic looks like scanning. Expected scanners (your list, or the Nessus scanner)
    are named as such; the rest are left for review."""
    found = res["summary"].get("traffic_scanners") or []
    if not found:
        return []
    total = res["summary"].get("traffic_scanners_total", len(found))
    unknown = [e for e in found if not e["expected"]]
    L = [heading, "",
         f"{total} {'host' if total == 1 else 'hosts'} probed many addresses or ports with mostly failed "
         f"sessions. {len(unknown)} {'is' if len(unknown) == 1 else 'are'} not on your list of expected "
         "scanners and should be reviewed: a scan can be an administrator's tool, a misconfigured "
         "system or an intruder mapping the network.", ""]
    shown = found if technical else found[:10]
    L += ["| Host | Status | Kind | Sessions | Addresses | Ports | Failed |", "|---|---|---|---:|---:|---:|---:|"]
    for e in shown:
        status = ("Expected" + (f": {_c(e['name'])}" if e["name"] else "")) if e["expected"] else "**Review**"
        where = "" if e["internal"] else " (outside)"
        failed = "from a Zeek notice" if e["failed_pct"] is None else f"{e['failed_pct']}%"
        L.append(f"| {_c(e['ip'])}{where} | {status} | {e['kind']} | {e['sessions']:,} | {e['hosts']:,} | "
                 f"{e['ports']:,} | {failed} |")
    if total > len(shown):
        L += ["", f"{total - len(shown)} more {'is' if total - len(shown) == 1 else 'are'} listed in "
                  + ("results.json." if technical else "the technical report.")]
    return L + [""]


def _report_intro(res: dict) -> list[str]:
    """The analyst's report name and description, under the page title (nothing when not given)."""
    r = res.get("report") or {}
    L = [f"**Report:** {r['name']}", ""] if r.get("name") else []
    for para in (r.get("description") or "").split("\n\n"):
        if para.strip():
            L += ["> " + ln for ln in para.splitlines() if ln.strip()] + [""]
    return L


def _tab_title(res: dict, title: str) -> str:
    name = (res.get("report") or {}).get("name")
    return f"{name} · {title}" if name else title


def _telemetry_report(res: dict, technical: bool) -> str:
    """Describe observations without turning missing scan data into zero risk."""
    s = res["summary"]
    title = "Technical Analysis" if technical else "Executive Summary"
    lines = [f"# {product_name()}: {title}", "", *_report_intro(res), "## Vulnerability status: unknown", "",
             "No vulnerability data is available for this run. No CVSS scores, vulnerability priorities, "
             "or conclusions about safety can be drawn from the supplied network telemetry.", "",
             f"{s['flows']:,} network sessions and {s['threat_alerts']} IPS/IDS alerts were parsed. "
             f"Observed window: {s['window_start'] or 'unknown'} to {s['window_end'] or 'unknown'}.", "",
             "## Network observations", "",
             f"{s['hosts_with_findings']} hosts have scored vulnerability findings. "
             f"{_hosts_seen(res['coverage'])} "
             "Observed connections show activity and reachability, not whether a service is vulnerable.", ""]
    if technical:
        lines += ["## Inputs and data quality", "",
                  "| File | Format | Records read | Kept | Notes |", "|---|---|---|---|---|"]
        for item in res["inputs"]:
            lines.append(f"| {_c(item['file'])} | {_c(item['format'])} | {item['read']} | "
                         f"{item['kept']} | {_c('; '.join(item['notes']))} |")
        lines += ["", "## Observed hosts", "", "| Host | Inbound sessions | Outbound sessions |",
                  "|---|---:|---:|"]
        for host in res["hosts"]:
            lines.append(f"| {_c(host['host'])} | {host['inbound_flows']} | {host['outbound_flows']} |")
        lines += [""]
    lines += _scanner_lines(res, technical)
    lines += ["## IPS/IDS leads", "",
              "Alerts describe sensor detections. A blocked alert is a stopped attempt; an unblocked alert "
              "does not prove exploitation.", ""]
    if res["telemetry_leads"]:
        for lead in res["telemetry_leads"]:
            side = (" (as the source)" if lead.get("role") == ["source"] else
                    " (as target and as source)" if len(lead.get("role", [])) > 1 else "")
            lines.append(f"- **{_c(lead['host'])}**{side}: {lead['unblocked']} unblocked, "
                         f"{lead['blocked']} blocked alert(s); signatures: "
                         f"{_c(', '.join(lead['signatures'][:5]))}.")
    else:
        lines.append("No IPS/IDS alerts were supplied or parsed.")
    lines += ["", "## Connection leads", "",
              "A return connection after outside contact can be routine. Review context before treating it as suspicious.", ""]
    if res.get("network_leads"):
        for lead in res["network_leads"][:50]:
            lines.append(f"- **{_c(lead['host'])}** connected to {_c(lead['peer'])} "
                         f"in {lead['sessions']} session(s) after inbound contact.")
    else:
        lines.append("No return connections of this kind were observed.")
    lines += ["", "## Next steps", "",
              "1. Review alerts and exact IOC matches against surrounding telemetry and host logs.",
              "2. Obtain vulnerability scan data before assigning CVSS scores or remediation priorities.",
              "3. Confirm suspicious behavior with host evidence; network observations alone cannot prove compromise.", ""]
    report = "\n".join(lines) + "\n"
    if "ioc_matches" in res:
        from .ioc_archive import markdown_section
        report += "\n" + markdown_section(res["ioc_matches"])
    return report


# ---------------------------------------------------------------- executive
def executive_summary(res: dict) -> str:
    if not res["summary"].get("vulnerability_data_available", True):
        return _telemetry_report(res, False)
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

    L = [f"# {product_name()}: Executive Summary", "", *_report_intro(res),
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
    L += _networks_table(res)
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
        L.append(f"{i}. **{_name(r['host'], r['hostname'])}**{_net(r)}: {r['plugin_name']}{cve}. "
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
    if not res["summary"].get("vulnerability_data_available", True):
        return _telemetry_report(res, True)
    s, cov, F, H, cfg = res["summary"], res["coverage"], res["findings"], res["hosts"], res["config"]
    L = [f"# {product_name()}: Technical Analysis", "", *_report_intro(res),
         f"Generated {res['generated']}. Telemetry window {s['window_start'] or 'n/a'} to {s['window_end'] or 'n/a'}.",
         "", "## 1. Inputs and data quality", "",
         "| File | Format | Records read | Kept | Dropped | Notes |", "|---|---|---|---|---|---|"]
    for i in res["inputs"]:
        dropped = ", ".join(f"{n} {k}" for k, n in i["dropped"].items()) or "0"
        L.append(f"| {_c(i['file'])} | {i['format']} | {i['read']} | {i['kept']} | {_c(dropped)} | {_c('; '.join(i['notes']))} |")
    L += ["", f"Exact duplicate sessions removed: {s['duplicate_flows_removed']}. "
              f"Sessions seen by two sensors counted once: {s.get('cross_sensor_duplicates_removed', 0)}. "
              f"Duplicate findings merged across scans: {s['duplicate_findings_merged']}. "
              f"IPS/IDS alerts loaded: {s.get('threat_alerts', 0)}. "
              + (f"Sessions started by the vulnerability scanner ({', '.join(s['scanner_ips'])}) are not "
                 f"counted as use of a service: {s.get('scanner_sessions_excluded', 0)}. " if s.get("scanner_ips") else "")
              + f"Internal address space: {', '.join(cfg['internal_nets'])}.",
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
          "0.75 reached internally; 0.45 attempts only; 0.35 blocked by firewall or refused by the host; 0.3 service not observed in use; "
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
    L += _networks_table(res)
    L += ["", "## 4. Host details", ""]
    by_host = {}
    for r in F:
        by_host.setdefault(r["host"], []).append(r)
    for h in H:
        bl = h["blast"]
        L += [f"### {_name(h['host'], h['hostname'])} - {PRIORITY_LABELS[h['priority']]}", "",
              f"- Operating system: {h['os'] or 'unknown'}",
              *([f"- Network: {h['network']}"] if h.get("network") else []),
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
                         f"{e['attempts']} attempts, {e['denied']} blocked"
                         + (f", {e['refused']} refused by the host" if e.get('refused') else "")
                         + f"; first {e['first_seen']}, last {e['last_seen']}"
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
          f"{_hosts_seen(cov)}", ""]
    if cov["scanned_not_seen"]:
        L += ["**Scanned but not seen in telemetry** (exposure unknown; check sensor placement): "
              + ", ".join(cov["scanned_not_seen"]), ""]
    if cov["active_servers_not_scanned"]:
        L += ["**Active internal servers not in the scan** (add to scan scope):", "",
              "| Host | Services observed | Sessions |", "|---|---|---|"]
        for g in cov["active_servers_not_scanned"][:25]:
            L.append(f"| {g['ip']} | {_c(', '.join(g['services']))} | {g['sessions']} |")
        L.append("")
    L += _scanner_lines(res, True, "**Scanning hosts**")
    L += ["## 6. Output files", "",
          "- `executive_summary.md/.html`: leadership summary",
          "- `technical_report.md/.html`: this report",
          "- `correlated_findings.csv`: one row per finding with scores, for ticketing or spreadsheets",
          "- `results.json`: full machine-readable result",
          "- `hostile_activity.svg`: the hostile activity diagram as a standalone image",
          "- `explorer.html`: interactive host explorer (who targets each host, and its internal blast radius)",
          "- `normalized/flows.csv`, `normalized/findings.csv`: cleaned inputs in the common schema",
          "- `normalized/threats.csv`: IPS/IDS alerts (signature, action and addresses)",
          "- `normalized/zeek_events.jsonl`: other Zeek streams with stream identity and source fields",
          "- `normalized/ot_events.jsonl`: industrial protocol records with operation and message direction"]
    report = "\n".join(L) + "\n"
    if "ioc_matches" in res:
        from .ioc_archive import markdown_section
        report += "\n" + markdown_section(res["ioc_matches"])
    return report


# ---------------------------------------------------------------- HTML
# Pages open in the default theme until one is picked (the browser remembers the pick). Pages that
# can't read the browser's choice (reopened reports and comparisons are sandboxed) always use it.
# The Explorer applies the same default in explorer.js.
DEFAULT_THEME = "graphite"
THEMES = (
    ("graphite", "Graphite"), ("dark", "SOC Dark"), ("amphibious", "Amphibious"), ("olive-drab", "Olive Drab"),
    ("matrix", "Matrix"), ("high-contrast", "High Contrast"), ("light", "Light"),
)

# Restrained themes share one structure (flat surfaces, one accent, one type scale); see html[data-calm] in CSS.
CALM_THEMES = ("graphite", "amphibious", "olive-drab", "matrix", "high-contrast", "light")

# Start of every page: the default theme is on <html> already, so a page shown without JavaScript
# (a file preview, for one) is in it too; THEME_INIT, or explorer.js, then applies the picked theme.
HTML_OPEN = (f'<!doctype html><html lang="en" data-theme="{DEFAULT_THEME}"'
             + (" data-calm" if DEFAULT_THEME in CALM_THEMES else "") + ">")

THEME_INIT = """<script>
const supportedThemes = new Set(__THEMES__);
let savedTheme = __DEFAULT__;
try { savedTheme = localStorage.getItem('vulnflow-theme') || __DEFAULT__; } catch (_) {}
const calmThemes = new Set(__CALM__);
function vfSetTheme(name) {
  const root = document.documentElement;
  root.dataset.theme = supportedThemes.has(name) ? name : __DEFAULT__;
  root.toggleAttribute('data-calm', calmThemes.has(root.dataset.theme));
}
vfSetTheme(savedTheme);
</script>""".replace("__THEMES__", json.dumps([value for value, _ in THEMES])).replace(
    "__CALM__", json.dumps(list(CALM_THEMES))).replace("__DEFAULT__", json.dumps(DEFAULT_THEME))


def theme_control() -> str:
    options = "".join(f'<option value="{value}">{label}</option>' for value, label in THEMES)
    return (f'<div class="theme-bar"><span class="theme-brand">{brand_html()}</span>'
            f'<label for="theme-choice">Theme</label><select id="theme-choice" aria-label="Theme">{options}</select></div>'
            '<script>(function(){const s=document.getElementById("theme-choice");'
            'const root=document.documentElement;'
            's.value=[...s.options].some(o=>o.value===root.dataset.theme)?root.dataset.theme:"' + DEFAULT_THEME + '";'
            's.addEventListener("change",()=>{vfSetTheme(s.value);'
            'try{localStorage.setItem("vulnflow-theme",s.value)}catch(_){}})})();</script>')


CSS = """
:root,[data-theme="dark"]{--desktop:#020617;--bg:#020617;--fg:#f1f5f9;--muted:#cbd5e1;--line:#334155;--head:#1e293b;--accent:#22d3ee;--accent-text:#082f49;--code:#1e293b;--panel:#0f172a;--radius:10px;--bar:#020617;--shadow:none;--background-art:url('__DARK_TEXTURE__');--background-overlay:linear-gradient(#02061755,#020617aa);--body-tint:#020617dd}
[data-theme="light"]{--desktop:#f7f7f5;--bg:#f7f7f5;--fg:#1b1c1e;--muted:#5c5e62;--line:#e2e2de;--head:#f0f0ed;--accent:#0f6f80;--accent-text:#ffffff;--code:#f0f0ed;--panel:#ffffff;--radius:4px;--bar:#ffffff;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#f7f7f5;--ctl:#ffffff;--ctl-line:#c9c9c4;--ctl-line-hi:#a3a39e;--hover:#ecece8;--accent-hi:#0b5a68;--sel:#e3f1f3}
[data-theme="graphite"]{--desktop:#111214;--bg:#111214;--fg:#e6e6e3;--muted:#a0a19d;--line:#2b2d31;--head:#1b1c20;--accent:#45b0c2;--accent-text:#0c0d0e;--code:#1e2024;--panel:#17181b;--radius:4px;--bar:#0c0d0e;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#111214;--ctl:#1e2024;--ctl-line:#3a3c41;--ctl-line-hi:#505358;--hover:#24262a;--accent-hi:#62c1d1;--sel:#16292e}
[data-theme="olive-drab"]{--desktop:#14160f;--bg:#14160f;--fg:#e8e7dc;--muted:#a5a794;--line:#33382a;--head:#1f2218;--accent:#c2b56e;--accent-text:#14160f;--code:#23271b;--panel:#1a1d14;--radius:4px;--bar:#0f110b;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#14160f;--ctl:#23271b;--ctl-line:#454b38;--ctl-line-hi:#5c6349;--hover:#2a2e20;--accent-hi:#d4c98a;--sel:#2e2d1a}
[data-theme="matrix"]{--desktop:#0a0f0b;--bg:#0a0f0b;--fg:#cfe8d6;--muted:#86a892;--line:#1f2e23;--head:#131c15;--accent:#4ccf7a;--accent-text:#06110a;--code:#16211a;--panel:#0f1611;--radius:4px;--bar:#070b08;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#0a0f0b;--ctl:#16211a;--ctl-line:#2c4233;--ctl-line-hi:#3d5c47;--hover:#1a271e;--accent-hi:#6fdd95;--sel:#11301d}
[data-theme="high-contrast"]{--desktop:#000000;--bg:#000000;--fg:#ffffff;--muted:#e0e0e0;--line:#7a7a7a;--head:#0d0d0d;--accent:#fde047;--accent-text:#000000;--code:#000000;--panel:#000000;--radius:0;--bar:#000000;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#000000;--ctl:#000000;--ctl-line:#ffffff;--ctl-line-hi:#fde047;--hover:#1a1a1a;--accent-hi:#fff27a;--sel:#333000}
[data-theme="amphibious"]{--desktop:#0f1729;--bg:#0f1729;--fg:#f2ede1;--muted:#c8c0af;--line:#3a4a6b;--head:#1f3052;--accent:#ffc72c;--accent-text:#0f1729;--code:#26375a;--panel:#1b2a47;--radius:3px;--bar:#0f1729;--shadow:none;--background-art:none;--background-overlay:none;--body-tint:#0f1729;--ctl:#26375a;--ctl-line:#526484;--ctl-line-hi:#7186a8;--hover:#34466a;--accent-hi:#ffdc70;--sel:#2c3a52}
html{background-color:var(--desktop);background-image:var(--background-overlay),var(--background-art);background-position:center;background-size:cover;background-attachment:fixed;color-scheme:dark}
[data-theme="light"]{color-scheme:light}
*{box-sizing:border-box}
body{background:var(--body-tint);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;max-width:1100px;min-height:100vh;margin:0 auto;padding:24px 22px;box-shadow:var(--shadow)}
h1{font-size:1.65rem;margin-top:.8rem}h2{margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
h3{margin-top:1.8rem;color:var(--accent)}h4{margin-bottom:.3rem}
a{color:var(--accent)}a:focus-visible,button:focus-visible,select:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.theme-bar{display:flex;align-items:center;gap:.65rem;padding:.55rem .8rem;margin:-24px -22px 24px;background:var(--bar);border-bottom:1px solid var(--line);color:var(--fg)}
.theme-brand{display:inline-flex;align-items:center;gap:.45rem;font-weight:800;letter-spacing:.02em;margin-right:auto;min-width:0}.brand-logo{height:36px;width:auto;max-width:180px;object-fit:contain;flex:none}.brand-logo.logo-small{height:24px;max-width:96px}.theme-bar label{font-size:.82rem;margin:0}.theme-bar select{max-width:180px;padding:.25rem .4rem;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--fg);font:inherit}
form,.msg{background:var(--panel)}button{background:var(--accent);color:var(--accent-text);border:1px solid var(--accent);border-radius:var(--radius);cursor:pointer}button:hover{filter:brightness(1.08)}
input,textarea,select{accent-color:var(--accent)}input[type=text],input[type=password],textarea,select{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:var(--radius)}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.9rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--head)}
code{background:var(--code);padding:1px 4px;border-radius:3px}li{margin:.2rem 0}
pre{background:var(--code);padding:10px;border-radius:var(--radius);overflow-x:auto}pre code{padding:0}
blockquote{margin:.8rem 0;padding:.4rem .9rem;border-left:3px solid var(--accent);color:var(--muted)}
/* Restrained themes (html[data-calm]: every theme except SOC Dark): flat neutral surfaces, one accent, one type scale (22/16/14/13/12), 4px grid; no textures, glows or shadows */
[data-calm] body{font-size:14px;line-height:1.5;padding:24px}
[data-calm] h1{font-size:22px;font-weight:600;letter-spacing:-.005em;margin:8px 0 16px}
[data-calm] h2{font-size:16px;font-weight:600;margin-top:32px;padding-bottom:8px}
[data-calm] h3{font-size:14px;font-weight:600;color:var(--fg);margin-top:24px}
[data-calm] h4{font-size:13px;font-weight:600;color:var(--muted)}
[data-calm] a{text-decoration:none}[data-calm] a:hover{text-decoration:underline}
[data-calm] a:focus-visible,[data-calm] button:focus-visible,[data-calm] select:focus-visible,[data-calm] input:focus-visible,[data-calm] textarea:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
[data-calm] .theme-bar{margin:-24px -24px 24px;padding:8px 16px;gap:8px}
[data-calm] .theme-brand{font-weight:600;font-size:14px;letter-spacing:0}
[data-calm] .theme-bar label{margin:0;font-size:12px;color:var(--muted);font-weight:400}
[data-calm] .theme-bar select{font-size:13px;padding:4px 8px;background:var(--bg)}
[data-calm] button{font-size:13px;font-weight:600;padding:7px 14px}
[data-calm] button:hover{filter:none;background:var(--accent-hi);border-color:var(--accent-hi)}
[data-calm] button.secondary,[data-calm] .ftools button{background:var(--head);color:var(--fg);border-color:var(--ctl-line);font-weight:500}
[data-calm] button.secondary:hover,[data-calm] .ftools button:hover{background:var(--hover);border-color:var(--ctl-line-hi)}
[data-calm] .ftools button[aria-pressed="true"]{background:var(--sel);color:var(--fg);border-color:var(--accent)}
[data-calm] input[type=text],[data-calm] input[type=password],[data-calm] textarea,[data-calm] select{background:var(--bg);border-color:var(--ctl-line);font-size:13px}
[data-calm] input[type=text],[data-calm] input[type=password],[data-calm] textarea{padding:7px 8px}
[data-calm] label{font-size:13px;font-weight:600}[data-calm] .hint{font-size:12.5px}
[data-calm] table{font-size:13px}
[data-calm] th,[data-calm] td{border:0;border-bottom:1px solid var(--line);padding:7px 10px}
[data-calm] th{font-weight:600;color:var(--muted)}
[data-calm] code{font-size:12.5px}
[data-calm] .hint{margin-top:6px}[data-calm] label{margin-top:20px}
[data-calm] form{background:none;border:0;padding:0;margin:8px 0 24px}
[data-calm] th{text-transform:none;letter-spacing:0;font-size:12px}
[data-calm] #pk-list li::before{content:"";display:inline-block;width:14px;height:14px;margin-right:8px;vertical-align:-2px;background:var(--muted);-webkit-mask:var(--ico-folder) center/contain no-repeat;mask:var(--ico-folder) center/contain no-repeat}
[data-calm]{--ico-folder:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='black' stroke-width='1.5' stroke-linejoin='round'%3E%3Cpath d='M1.75 4.25v8h12.5v-6.5H8L6.5 4.25z'/%3E%3C/svg%3E")}
[data-calm] blockquote{border-left-width:2px;border-left-color:var(--line)}
[data-theme="amphibious"] .theme-bar{border-bottom:3px solid #ba0c2f}
[data-theme="high-contrast"][data-calm] a{text-decoration:underline}
[data-theme="high-contrast"][data-calm] th{color:var(--fg)}
[data-theme="high-contrast"][data-calm] button.secondary,[data-theme="high-contrast"][data-calm] .ftools button{background:#000}
[data-theme="matrix"] body{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
@media(max-width:600px){body{padding:16px}.theme-bar{margin:-16px -16px 20px}.theme-brand{font-size:.9rem}.theme-bar select{max-width:145px}}
@media print{html{background:#fff;color-scheme:light}body{box-shadow:none;max-width:none;padding:0;background:#fff;color:#000}.theme-bar{display:none}a{color:#000}}
"""
CSS = CSS.replace("__DARK_TEXTURE__", texture_data("signal"))


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
    return (f"{HTML_OPEN}<head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)} · {html.escape(product_name())}</title><link rel=\"icon\" href=\"{icon_data_uri()}\">{THEME_INIT}<style>{CSS}{visual.VISUAL_CSS}"
            f"{ioc_archive.CSS if ioc_matches else ''}</style></head><body>"
            + theme_control()
            + body + script + ioc_archive.drawer_html(ioc_matches or [], article_briefs) + "</body></html>\n")


# ---------------------------------------------------------------- write all
FINDING_COLUMNS = ["priority", "score", "likelihood", "host", "hostname", "port", "proto", "service",
                   "plugin_id", "plugin_name", "severity_name", "cvss", "cves", "exploit_available",
                   "exposure", "external_sources", "internal_sources", "established_sessions",
                   "blocked_sessions", "blast_factor", "reachable_hosts", "vulnerable_pivots",
                   "indicators", "solution", "refused_sessions"]


_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(v):
    """Neutralise spreadsheet formulas in text taken from logs (CSV injection): a cell such as
    ``=HYPERLINK(...)`` is written as ``'=HYPERLINK(...)`` so Excel and Sheets show it as text."""
    if isinstance(v, str) and len(v) > 1 and v.startswith(_FORMULA_START):
        return "'" + v
    return v


def csv_row(values) -> list:
    """A CSV row with every text cell neutralised against spreadsheet formulas (see _cell)."""
    return [_cell(v) for v in values]


def write_reports(res: dict, outdir: str) -> dict[str, str]:
    """The pages and files built from ``results.json`` alone: summaries, technical report,
    hostile-activity diagram, results.json itself and the correlated findings CSV. Used by a
    fresh analysis and when a saved results.json is reopened."""
    os.makedirs(outdir, mode=0o700, exist_ok=True)
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
    telemetry_only = not res["summary"].get("vulnerability_data_available", True)
    w("executive_summary.html", md_to_html(ex, _tab_title(res, "Executive Summary"), None if telemetry_only else visual.executive_inserts(res),
                                           res.get("ioc_matches"), res.get("article_briefs")))
    w("technical_report.md", tech)
    w("technical_report.html", md_to_html(tech, _tab_title(res, "Technical Analysis"), None if telemetry_only else visual.technical_inserts(res),
                                         res.get("ioc_matches"), res.get("article_briefs")))
    if not telemetry_only:
        w("hostile_activity.svg", hostile_activity_svg(res, standalone=True))
    w("results.json", json.dumps(res, indent=2, default=str))

    blast = {h["host"]: h["blast"] for h in res["hosts"]}
    p = os.path.join(outdir, "correlated_findings.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cw.writerow(FINDING_COLUMNS)
        for r in res["findings"]:
            e, b = r["exposure"], blast[r["host"]]
            cw.writerow(csv_row([r["priority"], r["score"], r["likelihood"], r["host"], r["hostname"], r["port"],
                         r["proto"], r["service"], r["plugin_id"], r["plugin_name"], r["severity_name"],
                         r["cvss"], " ".join(r["cves"]), r["exploit_available"], e["label"],
                         e["external_sources"], e["internal_sources"], e["established"], e["denied"],
                         r["blast_factor"], b["reachable_count"], " ".join(b["vulnerable_pivots"]),
                         " | ".join(i["text"] for i in r["indicators"]), _short(r["solution"], 500),
                         e.get("refused", 0)]))
    paths["correlated_findings.csv"] = p
    return paths


def write_all(res: dict, ds, outdir: str) -> dict[str, str]:
    os.makedirs(os.path.join(outdir, "normalized"), mode=0o700, exist_ok=True)
    paths = write_reports(res, outdir)
    from . import explore
    p = os.path.join(outdir, "explorer.html")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(explore.html(explore.build(res, ds)))
    paths["explorer.html"] = p

    p = os.path.join(outdir, "normalized", "flows.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cols = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "action", "established",
                "bytes_out", "bytes_in", "app", "src_zone", "dst_zone", "source"]
        cw.writerow(cols)
        for f in ds.flows:
            cw.writerow(csv_row((f.ts.isoformat() if f.ts else "") if c == "ts" else getattr(f, c) for c in cols))
    paths["normalized/flows.csv"] = p

    # every internal address that was probed and never answered: not a host, but nothing is dropped
    from .correlate import _Net
    from .store import utc
    net = _Net(res["config"]["internal_nets"])
    p = os.path.join(outdir, "normalized", "probed_addresses.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cw.writerow(["address", "probed_by", "sources", "ports_tried", "attempts", "blocked_by_firewall",
                     "first_seen", "last_seen"])
        for ip, srcs, n_src, ports, n, blocked, first, last in ds.flow_store().probed_rows():
            if ip in ds.scanned_hosts or not net.internal(ip):
                continue
            cw.writerow(csv_row([ip, " ".join(srcs), n_src, " ".join(str(x) for x in ports), n,
                                 "yes" if blocked else "no",
                                 utc(first).isoformat() if first else "", utc(last).isoformat() if last else ""]))
    paths["normalized/probed_addresses.csv"] = p

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
            cw.writerow(csv_row(row))
    paths["normalized/findings.csv"] = p

    p = os.path.join(outdir, "normalized", "threats.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cols = ["ts", "src_ip", "dst_ip", "dst_port", "name", "severity", "action", "source"]
        cw.writerow(cols)
        for t in ds.threats:
            cw.writerow(csv_row((t.ts.isoformat() if t.ts else "") if c == "ts" else getattr(t, c) for c in cols))
    paths["normalized/threats.csv"] = p
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
        ("executive_summary", "Executive Summary", None if not res["summary"].get("vulnerability_data_available", True) else visual.executive_inserts(res)),
        ("technical_report", "Technical Analysis", None if not res["summary"].get("vulnerability_data_available", True) else visual.technical_inserts(res)),
    ):
        with open(os.path.join(outdir, name + ".md"), encoding="utf-8") as fh:
            markdown = fh.read()
        pages[name + ".html"] = md_to_html(markdown, _tab_title(res, title), inserts,
                                            res.get("ioc_matches"), res.get("article_briefs"))

    explorer_path = os.path.join(outdir, "explorer.html")
    if os.path.exists(explorer_path):           # a run reopened from results.json alone has none
        with open(explorer_path, encoding="utf-8") as fh:
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
