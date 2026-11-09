"""Built-in offline Security Assistant: explains one run's results without any AI model.

Everything here is assembled from results.json by fixed rules and templates, so it works with
no provider, no API key and no network, and gives the same answer every time. It reads the
full results (not the trimmed context a model gets), so it can explain any host, CVE, plugin
or IOC in the run.

Every string that came from scanner output or logs (hostnames, plugin names, signatures) is
treated as data: it is flattened to one line and table-escaped before it goes into Markdown,
and the Markdown renderer escapes all HTML.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict

BANNER = "_Built-in offline assistant: assembled from this run's results by fixed rules. No AI model is used and nothing leaves this machine._"

OWNER = {"corroborated": "SOC / IR", "lead": "SOC / IR"}
PRIO_WORDS = {"P1": "act now", "P2": "this cycle", "P3": "scheduled", "P4": "routine"}
SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0, "": -1}
STOP = {"host", "hosts", "with", "from", "this", "that", "what", "why", "the", "and", "for", "is"}

IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])")
CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.I)
NUM_RE = re.compile(r"\b\d{4,7}\b")

INTENTS = [
    ("help", ("what can you", "help", "how do i use", "what do you know")),
    ("scoring", ("score", "scoring", "calculat", "how is", "how are", "what does p", "mean")),
    ("priorities", ("first", "priorit", "p1", "urgent", "fix", "patch", "top", "worst", "most important", "critical")),
    ("exposure", ("internet", "exposed", "exposure", "external", "inbound", "public", "facing")),
    ("outbound", ("outbound", "callback", "call back", "exfil", "egress", "beacon", "return connection", "upload")),
    ("paths", ("path", "lateral", "pivot", "spread", "blast", "reach", "move", "chain")),
    ("ioc", ("ioc", "indicator", "threat intel", "domain", "match")),
    ("coverage", ("coverage", "not scanned", "unscanned", "missing", "gap", "blind", "wrong", "false")),
    ("compromise", ("compromis", "breach", "exploit", "hacked", "incident", "attack")),
    ("summary", ("summary", "summar", "overview", "brief", "going on", "status", "explain", "results", "tell me")),
]


# ------------------------------------------------------------------ helpers
def _t(value, limit: int = 160) -> str:
    """One line of untrusted text, safe inside Markdown tables and inline formatting."""
    s = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    s = s.replace("|", "\\|").replace("`", "'")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _plural(n, word, many=None):
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _join(items, limit=6):
    items = [str(i) for i in items]
    more = len(items) - limit
    items = items[:limit]
    if more > 0:
        return ", ".join(items) + f" and {more} more"
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _mb(n) -> str:
    return f"{(n or 0) / 1048576:.1f} MB"


def _alerts(lead: dict) -> str:
    n, blocked = lead.get("alerts", 0), lead.get("blocked", 0)
    if blocked and blocked == n:
        return f"{_plural(n, 'IPS/IDS alert')}, all blocked"
    return f"{_plural(n, 'IPS/IDS alert')}" + (f", {blocked} blocked" if blocked else ", not blocked")


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class _Index:
    def __init__(self, res: dict):
        self.res = res
        self.summary = res.get("summary", {})
        self.scan = self.summary.get("vulnerability_data_available", True)
        self.findings = res.get("findings", [])
        self.hosts = {h["host"]: h for h in res.get("hosts", [])}
        self.by_host = defaultdict(list)
        for r in self.findings:
            self.by_host[r["host"]].append(r)
        self.names = {}
        for ip, h in self.hosts.items():
            name = (h.get("hostname") or "").lower()
            if name:
                self.names[name] = ip
                short = name.split(".")[0]
                if len(short) > 3 and short not in STOP:
                    self.names.setdefault(short, ip)
        for r in self.findings:
            name = (r.get("hostname") or "").lower()
            if name:
                self.names.setdefault(name, r["host"])
                short = name.split(".")[0]
                if len(short) > 3 and short not in STOP:
                    self.names.setdefault(short, r["host"])
        self.iocs = res.get("ioc_matches", []) or []
        self.tel_leads = {l["host"]: l for l in res.get("telemetry_leads", []) or []}
        self.net_leads = defaultdict(list)
        for l in res.get("network_leads", []) or []:
            self.net_leads[l["host"]].append(l)

    def label(self, ip: str) -> str:
        h = self.hosts.get(ip) or {}
        name = h.get("hostname") or next((r.get("hostname") for r in self.by_host.get(ip, []) if r.get("hostname")), "")
        return f"{_t(name, 60)} ({ip})" if name else ip

    def indicators(self, ip: str) -> list[dict]:
        seen, out = set(), []
        for r in self.by_host.get(ip, []):
            for i in r.get("indicators", []):
                key = (i.get("type"), i.get("text"))
                if key not in seen:
                    seen.add(key)
                    out.append(dict(i, _finding=r))
        return out

    def host_iocs(self, ip: str) -> list[dict]:
        return [m for m in self.iocs if ip in (m.get("hosts") or [])]

    # -------------------------------------------------- entity lookup
    def entities(self, text: str) -> dict:
        low = (text or "").lower()
        hosts, externals = [], []
        for ip in IP_RE.findall(low):
            if not _is_ip(ip):
                continue
            if ip in self.hosts or ip in self.by_host:
                hosts.append(ip)
            else:
                externals.append(ip)
        for name, ip in sorted(self.names.items(), key=lambda kv: -len(kv[0])):
            if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])", low) and ip not in hosts:
                hosts.append(ip)
        cves = sorted({c.upper() for c in CVE_RE.findall(low)})
        plugins = sorted({n for n in NUM_RE.findall(low) if any(r["plugin_id"] == n for r in self.findings)})
        iocs = [m for m in self.iocs if str(m.get("value", "")).lower() in low and len(str(m.get("value", ""))) > 3]
        return {"hosts": hosts, "externals": externals, "cves": cves, "plugins": plugins, "iocs": iocs}


def _intents(question: str) -> list[str]:
    q = question.lower()
    return [name for name, words in INTENTS if any(w in q for w in words)]


# ------------------------------------------------------------------ filters
def _zeek_filter(src=None, dst=None, port=None) -> str:
    parts = []
    if src:
        parts.append(f'$3=="{src}"')
    if dst:
        parts.append(f'$5=="{dst}"')
    if port:
        parts.append(f'$6=="{port}"')
    cond = " && ".join(parts) or "1"
    return ("zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto conn_state orig_bytes resp_bytes "
            f"< conn.log | awk '{cond}'")


def _pan_filter(src=None, dst=None, port=None) -> str:
    parts = []
    if src:
        parts.append(f"( addr.src in {src} )")
    if dst:
        parts.append(f"( addr.dst in {dst} )")
    if port:
        parts.append(f"( port.dst eq {port} )")
    return " and ".join(parts)


def _checks(src=None, dst=None, port=None) -> list[str]:
    return [f"- Zeek: `{_zeek_filter(src, dst, port)}`",
            f"- Palo Alto (Monitor > Traffic / Threat): `{_pan_filter(src, dst, port)}`"]


# ------------------------------------------------------------------ host explanations
def _finding_table(rows: list[dict], limit: int = 8) -> list[str]:
    out = ["| Priority | Score | Finding | Port | Exposure |", "|---|---|---|---|---|"]
    for r in rows[:limit]:
        cves = _cves(r)
        port = f"{r['port']}/{r['proto']}" if r.get("port") else "host"
        out.append(f"| {r['priority']} | {r['score']} | {_t(r['plugin_name'], 70)}{cves} · plugin {r['plugin_id']} "
                   f"| {port} | {_t(r['exposure']['label'], 60)} |")
    if len(rows) > limit:
        out.append(f"| | | …and {len(rows) - limit} more in the technical report | | |")
    return out


def _explain_host(ix: _Index, ip: str) -> list[str]:
    h = ix.hosts.get(ip, {})
    rows = sorted(ix.by_host.get(ip, []), key=lambda r: -r["score"])
    lines = []
    if ix.scan and rows:
        top = rows[0]
        lines.append(f"## {ix.label(ip)}: {top['priority']} ({PRIO_WORDS.get(top['priority'], '')}), score {top['score']}")
        sev = h.get("by_severity") or Counter(r["severity_name"] for r in rows)
        sev_txt = ", ".join(f"{n} {s}" for s, n in sorted(sev.items(), key=lambda kv: -SEV_ORDER.get(kv[0], 0)))
        os_txt = f" Reported OS: {_t(h.get('os') or top.get('os'), 80)}." if (h.get("os") or top.get("os")) else ""
        lines.append(f"{_plural(len(rows), 'scored finding')} ({sev_txt}).{os_txt}")
        lines += ["", f"**Why it ranks here** (top finding: {_t(top['plugin_name'], 90)}, plugin {top['plugin_id']}):"]
        lines += [f"- {_t(x, 240)}" for x in top.get("rationale", [])[:6]]
        lines += [""] + _finding_table(rows)
    elif ix.scan:
        lines.append(f"## {ix.label(ip)}")
        lines.append("This host appears in the network data but has no scored vulnerability findings "
                     "(not scanned, or nothing at or above the minimum severity).")
    else:
        lines.append(f"## {ix.label(ip)}")
        lines.append("No vulnerability data in this run, so this host's vulnerability status is unknown.")

    if h:
        traffic = (f"**Traffic:** {h.get('inbound_flows', 0)} inbound and {h.get('outbound_flows', 0)} outbound "
                   f"sessions observed")
        if not h.get("telemetry_seen", True):
            traffic = "**Traffic:** no telemetry for this host, so its exposure is unknown (not safe)"
        if h.get("internet_exposed"):
            traffic += "; at least one vulnerable service was reached from the internet"
        lines += ["", traffic + "."]

    inds = ix.indicators(ip)
    lead = ix.tel_leads.get(ip)
    nets = ix.net_leads.get(ip, [])
    if inds or lead or nets:
        lines += ["", "**Signals in the telemetry:**"]
        for i in sorted(inds, key=lambda i: i.get("confidence") != "corroborated"):
            tag = "Corroborated" if i.get("confidence") == "corroborated" else "Lead"
            lines.append(f"- {tag}: {_t(i.get('text'), 360)}")
        if lead:
            lines.append(f"- Lead: {_alerts(lead)}: {_t('; '.join(lead.get('signatures', [])[:3]), 200)}.")
        for n in nets[:3]:
            lines.append(f"- Lead: connected out to {n['peer']} ({_plural(n.get('sessions', 0), 'session')}) after "
                         "inbound contact from it. This can be legitimate.")
    elif ix.scan and rows:
        lines += ["", "**Signals in the telemetry:** no exploitation leads (no IPS/IDS alert on a vulnerable service, "
                  "callback, new lateral connection or large upload after outside contact)."]

    b = h.get("blast") or {}
    if b.get("direct_count") or b.get("reachable_count"):
        lines += ["", f"**Reach if compromised:** talks directly to {_plural(b.get('direct_count', 0), 'internal host')}, "
                  f"{b.get('reachable_count', 0)} within {ix.res.get('config', {}).get('hops', 2)} hops."]
        if b.get("vulnerable_pivots"):
            lines.append(f"- Vulnerable pivots (High/Critical findings): {_join([ix.label(p) for p in b['vulnerable_pivots']], 6)}")
        if b.get("lateral_protocols"):
            lines.append("- Lateral protocols seen: " + ", ".join(f"{_t(k, 20)} ({v})" for k, v in b["lateral_protocols"].items()))
        if b.get("top_external_destinations"):
            lines.append("- Top outside destinations: " + ", ".join(f"{_t(d, 60)} ({n})" for d, n in b["top_external_destinations"][:5]))

    hi = ix.host_iocs(ip)
    if hi:
        lines += ["", "**IOC matches:**"]
        for m in hi[:5]:
            lines.append(f"- {_t(m.get('type'), 20)} `{_t(m.get('value'), 80)}` "
                         f"({_t(m.get('disposition') or 'no disposition', 30)}; source {_t(_join(m.get('sources', []), 3), 80)})")

    lines += ["", "**Next steps:**"] + _host_steps(ix, ip, rows, inds, lead, nets)
    return lines


def _host_steps(ix, ip, rows, inds, lead, nets) -> list[str]:
    steps, filters = [], []

    def step(text, extra=(), label=""):
        steps.append(f"{len(steps) + 1}. {text}")
        if extra:
            filters.append(f"**{label}**")
            filters.extend(extra)

    types = {i.get("type") for i in inds}
    if "corroborated" in types:
        step(f"Start incident response for {ix.label(ip)}: collect host evidence (process, auth and web/app logs, EDR) "
             "before patching wipes it, and consider isolating it. This is likely exploitation, not yet a confirmed compromise.")
    peers = {i.get("peer") for i in inds if i.get("peer")} | {n["peer"] for n in nets}
    for peer in sorted(p for p in peers if p)[:2]:
        step(f"Check every session between {ip} and {peer} (filters below).", _checks(ip, peer),
             f"Sessions {ip} → {peer}:")
    for i in inds:
        if i.get("type") == "new_lateral":
            tg = [t["ip"] for t in i.get("targets", [])]
            step(f"Review the new internal connections to {_join(tg, 5)} for logons and file transfers.")
            break
    if rows:
        top = rows[0]
        if top.get("solution"):
            step(f"Remediate plugin {top['plugin_id']}: {_end(top['solution'], 220)}")
        if top.get("port") and top["exposure"].get("external_sources"):
            step(f"Until patched, restrict who can reach {top['port']}/{top['proto']} from the internet; "
                 "first confirm who uses it (filters below).", _checks(None, ip, top["port"]),
                 f"Who reaches {ip} port {top['port']}:")
    if lead and not rows:
        step(f"Review the IPS/IDS evidence for {ip} and scan the host so its vulnerability status is known.")
    if not steps:
        step("Nothing here needs urgent action; handle remaining findings in the normal patch cycle.")
    if filters:
        steps += ["", "**Log filters to paste:**", ""]
        for f in filters:
            steps += (["", f, ""] if f.startswith("**") else [f])
    return steps


def _end(text, limit=220) -> str:
    """Untrusted sentence, ending in exactly one full stop."""
    return _t(text, limit).rstrip(" .") + "."


def _cves(r, limit=2) -> str:
    """CVE list in brackets, unless the plugin name already shows them."""
    cves = [c for c in r.get("cves", []) if c.lower() not in (r.get("plugin_name") or "").lower()][:limit]
    return f" ({_t(', '.join(cves), 40)})" if cves else ""


# ------------------------------------------------------------------ other explanations
def _explain_finding(ix: _Index, key: str, kind: str) -> list[str]:
    rows = [r for r in ix.findings if (key in r.get("cves", []) if kind == "cve" else r["plugin_id"] == key)]
    if not rows:
        return [f"## {key}", f"{key} does not appear in this run's findings. It may be absent, below the minimum severity, "
                "or on a host that was not scanned."]
    rows.sort(key=lambda r: -r["score"])
    top = rows[0]
    hosts = sorted({r["host"] for r in rows}, key=lambda ip: -max(x["score"] for x in rows if x["host"] == ip))
    lines = [f"## {key}: {_t(top['plugin_name'], 100)}",
             f"{top['severity_name']}, CVSS {top.get('cvss')}, on {_plural(len(hosts), 'host')}. "
             + ("A public exploit is available" + (f" ({_t(', '.join(top['exploit_frameworks']), 60)})" if top.get('exploit_frameworks') else "") + "."
                if top.get("exploit_available") else "No public exploit is recorded by the scanner.")]
    if top.get("synopsis"):
        lines.append(f"Scanner synopsis: {_t(top['synopsis'], 300)}")
    lines += ["", "| Host | Priority | Score | Port | Exposure |", "|---|---|---|---|---|"]
    for r in rows[:12]:
        port = f"{r['port']}/{r['proto']}" if r.get("port") else "host"
        lines.append(f"| {ix.label(r['host'])} | {r['priority']} | {r['score']} | {port} | {_t(r['exposure']['label'], 60)} |")
    if len(rows) > 12:
        lines.append(f"| …and {len(rows) - 12} more | | | | |")
    labels = Counter(r["exposure"]["label"] for r in rows)
    lines += ["", "**What the exposure means:** " + "; ".join(f"{n} × {_t(l, 60).lower()}" for l, n in labels.most_common())
              + ". Exposure comes from observed sessions to the vulnerable port; \"not observed\" is not the same as unreachable."]
    if top.get("solution"):
        lines += ["", f"**Fix:** {_end(top['solution'], 300)}"]
    if top.get("port"):
        lines += ["", f"**Check who reaches it** (top host {top['host']}):"] + _checks(None, top["host"], top["port"])
    return lines


def _explain_external(ix: _Index, ip: str) -> list[str]:
    lines = [f"## {ip} (outside address)"]
    hits = []
    for r in ix.findings:
        for s in r["exposure"].get("top_sources", []):
            if s[0] == ip:
                hits.append(f"- Reached {ix.label(r['host'])} port {r['port']} ({_t(r['plugin_name'], 60)}) {_plural(s[1], 'time')}.")
        for i in r.get("indicators", []):
            if i.get("peer") == ip or any(s[0] == ip for s in i.get("sources", [])):
                hits.append(f"- {_t(i['text'], 300)}")
    for host, leads in ix.net_leads.items():
        for n in leads:
            if n["peer"] == ip:
                hits.append(f"- {ix.label(host)} connected out to it after inbound contact ({_plural(n.get('sessions', 0), 'session')}).")
    hits = list(dict.fromkeys(hits))
    if not hits:
        lines.append("This address does not appear in the findings' top sources or indicators. "
                     "It may still be in the raw sessions; search the normalized flows for it.")
    else:
        lines += hits[:12]
    lines += ["", "**Look it up in the logs:**"] + _checks(ip) + _checks(None, ip)
    return lines


def _explain_ioc(ix: _Index, m: dict) -> list[str]:
    lines = [f"## IOC {_t(m.get('type'), 20)} `{_t(m.get('value'), 80)}`",
             f"Matched on {_join([ix.label(h) for h in m.get('hosts', [])], 6) or 'no internal host'}; "
             f"disposition {_t(m.get('disposition') or 'none', 30)}; source {_t(_join(m.get('sources', []), 3), 80)}; "
             f"indicator first/last seen in the feed {_t(m.get('first_seen') or '?', 30)} / {_t(m.get('last_seen') or '?', 30)}."]
    obs = m.get("observed") or {}
    if obs:
        lines.append("Seen in: " + ", ".join(f"{_t(k, 30)} ({v})" for k, v in obs.items()) + ".")
    lines.append("An IOC match is a lead, not proof: confirm the host actually resolved or contacted it and what followed.")
    return lines


def _scoring() -> list[str]:
    return ["## How scores and priorities work",
            "- **Score** = CVSS × 10 × Exploit × Exposure × Blast radius (× 1.25 with exploitation indicators), capped at 100.",
            "- **Exploit** rises when a public exploit or framework module exists.",
            "- **Exposure** comes from sessions seen to the vulnerable port: from the internet, internal only, blocked, "
            "attempts only, not observed, or no telemetry at all (unknown, which is not treated as safe). "
            "Host-level findings use the host's overall activity.",
            "- **Blast radius** walks completed internal sessions out from the host; reachable hosts with High/Critical "
            "findings are vulnerable pivots.",
            "- **Indicators** are leads (an unblocked IPS/IDS alert, a callback to the address that reached the service, "
            "new lateral connections or large uploads after that contact) or corroborated (an alert plus that behaviour).",
            "- **Priority:** P1 act now, P2 this cycle, P3 scheduled, P4 routine."]


def _help(ix: _Index) -> list[str]:
    examples = []
    if ix.findings:
        top = ix.findings[0]
        name = (top.get("hostname") or top["host"]).split(".")[0]
        examples += [f"\"Why is {name} a {top['priority']}?\"", "\"What should we fix first?\""]
        if top.get("cves"):
            examples.append(f"\"Which hosts have {top['cves'][0]}?\"")
    examples += ["\"Show outbound callbacks\"", "\"What is exposed to the internet?\"", "\"Any lateral movement?\"",
                 "\"Which IOCs matched?\"", "\"What could this analysis be missing?\"", "\"How is the score calculated?\""]
    return ["## What I can explain",
            "I answer from this run's results only: hosts (by IP or name), CVEs, plugin IDs, outside addresses, IOC values, "
            "priorities, internet exposure, outbound callbacks, attack paths, coverage gaps and scoring. "
            "I don't use an AI model, so I can't reason beyond the data or answer general questions.",
            "", "Try: " + ", ".join(examples) + "."]


# ------------------------------------------------------------------ topic sections
def _take(ix: _Index) -> list[str]:
    s = ix.summary
    if not ix.scan:
        leads = len(ix.tel_leads) + sum(len(v) for v in ix.net_leads.values())
        return [f"No vulnerability data is available, so vulnerability status is unknown. {s.get('flows', 0)} sessions and "
                f"{_plural(s.get('threat_alerts', 0), 'IPS/IDS alert')} were parsed between {s.get('window_start') or '?'} and "
                f"{s.get('window_end') or '?'}. {_plural(leads, 'network lead')} and {_plural(len(ix.iocs), 'IOC match', 'IOC matches')} "
                "need review; none of them is proof of compromise on its own."]
    pc = s.get("priority_counts", {})
    corr, inv, spread = s.get("hosts_corroborated", []), s.get("hosts_to_investigate", []), s.get("hosts_possible_spread", [])
    if corr:
        mood = "Treat this as an active incident until ruled out"
    elif inv or spread:
        mood = "There are leads worth investigating today"
    elif pc.get("P1"):
        mood = "No exploitation leads, but there is urgent patching"
    else:
        mood = "Nothing here points to active exploitation"
    out = [f"{mood}. {s.get('findings_scored', 0)} findings were scored on {_plural(s.get('hosts_with_findings', 0), 'host')}: "
           f"P1 {pc.get('P1', 0)}, P2 {pc.get('P2', 0)}, P3 {pc.get('P3', 0)}, P4 {pc.get('P4', 0)}. "
           f"{_plural(s.get('internet_exposed_findings', 0), 'finding')} on a service reached from the internet; "
           f"{s.get('exploitable_and_exposed', 0)} have a public exploit and observed exposure."]
    if corr:
        out.append(f"Corroborated exploitation signals on {_join([ix.label(h) for h in corr])}.")
    if inv:
        out.append(f"Leads to investigate on {_join([ix.label(h) for h in inv])}.")
    if spread:
        out.append(f"Possible spread to {_join([ix.label(h) for h in spread])}.")
    return [" ".join(out)]


def _groups(ix: _Index, prios=("P1",)) -> list[dict]:
    g = {}
    for r in ix.findings:
        if r["priority"] in prios:
            k = r["plugin_id"]
            g.setdefault(k, {"rows": [], "top": r})["rows"].append(r)
    return sorted(g.values(), key=lambda x: (-x["top"]["score"], -len(x["rows"])))


def _priorities(ix: _Index, limit: int = 7) -> list[str]:
    if not ix.scan:
        return ["## What to do first", "1. Get vulnerability scan data for the hosts with leads before assigning priorities."]
    lines, n = ["## What to do first"], 0
    for h in ix.summary.get("hosts_corroborated", []):
        n += 1
        lines.append(f"{n}. **{ix.label(h)}: start incident response.** Corroborated exploitation signals; collect host "
                     "evidence before patching. Owner: SOC / IR.")
    for g in _groups(ix, ("P1",))[: max(0, limit - n)] or _groups(ix, ("P2",))[: max(0, limit - n)]:
        n += 1
        top, hosts = g["top"], sorted({r["host"] for r in g["rows"]})
        why = _t(top["exposure"]["label"], 70).lower()
        exp = ", public exploit" if top.get("exploit_available") else ""
        cves = _cves(top)
        lines.append(f"{n}. **Patch {_t(top['plugin_name'], 80)}{cves}** on {_join([ix.label(h) for h in hosts], 4)}: "
                     f"{top['priority']}, score {top['score']}, {why}{exp}. Owner: system owner.")
    if n == 0:
        lines.append("1. No P1 or P2 findings. Work through P3 findings in the normal cycle.")
    return lines


def _paths(ix: _Index) -> list[str]:
    lines = ["## Likely attack paths"]
    found = False
    for ip in list(dict.fromkeys(ix.summary.get("hosts_with_indicators", []) or [])):
        inds = ix.indicators(ip)
        if not inds:
            continue
        found = True
        steps = []
        for i in inds:
            r = i["_finding"]
            if i["type"] == "threat_alert":
                srcs = _join([s[0] for s in i.get("sources", [])], 3)
                steps.append(f"{srcs} hit {ix.label(ip)} on {r['port']}/{r['proto']} ({_t(r['plugin_name'], 60)}) and the IPS/IDS did not block it")
            elif i["type"] == "return_connection":
                steps.append(f"{ip} called back to {i['peer']} on port {_join(i.get('ports', []), 4)}")
            elif i["type"] == "new_lateral":
                steps.append(f"{ip} started new internal connections to {_join([t['ip'] for t in i.get('targets', [])], 4)}")
            elif i["type"] == "exfil":
                steps.append(f"{ip} sent {_mb(i.get('bytes'))} to {i['peer']}")
            elif i["type"] == "lateral_spread":
                steps.append(f"flagged host {i['peer']} newly reached {ix.label(ip)} port {i.get('port')}")
        steps = list(dict.fromkeys(steps))
        conf = "corroborated" if any(i["type"] == "corroborated" for i in inds) else "lead"
        lines.append(f"- **{ix.label(ip)}** ({conf}): " + " → ".join(steps) + ".")
        piv = (ix.hosts.get(ip, {}).get("blast") or {}).get("vulnerable_pivots") or []
        if piv:
            lines.append(f"  - From there, vulnerable pivots: {_join([ix.label(p) for p in piv], 5)}.")
    if not found and ix.scan:
        exposed = [r for r in ix.findings if r["exposure"].get("external_sources")]
        if exposed:
            r = exposed[0]
            piv = (ix.hosts.get(r["host"], {}).get("blast") or {}).get("vulnerable_pivots") or []
            lines.append(f"No exploitation leads were seen. The most likely entry point is {ix.label(r['host'])} "
                         f"port {r['port']} ({_t(r['plugin_name'], 80)}), reached from "
                         f"{_plural(r['exposure']['external_sources'], 'outside address', 'outside addresses')}"
                         + (f", with vulnerable pivots {_join([ix.label(p) for p in piv], 4)}." if piv else "."))
        else:
            lines.append("No exploitation leads and no vulnerable service reached from the internet were seen.")
    elif not found:
        for ip, l in ix.tel_leads.items():
            lines.append(f"- {ix.label(ip)}: {_alerts(l)}: {_t('; '.join(l.get('signatures', [])[:2]), 160)}.")
        for ip, ls in ix.net_leads.items():
            for l in ls:
                lines.append(f"- {ix.label(ip)} connected out to {l['peer']} after inbound contact from it.")
        if len(lines) == 1:
            lines.append("No network leads in this run.")
    return lines


def _exposure(ix: _Index) -> list[str]:
    lines = ["## Reached from the internet"]
    rows = [r for r in ix.findings if r["exposure"].get("external_sources")]
    if not ix.scan:
        hosts = sorted(ix.hosts.values(), key=lambda h: -(h.get("inbound_flows") or 0))[:8]
        lines.append("No vulnerability data, so only traffic is shown. Busiest inbound hosts:")
        lines += [f"- {ix.label(h['host'])}: {h.get('inbound_flows', 0)} inbound sessions" for h in hosts]
        return lines
    if not rows:
        lines.append("No vulnerable service was reached from the internet in the telemetry window.")
        return lines
    lines += ["| Host | Finding | Port | Outside sources | Sessions | Priority |", "|---|---|---|---|---|---|"]
    for r in rows[:12]:
        e = r["exposure"]
        lines.append(f"| {ix.label(r['host'])} | {_t(r['plugin_name'], 60)} | {r['port']}/{r['proto']} | {e['external_sources']} "
                     f"| {e['established']} | {r['priority']} |")
    if len(rows) > 12:
        lines.append(f"| …and {len(rows) - 12} more | | | | | |")
    return lines


def _outbound(ix: _Index) -> list[str]:
    lines = ["## Outbound traffic worth a look"]
    hits = []
    for ip in ix.by_host:
        for i in ix.indicators(ip):
            if i["type"] in ("return_connection", "exfil"):
                hits.append(f"- {ix.label(ip)}: {_t(i['text'], 300)}")
    for ip, ls in ix.net_leads.items():
        for l in ls:
            hits.append(f"- {ix.label(ip)} connected out to {l['peer']} ({_plural(l.get('sessions', 0), 'session')}) "
                        "after inbound contact from it. This can be legitimate.")
    if hits:
        lines += list(dict.fromkeys(hits))[:12]
    else:
        lines.append("No callbacks or large uploads after outside contact were found.")
    top = sorted(ix.hosts.values(), key=lambda h: -(h.get("outbound_flows") or 0))[:5]
    top = [h for h in top if h.get("outbound_flows")]
    if top:
        lines += ["", "Hosts with the most outbound sessions: " +
                  ", ".join(f"{ix.label(h['host'])} ({h['outbound_flows']})" for h in top) + "."]
    return lines


def _ioc_section(ix: _Index) -> list[str]:
    lines = ["## IOC matches"]
    if not ix.iocs:
        lines.append("No IOC CSV indicators matched this run." if "ioc_matches" in ix.res
                     else "No IOC CSV was supplied with this run.")
        return lines
    lines += ["| Indicator | Type | Hosts | Disposition | Source |", "|---|---|---|---|---|"]
    for m in ix.iocs[:15]:
        lines.append(f"| `{_t(m.get('value'), 60)}` | {_t(m.get('type'), 15)} | {_t(_join(m.get('hosts', []), 3), 80)} "
                     f"| {_t(m.get('disposition') or '', 25)} | {_t(_join(m.get('sources', []), 2), 50)} |")
    if len(ix.iocs) > 15:
        lines.append(f"| …and {len(ix.iocs) - 15} more | | | | |")
    lines.append("")
    lines.append("A match is a lead, not proof. Confirm the host really contacted the indicator and what happened next.")
    return lines


def _coverage(ix: _Index) -> list[str]:
    cov = ix.res.get("coverage", {})
    lines = ["## Where this analysis may be wrong"]
    if not ix.scan:
        lines.append("- No vulnerability scan was supplied: nothing here says whether hosts are vulnerable.")
    if cov.get("active_servers_not_scanned"):
        srv = cov["active_servers_not_scanned"]
        lines.append(f"- {_plural(len(srv), 'busy server')} answered sessions but {'was' if len(srv) == 1 else 'were'} not scanned: "
                     + _join([f"{s['ip']} ({_t(', '.join(s.get('services', [])[:3]), 40)})" for s in srv], 5) + ".")
    if cov.get("scanned_not_seen"):
        lines.append(f"- {_plural(len(cov['scanned_not_seen']), 'scanned host')} had no telemetry, so exposure is unknown: "
                     + _join(cov["scanned_not_seen"], 5) + ".")
    if ix.scan:
        quiet = sum(1 for r in ix.findings if r["exposure"]["label"].lower().startswith("service not observed"))
        if quiet:
            lines.append(f"- {_plural(quiet, 'finding')} scored low because the service was not seen in use. "
                         "That only covers the telemetry window and sensors you supplied.")
    s = ix.summary
    lines.append(f"- Telemetry window: {s.get('window_start') or '?'} to {s.get('window_end') or '?'}. Activity outside it is not counted.")
    lines.append("- The tool never sees payloads or host evidence, so leads need host or application logs to confirm.")
    return lines


def _validate(ix: _Index, limit: int = 4) -> list[str]:
    lines = ["## How to validate the top findings"]
    for g in (_groups(ix, ("P1", "P2")))[:limit]:
        top = g["top"]
        hosts = sorted({r["host"] for r in g["rows"]})
        lines.append(f"- **{_t(top['plugin_name'], 80)}** (plugin {top['plugin_id']}) on {_join(hosts, 4)}: confirm the "
                     "installed version on the host. " + (f"Fix: {_end(top['solution'], 160)}" if top.get("solution") else ""))
        if top.get("port"):
            lines += ["  " + c for c in _checks(None, top["host"], top["port"])]
    if len(lines) == 1:
        lines.append("No P1 or P2 findings to validate.")
    return lines


def _questions(ix: _Index) -> list[str]:
    lines = ["## Questions for system owners"]
    for g in _groups(ix, ("P1",))[:3]:
        top = g["top"]
        if top.get("port") and top["exposure"].get("external_sources"):
            lines.append(f"- Does {ix.label(top['host'])} need {top['port']}/{top['proto']} open to the internet?")
    srv = ix.res.get("coverage", {}).get("active_servers_not_scanned", [])
    if srv:
        lines.append(f"- Why isn't {srv[0]['ip']} in the scan scope?")
    for ip in ix.summary.get("hosts_corroborated", [])[:2]:
        peers = sorted({i["peer"] for i in ix.indicators(ip) if i.get("peer")})
        if peers:
            lines.append(f"- Is there any legitimate reason for {ip} to talk to {_join(peers, 2)}?")
    lines.append("- Are any of these hosts already scheduled for decommissioning or a maintenance window?")
    return lines


# ------------------------------------------------------------------ public API
def brief(res: dict) -> str:
    ix = _Index(res)
    if not ix.scan:
        parts = [["## Analyst take"] + _take(ix), ["## Leads to review"] + _paths(ix)[1:],
                 _outbound(ix), _ioc_section(ix),
                 ["## Next steps", "1. Review the IPS/IDS and session evidence for each lead above.",
                  "2. Scan the hosts with leads so their vulnerability status is known.",
                  "3. Do not assign CVSS scores or remediation priorities from telemetry alone."],
                 _coverage(ix)]
    else:
        parts = [["## Analyst take"] + _take(ix), _priorities(ix), _paths(ix), _validate(ix),
                 _ioc_section(ix), _coverage(ix), _questions(ix)]
    return "\n".join([BANNER, ""] + ["\n".join(p) + "\n" for p in parts if p])


def answer(res: dict, question: str, history: list[dict] | None = None) -> str:
    ix = _Index(res)
    q = (question or "").strip()
    ents = ix.entities(q)
    intents = _intents(q)
    if not any(ents.values()):
        # follow-ups like "why?" or "how do I check it?" reuse the last thing named in the conversation
        for h in reversed(history or []):
            if h.get("role") == "user" and isinstance(h.get("content"), str):
                prev = ix.entities(h["content"])
                pronoun = re.search(r"\b(it|its|this|that|them|those|they|there|he|she)\b", q.lower())
                bare = not intents and len(q.split()) <= 3 and re.match(r"(why|how|and|more|details?)\b", q.lower())
                if any(prev.values()) and (pronoun or bare):
                    ents = prev
                break
    sections: list[list[str]] = []
    for ip in ents["hosts"][:3]:
        sections.append(_explain_host(ix, ip))
    for c in ents["cves"][:3]:
        sections.append(_explain_finding(ix, c, "cve"))
    for p in ents["plugins"][:3]:
        if not ents["cves"]:
            sections.append(_explain_finding(ix, p, "plugin"))
    for ip in ents["externals"][:2]:
        sections.append(_explain_external(ix, ip))
    for m in ents["iocs"][:3]:
        sections.append(_explain_ioc(ix, m))
    if not sections:
        topic = {"help": lambda: _help(ix), "scoring": _scoring,
                 "priorities": lambda: _priorities(ix), "exposure": lambda: _exposure(ix),
                 "outbound": lambda: _outbound(ix), "paths": lambda: _paths(ix),
                 "ioc": lambda: _ioc_section(ix), "coverage": lambda: _coverage(ix),
                 "compromise": lambda: ["## Signs of exploitation"] + _take(ix) + [""] + _paths(ix)[1:],
                 "summary": lambda: ["## Summary"] + _take(ix) + [""] + _priorities(ix, 5)}
        for name in intents:
            if name == "scoring" and ("priorities" in intents and "mean" not in q.lower() and "score" not in q.lower()):
                continue
            sections.append(topic[name]())
            if len(sections) == 2:
                break
    if not sections:
        sections = [["## Summary"] + _take(ix), [""] + _help(ix)]
    return "\n".join([BANNER, ""] + ["\n".join(s) + "\n" for s in sections])
