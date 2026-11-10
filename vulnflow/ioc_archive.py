"""Import typed IOC CSV files and retain optional source provenance."""
from __future__ import annotations

import csv
import html
import ipaddress
import json
from collections import defaultdict
from urllib.parse import urlsplit

from .branding import brand_html
from .schema import ParseStats

TYPES = {"ip", "domain", "url", "hash", "cve", "package"}
KIND_COLUMNS = ("indicatorType", "type", "ioc_type")
VALUE_COLUMNS = ("indicator", "value", "ioc")
ARTICLE_COLUMNS = ("articleUrls", "sourceUrls", "source_url", "sourceUrl")


def _column(fieldnames, choices):
    names = {name.strip().lower(): name for name in fieldnames or [] if name}
    return next((names[choice.lower()] for choice in choices if choice.lower() in names), None)


def is_archive(path: str) -> bool:
    if not path.lower().endswith(".csv"):
        return False
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            header = next(csv.reader(fh), [])
            return bool(_column(header, KIND_COLUMNS) and _column(header, VALUE_COLUMNS))
    except (OSError, UnicodeError, csv.Error):
        return False


def _value(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ""
    if kind == "cve":
        return value.upper() if value.upper().startswith("CVE-") else ""
    if kind == "domain":
        return value.lower().rstrip(".")
    if kind in ("hash", "package"):
        return value.lower()
    return value


def _urls(value: str) -> list[str]:
    urls = []
    for raw in value.split(";"):
        url = raw.strip()
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        if parts.scheme not in ("https", "http") or not parts.netloc or parts.username or parts.password:
            continue
        if url not in urls:
            urls.append(url)
    return urls


def read_archives(paths: list[str]) -> tuple[dict, list[ParseStats]]:
    archive: dict[tuple[str, str], dict] = {}
    stats = []
    for path in paths:
        stat = ParseStats(file=path.rsplit("/", 1)[-1], fmt="ioc_csv")
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            kind_column = _column(reader.fieldnames, KIND_COLUMNS)
            value_column = _column(reader.fieldnames, VALUE_COLUMNS)
            article_column = _column(reader.fieldnames, ARTICLE_COLUMNS)
            if not kind_column or not value_column:
                raise ValueError(f"IOC CSV needs type and indicator columns: {path}")
            for row in reader:
                stat.read += 1
                kind = (row.get(kind_column) or "").strip().lower()
                value = _value(kind, row.get(value_column) or "") if kind in TYPES else ""
                links = _urls(row.get(article_column) or "") if article_column else []
                if not value:
                    stat.drop("missing or invalid indicator")
                    continue
                stat.kept += 1
                key = (kind, value)
                item = archive.setdefault(key, {"id": f"{kind}:{value}", "type": kind,
                                                "value": value, "articles": [], "sources": [],
                                                "first_seen": "", "last_seen": "",
                                                "disposition": ""})
                for link in links:
                    if link not in item["articles"]:
                        item["articles"].append(link)
                for source in (row.get("sources") or "").split(";"):
                    source = source.strip()
                    if source and source not in item["sources"]:
                        item["sources"].append(source)
                first, last = (row.get("firstSeenAt") or ""), (row.get("lastSeenAt") or "")
                if first and (not item["first_seen"] or first < item["first_seen"]):
                    item["first_seen"] = first
                if last and last > item["last_seen"]:
                    item["last_seen"] = last
                item["disposition"] = item["disposition"] or (row.get("disposition") or "")
        stats.append(stat)
    return archive, stats


def match_archive(ds, archive: dict, observed_hosts: set[str] | None = None) -> list[dict]:
    """Exact matches in normalized traffic, findings, and named Zeek fields."""
    seen: dict[tuple[str, str], dict] = {}
    scanned = set(ds.scanned_hosts) or (observed_hosts or set())

    def record(key, hosts, label):
        if key not in archive:
            return
        row = seen.setdefault(key, {**archive[key], "hosts": set(), "observed": defaultdict(int)})
        row["hosts"].update(h for h in hosts if h in scanned)
        row["observed"][label] += 1

    for flow in ds.flows:
        for value, other in ((flow.src_ip, flow.dst_ip), (flow.dst_ip, flow.src_ip)):
            key = ("ip", _value("ip", value))
            if key in archive:
                record(key, (value, other), "network session")
    for event in ds.threats:
        for value, other in ((event.src_ip, event.dst_ip), (event.dst_ip, event.src_ip)):
            key = ("ip", _value("ip", value))
            if key in archive:
                record(key, (value, other), "IDS/IPS alert")
    for finding in ds.findings:
        for cve in finding.cves:
            record(("cve", _value("cve", cve)), (finding.host_ip,), "scan finding")

    field_types = {
        "domain": {"query", "domain", "hostname", "host", "server_name", "dns_name"},
        "url": {"url", "uri"},
        "hash": {"hash", "md5", "sha1", "sha256"},
        "package": {"package", "package_name"},
    }
    for event in ds.zeek_events:
        for field, raw in event.fields.items():
            name = field.lower().rsplit(".", 1)[-1]
            values = raw if isinstance(raw, list) else [raw]
            for kind, fields in field_types.items():
                if name not in fields:
                    continue
                for value in values:
                    if isinstance(value, str):
                        record((kind, _value(kind, value)),
                               (event.src_ip, event.dst_ip), f"{event.stream} event")

    return [{**row, "hosts": sorted(row["hosts"]),
             "observed": dict(sorted(row["observed"].items()))}
            for _, row in sorted(seen.items())]


def markdown_section(matches: list[dict]) -> str:
    lines = ["## IOC matches", "",
             "Exact matches to the imported IOC CSV are leads for review, not proof of malicious activity.", ""]
    if not matches:
        return "\n".join(lines + ["No imported indicators matched the supplied telemetry or scan findings.", ""])
    lines += ["| Indicator | Type | Related hosts | Observed in | Source links |",
              "|---|---|---|---|---|"]
    for row in matches:
        observed = ", ".join(f"{count} {label}" for label, count in row["observed"].items())
        articles = "; ".join(row["articles"][:3]) or "—"
        cells = [row["value"], row["type"], ", ".join(row["hosts"]) or "network",
                 observed, articles]
        lines.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
    return "\n".join(lines + [""])


def table_html(matches: list[dict]) -> str:
    rows = []
    for row in matches:
        key = html.escape(row["id"], quote=True)
        value = html.escape(row["value"])
        observed = ", ".join(f"{count} {label}" for label, count in row["observed"].items())
        rows.append("<tr><td><button type=\"button\" class=\"ioc-link\" data-ioc-key=\"" + key +
                    "\">" + value + "</button></td><td>" + html.escape(row["type"]) +
                    "</td><td>" + html.escape(", ".join(row["hosts"]) or "network") +
                    "</td><td>" + html.escape(observed) + "</td><td>" +
                    f"{len(row['articles'])} source link(s)</td></tr>")
    return ("<table><thead><tr><th>Indicator</th><th>Type</th><th>Related hosts</th>"
            "<th>Observed in</th><th>Sources</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


CSS = """
.ioc-link{font:inherit;color:#2da8b7;background:transparent;border:0;padding:0;text-align:left;
text-decoration:underline;text-underline-offset:3px;cursor:pointer;overflow-wrap:anywhere}
.ioc-link:hover,.ioc-link:focus-visible{color:#7ce7ef}
.ioc-shade[hidden],.ioc-drawer[hidden]{display:none!important}
.ioc-shade{position:fixed;inset:0;background:#0009;z-index:1000}
.ioc-drawer{position:fixed;right:0;top:0;bottom:0;width:min(460px,100vw);padding:24px;
overflow:auto;background:#101c2b;color:#eef7ff;border-left:1px solid #42637c;z-index:1001;
box-shadow:-16px 0 45px #0009;font:14px/1.5 system-ui,sans-serif}
.ioc-drawer h2{margin:0 0 8px;font-size:20px}.ioc-drawer p{margin:8px 0;color:#b9cadb}
.ioc-drawer-brand{display:flex;align-items:center;gap:8px;margin:0 0 18px;font-weight:800;letter-spacing:.03em}
.ioc-drawer-brand .brand-logo{height:28px;width:auto;max-width:140px;object-fit:contain}
.ioc-drawer-brand .brand-logo.logo-small{height:20px;max-width:80px}
.ioc-drawer-brand span{font-size:11px;font-weight:500;color:#b9cadb}
.ioc-drawer .ioc-close{float:right;background:#253a4d;color:#fff;border:1px solid #54728d;
border-radius:6px;padding:5px 10px;cursor:pointer}
.ioc-drawer a{color:#79dce7;overflow-wrap:anywhere}.ioc-drawer li{margin:8px 0}
.ioc-brief{margin:12px 0;padding:12px;border:1px solid #42637c;border-radius:8px;background:#172a3c}
.ioc-brief h4{margin:0 0 6px;color:#79dce7}.ioc-brief ol{padding-left:20px;margin:6px 0}
.ioc-brief details{margin-top:10px}.ioc-brief summary{cursor:pointer;color:#79dce7}
.ioc-radar{margin:14px 0;padding:12px;border:1px solid #42637c;border-radius:8px;background:#172a3c}
.ioc-radar button{padding:6px 10px;cursor:pointer}.ioc-radar p{margin:6px 0}
.ioc-radar strong{color:#eef7ff}
@media print{.ioc-shade,.ioc-drawer{display:none!important}}
"""

SCRIPT = r"""<script>
(() => {
  const data = JSON.parse(document.getElementById('ioc-provenance-data').textContent);
  const briefs = JSON.parse(document.getElementById('ioc-article-briefs').textContent);
  const byId = new Map(data.map(item => [item.id, item]));
  const shade = document.getElementById('ioc-shade');
  const drawer = document.getElementById('ioc-drawer');
  const body = document.getElementById('ioc-drawer-body');
  const runPath = location.pathname.match(/^\/runs\/[a-f0-9]{16}\/(?:executive_summary|technical_report|explorer)\.html$/);
  const radarPath = runPath ? runPath[0].replace(/[^/]+$/, '') : null;
  let previous = null;
  function addRadar(item) {
    if (!radarPath || !['ip', 'domain'].includes(item.type)) return;
    const box = document.createElement('section'); box.className = 'ioc-radar';
    const heading = document.createElement('h3'); heading.textContent = 'Cloudflare Radar context';
    const button = document.createElement('button'); button.type = 'button';
    button.textContent = 'Check Cloudflare Radar';
    const result = document.createElement('div'); result.setAttribute('role', 'status');
    const row = (label, value) => {
      if (value === undefined || value === null || value === '') return;
      const p = document.createElement('p');
      const strong = document.createElement('strong'); strong.textContent = label + ': ';
      p.append(strong, document.createTextNode(String(value))); result.append(p);
    };
    button.addEventListener('click', async () => {
      button.disabled = true; result.textContent = 'Checking Cloudflare Radar…';
      try {
        const statusResponse = await fetch(radarPath + 'radar-status', {cache: 'no-store'});
        if (!statusResponse.ok) throw new Error('Radar configuration could not be checked.');
        const status = await statusResponse.json();
        if (!status.enabled) throw new Error('Set CLOUDFLARE_RADAR_API_TOKEN on the VulnScope server first.');
        const response = await fetch(radarPath + 'radar', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({csrf: status.csrf, type: item.type, value: item.value})
        });
        const info = await response.json();
        if (!response.ok) throw new Error(info.error || 'Radar lookup failed.');
        result.replaceChildren();
        if (info.type === 'ip') {
          row('Network', [info.asn && 'AS' + info.asn, info.asnOrgName || info.asnName].filter(Boolean).join(' · '));
          row('IP location', info.locationName);
          row('Network location', info.asnLocation);
        } else {
          if (info.rank) row('Popularity rank', info.rank);
          else if (info.bucket) row('Popularity bucket', 'Top ' + info.bucket);
          else row('Popularity ranking', 'Not available');
          row('Categories', (info.categories || []).join(', '));
        }
        row('Checked', info.retrieved_at);
        const caution = document.createElement('p');
        caution.textContent = 'Radar context is not proof of malicious activity.';
        result.append(caution);
      } catch (error) {
        result.textContent = error.message || 'Radar lookup failed.';
      } finally { button.disabled = false; }
    });
    box.append(heading, button, result); body.append(box);
  }
  function close() {
    drawer.hidden = shade.hidden = true;
    if (previous && previous.isConnected) previous.focus();
  }
  function open(item, trigger) {
    previous = trigger;
    body.replaceChildren();
    const heading = document.createElement('h2');
    heading.textContent = item.type.toUpperCase() + ' · ' + item.value;
    body.append(heading);
    const note = document.createElement('p');
    note.textContent = 'Exact IOC match. Review the source and surrounding telemetry before drawing a conclusion.';
    body.append(note);
    const context = document.createElement('p');
    context.textContent = 'Observed in: ' + Object.entries(item.observed).map(([k,v]) => v + ' ' + k).join(', ')
      + (item.hosts.length ? ' · Related hosts: ' + item.hosts.join(', ') : '');
    body.append(context);
    addRadar(item);
    if (item.sources && item.sources.length) {
      const sources = document.createElement('p');
      sources.textContent = 'Sources: ' + item.sources.join(', '); body.append(sources);
    }
    const label = document.createElement('h3'); label.textContent = 'Source links'; body.append(label);
    const list = document.createElement('ul');
    item.articles.forEach(url => {
      const li = document.createElement('li');
      const preview = item.article_previews && item.article_previews[url];
      const source = document.createElement('small');
      source.textContent = new URL(url).hostname; li.append(source);
      if (preview && preview.title) {
        const title = document.createElement('strong');
        title.textContent = ' · ' + preview.title; li.append(title);
      }
      const saved = briefs[url] && briefs[url].brief;
      if (saved) {
        const card = document.createElement('div'); card.className = 'ioc-brief';
        const label = document.createElement('h4');
        label.textContent = 'Múcaro AI Brief' + (saved.mobile_summary && saved.mobile_summary.priority
          ? ' · ' + saved.mobile_summary.priority : ''); card.append(label);
        const summary = document.createElement('p');
        summary.textContent = saved.executive_summary || ''; card.append(summary);
        const actions = saved.mobile_summary && saved.mobile_summary.what_to_do_now || [];
        if (actions.length) {
          const actionLabel = document.createElement('strong'); actionLabel.textContent = 'What to do now';
          card.append(actionLabel);
          const actionList = document.createElement('ol');
          actions.slice(0, 3).forEach(action => {
            const row = document.createElement('li'); row.textContent = action; actionList.append(row);
          });
          card.append(actionList);
        }
        const more = document.createElement('details');
        const moreLabel = document.createElement('summary'); moreLabel.textContent = 'More from AI Brief';
        more.append(moreLabel);
        (saved.key_takeaways || []).forEach(takeaway => {
          const row = document.createElement('p'); row.textContent = '• ' + takeaway; more.append(row);
        });
        const iocs = saved.iocs || {};
        const indicatorValues = ['ips', 'domains', 'urls', 'hashes', 'cves'].flatMap(k => iocs[k] || []);
        if (indicatorValues.length) {
          const row = document.createElement('p');
          row.textContent = 'Indicators reported in article: ' + indicatorValues.slice(0, 12).join(', ');
          more.append(row);
        }
        card.append(more);
        const caution = document.createElement('small');
        caution.textContent = 'AI-generated from the article. The IOC match is a lead, not proof of compromise.';
        card.append(caution);
        li.append(card);
      } else if (preview && preview.overview) {
        const summary = document.createElement('p');
        summary.textContent = preview.overview; li.append(summary);
      } else {
        const unavailable = document.createElement('p');
        unavailable.textContent = 'Short overview unavailable; the source link is still available.';
        li.append(unavailable);
      }
      const link = document.createElement('a'); link.href = url; link.target = '_blank';
      link.rel = 'noopener noreferrer'; link.textContent = 'Read full article ↗';
      li.append(link); list.append(li);
    });
    if (item.articles.length) body.append(list);
    else {
      const missing = document.createElement('p');
      missing.textContent = 'No source link was provided in the IOC CSV.';
      body.append(missing);
    }
    drawer.hidden = shade.hidden = false;
    document.getElementById('ioc-close').focus();
  }
  document.addEventListener('click', event => {
    const trigger = event.target.closest('[data-ioc-key]');
    if (!trigger) return;
    const item = byId.get(trigger.dataset.iocKey);
    if (!item) return;
    event.stopPropagation();
    open(item, trigger);
  }, true);
  document.addEventListener('ioc:open', event => {
    const item = byId.get(event.detail && event.detail.id);
    if (item) open(item, document.activeElement);
  });
  document.getElementById('ioc-close').addEventListener('click', close);
  shade.addEventListener('click', close);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !drawer.hidden) { event.stopPropagation(); close(); }
  });
})();
</script>"""


def drawer_html(matches: list[dict], article_briefs: dict | None = None) -> str:
    if not matches:
        return ""
    blob = json.dumps(matches, separators=(",", ":")).replace("<", "\\u003c")
    brief_blob = json.dumps(article_briefs or {}, separators=(",", ":")).replace("<", "\\u003c")
    return (f'<script id="ioc-provenance-data" type="application/json">{blob}</script>'
            f'<script id="ioc-article-briefs" type="application/json">{brief_blob}</script>'
            '<div id="ioc-shade" class="ioc-shade" hidden></div>'
            '<aside id="ioc-drawer" class="ioc-drawer" role="dialog" aria-modal="true" '
            'aria-label="Indicator details" hidden>'
            '<button id="ioc-close" class="ioc-close" type="button">Close</button>'
            '<div class="ioc-drawer-brand">' + brand_html() + ' <span>Source intelligence</span></div>'
            '<div id="ioc-drawer-body"></div></aside>' + SCRIPT)
