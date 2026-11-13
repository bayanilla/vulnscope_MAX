// Compare reports: draws the comparison embedded in #cmp-data (see compare.py). Everything taken
// from the reports is set as text, never as HTML.
(function () {
  const data = JSON.parse(document.getElementById("cmp-data").textContent);
  const root = document.getElementById("cmp");
  const R = data.reports, S = data.summary, sample = +root.dataset.sample || 12;
  const PAGE = 300;

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "text") n.textContent = v;
      else if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false)
      n.append(kid instanceof Node ? kid : String(kid));
    return n;
  }
  const plural = (n, one, many) => n.toLocaleString() + " " + (n === 1 ? one : (many || one + "s"));
  const day = iso => (iso || "").replace("T", " ").slice(0, 16);
  const safeUrl = u => { try { const p = new URL(u).protocol; return p === "https:" || p === "http:" ? u : null; } catch (e) { return null; } };
  const repName = i => (i + 1) + ". " + R[i].name + (R[i].network !== R[i].name ? " (" + R[i].network + ")" : "");

  // -- summary -------------------------------------------------------------------------------
  const dates = R.map(r => (r.generated || "").slice(0, 10)).filter(Boolean).sort();
  const first = dates[0], last = dates[dates.length - 1];
  root.append(el("p", {class: "cmp-lede"},
    plural(S.reports, "report") + " from " + plural(S.networks, "network") +
    (first ? ", analyzed " + (first === last ? first : first + " to " + last) : "") +
    ". Compared " + day(data.generated) + " UTC."));
  const hunt = data.rehunt;
  if (hunt.indicators) {
    const from = [];
    if (hunt.files.length) from.push(hunt.files.join(", "));
    if (hunt.crosscheck) from.push("every IOC any of these reports matched");
    root.append(el("p", {class: "hint"}, "Re-hunt: looked for " + plural(hunt.indicators, "indicator") +
      " (" + from.join(", plus ") + ") in each report's saved traffic, scan findings and Zeek events."));
  } else if (hunt.crosscheck) {
    root.append(el("p", {class: "hint"}, "No IOC was matched in these reports, so there was nothing to look for again. " +
      "Add an IOC CSV to look for indicators in all of them."));
  }
  const tile = (n, label, sub, cls) => el("div", {class: "cmp-tile" + (cls ? " " + cls : "")},
    el("b", {text: n.toLocaleString()}), el("span", {text: label}), el("small", {text: sub}));
  const tiles = el("div", {class: "cmp-tiles"},
    tile(S.iocs_shared, "IOCs in more than one report", "of " + plural(S.iocs, "IOC") + " seen", S.iocs_shared ? "hot" : ""),
    tile(S.vulns_shared, "vulnerabilities in more than one report", "of " + plural(S.vulns, "vulnerability", "vulnerabilities") + " found"),
    tile(S.networks, S.networks === 1 ? "network" : "networks", "in " + plural(S.reports, "report")));
  if (hunt.indicators) tiles.append(tile(S.found_by_hunt, "sightings found by the re-hunt", "the analysis didn't have these IOCs"));
  root.append(tiles);

  // -- every network on one Explorer map (combine.py) ----------------------------------------------
  const ex = data.explorer;
  if (ex && ex.file) {
    root.append(el("div", {class: "cmp-explorer"},
      el("a", {href: ex.file, class: "cmp-explorer-link", text: "Open all networks in the Explorer"}),
      el("p", {class: "hint", text: ex.drawn.toLocaleString() + (ex.drawn < ex.hosts ? " of " + ex.hosts.toLocaleString() : "") +
        " hosts from " + plural(ex.reports, "report") + " on one map, one island per report. Hosts with an IOC or vulnerability " +
        "that more than one report has are lit up in every network."}),
      ex.notes.map(n => el("p", {class: "hint", text: n}))));
  } else if (ex && ex.notes && ex.notes.length) {
    root.append(el("div", {class: "cmp-explorer"}, el("p", {class: "hint", text: "No all-networks Explorer: none of these reports has an Explorer page."}),
      ex.notes.map(n => el("p", {class: "hint", text: n}))));
  }

  // -- tabs ----------------------------------------------------------------------------------
  const tabs = el("div", {class: "cmp-tabs", role: "tablist"});
  const panels = el("div");
  root.append(tabs, panels);
  const tabList = [];
  function addTab(id, label, build) {
    const panel = el("section", {id: "p-" + id, role: "tabpanel", "aria-labelledby": "t-" + id, hidden: true});
    const btn = el("button", {type: "button", role: "tab", id: "t-" + id, "aria-controls": "p-" + id,
      "aria-selected": "false", text: label, onclick: () => select(id)});
    tabs.append(btn); panels.append(panel); tabList.push({id, btn, panel, build, built: false});
  }
  function select(id) {
    for (const t of tabList) {
      const on = t.id === id;
      t.btn.setAttribute("aria-selected", on ? "true" : "false"); t.panel.hidden = !on;
      if (on && !t.built) { t.build(t.panel); t.built = true; }
    }
    try { history.replaceState(null, "", "#" + id); } catch (e) {}
  }

  // -- presence strip: one cell per report, oldest first ---------------------------------------
  function strip(seen) {
    const at = new Map(seen.map(s => [s.r, s]));
    const names = seen.map(s => R[s.r].name);
    const box = el("span", {class: "cmp-strip", role: "img", "aria-label": "Seen in " + names.join(", ")});
    R.forEach((r, i) => {
      const s = at.get(i);
      box.append(el("span", {class: "cell" + (s ? " on" : "") + (s && s.how && s.how.length === 1 && s.how[0] === "re-hunt" ? " hunted" : ""),
        title: repName(i) + (s ? ": " + plural(s.hosts, "related host") + (s.how && s.how.length === 1 && s.how[0] === "re-hunt" ? ", found by the re-hunt" : "") : ": not seen")}));
    });
    return box;
  }

  function hostList(s) {
    if (!s.hosts) return "no internal host named";
    const shown = s.related.join(", ");
    return plural(s.hosts, "host") + ": " + shown + (s.hosts > s.related.length ? " (+" + (s.hosts - s.related.length).toLocaleString() + " more in the CSV)" : "");
  }

  // -- item tables (IOCs, vulnerabilities) ------------------------------------------------------
  function itemPanel(panel, cfg) {
    const rows = cfg.rows;
    if (!rows.length) { panel.append(el("p", {class: "cmp-empty", text: cfg.none})); return; }
    const most = Math.max(...rows.map(r => r.reports));
    const search = el("input", {type: "search", placeholder: cfg.searchHint, "aria-label": cfg.searchHint});
    const minSel = el("select", {"aria-label": "Seen in at least"});
    for (let n = 1; n <= Math.max(2, R.length); n++) minSel.append(el("option", {value: n, text: n === 1 ? "any number of reports" : "at least " + n + " reports"}));
    minSel.value = R.length > 1 ? "2" : "1";
    const kindSel = el("select", {"aria-label": cfg.kindLabel}, el("option", {value: "", text: cfg.kindAll}),
      cfg.kinds.map(k => el("option", {value: k[0], text: k[1]})));
    const count = el("span", {class: "hint", role: "status", "aria-live": "polite"});
    panel.append(el("div", {class: "cmp-controls"}, search, el("label", {}, "Seen in ", minSel), kindSel, count));
    if (cfg.legend) panel.append(cfg.legend());
    const thead = el("tr");
    let sortKey = "reports", dir = -1;
    cfg.columns.forEach(c => {
      const th = el("th", {scope: "col", class: c.num ? "num" : ""});
      if (c.sort) {
        th.append(el("button", {type: "button", class: "cmp-sort", text: c.label, onclick: () => {
          if (sortKey === c.sort) dir = -dir; else { sortKey = c.sort; dir = c.num ? -1 : 1; }
          draw();
        }}));
        th.dataset.sort = c.sort;
      } else th.textContent = c.label;
      thead.append(th);
    });
    const tbody = el("tbody");
    const more = el("button", {type: "button", class: "secondary cmp-more", hidden: true});
    panel.append(el("div", {class: "cmp-scroll"}, el("table", {class: "cmp-table"}, el("thead", {}, thead), tbody)), more);
    let limit = PAGE, list = [];
    const value = (r, k) => k === "name" ? (r.name || r.value || "").toLowerCase() : r[k];
    function draw() {
      const q = search.value.trim().toLowerCase(), min = +minSel.value, kind = kindSel.value;
      list = rows.filter(r => r.reports >= min && (!kind || cfg.kindOf(r) === kind) && (!q || cfg.text(r).includes(q)));
      list.sort((a, b) => {
        const x = value(a, sortKey), y = value(b, sortKey);
        return (x < y ? -1 : x > y ? 1 : 0) * dir || b.reports - a.reports || b.hosts - a.hosts;
      });
      thead.querySelectorAll("th[data-sort]").forEach(th => th.setAttribute("aria-sort",
        th.dataset.sort === sortKey ? (dir < 0 ? "descending" : "ascending") : "none"));
      tbody.innerHTML = "";
      list.slice(0, limit).forEach(r => tbody.append(...cfg.row(r)));
      if (!list.length) tbody.append(el("tr", {}, el("td", {colspan: cfg.columns.length, class: "cmp-empty"},
        min > 1 && rows.some(r => r.reports >= 1) && !q && !kind ? cfg.noneShared : "Nothing matches.")));
      count.textContent = "Showing " + Math.min(limit, list.length).toLocaleString() + " of " + plural(list.length, cfg.noun, cfg.nouns) +
        (most > 1 ? "" : " (none is in more than one report)");
      more.hidden = list.length <= limit;
      more.textContent = "Show " + Math.min(PAGE, list.length - limit).toLocaleString() + " more";
    }
    more.onclick = () => { limit += PAGE; draw(); };
    let timer = null;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { limit = PAGE; draw(); }, 150); });
    minSel.onchange = kindSel.onchange = () => { limit = PAGE; draw(); };
    draw();
  }

  function detailRow(cols, kids) {
    return el("tr", {class: "cmp-detail", hidden: true}, el("td", {colspan: cols}, kids));
  }
  function toggle(btn, detail) {
    const open = detail.hidden;
    detail.hidden = !open; btn.setAttribute("aria-expanded", open ? "true" : "false");
  }

  const legend = hunted => () => el("p", {class: "cmp-legend hint"}, "Each square is one report, oldest first: ",
    el("span", {class: "cmp-strip", "aria-hidden": "true"}, el("span", {class: "cell on"})), hunted ? " found when it was analyzed, " : " found in it, ",
    hunted ? [el("span", {class: "cmp-strip", "aria-hidden": "true"}, el("span", {class: "cell on hunted"})), " found by the re-hunt, "] : "",
    el("span", {class: "cmp-strip", "aria-hidden": "true"}, el("span", {class: "cell"})), " not in that report. Click a row for the hosts in each report.");

  addTab("iocs", "IOCs (" + S.iocs.toLocaleString() + ")", panel => itemPanel(panel, {
    rows: data.iocs, noun: "IOC", legend: legend(!!hunt.indicators), none: hunt.indicators || S.iocs ? "No IOC was seen in these reports." :
      "None of these reports had IOC matches. Add an IOC CSV to look for indicators in all of them.",
    noneShared: "No IOC is in more than one of these reports. Choose “any number of reports” to see them all.",
    searchHint: "Search indicator, host or report", kindLabel: "Indicator type", kindAll: "All types",
    kinds: [["ip", "IP addresses"], ["domain", "Domains"], ["url", "URLs"], ["hash", "Hashes"], ["cve", "CVEs"], ["package", "Packages"]],
    kindOf: r => r.type,
    text: r => (r.value + " " + r.type + " " + r.seen.map(s => R[s.r].name + " " + R[s.r].network + " " + s.related.join(" ")).join(" ")).toLowerCase(),
    columns: [{label: "Indicator", sort: "name"}, {label: "Type"}, {label: "Reports", sort: "reports", num: true},
              {label: "Networks", sort: "networks", num: true}, {label: "Hosts", sort: "hosts", num: true},
              {label: "Seen in (oldest report first)"}, {label: "Found by"}],
    row: r => {
      const hunted = r.seen.filter(s => s.how.length === 1 && s.how[0] === "re-hunt").length;
      const btn = el("button", {type: "button", class: "cmp-open", "aria-expanded": "false", text: r.value});
      const links = (r.articles || []).map(safeUrl).filter(Boolean);
      const detail = detailRow(7, [
        el("ul", {class: "cmp-seen"}, r.seen.map(s => el("li", {},
          el("b", {text: repName(s.r)}), " — ", hostList(s),
          Object.keys(s.observed).length ? " — " + Object.entries(s.observed).map(([l, n]) => n.toLocaleString() + " " + l).join(", ") : "",
          s.how.includes("analysis") ? "" : el("span", {class: "badge hunt", text: "found by the re-hunt"})))),
        (r.disposition || (r.sources || []).length || links.length) ? el("p", {class: "hint"},
          r.disposition ? "Disposition: " + r.disposition + ". " : "",
          (r.sources || []).length ? "Sources: " + r.sources.join(", ") + ". " : "",
          links.slice(0, 5).map((u, k) => [k ? ", " : "Articles: ", el("a", {href: u, target: "_blank", rel: "noopener noreferrer", text: u})])) : ""]);
      btn.onclick = () => toggle(btn, detail);
      return [el("tr", {},
        el("td", {class: "cmp-ind"}, btn),
        el("td", {}, el("span", {class: "badge t-" + r.type, text: r.type})),
        el("td", {class: "num"}, el("b", {text: r.reports})),
        el("td", {class: "num", text: r.networks}),
        el("td", {class: "num", text: r.hosts.toLocaleString()}),
        el("td", {}, strip(r.seen)),
        el("td", {}, hunted ? el("span", {class: "badge hunt", text: "re-hunt in " + hunted,
          title: "Found by the re-hunt in " + plural(hunted, "report") + " analyzed without this IOC"}) :
          el("span", {class: "hint", text: "when analyzed"}))), detail];
    }}));

  addTab("vulns", "Vulnerabilities (" + S.vulns.toLocaleString() + ")", panel => itemPanel(panel, {
    rows: data.vulns, noun: "vulnerability", nouns: "vulnerabilities", legend: legend(false),
    none: "None of these reports has scan findings (they may be telemetry-only).",
    noneShared: "No vulnerability is in more than one of these reports. Choose “any number of reports” to see them all.",
    searchHint: "Search name, plugin, CVE, host or report", kindLabel: "Severity", kindAll: "All severities",
    kinds: [["4", "Critical"], ["3", "High"], ["2", "Medium"], ["1", "Low"], ["0", "Info"]],
    kindOf: r => String(r.severity),
    text: r => (r.name + " " + r.plugin_id + " " + r.cves.join(" ") + " " + r.seen.map(s => R[s.r].name + " " + R[s.r].network + " " + s.related.join(" ")).join(" ")).toLowerCase(),
    columns: [{label: "Vulnerability", sort: "name"}, {label: "Severity", sort: "severity", num: true},
              {label: "Reports", sort: "reports", num: true}, {label: "Networks", sort: "networks", num: true},
              {label: "Hosts", sort: "hosts", num: true}, {label: "Seen in (oldest report first)"}, {label: "CVEs"}],
    row: r => {
      const btn = el("button", {type: "button", class: "cmp-open", "aria-expanded": "false", text: r.name});
      const detail = detailRow(7, [
        el("p", {class: "hint"}, "Nessus plugin " + r.plugin_id + (r.cvss !== null ? " · CVSS " + r.cvss : "") +
          (r.exploit ? " · a public exploit is available" : "") + (r.cves.length ? " · " + r.cves.join(", ") : "")),
        el("ul", {class: "cmp-seen"}, r.seen.map(s => el("li", {}, el("b", {text: repName(s.r)}), " — ", hostList(s))))]);
      btn.onclick = () => toggle(btn, detail);
      const cves = r.cves.slice(0, 3).join(", ") + (r.cves.length > 3 ? " +" + (r.cves.length - 3) : "");
      return [el("tr", {},
        el("td", {class: "cmp-ind"}, btn, r.exploit ? el("span", {class: "badge exploit", text: "exploit"}) : ""),
        el("td", {class: "num"}, el("span", {class: "badge sev-" + r.severity, text: r.severity_name})),
        el("td", {class: "num"}, el("b", {text: r.reports})),
        el("td", {class: "num", text: r.networks}),
        el("td", {class: "num", text: r.hosts.toLocaleString()}),
        el("td", {}, strip(r.seen)),
        el("td", {class: "cmp-cves", text: cves || "—"})), detail];
    }}));

  addTab("reports", "Reports (" + S.reports + ")", panel => {
    panel.append(el("p", {class: "hint", text: "A report's network is its Network name from Report details, or its name when it has none. " +
      "Reports with the same network count as one network."}));
    const body = el("tbody");
    R.forEach((r, i) => body.append(el("tr", {},
      el("td", {class: "num", text: i + 1}),
      el("td", {}, r.href ? el("a", {href: r.href, target: "_blank", rel: "noopener", text: r.name}) : r.name,
        r.reopened_from ? el("div", {class: "hint", text: "Reopened from " + r.reopened_from}) : ""),
      el("td", {text: r.network}),
      el("td", {text: day(r.generated)}),
      el("td", {class: "num", text: r.hosts.toLocaleString()}),
      el("td", {class: "num", text: r.telemetry_only ? "no scan" : r.findings.toLocaleString()}),
      el("td", {class: "num", text: r.ioc_matches === null ? "no IOC CSV" : r.ioc_matches.toLocaleString()}),
      el("td", {}, r.hunted ? (r.found_by_hunt ? el("span", {class: "badge hunt", text: "+" + r.found_by_hunt + " found"}) : "nothing new") : "not searched",
        r.notes.map(n => el("div", {class: "hint", text: n}))))));
    panel.append(el("div", {class: "cmp-scroll"}, el("table", {class: "cmp-table"}, el("thead", {}, el("tr", {},
      ["#", "Report", "Network", "Analyzed", "Hosts", "Findings", "IOC matches when analyzed", "Re-hunt"].map(h => el("th", {scope: "col", text: h})))), body)));
  });

  // -- notes and downloads ---------------------------------------------------------------------
  root.append(el("section", {class: "cmp-notes"},
    el("h2", {text: "How to read this"}),
    el("ul", {},
      el("li", {text: "Reports: how many of the compared reports show the IOC or vulnerability. Networks: how many different networks those reports cover."}),
      el("li", {text: "Hosts: related hosts added up over the reports. Internal addresses repeat between networks, so the same address in two reports can be two different machines."}),
      el("li", {text: "IOC matches are exact matches to the indicator lists, not proof of malicious activity. The re-hunt uses each report's saved data and the same rules as the analysis."}),
      data.notes.map(n => el("li", {text: n}))),
    el("p", {}, "Download: ",
      el("a", {href: "ioc_overlap.csv", download: true, text: "IOCs (CSV)"}), " · ",
      el("a", {href: "vulnerability_overlap.csv", download: true, text: "vulnerabilities (CSV)"}), " · ",
      el("a", {href: "comparison.json", download: true, text: "everything (JSON)"}),
      el("span", {class: "hint", text: " — one row per item per report, with every related host."})),
    ex && ex.file ? el("p", {}, "The all-networks Explorer's data: ", el("a", {href: ex.data, download: true, text: "explorer.json"}),
      el("span", {class: "hint", text: " — the hosts, subnets, traffic and highlights it draws, per report."})) : ""));

  const start = (location.hash || "").slice(1);
  select(tabList.some(t => t.id === start) ? start : (S.iocs || !S.vulns ? "iocs" : "vulns"));
})();
