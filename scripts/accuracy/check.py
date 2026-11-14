"""Compare VulnScope's results.json with ground truth for each Brim data set.

Usage: python3 check.py DATA RUNS [ZEEK_LOGS]
  DATA       the folder fetch.py filled (one sub-folder per data set)
  RUNS       VulnScope output, one sub-folder per data set (RUNS/<set>/results.json)
  ZEEK_LOGS  reference Zeek logs for each PCAP set, made by a separate Zeek run (ZEEK_LOGS/<set>/)
Exits 1 when any check fails. Writes a Markdown table to $GITHUB_STEP_SUMMARY when it is set.
"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from groundtruth import suricata_only_truth, zeek_truth  # noqa: E402

PCAP_SETS = ["zui_sample_pcap", "zui_sample_pcapng", "brimcap_alerts_pcap", "brimcap_in_pcap",
             "brimcap_ng_pcap", "brimcap_extra_pcapng", "brimcap_oneflow_pcap", "brimcap_loopback_pcap",
             "brimcap_pings_pcapnano"]
LOG_SETS = ["wrccdc_tsv", "wrccdc_json", "zui_export"]


def iso(t):
    return None if t is None else datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hosts(res):
    return {h["host"]: h for h in res["hosts"] if h.get("telemetry_seen")}


def _leads(res):
    return {l["host"]: {"alerts": l["alerts"], "role": sorted(l["role"])} for l in res["telemetry_leads"]}


def check_zeek(truth, res):
    s, cov = res["summary"], res["coverage"]
    H = _hosts(res)
    got_hosts = {h: {"in": m["inbound_flows"], "out": m["outbound_flows"], "ext": m["blast"]["external_destinations"],
                     "top_ext": sorted(n for _, n in m["blast"]["top_external_destinations"])} for h, m in H.items()}
    scanners = {e["ip"]: {k: e[k] for k in ("sessions", "targets", "hosts", "ports", "failed_pct")}
                for e in s["traffic_scanners"]}
    return [
        ("sessions", truth["sessions"], s["flows"]),
        ("window start", iso(truth["window_start"]), s["window_start"]),
        ("window end", iso(truth["window_end"]), s["window_end"]),
        ("hosts", len(truth["hosts"]), cov["telemetry_internal_hosts"]),
        ("host list", truth["hosts"], sorted(H)),
        ("probed-only addresses", truth["probed_only"], cov["probed_only_addresses"]),
        ("answered %", truth["answered_pct"], cov["sessions_answered_pct"]),
        ("alerts", truth["alerts"], s["threat_alerts"]),
        ("Zeek event counts", truth["event_counts"], dict(sorted(s["zeek_event_counts"].items()))),
        ("per-host sessions and external destinations", truth["per_host"], got_hosts),
        ("alert leads per host", truth["leads"], _leads(res)),
        ("traffic scanners", truth["scanners"], scanners),
    ]


def check_suricata_only(truth, res):
    H = {h["host"]: {"in": h["inbound_flows"], "out": h["outbound_flows"]} for h in res["hosts"]}
    return [
        ("sessions", truth["sessions"], res["summary"]["flows"]),
        ("alerts", truth["alerts"], res["summary"]["threat_alerts"]),
        ("per-host sessions (direction from Zeek)", truth["per_host"], {h: H[h] for h in truth["per_host"] if h in H}),
        ("alert leads per host", truth["leads"], _leads(res)),
    ]


def diff(exp, got):
    if isinstance(exp, dict) and isinstance(got, dict):
        keys = sorted(set(exp) | set(got), key=str)
        bad = [(k, exp.get(k), got.get(k)) for k in keys if exp.get(k) != got.get(k)]
        return f"{len(bad)} differ, e.g. " + "; ".join(f"{k}: expected {e}, got {g}" for k, e, g in bad[:3])
    return f"expected {str(exp)[:300]}, got {str(got)[:300]}"


def main(data, runs, zeek_logs=None):
    cases = []
    for name in PCAP_SETS:
        cases.append((name, os.path.join(zeek_logs, name), "zeek"))
    for name in LOG_SETS:
        cases.append((name, os.path.join(data, name), "zeek"))
    cases.append(("suricata_with_zeek", None, "suricata_with_zeek"))
    cases.append(("suricata_only", None, "suricata_only"))

    rows, failures = [], 0
    for name, logs, kind in cases:
        res_path = os.path.join(runs, name, "results.json")
        if not os.path.exists(res_path):
            rows.append((name, 0, 1, ["no results.json"]))
            failures += 1
            continue
        with open(res_path) as fh:
            res = json.load(fh)
        if kind == "zeek":
            checks = check_zeek(zeek_truth(logs), res)
        elif kind == "suricata_with_zeek":
            # Zeek logs of alerts.pcap plus Suricata's eve.json: every session counted once
            truth = zeek_truth(os.path.join(zeek_logs, "suricata_with_zeek"))
            checks = check_zeek(truth, res)
        else:
            truth = suricata_only_truth(os.path.join(runs, "_eve", "eve.json"),
                                        os.path.join(zeek_logs, "brimcap_alerts_pcap"))
            checks = check_suricata_only(truth, res)
        bad = [f"{label}: {diff(e, g)}" for label, e, g in checks if e != g]
        failures += bool(bad)
        rows.append((name, len(checks) - len(bad), len(checks), bad))

    lines = ["| Data set | Checks passed | Problems |", "|---|---|---|"]
    for name, ok, n, bad in rows:
        lines.append(f"| {name} | {ok}/{n} | {'<br>'.join(bad) if bad else ''} |")
        print(f"{'PASS' if not bad else 'FAIL'} {name}: {ok}/{n}")
        for b in bad:
            print("     " + b)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write("## Accuracy on Brim sample data\n\n" + "\n".join(lines) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
