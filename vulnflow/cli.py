"""Command line entry point: python -m vulnflow {analyze,serve,samples}."""
from __future__ import annotations

import argparse
import os
import sys

from .correlate import DEFAULT_INTERNAL_NETS, Config
from .parsers import FORMATS


def _cfg(a) -> Config:
    return Config(internal_nets=a.internal_net or list(DEFAULT_INTERNAL_NETS), hops=a.hops,
                  min_severity=a.min_severity,
                  scan_window_days=a.scan_window_days or None,
                  dedup_skew_seconds=None if a.dedup_skew < 0 else a.dedup_skew)


def _llm_cfg(a, required=True):
    """Resolve the AI provider from flags/env. No vendor is assumed: one must be chosen.
    When the chosen provider needs a key and none is set, ask for it without echoing."""
    from .llm import KEY_ENV, PROVIDER_NAMES, LLMConfig, LLMError
    cfg = LLMConfig.from_env(provider=a.llm_provider, model=a.llm_model, base_url=a.llm_base_url,
                             redact=True if a.redact else None)
    if not cfg.ready:
        if required:
            raise LLMError("Choose an AI provider with --llm-provider "
                           f"({', '.join(p for p in PROVIDER_NAMES if p != 'mock')}) or VULNFLOW_LLM_PROVIDER.")
        return cfg
    if cfg.needs_key() and sys.stdin.isatty():
        import getpass
        cfg.api_key = getpass.getpass(f"{PROVIDER_NAMES[cfg.provider]} API key "
                                      f"(or set {KEY_ENV[cfg.provider]}): ").strip()
    return cfg


def _llm_flags(p):
    p.add_argument("--llm-provider", choices=["anthropic", "openai", "local", "mock"],
                   help="AI provider; no default, nothing is sent until you choose (env: VULNFLOW_LLM_PROVIDER)")
    p.add_argument("--llm-model", help="model name (required for openai; suggested defaults: "
                                       "anthropic claude-opus-5-5, local llama3.1)")
    p.add_argument("--llm-base-url", help="endpoint for openai/local, e.g. http://localhost:11434/v1")
    p.add_argument("--redact", action="store_true",
                   help="replace IPs and hostnames with tokens before anything is sent to the model")


def _chat(outdir, analyst, cfg, first=None) -> int:
    from .llm import LLMError, log_qa
    history = []
    print(f"Asking {cfg.label()} about {outdir}. Empty line or Ctrl-D to quit.")
    while True:
        q = first
        first = None
        if q is None:
            try:
                q = input("\nquestion> ").strip()
            except EOFError:
                q = ""
        if not q:
            return 0
        try:
            a = analyst.ask(q, history)
        except LLMError as exc:
            print(f"error: {exc}", file=sys.stderr)
            continue
        print("\n" + a)
        log_qa(outdir, cfg, q, a)
        history += [{"role": "user", "content": q}, {"role": "assistant", "content": a}]


def _input_files(paths, outdir):
    """Expand input directories recursively, ignoring hidden files and the output folder."""
    files = []
    output = os.path.abspath(outdir)
    for path in paths:
        if not os.path.isdir(path):
            files.append(path)
            continue
        for root, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and
                             os.path.abspath(os.path.join(root, d)) != output)
            files.extend(os.path.join(root, name) for name in sorted(names)
                         if not name.startswith(".") and os.path.isfile(os.path.join(root, name)))
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnflow", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--internal-net", action="append", metavar="CIDR",
                       help="internal address range (repeatable; default RFC1918 etc.)")
        p.add_argument("--hops", type=int, default=2, help="blast-radius depth (default 2)")
        p.add_argument("--min-severity", type=int, default=1, choices=range(5),
                       help="lowest Nessus severity to score, 0=Info..4=Critical (default 1)")
        p.add_argument("--scan-window-days", type=float, default=7, metavar="DAYS",
                       help="use telemetry within DAYS of each host's scan time (0 = all; default 7)")
        p.add_argument("--dedup-skew", type=float, default=2.0, metavar="SECONDS",
                       help="clock skew allowed when matching one session seen by two sensors "
                            "(default 2; negative disables cross-sensor matching)")
        p.add_argument("--workdir", metavar="DIR",
                       help="where to write temporary Parquet/DuckDB files (default: system temp "
                            "or $VULNSCOPE_WORKDIR); use a disk with room for large inputs")

    a = sub.add_parser("analyze", help="run the workflow on local files")
    a.add_argument("files", nargs="+")
    a.add_argument("-o", "--out", default="vulnflow_out")
    a.add_argument("--format", action="append", default=[], metavar="FILE=FORMAT",
                   help=f"force a file's format ({', '.join(FORMATS)})")
    a.add_argument("--ioc-csv", dest="ioc_archive", action="append", default=[], metavar="CSV",
                   help="typed IOC CSV (repeatable; also detected inside input folders)")
    a.add_argument("--ioc-archive", dest="ioc_archive", action="append", help=argparse.SUPPRESS)
    a.add_argument("--no-article-preview", action="store_true",
                   help="skip fetching short source previews for matched archive articles")
    a.add_argument("--article-preview-cache", metavar="JSON",
                   help="saved short source overviews keyed by article URL (useful offline)")
    a.add_argument("--llm", action="store_true", help="also write a Security Assistant brief")
    common(a)
    _llm_flags(a)

    b = sub.add_parser("brief", help="write a Security Assistant brief for an existing output folder")
    b.add_argument("outdir")
    _llm_flags(b)

    ab = sub.add_parser("article-briefs", help="generate AI briefs for matched source articles")
    ab.add_argument("outdir")
    _llm_flags(ab)

    q = sub.add_parser("ask", help="ask the Security Assistant about an output folder (interactive without a question)")
    q.add_argument("outdir")
    q.add_argument("question", nargs="*")
    q.add_argument("--once", action="store_true", help="answer the question and exit")
    _llm_flags(q)

    s = sub.add_parser("serve", help="start the local upload page")
    s.add_argument("--host", default="127.0.0.1",
                   help="address to listen on (default 127.0.0.1; any other address needs --allow-remote)")
    s.add_argument("--allow-remote", action="store_true",
                   help="allow a non-loopback --host; every visitor then needs the printed access-token link")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--data-dir", default="vulnflow_runs")
    s.add_argument("--max-upload-mb", type=int, default=1024, help="largest accepted upload (default 1024)")
    common(s)
    _llm_flags(s)
    s.add_argument("--no-llm", action="store_true", help="hide the Security Assistant on the results page")
    # serve: provider/key can also be chosen later on the page's AI settings screen

    x = sub.add_parser("explore", help="analyze a folder and open the interactive host explorer")
    x.add_argument("files", nargs="+", metavar="FOLDER", help="folder (or files) with telemetry; Nessus scans optional")
    x.add_argument("-o", "--out", default=None, help="output folder (default: vulnflow_out/<folder name>)")
    x.add_argument("--host", dest="focus", metavar="IP", help="open focused on this host")
    x.add_argument("--no-open", action="store_true", help="write the explorer without opening a browser")
    x.add_argument("--format", action="append", default=[], metavar="FILE=FORMAT", help=argparse.SUPPRESS)
    x.add_argument("--ioc-csv", dest="ioc_archive", action="append", default=[], metavar="CSV",
                   help="typed IOC CSV")
    x.add_argument("--ioc-archive", dest="ioc_archive", action="append", help=argparse.SUPPRESS)
    x.add_argument("--no-article-preview", action="store_true",
                   help="skip fetching short source previews")
    x.add_argument("--article-preview-cache", metavar="JSON",
                   help="saved short source overviews keyed by article URL")
    common(x)

    g = sub.add_parser("samples", help="write scan-backed and telemetry-only sample folders")
    g.add_argument("outdir", nargs="?", default="samples")

    args = ap.parse_args(argv)
    if args.cmd in ("analyze", "explore", "serve"):
        os.umask(0o077)          # reports, normalized logs and spooled data are private to this account
    if args.cmd == "samples":
        from .samples import generate_bundles
        for p in generate_bundles(args.outdir):
            print(p)
        return 0
    if args.cmd == "serve":
        from .web import serve
        llm_cfg = None
        if not args.no_llm:
            from .llm import LLMConfig, LLMError
            try:
                llm_cfg = _llm_cfg(args, required=False)
            except LLMError as exc:
                print(f"warning: {exc} Choose a provider on the AI settings page instead.", file=sys.stderr)
                llm_cfg = LLMConfig()
        serve(args.host, args.port, args.data_dir, _cfg(args), llm_cfg=llm_cfg,
              max_upload=args.max_upload_mb * 1024 * 1024, allow_remote=args.allow_remote)
        return 0
    if args.cmd in ("brief", "article-briefs", "ask"):
        from .llm import Analyst, LLMError, load_results, write_brief
        try:
            cfg = _llm_cfg(args)
            res = load_results(args.outdir)
            if args.cmd == "article-briefs":
                from .article_brief import generate_article_briefs
                from .report import save_article_briefs
                summary = generate_article_briefs(res, cfg)
                if summary["generated"]:
                    save_article_briefs(res, args.outdir)
                print(f"Generated {summary['generated']} article brief(s); "
                      f"{summary['saved']} saved, {summary['unavailable']} source(s) unavailable.")
                for error in summary["errors"]:
                    print(f"warning: {error}", file=sys.stderr)
                return 0 if summary["saved"] else 2
            if args.cmd == "brief":
                print(write_brief(res, args.outdir, cfg))
                return 0
            question = " ".join(args.question) or None
            analyst = Analyst(res, cfg)
            if args.once and question:
                from .llm import log_qa
                answer = analyst.ask(question)
                print(answer)
                log_qa(args.outdir, cfg, question, answer)
                return 0
            return _chat(args.outdir, analyst, cfg, question)
        except LLMError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    from .pipeline import run
    if args.cmd == "explore" and not args.out:
        args.out = os.path.join("vulnflow_out", os.path.basename(os.path.abspath(args.files[0])) or "explore")
    overrides = dict(x.split("=", 1) for x in args.format)
    files = _input_files(args.files, args.out) + args.ioc_archive
    try:
        res, paths = run(files, args.out, _cfg(args), overrides,
                         article_previews=not args.no_article_preview,
                         article_preview_cache=args.article_preview_cache,
                         workdir=args.workdir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    s, pc = res["summary"], res["summary"]["priority_counts"]
    for i in res["inputs"]:
        print(f"  {i['file']:<32} {i['format']:<11} read {i['read']:>6}  kept {i['kept']:>6}")
    if s["vulnerability_data_available"]:
        print(f"\n{s['flows']} sessions, {s['findings_scored']} findings scored on {s['hosts_with_findings']} hosts")
        print(f"P1 {pc['P1']}  P2 {pc['P2']}  P3 {pc['P3']}  P4 {pc['P4']}")
        print(f"corroborated exploitation evidence: {', '.join(s['hosts_corroborated']) or 'none'}; "
              f"leads to investigate: {', '.join(s['hosts_to_investigate'] + s['hosts_possible_spread']) or 'none'}")
    else:
        print(f"\n{s['flows']} sessions. No vulnerability data available; vulnerability status unknown.")
        print(f"{s['threat_alerts']} IPS/IDS alerts; {len(res['network_leads'])} return-connection leads for review.")
    if "ioc_matches" in res:
        print(f"IOC CSV matches for review: {len(res['ioc_matches'])}")
    if args.cmd == "explore":
        url = "file://" + os.path.abspath(paths["explorer.html"]) + (f"#host={args.focus}" if args.focus else "")
        print(f"\nExplorer: {url}")
        if not args.no_open:
            import webbrowser
            webbrowser.open(url)
        return 0
    if args.llm:
        from .llm import LLMError, write_brief
        try:
            cfg = _llm_cfg(args)
            print(f"\nWriting Security Assistant brief with {cfg.label()} ...")
            write_brief(res, args.out, cfg)
            paths["ai_analyst_brief.md"] = os.path.join(args.out, "ai_analyst_brief.md")
            paths["ai_analyst_brief.html"] = os.path.join(args.out, "ai_analyst_brief.html")
        except LLMError as exc:
            print(f"warning: AI brief skipped: {exc}", file=sys.stderr)
    print(f"\nReports written to {os.path.abspath(args.out)}:")
    for name in paths:
        print(f"  {name}")
    return 0
