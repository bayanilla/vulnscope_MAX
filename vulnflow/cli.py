"""Command line entry point: python -m vulnflow {analyze,serve,samples}."""
from __future__ import annotations

import argparse
import os
import sys

from .correlate import DEFAULT_INTERNAL_NETS, Config
from .parsers import FORMATS


def _cfg(a) -> Config:
    return Config(internal_nets=a.internal_net or list(DEFAULT_INTERNAL_NETS), hops=a.hops,
                  min_severity=a.min_severity)


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

    a = sub.add_parser("analyze", help="run the workflow on local files")
    a.add_argument("files", nargs="+")
    a.add_argument("-o", "--out", default="vulnflow_out")
    a.add_argument("--format", action="append", default=[], metavar="FILE=FORMAT",
                   help=f"force a file's format ({', '.join(FORMATS)})")
    a.add_argument("--ioc-archive", action="append", default=[], metavar="CSV",
                   help="Múcaro IOC Archive CSV export (repeatable; also detected inside input folders)")
    a.add_argument("--no-article-preview", action="store_true",
                   help="skip fetching short source previews for matched archive articles")
    a.add_argument("--article-preview-cache", metavar="JSON",
                   help="saved short source overviews keyed by article URL (useful offline)")
    a.add_argument("--llm", action="store_true", help="also write an AI analyst brief")
    common(a)
    _llm_flags(a)

    b = sub.add_parser("brief", help="write an AI analyst brief for an existing output folder")
    b.add_argument("outdir")
    _llm_flags(b)

    q = sub.add_parser("ask", help="ask the AI analyst about an output folder (interactive without a question)")
    q.add_argument("outdir")
    q.add_argument("question", nargs="*")
    q.add_argument("--once", action="store_true", help="answer the question and exit")
    _llm_flags(q)

    s = sub.add_parser("serve", help="start the local upload page")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--data-dir", default="vulnflow_runs")
    s.add_argument("--max-upload-mb", type=int, default=1024, help="largest accepted upload (default 1024)")
    common(s)
    _llm_flags(s)
    s.add_argument("--no-llm", action="store_true", help="hide the AI analyst on the results page")
    # serve: provider/key can also be chosen later on the page's AI settings screen

    x = sub.add_parser("explore", help="analyze a folder and open the interactive host explorer")
    x.add_argument("files", nargs="+", metavar="FOLDER", help="folder (or files) with telemetry and Nessus scans")
    x.add_argument("-o", "--out", default=None, help="output folder (default: vulnflow_out/<folder name>)")
    x.add_argument("--host", dest="focus", metavar="IP", help="open focused on this host")
    x.add_argument("--no-open", action="store_true", help="write the explorer without opening a browser")
    x.add_argument("--format", action="append", default=[], metavar="FILE=FORMAT", help=argparse.SUPPRESS)
    x.add_argument("--ioc-archive", action="append", default=[], metavar="CSV",
                   help="Múcaro IOC Archive CSV export")
    x.add_argument("--no-article-preview", action="store_true",
                   help="skip fetching short source previews")
    x.add_argument("--article-preview-cache", metavar="JSON",
                   help="saved short source overviews keyed by article URL")
    common(x)

    g = sub.add_parser("samples", help="write synthetic sample inputs")
    g.add_argument("outdir", nargs="?", default="samples")

    args = ap.parse_args(argv)
    if args.cmd == "samples":
        from .samples import generate
        for p in generate(args.outdir):
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
              max_upload=args.max_upload_mb * 1024 * 1024)
        return 0
    if args.cmd in ("brief", "ask"):
        from .llm import Analyst, LLMError, load_results, write_brief
        try:
            cfg = _llm_cfg(args)
            res = load_results(args.outdir)
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
                         article_preview_cache=args.article_preview_cache)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    s, pc = res["summary"], res["summary"]["priority_counts"]
    for i in res["inputs"]:
        print(f"  {i['file']:<32} {i['format']:<11} read {i['read']:>6}  kept {i['kept']:>6}")
    print(f"\n{s['flows']} sessions, {s['findings_scored']} findings scored on {s['hosts_with_findings']} hosts")
    print(f"P1 {pc['P1']}  P2 {pc['P2']}  P3 {pc['P3']}  P4 {pc['P4']}")
    print(f"corroborated exploitation evidence: {', '.join(s['hosts_corroborated']) or 'none'}; "
          f"leads to investigate: {', '.join(s['hosts_to_investigate'] + s['hosts_possible_spread']) or 'none'}")
    if "ioc_matches" in res:
        print(f"Múcaro IOC Archive matches for source review: {len(res['ioc_matches'])}")
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
            print(f"\nWriting AI analyst brief with {cfg.label()} ...")
            write_brief(res, args.out, cfg)
            paths["ai_analyst_brief.md"] = os.path.join(args.out, "ai_analyst_brief.md")
            paths["ai_analyst_brief.html"] = os.path.join(args.out, "ai_analyst_brief.html")
        except LLMError as exc:
            print(f"warning: AI brief skipped: {exc}", file=sys.stderr)
    print(f"\nReports written to {os.path.abspath(args.out)}:")
    for name in paths:
        print(f"  {name}")
    return 0
