"""Container entry point (Python, so a Windows checkout with CRLF line endings still works).

  serve [flags]           upload page on port 8080 (the default command)
  analyze|explore|...     any `python -m vulnflow` command, e.g. analyze /data/case1 -o /runs/case1
  compare-sample          load the two-company Compare sample into the upload page's runs (/runs/web)
  zeek ...                run the bundled Zeek directly
  anything else           run as a command (sh, bash, ...)

Started as root, it makes sure /runs is writable, then drops to the owner of /runs (so files
written to a bind-mounted folder on Linux belong to you), or to uid 1000 when /runs is owned
by root. It never runs the analysis as root.
"""
import os
import sys

RUNS = "/runs"
VULNFLOW_COMMANDS = {"analyze", "explore", "serve", "samples", "brief", "ask", "article-briefs", "compare",
                     "compare-sample", "filebeat-to-zeek", "branding-password", "-h", "--help"}


def drop_privileges():
    if os.getuid() != 0:
        return
    st = os.stat(RUNS)
    uid, gid = st.st_uid, st.st_gid
    if uid == 0:
        uid, gid = 1000, 1000
        try:
            os.chown(RUNS, uid, gid)
        except OSError:
            pass
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def main():
    args = sys.argv[1:] or ["serve"]
    drop_privileges()
    os.umask(0o077)
    for d in (os.environ.get("VULNSCOPE_WORKDIR"), os.environ.get("VULNSCOPE_HOME")):
        if d:
            try:
                os.makedirs(d, mode=0o700, exist_ok=True)
            except OSError as exc:
                sys.exit(f"Cannot write to {d} ({exc.strerror}). Mount a writable folder at {RUNS}.")
    if args[0] == "serve":
        defaults = []
        if "--host" not in args:
            defaults += ["--host", "0.0.0.0"]
        if "--data-dir" not in args:
            defaults += ["--data-dir", os.path.join(RUNS, "web")]
        args = ["serve"] + defaults + args[1:]
    if args[0] == "compare-sample" and not any(a.split("=")[0] == "--data-dir" for a in args):
        args.append("--data-dir=" + os.path.join(RUNS, "web"))   # where the upload page keeps its runs
    if args[0] == "explore" and "--no-open" not in args:
        args.append("--no-open")              # no browser inside the container
    if args[0] in VULNFLOW_COMMANDS:
        os.execv(sys.executable, [sys.executable, "-m", "vulnflow"] + args)
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()
