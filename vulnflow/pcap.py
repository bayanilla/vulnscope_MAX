"""Turn packet captures into Zeek logs with a local Zeek, so PCAP can be analyzed like any log.

VulnScope does not decode packets itself. When an input is a .pcap or .pcapng file (plain or
.gz, recognised by its first bytes, not its name), it runs ``zeek -C -r <file> local`` into a
temporary folder and analyzes the conn/dns/http/... logs Zeek writes. The container image ships
Zeek; elsewhere install it (``brew install zeek``, the zeek/zeek Docker image, or a Linux package)
or point ``VULNSCOPE_ZEEK`` at the binary.
"""
from __future__ import annotations

import gzip
import os
import re
import shutil
import subprocess
import sys
import tempfile

from .errors import UserError
from .schema import ParseStats

# pcap (micro- and nanosecond, either byte order) and the pcapng section header block
_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
          b"\x0a\x0d\x0d\x0a")
# Zeek's own bookkeeping logs: nothing about the network in them.
_SKIP_LOGS = {"loaded_scripts", "packet_filter", "stats", "reporter", "telemetry",
              "print", "broker", "cluster", "config"}
_ZEEK_CANDIDATES = ("/usr/local/zeek/bin/zeek", "/opt/zeek/bin/zeek", "/opt/homebrew/bin/zeek",
                    "/usr/local/bin/zeek")
INSTALL_HINT = ("Install Zeek (macOS: brew install zeek; Linux: your distribution's zeek package; "
                "or use the VulnScope container, which includes it), set VULNSCOPE_ZEEK to the zeek "
                "binary, or convert first with: zeek -C -r capture.pcap local")


class ZeekMissing(UserError):
    """PCAP input was given but no Zeek binary could be found."""


def _head(path: str, n: int = 4) -> bytes:
    try:
        with open(path, "rb") as fh:
            head = fh.read(n)
            if head[:2] == b"\x1f\x8b":
                fh.seek(0)
                with gzip.open(fh) as gz:
                    return gz.read(n)
            return head
    except (OSError, EOFError, gzip.BadGzipFile):
        return b""


def is_pcap(path: str) -> bool:
    """True for a pcap/pcapng file, plain or gzip-compressed, judged by its magic bytes."""
    return _head(path) in _MAGIC


def find_zeek() -> str | None:
    configured = os.environ.get("VULNSCOPE_ZEEK", "").strip()
    if configured:
        return configured if os.path.isfile(configured) and os.access(configured, os.X_OK) else None
    found = shutil.which("zeek")
    if found:
        return found
    return next((p for p in _ZEEK_CANDIDATES if os.path.isfile(p) and os.access(p, os.X_OK)), None)


def zeek_version(zeek: str) -> str:
    try:
        out = subprocess.run([zeek, "--version"], capture_output=True, text=True, timeout=30)
        m = re.search(r"version\s+(\S+)", out.stdout + out.stderr)
        return f"Zeek {m[1]}" if m else "Zeek"
    except (OSError, subprocess.SubprocessError):
        return "zeek"


def _safe_stem(name: str) -> str:
    stem = re.sub(r"(\.gz)?$", "", name, flags=re.I)
    stem = re.sub(r"\.(pcapng|pcap|cap|dmp)$", "", stem, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:80] or "capture"


def convert(paths: list[str], workdir: str) -> tuple[list[str], list[ParseStats]]:
    """Run Zeek on each capture; return the network logs it wrote and one stats row per capture.

    Logs land in ``workdir/<n>_<capture>/`` and are named ``<capture>-conn.log`` and so on (Zeek's
    ``#path`` header still says which stream each one is). A capture Zeek cannot read is reported
    in its stats row instead of stopping the run, like any other broken input file.
    """
    if not paths:
        return [], []
    zeek = find_zeek()
    if not zeek:
        names = ", ".join(os.path.basename(p) for p in paths[:3]) + (" ..." if len(paths) > 3 else "")
        raise ZeekMissing(f"Packet captures need Zeek to be analyzed ({names}), and no zeek binary was "
                          f"found. {INSTALL_HINT}.")
    version = zeek_version(zeek)
    logs: list[str] = []
    stats: list[ParseStats] = []
    for i, path in enumerate(paths, 1):
        name = os.path.basename(path)
        st = ParseStats(file=name, fmt="pcap")
        stem = _safe_stem(name)
        out = os.path.join(workdir, f"{i:03d}_{stem}")
        os.makedirs(out, exist_ok=True)
        print(f"Converting {name} with {version} ...", file=sys.stderr)
        compressed = _is_gzip(path)
        cmd = [zeek, "-C", "-r", "-" if compressed else os.path.abspath(path), "local"]
        try:
            with tempfile.TemporaryFile(dir=out) as errfile:
                if compressed:
                    proc = subprocess.Popen(cmd, cwd=out, stdin=subprocess.PIPE,
                                            stdout=subprocess.DEVNULL, stderr=errfile)
                    try:
                        with gzip.open(path, "rb") as src:
                            shutil.copyfileobj(src, proc.stdin, 1 << 20)
                    except (OSError, EOFError) as exc:     # truncated .gz or Zeek gave up early
                        errfile.write(f"\nerror: {exc}".encode())
                    finally:
                        try:
                            proc.stdin.close()
                        except OSError:
                            pass
                    code = proc.wait()
                else:
                    code = subprocess.run(cmd, cwd=out, stdout=subprocess.DEVNULL, stderr=errfile).returncode
                errfile.seek(0)
                err = errfile.read()
        except OSError as exc:
            raise ZeekMissing(f"Zeek could not be started ({zeek}: {exc}). {INSTALL_HINT}.") from exc
        made = []
        for log in sorted(os.listdir(out)):
            m = re.fullmatch(r"(.+)\.log", log)
            if not m or m[1] in _SKIP_LOGS:
                continue
            target = os.path.join(out, f"{stem}-{log}")
            os.replace(os.path.join(out, log), target)
            made.append(target)
        message = _last_error(err)
        if code != 0 and not made:
            st.note(f"Zeek could not read this capture: {message or f'exit code {code}'}")
        else:
            streams = ", ".join(re.sub(r"^.*-(.+)\.log$", r"\1", p) for p in made) or "none"
            st.note(f"converted with {version}; Zeek logs: {streams}")
            if code != 0:
                st.note(f"Zeek stopped early ({message or f'exit code {code}'}); logs written before that are used")
            if not any(p.endswith("-conn.log") for p in made):
                st.note("Zeek found no connections in this capture")
        logs.extend(made)
        stats.append(st)
    return logs, stats


def _is_gzip(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def _last_error(err: bytes | None) -> str:
    lines = [l.strip() for l in (err or b"").decode("utf-8", "replace").splitlines() if l.strip()]
    lines = [l for l in lines if "error" in l.lower() or "fatal" in l.lower()] or lines
    return lines[-1][:300] if lines else ""
