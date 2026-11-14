#!/usr/bin/env python3
"""Repository hygiene check: things that must never be committed to VulnScope.

Checks every file git tracks (including files staged for the next commit) and fails, listing each problem, on:

  local data    branding.json, .vulnscope/ and vulnscope-out/ folders, .env files (.env.example is fine).
                Branding set for local testing stays on the analyst's machine (~/.vulnscope).
  captures and  packet captures (.pcap, .pcapng, .cap, .pcapnano), Windows/Linux/macOS executables and
  binaries      libraries, archives. Checked by file name AND by the first bytes, so a renamed file is caught.
                Test data that needs captures is downloaded at test time (see scripts/accuracy/), never committed.
  keys          private keys and API keys that look real (Anthropic, OpenAI, AWS access keys).
  size          any file over 5 MB.
  images        images outside screenshots/, vulnflow/static/ and example_output/ (a logo dropped anywhere
                else is most likely local branding).

Run it before committing:  python scripts/check_repo.py
As a git hook:              printf '#!/bin/sh\\nexec python3 scripts/check_repo.py\\n' > .git/hooks/pre-commit
                            chmod +x .git/hooks/pre-commit
CI runs it on every pull request (.github/workflows/ci.yml).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 5 * 1024 * 1024

LOCAL_NAMES = {"branding.json"}
LOCAL_DIRS = {".vulnscope", "vulnscope-out"}
BINARY_EXT = {".pcap", ".pcapng", ".cap", ".pcapnano", ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".scr",
              ".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".jar", ".apk", ".iso", ".dmg"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff"}
IMAGE_DIRS = ("screenshots/", "vulnflow/static/", "example_output/")
MAGIC = [  # first bytes -> what it is
    (b"\xd4\xc3\xb2\xa1", "packet capture (pcap)"), (b"\xa1\xb2\xc3\xd4", "packet capture (pcap)"),
    (b"\x4d\x3c\xb2\xa1", "packet capture (pcap)"), (b"\xa1\xb2\x3c\x4d", "packet capture (pcap)"),
    (b"\x0a\x0d\x0d\x0a", "packet capture (pcapng)"),
    (b"MZ", "Windows executable"), (b"\x7fELF", "Linux executable"),
    (b"\xcf\xfa\xed\xfe", "macOS executable"), (b"\xce\xfa\xed\xfe", "macOS executable"), (b"\xca\xfe\xba\xbe", "macOS executable"),
    (b"PK\x03\x04", "zip archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"Rar!", "RAR archive"),
    (b"\x1f\x8b", "gzip file"),
]
SECRETS = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-ant-[A-Za-z0-9_-]{20,}|\bsk-(?:proj-)?[A-Za-z0-9]{32,}|"
                     rb"\bAKIA[0-9A-Z]{16}\b")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z", "--cached"], cwd=ROOT, check=True, capture_output=True).stdout
    return [p for p in out.decode().split("\0") if p]


def problems_for(rel: str) -> list[str]:
    path, pure = ROOT / rel, PurePosixPath(rel)
    found = []
    name, ext = pure.name.lower(), pure.suffix.lower()
    if name in LOCAL_NAMES or LOCAL_DIRS & set(pure.parts[:-1]):
        found.append("local branding or output data; keep it in ~/.vulnscope or vulnscope-out/, outside git")
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        found.append("environment file (may hold keys); only .env.example belongs in the repository")
    if ext in BINARY_EXT:
        found.append(f"{ext} file: captures, executables and archives are never committed")
    if ext in IMAGE_EXT and not rel.startswith(IMAGE_DIRS):
        found.append(f"image outside {', '.join(IMAGE_DIRS)} (local branding?)")
    if not path.is_file():   # deleted in the working tree but still in the index
        return found
    size = path.stat().st_size
    if size > MAX_BYTES:
        found.append(f"{size / 1048576:.1f} MB, over the 5 MB limit")
    with path.open("rb") as f:
        head = f.read(8)
    for magic, what in MAGIC:
        if head.startswith(magic) and ext not in BINARY_EXT and not (what == "zip archive" and ext in {".xlsx", ".docx"}):
            found.append(f"content is a {what}")
            break
    if size <= MAX_BYTES and ext not in IMAGE_EXT and SECRETS.search(path.read_bytes()):
        found.append("contains what looks like a private key or API key")
    return found


def main() -> int:
    bad = 0
    for rel in tracked_files():
        for problem in problems_for(rel):
            print(f"{rel}: {problem}")
            bad += 1
    if bad:
        print(f"\n{bad} problem(s). Remove the file(s) from git (git rm --cached <file>) and keep them local.")
        return 1
    print("Repository hygiene: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
