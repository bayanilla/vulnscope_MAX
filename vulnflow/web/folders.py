"""Finding a folder on this machine for the upload page: the in-page folder list, the macOS
Choose Folder dialog, and (in the container) locating the folder picked in the browser's own
folder window among the folders shared with the container."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

NATIVE_PICKER = sys.platform == "darwin" and shutil.which("osascript") is not None

# In the container image: the folders shared from the host, separated by ":" (for example your
# home folder, mounted read-only at the same path, then /data). The folder picker starts at the
# first one and stays inside them, since nothing else in the container is yours.
CONTAINER_DATA = os.environ.get("VULNSCOPE_DATA_ROOT", "").strip()
BROWSE_ROOTS = [os.path.realpath(r) for r in CONTAINER_DATA.split(":") if r.strip() and os.path.isdir(r)]


def browse_root() -> str:
    return BROWSE_ROOTS[0] if BROWSE_ROOTS else (CONTAINER_DATA.split(":")[0] if CONTAINER_DATA else "~")


# The shared folder as the host names it (e.g. C:\Users\you on Windows), so a path copied from
# Explorer or Finder can be pasted as is and is translated to where the container sees it.
HOST_ROOT = os.environ.get("VULNSCOPE_HOST_ROOT", "").strip()


def host_to_container(raw: str) -> str:
    if not (HOST_ROOT and BROWSE_ROOTS):
        return raw
    norm = lambda p: p.replace("\\", "/").rstrip("/")
    host, given = norm(HOST_ROOT), norm(raw)
    if given.lower() == host.lower() or given.lower().startswith(host.lower() + "/"):
        return BROWSE_ROOTS[0].rstrip("/") + given[len(host):]
    return raw


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


_LOCATE_SKIP = {"Library", "AppData", "node_modules", "$RECYCLE.BIN", "System Volume Information",
                "Applications", "Pictures", "Music", "Movies"}


def _match_score(folder: str, samples: list) -> int | None:
    """None unless most sample files exist in ``folder`` with the same size; otherwise how many
    also have the same modification time (within 2 s), which tells copies of a folder apart."""
    hits = same_time = 0
    for item in samples:
        try:
            rel, size = str(item[0]), int(item[1])
            mtime = float(item[2]) / 1000 if len(item) > 2 and item[2] is not None else None
        except (TypeError, ValueError, IndexError):
            continue
        p = os.path.join(folder, *[part for part in rel.split("/") if part not in ("", ".", "..")])
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_size == size:
            hits += 1
            if mtime is not None and abs(st.st_mtime - mtime) <= 2:
                same_time += 1
    return same_time if samples and hits >= max(1, (len(samples) * 4) // 5) else None


def locate_folder(name: str, samples: list, budget_s: float = 8.0, max_depth: int = 8) -> dict:
    """Search the shared folders for one called ``name`` holding files with the given relative
    paths and sizes (the browser's folder window gives only these, never the real path).
    Breadth-first, skipping hidden and bulky system folders, within a time budget."""
    samples = samples[:20]
    if not BROWSE_ROOTS:
        return {"error": "Folder search is only available in the container."}
    deadline, found, queue = time.monotonic() + budget_s, {}, [(r, 0) for r in BROWSE_ROOTS]
    for root in BROWSE_ROOTS:                      # the shared folder itself (e.g. the inbox)
        score = _match_score(root, samples)
        if score is not None:
            found[root] = score
    timed_out = False
    while queue and len(found) < 50:
        if time.monotonic() > deadline:
            timed_out = True
            break
        folder, depth = queue.pop(0)
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name.lower())
        except OSError:
            continue
        for e in entries:
            if e.name.startswith(".") or e.name in _LOCATE_SKIP:
                continue
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if e.name == name and e.path not in found:
                score = _match_score(e.path, samples)
                if score is not None:
                    found[e.path] = score
            if depth + 1 < max_depth:
                queue.append((e.path, depth + 1))
    if found:
        # Copies of the same folder (same names and sizes) are told apart by file times: keep
        # only the folders whose files have the picked folder's modification times.
        best = max(found.values())
        return {"matches": [p for p, score in found.items() if score == best]}
    shared = ", ".join(BROWSE_ROOTS)
    return {"error": (f"VulnScope can't find {name}"
                      + (" in time; type its full path instead." if timed_out else
                         f". It's outside the folders VulnScope can see ({shared}); move it there, "
                         "type its full path, or use Upload below."))}


def list_folder(raw: str) -> dict:
    """Subfolders of `raw` (default: home, or the container's data folder), skipping hidden ones;
    falls back to the nearest existing parent."""
    path = os.path.realpath(os.path.expanduser(host_to_container(raw.strip().strip('"').strip("'"))
                                               or browse_root()))
    while not os.path.isdir(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    if BROWSE_ROOTS and not any(_within(path, r) for r in BROWSE_ROOTS):
        path = BROWSE_ROOTS[0]
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        return {"error": f"Cannot open {path}: {exc.strerror or exc}"}
    dirs, files = [], 0
    for e in entries:
        if e.name.startswith("."):
            continue
        try:
            if e.is_dir():
                dirs.append(e.name)
            elif e.is_file():
                files += 1
        except OSError:
            continue
    parent = os.path.dirname(path)
    if parent == path or (BROWSE_ROOTS and path in BROWSE_ROOTS):
        parent = None
    return {"path": path, "parent": parent, "sep": os.sep, "roots": BROWSE_ROOTS[1:] and BROWSE_ROOTS,
            "dirs": sorted(dirs, key=str.lower), "files": files}


def native_pick(start: str) -> dict:
    """Show the macOS Choose Folder dialog in front of the browser and return the chosen path."""
    start = os.path.realpath(os.path.expanduser(start.strip() or "~"))
    script = ['tell application (path to frontmost application as text)',
              'activate',
              'POSIX path of (choose folder with prompt "Choose a folder of telemetry and Nessus scans"'
              + (' default location (POSIX file %s)' % json.dumps(start) if os.path.isdir(start) else "") + ")",
              'end tell']
    try:
        out = subprocess.run(["osascript"] + sum((["-e", line] for line in script), []),
                             capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return {"error": "The folder dialog could not be opened."}
    if out.returncode != 0:
        return {"cancelled": True} if "-128" in out.stderr else {"error": "The folder dialog could not be opened."}
    return {"path": out.stdout.strip().rstrip("/") or "/"}


def resolve(raw: str) -> str:
    """The real path of a folder typed or pasted on the page ("" when nothing was given)."""
    raw = raw.strip().strip('"').strip("'")
    return os.path.realpath(os.path.expanduser(host_to_container(raw))) if raw else ""


def path_example() -> str:
    return browse_root() + "/case-logs" if CONTAINER_DATA else "~/Documents/case-logs"


# -- views ------------------------------------------------------------------------------------
def browse(req):
    """List the subfolders of a folder on this machine, for the folder picker."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    return req.send_json(200, list_folder(str(body.get("path") or "")))


def locate(req):
    """Find the folder chosen in the browser's folder window among the shared folders."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    name, samples = body.get("name"), body.get("samples")
    if not isinstance(name, str) or not name or not isinstance(samples, list):
        return req.send_json(400, {"error": "Bad request"})
    return req.send_json(200, locate_folder(name, samples))


def pick(req):
    """Open the operating system's own folder dialog (macOS) on the machine running the server."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    if not NATIVE_PICKER:
        return req.send_json(200, {"unsupported": True})
    return req.send_json(200, native_pick(str(body.get("path") or "")))
