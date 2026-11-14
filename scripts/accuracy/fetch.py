"""Download the pinned Brim sample files listed in brim_manifest.txt and check each SHA-256.

Usage: python3 fetch.py DEST_DIR. A file already present with the right hash is kept. Any hash
mismatch stops the run, so a changed upstream file can never reach the tests."""
import hashlib
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(dest):
    entries = []
    with open(os.path.join(HERE, "brim_manifest.txt")) as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                entries.append(line.split())
    for digest, rel, url in entries:
        path = os.path.join(dest, rel)
        if os.path.exists(path) and sha256(path) == digest:
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        for attempt in range(4):
            try:
                urllib.request.urlretrieve(url, path + ".part")
                break
            except OSError as exc:
                if attempt == 3:
                    raise
                print(f"retrying {url}: {exc}", file=sys.stderr)
                time.sleep(2 ** (attempt + 1))
        got = sha256(path + ".part")
        if got != digest:
            os.remove(path + ".part")
            sys.exit(f"SHA-256 mismatch for {rel}: expected {digest}, got {got}")
        os.replace(path + ".part", path)
    print(f"{len(entries)} files present and verified in {dest}")


if __name__ == "__main__":
    main(sys.argv[1])
