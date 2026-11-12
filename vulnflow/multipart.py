"""Streaming multipart/form-data reader.

Uploaded files are written to disk in fixed-size chunks as they arrive, so memory use
stays flat no matter how large the logs are. Small text fields are kept in memory
up to a cap.
"""
from __future__ import annotations

import os
import re
from email.parser import HeaderParser

from .errors import UserError

CHUNK = 1 << 16
MAX_HEADER = 16 * 1024
MAX_FIELD = 64 * 1024


class MultipartError(UserError):
    pass


def boundary_of(content_type: str) -> bytes:
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m or not content_type.lower().startswith("multipart/form-data"):
        raise MultipartError("Expected a multipart/form-data upload.")
    return m[1].encode()


def parse(rfile, length: int, content_type: str, dest_dir: str, safe_name):
    """Read `length` bytes of multipart body from `rfile`.

    Returns (fields, files): fields maps name -> str for plain fields; files is a list of
    (field_name, path) for uploaded files, written into dest_dir as safe_name(index, filename).
    Empty file parts are skipped.
    """
    delim = b"\r\n--" + boundary_of(content_type)
    remaining = length
    buf = b"\r\n"            # lets the very first boundary match the same "\r\n--boundary" pattern
    fields: dict[str, str] = {}
    files: list[tuple[str, str]] = []

    def fill(min_len: int) -> bool:
        nonlocal buf, remaining
        while len(buf) < min_len and remaining > 0:
            chunk = rfile.read(min(CHUNK, remaining))
            if not chunk:
                raise MultipartError("Upload ended early.")
            remaining -= len(chunk)
            buf += chunk
        return len(buf) >= min_len

    # skip the preamble up to the first boundary
    while True:
        i = buf.find(delim)
        if i >= 0:
            buf = buf[i + len(delim):]
            break
        if remaining <= 0:
            raise MultipartError("No form parts found in the upload.")
        buf = buf[-(len(delim) - 1):]
        fill(len(buf) + CHUNK)

    while True:
        fill(2)
        if buf.startswith(b"--"):
            break                                       # closing boundary
        if not buf.startswith(b"\r\n"):
            raise MultipartError("Malformed boundary in upload.")
        buf = buf[2:]
        while (h := buf.find(b"\r\n\r\n")) < 0:
            if len(buf) > MAX_HEADER or not fill(len(buf) + 1024) and buf.find(b"\r\n\r\n") < 0:
                raise MultipartError("Malformed part headers in upload.")
        headers = HeaderParser().parsestr(buf[:h].decode("utf-8", "replace"))
        buf = buf[h + 4:]
        name = headers.get_param("name", header="content-disposition") or ""
        filename = headers.get_filename()
        # an empty file input still sends filename="", which get_filename() reports as None
        is_file = filename is not None or "filename=" in (headers.get("content-disposition") or "").lower()

        out, path, size, field = None, None, 0, bytearray()
        if filename:
            path = os.path.join(dest_dir, safe_name(len(files), filename))
            out = open(path, "wb")
        try:
            while True:
                i = buf.find(delim)
                if i >= 0:
                    data, buf = buf[:i], buf[i + len(delim):]
                else:
                    keep = len(delim) - 1               # a boundary may straddle two chunks
                    data, buf = buf[:-keep] if len(buf) > keep else b"", buf[-keep:] if len(buf) > keep else buf
                if out:
                    out.write(data)
                    size += len(data)
                elif len(field) + len(data) <= MAX_FIELD:
                    field += data
                if i >= 0:
                    break
                if remaining <= 0:
                    raise MultipartError("Upload ended in the middle of a part.")
                fill(len(buf) + CHUNK)
        finally:
            if out:
                out.close()
        if is_file:
            if filename and size:
                files.append((name, path))
            elif path:
                os.remove(path)
        elif name:
            fields[name] = field.decode("utf-8", "replace")
    # drain anything after the closing boundary (epilogue) so the connection stays usable
    while remaining > 0:
        chunk = rfile.read(min(CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
    return fields, files
