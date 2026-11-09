"""Start the vulnScope upload page with VS Code's Run Python File button."""

import errno
import os
from pathlib import Path
import socket
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

from vulnflow.cli import main

HOST = "127.0.0.1"
PORT = 8080
URL = f"http://{HOST}:{PORT}/"
PAGE_TITLE = b"VulnScope</title>"   # the name before "VulnScope" is analyst-set branding


def _upload_page_is_ready(url: str) -> bool:
    try:
        with urlopen(url, timeout=0.5) as response:
            return PAGE_TITLE in response.read(4096)
    except (OSError, URLError):
        return False


def _first_available_port() -> int:
    for port in range(PORT, 65536):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind((HOST, port))
            return port
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
    raise SystemExit("No local port is available for the upload page.")


def _open_when_ready(url: str) -> None:
    for _ in range(100):
        if _upload_page_is_ready(url):
            webbrowser.open(url)
            return
        time.sleep(0.1)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parent)
    if _upload_page_is_ready(URL):
        webbrowser.open(URL)
    else:
        port = _first_available_port()
        url = f"http://{HOST}:{port}/"
        if port != PORT:
            print(f"Port {PORT} is in use; starting the upload page on port {port} instead.")
        threading.Thread(target=_open_when_ready, args=(url,), daemon=True).start()
        raise SystemExit(main(["serve", "--port", str(port)]))
