"""Start the upload page: loopback only by default, an access token for remote use, or the
container's own interface (published on the host's loopback) in the Docker image."""
from __future__ import annotations

import ipaddress
import os
import secrets
from http.server import ThreadingHTTPServer

from .. import resources
from ..correlate import Config
from ..llm import LLMConfig
from .app import App
from .handler import LOOPBACK_NAMES, Handler

MAX_UPLOAD = 1024 * 1024 * 1024   # default cap; uploads stream to disk, so this is about disk and run time


def make_handler(data_dir: str, base_cfg: Config, llm_cfg: LLMConfig | None = None,
                 max_upload: int = MAX_UPLOAD, access_token: str | None = None,
                 allowed_hosts: tuple[str, ...] = ()):
    """The request handler class for one server.

    ``llm_cfg`` None hides the Security Assistant entirely; an unready LLMConfig falls back to
    the built-in offline assistant, so the assistant always works without a provider.

    Without ``access_token`` the server only answers requests whose Host header names this
    machine's loopback address (or one of ``allowed_hosts``), which defeats DNS rebinding.
    With ``access_token`` (remote access) every request must carry the token, as a cookie
    set from the one-time ``?token=`` link printed at start-up.
    """
    app = App(data_dir=data_dir, base_cfg=base_cfg, llm=llm_cfg, max_upload=max_upload,
              access_token=access_token, allowed_hosts=frozenset(h.lower() for h in allowed_hosts))
    return type("VulnScopeHandler", (Handler,), {"app": app})


def is_loopback_host(host: str) -> bool:
    """True for a bind address that only this machine can reach."""
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve(host: str, port: int, data_dir: str, cfg: Config, llm_cfg: LLMConfig | None = None,
          max_upload: int = MAX_UPLOAD, allow_remote: bool = False, container: bool = False,
          public_port: int | None = None):
    """Serve on loopback only, unless ``allow_remote``: then every request needs a random access token.

    ``container`` is for the Docker image: the server must listen on the container's own interface
    so the published port can reach it, and Docker publishes that port on the host's loopback only
    (``-p 127.0.0.1:PORT:8080``). The Host-header check stays on, for ``localhost:<public_port>``,
    so DNS rebinding is still refused. No access token is used unless ``allow_remote`` is also set.
    """
    remote = not is_loopback_host(host)
    if container and remote and not allow_remote:
        public_port = public_port or port
        os.umask(0o077)
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        os.chmod(data_dir, 0o700)
        allowed = {f"{n}:{public_port}" for n in LOOPBACK_NAMES} | {f"{n}:{port}" for n in LOOPBACK_NAMES}
        srv = ThreadingHTTPServer((host, port), make_handler(os.path.abspath(data_dir), cfg, llm_cfg, max_upload,
                                                             allowed_hosts=tuple(sorted(allowed))))
        print(f"Upload page: http://127.0.0.1:{public_port}/  (container mode: listening on {host}:{port}; "
              "publish the port on 127.0.0.1 only)", end="")
        _serve_forever(srv, data_dir, llm_cfg)
        return
    if remote and not allow_remote:
        raise SystemExit(f"Refusing to listen on {host}: the upload page can read any folder this account can. "
                         "Use the default 127.0.0.1, or pass --allow-remote to require an access token.")
    os.umask(0o077)                                     # runs hold raw logs and scan results
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    os.chmod(data_dir, 0o700)
    token = secrets.token_urlsafe(24) if remote else None
    srv = ThreadingHTTPServer((host, port), make_handler(os.path.abspath(data_dir), cfg, llm_cfg, max_upload,
                                                         access_token=token, allowed_hosts=(f"{host}:{port}",)))
    if token:
        print(f"Upload page (remote access; keep this link private): http://{host}:{port}/?token={token}")
        print("Traffic is plain HTTP; use it only on a trusted network or through an SSH tunnel.")
    else:
        print(f"Upload page: http://{host}:{port}/", end="")
    _serve_forever(srv, data_dir, llm_cfg)


def _serve_forever(srv, data_dir, llm_cfg):
    print(f"  (results stored in {os.path.abspath(data_dir)})")
    print(f"Analyses: {resources.max_jobs()} at a time; " + resources.plan(workdir=data_dir).describe())
    from .. import pcap
    zeek = pcap.find_zeek()
    print(f"Packet captures: {'converted with ' + pcap.zeek_version(zeek) if zeek else 'Zeek not found; ' + pcap.INSTALL_HINT}")
    if llm_cfg is not None:
        print(f"Security Assistant: {llm_cfg.label() if llm_cfg.ready else 'built-in offline assistant (no AI)'}"
              "; choose an AI model at /settings")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
