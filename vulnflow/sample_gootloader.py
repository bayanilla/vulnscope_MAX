"""Generate the Gootloader sample: one intrusion, from a poisoned search result to the domain controllers.

The story replays the intrusion The DFIR Report described in "SEO Poisoning to Domain Control: The
Gootloader Saga Continues" (2024-02-26) against a fictional 120-host company, "ridgeline.example".
Times follow the report's relative timeline; the dates, hosts, users and every internal address are
invented. Outside addresses are reserved documentation/benchmark ranges, except the three addresses the
report publishes as indicators (the Gootloader server, the Cobalt Strike C2 and the SystemBC C2): those
appear in the traffic so the bundled IOC list has something to match. Domains and file hashes are the
report's published indicators; which host received which beacon file is fictional.

  T0        hr-ws-07 searches for an employment agreement template, lands on an SEO-poisoned blog and
            downloads a zip with a JavaScript file. The user runs it.
  T0+2m     Gootloader polls ten compromised WordPress sites (/xmlrpc.php); most answer 405.
  T0+9h     The one weaponized server (46.28.105.94) answers 200 with the payload: a Cobalt Strike
            beacon to 91.215.85.143:443.
  +10m      LDAP (389/3268) and SMB discovery from the beachhead, a burst of port-445 probes.
  +20m      Lateral movement over SMB: remote service (svcctl) to switch off Defender, beacon .exe copied
            to ADMIN$ and run as a service on dc01, dc02, fs01 and sql01. dc01 starts its own HTTPS beacon.
  T0+10.5h  SystemBC (s5.ps1) on the beachhead: SOCKS5 to 91.92.136.20:4001, then RDP through the tunnel
            to dc01. Advanced IP Scanner runs from dc01; the attacker opens a Passwords file on fs01.
  T0+11.3h  WinRM, then RDP, to backup01; SystemBC copied there (.ps1 over SMB) and started.
  ~5 hours  Quiet.
  Day 2     06:00-11:00 UTC: hands-on review of file shares and backup settings over the tunnels, then
            the activity stops.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

FOLDER = "gootloader_seo_poisoning"
REPORT_URL = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
DOMAIN = "ridgeline.example"
START = datetime(2026, 10, 26, tzinfo=timezone.utc)          # data window: two days
END = START + timedelta(days=2)
T0 = datetime(2026, 10, 26, 14, 2, tzinfo=timezone.utc)      # the poisoned download
PAYLOAD = T0 + timedelta(hours=9)                            # Gootloader's final payload arrives
DAY2 = datetime(2026, 10, 27, 6, 0, tzinfo=timezone.utc)     # report: most activity 06:00-11:00 UTC on day 2
STOP = datetime(2026, 10, 27, 11, 5, tzinfo=timezone.utc)    # activity stops
QUIET = datetime(2026, 10, 27, 2, 0, tzinfo=timezone.utc)    # ~5 quiet hours until DAY2

# -- outside addresses ---------------------------------------------------------------------------
GOOT_SERVER = "46.28.105.94"     # published: weaponized Gootloader server (blog.lilianpraskova.cz)
CS_C2 = "91.215.85.143"          # published: Cobalt Strike HTTPS C2 (port 443)
SYSTEMBC_C2 = "91.92.136.20"     # published: SystemBC SOCKS5 C2 (port 4001)
LURE_SITE, LURE_DOMAIN = "198.51.100.23", "freelegalforms-blog.example"   # fictional poisoned result
SEARCH = "198.18.10.20"
# The ten Gootloader URLs from the report. Only one server address is published; the other nine get
# documentation addresses. https=False marks the two plain-HTTP sites.
GOOT_SITES = [
    ("hrclubphilippines.com", "203.0.113.101", True),
    ("mediacratia.ru", "203.0.113.102", True),
    ("daraltanweer.com", "203.0.113.103", True),
    ("ukrainians.today", "203.0.113.104", True),
    ("my-little-kitchen.com", "203.0.113.105", True),
    ("montages.no", "203.0.113.106", True),
    ("pocketofpreschool.com", "203.0.113.107", True),
    ("blog.lilianpraskova.cz", GOOT_SERVER, False),
    ("sitmeanssit.com", "203.0.113.108", True),
    ("artmodel.com.ua", "203.0.113.109", False),
]
SAAS = [("outlook.office365.example", "198.18.10.31"), ("teams.collab.example", "198.18.10.44"),
        ("crm.saas.example", "198.18.20.12"), ("payroll.saas.example", "198.18.20.57"),
        ("cdn.news.example", "192.0.2.80"), ("updates.vendor.example", "192.0.2.120"),
        ("www.bing.com", SEARCH)]
UPSTREAM_DNS = "192.0.2.53"
WSUS_UPSTREAM = "192.0.2.140"

# -- internal estate ---------------------------------------------------------------------------
HOSTS: dict[str, tuple[str, str]] = {}          # ip -> (fqdn, os)   (everything here is in the scan)
DC1, DC2, FS, BACKUP, SQL, APP, PRINT, WSUS, IT_ADM = (
    "10.20.0.10", "10.20.0.11", "10.20.0.20", "10.20.0.30", "10.20.0.40", "10.20.0.41",
    "10.20.0.50", "10.20.0.51", "10.20.0.60")
DNS = "10.20.0.53"            # resolver appliance; excluded from the scan, so DNS lookups are not pinned on a DC
for ip, name, os_name in (
        (DC1, "dc01", "Microsoft Windows Server 2019 Standard"),
        (DC2, "dc02", "Microsoft Windows Server 2019 Standard"),
        (FS, "fs01", "Microsoft Windows Server 2016 Standard"),
        (BACKUP, "backup01", "Microsoft Windows Server 2019 Standard"),
        (SQL, "sql01", "Microsoft Windows Server 2016 Standard"),
        (APP, "erp01", "Microsoft Windows Server 2019 Standard"),
        (PRINT, "print01", "Microsoft Windows Server 2016 Standard"),
        (WSUS, "wsus01", "Microsoft Windows Server 2019 Standard"),
        (IT_ADM, "it-adm01", "Microsoft Windows Server 2022 Standard")):
    HOSTS[ip] = (f"{name}.{DOMAIN}", os_name)
DEPTS = [("hr", 12), ("fin", 16), ("ops", 30), ("sales", 22), ("legal", 8), ("it", 6), ("exec", 6)]
WORKSTATIONS: list[str] = []
_n = 21
for dept, count in DEPTS:
    for k in range(1, count + 1):
        ip = f"10.20.10.{_n}"
        HOSTS[ip] = (f"{dept}-ws-{k:02}.{DOMAIN}",
                     "Microsoft Windows 11 Enterprise" if _n % 3 else "Microsoft Windows 10 Enterprise")
        WORKSTATIONS.append(ip)
        _n += 1
PATIENT0 = next(ip for ip, (n, _) in HOSTS.items() if n.startswith("hr-ws-07."))
PRINTERS = [f"10.20.30.{i}" for i in range(10, 16)]
for ip in PRINTERS:
    HOSTS[ip] = (f"prn-{ip.split('.')[-1]}.{DOMAIN}", "HP LaserJet")
SERVERS = [DC1, DC2, FS, BACKUP, SQL, APP, PRINT, WSUS, IT_ADM]
SMB_BEACONS = [  # (target, file name, md5, sha1, sha256) -- hashes from the report, target fictional
    (DC1, "e544944.exe", "f769cb73317421c290832777c9e14f92", "f043898fc9db6985c4ad8bb84669c081cdaa8e6f",
     "40c40495434bf987b04f0742c3e9201189675d87a042aa72abbd0084c3de66d8"),
    (DC2, "5d78365.exe", "9f9c7b2c8f245e62a08bf5f8a3eb3498", "3cf851eb09c934cafe9b98d4706f903dff804b0c",
     "aad75498679aada9ee2179a8824291e3b4781d5683c2fa5b3ec92267ce4a4a33"),
    (FS, "dae50de.exe", "a617e6687ab5d747c530b930bb4a3209", "d53e550b54c08606e19965a9f74bbaa7063e10f1",
     "be3222219f029b47120390b2b1ad46ae86287e64a1f7228d6b2ffd89345a889e"),
    (SQL, "a4a2ea4.exe", "e9fc0203d1dea15dff56a285d0f86b62", "72076af2ce8df6f8b1121c38f3c3db043c540369",
     "792a95234b01c256019b16a242b9487b99e98ed8a955eaecf1e44b0141aa12f4"),
]
# Other published hashes (no network sighting in this sample: they arrive inside HTTPS or the registry)
OTHER_HASHES = [
    ("Implied_employment_agreement_70159.zip", "fb6e4f75763fad6d0e7fe85a563b0c24",
     "7e8543f2bc09bf320510fde5e34e32065339d9d2", "873dd1dcdfcbe9826b274c5880f5be81a878ee93715fbb18a654d9dba61c5dfc"),
    ("implied employment agreement 24230.js", "deb24dfaf8178fda2d070aba9134a30c",
     "ecc0b26106703e129fb1e2ec132c373870c2e7b6", "f94048917ac75709452040754bb3d1a0aff919f7c2b4b42c5163c7bdb1fbf346"),
    ("Frontline Management.js", "4f4ee823a8c7e2511f05b3ea633c0d2c",
     "877515fecc14ed193167e8a20c6b9a684a74564d", "ecc7f13c3f0f8d4775e05715810b0164c52b7bd233e4a2e4f5a37769becb0092"),
    ("payload1.dll_ (stage 1)", "25b38e45df3cd215386077850c59be07",
     "a88a28c73aa42956c9f9d12585a8de63d4a00e47", "68dd1a2da732d56b0618f8581502fcf209b1c828c97d05f239c98d55bb78b562"),
    ("payload2.exe_ (stage 2)", "1b8b4f05058ac39091b99cc153ab00c0",
     "e0b568a3e35257cd30b0c42727c3529cef13b081", "831955bd05186381a8f15539a41f48166873eab3feb55fb1104202e4152bd507"),
]
PRIVACY = "Potential Corporate Privacy Violation"
CS_JA3, CS_JA3S = "72a589da586844d7f0818ce684948eea", "f176ba63b4d68e576b5ba345bec2c7b7"

# (ip, port, proto, svc, pluginID, name, sev, cvss3, cves, exploit, metasploit, synopsis, solution)
VULNS: list[tuple] = []


def _v(ip, port, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol, proto="tcp"):
    VULNS.append((ip, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol))


_v(DC2, 445, "cifs", "140657", "Netlogon Elevation of Privilege (CVE-2020-1472) (Zerologon)", 4, 10.0,
   ["CVE-2020-1472"], True, True,
   "The remote domain controller is affected by an elevation of privilege vulnerability in Netlogon.",
   "Apply the August 2020 security update and enforce secure RPC for Netlogon.")
for dc in (DC1, DC2):
    _v(dc, 3389, "msrdp", "58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", 2, 4.0,
       [], False, False, "The remote Terminal Services doesn't use NLA only.", "Enable Network Level Authentication.")
    _v(dc, 389, "ldap", "191001", "Active Directory LDAP Signing and Channel Binding Not Required", 2, 5.9, [],
       False, False, "The domain controller accepts unsigned LDAP binds.", "Require LDAP signing and channel binding.")
_v(BACKUP, 9401, "www", "173380", "Veeam Backup & Replication Credential Disclosure (CVE-2023-27532)", 4, 7.5,
   ["CVE-2023-27532"], True, True,
   "The backup service lets an unauthenticated user request encrypted credentials from the configuration database.",
   "Upgrade Veeam Backup & Replication to a fixed build.")
_v(BACKUP, 3389, "msrdp", "58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", 2, 4.0,
   [], False, False, "The remote Terminal Services doesn't use NLA only.", "Enable Network Level Authentication.")
_v(BACKUP, 5985, "www", "187900", "Windows Remote Management (WinRM) over HTTP Enabled", 2, 5.3, [], False, False,
   "WinRM accepts connections over unencrypted HTTP.", "Restrict WinRM to HTTPS and to administration hosts.")
for ip in (DC1, FS, PRINT):     # Print Spooler left running on a DC is a classic finding
    _v(ip, 445, "cifs", "151440", "Windows Print Spooler Service Enabled (PrintNightmare, CVE-2021-34527)", 4, 8.8,
       ["CVE-2021-34527"], True, True,
       "The Print Spooler service is affected by a remote code execution vulnerability.",
       "Apply the July 2021 security updates or disable the Print Spooler service.")
_v(SQL, 1433, "mssql", "73756", "Microsoft SQL Server Unsupported Version Detection", 4, 10.0, [], False, False,
   "The installed version of SQL Server is no longer supported.", "Upgrade to a supported version of SQL Server.")
for ip in (FS, SQL, BACKUP, APP, PRINT, WSUS, IT_ADM) + tuple(WORKSTATIONS):
    _v(ip, 445, "cifs", "57608", "SMB Signing not required", 2, 5.3, [], False, False,
       "Signing is not required on the remote SMB server.", "Enforce message signing in the host's configuration.")
_E = random.Random(4207)
for ip in WORKSTATIONS:
    if ip == PATIENT0 or _E.random() < 0.35:
        _v(ip, 0, "general", "207053", "Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities", 3, 8.8,
           ["CVE-2024-7965", "CVE-2024-7971"], True, False,
           "The browser installed on the remote host is affected by multiple vulnerabilities.",
           "Upgrade to Microsoft Edge version 129.0.2792.52 or later.")


class _Log:
    """Collects the records of every file; one session can be written to several sensors."""

    def __init__(self, rng):
        self.rng = rng
        self.conn, self.pan, self.threats, self.dns, self.http, self.ssl, self.files, self.eve = ([] for _ in range(8))
        self.uid = 0

    def _uid(self):
        self.uid += 1
        return f"G{self.uid:09x}"

    def session(self, ts, s, d, dp, svc="-", proto="tcp", state="SF", ob=None, rb=None, dur=None,
                app=None, fz=None, tz=None, action="allow", zeek=True):
        """One session: always in Zeek (the core/egress tap); also in the firewall log when it crosses
        a zone (``app`` given). Returns the Zeek uid."""
        rng = self.rng
        sp = rng.randint(49152, 65535)
        ob = rng.randint(300, 4000) if ob is None else ob
        rb = (rng.randint(800, 40000) if state == "SF" else 0) if rb is None else rb
        dur = rng.uniform(0.05, 20) if dur is None else dur
        uid = self._uid()
        if zeek and action == "allow":
            self.conn.append(dict(ts=ts, uid=uid, s=s, sp=sp, d=d, dp=dp, proto=proto, svc=svc, dur=dur,
                                  ob=ob, rb=rb, state=state))
        if app:
            self.pan.append(dict(ts=ts, s=s, sp=sp, d=d, dp=dp, app=app, fz=fz, tz=tz, action=action,
                                 sent=ob if action == "allow" else rng.randint(60, 200),
                                 rcvd=rb if action == "allow" else 0, proto=proto))
        return uid, sp

    def lookup(self, ts, client, query, answer):
        self.dns.append(dict(ts=ts, uid=self._uid(), s=client, sp=self.rng.randint(49152, 65535), d=DNS,
                             q=query, a=answer))

    def threat(self, ts, s, d, dp, name, sev, action="alert", kind="spyware", app="ssl", fz="trust", tz="untrust"):
        self.threats.append(dict(ts=ts, s=s, d=d, dp=dp, name=name, sev=sev, action=action, kind=kind,
                                 app=app, fz=fz, tz=tz))

    def ids(self, ts, s, d, dp, sig, sid, category, sev=2, app="smb"):
        """A Suricata alert. Signature names are the ones the report lists; the sids are local placeholders."""
        self.eve.append(dict(ts=ts, s=s, d=d, dp=dp, sig=sig, sid=sid, cat=category, sev=sev, app=app))


def _out(log, ts, s, d, dp, app, svc="ssl", **kw):
    """Outbound internet session through the firewall."""
    return log.session(ts, s, d, dp, svc=svc, app=app, fz="trust", tz="untrust", **kw)


def _background(log, rng):
    span = (END - START).total_seconds()

    def work_ts():
        """Mostly business hours (13:00-23:00 UTC, i.e. 08:00-18:00 local), some off-hours."""
        while True:
            t = START + timedelta(seconds=rng.uniform(0, span))
            if 13 <= t.hour < 23 or rng.random() < 0.15:
                return t

    for ws in WORKSTATIONS:
        for _ in range(rng.randint(10, 16)):
            log.session(work_ts(), ws, rng.choice([DC1, DC2]), 88, svc="krb", ob=rng.randint(1200, 1800))
        for _ in range(rng.randint(6, 10)):
            log.session(work_ts(), ws, rng.choice([DC1, DC2]), 389, svc="ldap")
        for _ in range(rng.randint(8, 14)):
            log.session(work_ts(), ws, FS, 445, svc="smb", rb=rng.randint(20_000, 2_000_000))
        for _ in range(rng.randint(2, 5)):
            log.session(work_ts(), ws, rng.choice([APP, SQL]), rng.choice([443, 1433]),
                        svc="ssl")
        if rng.random() < 0.4:
            log.session(work_ts(), ws, PRINT, 445, svc="smb", ob=rng.randint(50_000, 900_000), rb=2000)
        for _ in range(rng.randint(6, 12)):
            name, ip = rng.choice(SAAS)
            t = work_ts()
            if rng.random() < 0.25:
                log.lookup(t - timedelta(seconds=1), ws, name, ip)
            _out(log, t, ws, ip, 443, "ssl")
    for t in (START + timedelta(hours=h, minutes=rng.randint(0, 59)) for h in range(0, 48, 1)):
        log.session(t, DNS, UPSTREAM_DNS, 53, svc="dns", proto="udp", app="dns", fz="trust", tz="untrust",
                    ob=rng.randint(60, 90), rb=rng.randint(90, 300))
    for k in range(8):
        log.session(START + timedelta(hours=3 + 6 * k), WSUS, WSUS_UPSTREAM, 80, svc="http", app="windows-update",
                    fz="trust", tz="untrust", rb=rng.randint(2_000_000, 40_000_000))
        for ws in rng.sample(WORKSTATIONS, 12):
            log.session(START + timedelta(hours=3 + 6 * k, minutes=rng.randint(5, 50)), ws, WSUS, 8530,
                        svc="http", rb=rng.randint(100_000, 3_000_000))
    for _ in range(40):                                   # IT administration from the jump server
        log.session(work_ts(), IT_ADM, rng.choice(SERVERS[:6]), rng.choice([3389, 5985, 445]),
                    svc="-", rb=rng.randint(10_000, 900_000))
    for _ in range(30):                                   # nightly backup jobs pull from the servers
        log.session(START + timedelta(hours=rng.choice([2, 3, 26, 27]), minutes=rng.randint(0, 59)),
                    BACKUP, rng.choice([FS, SQL, APP, DC1]), 445, svc="smb", ob=4000,
                    rb=rng.randint(50_000_000, 400_000_000), dur=rng.uniform(300, 1800))
    for p in PRINTERS:
        log.session(work_ts(), PRINT, p, 9100, svc="-", ob=rng.randint(30_000, 600_000), rb=200)
    for ws in rng.sample(WORKSTATIONS, 30):               # direct outside DNS is blocked
        log.session(work_ts(), ws, "8.8.8.8", 53, svc="dns", proto="udp", app="dns", fz="trust", tz="untrust",
                    action="deny")


def _gootloader(log, rng):
    """T0 to the payload: the poisoned download, then nine hours of polling the ten sites."""
    ws = PATIENT0
    log.lookup(T0 - timedelta(seconds=40), ws, "www.bing.com", SEARCH)
    _out(log, T0 - timedelta(seconds=39), ws, SEARCH, 443, "ssl", ob=2400, rb=86_000)
    log.lookup(T0 - timedelta(seconds=5), ws, LURE_DOMAIN, LURE_SITE)
    uid, sp = _out(log, T0, ws, LURE_SITE, 443, "ssl", ob=3100, rb=412_000, dur=6.4)
    log.ssl.append(dict(ts=T0, uid=uid, s=ws, sp=sp, d=LURE_SITE, dp=443, sni=LURE_DOMAIN, ja3="", ja3s=""))

    def poll(t, payload=False):
        for name, ip, https in GOOT_SITES:
            t += timedelta(seconds=rng.uniform(2, 6))
            log.lookup(t, ws, name, ip)
            hit = payload and ip == GOOT_SERVER
            rb = rng.randint(380_000, 420_000) if hit else rng.randint(420, 900)
            if https:
                uid, sp = _out(log, t, ws, ip, 443, "ssl", ob=rng.randint(900, 1600), rb=rb)
                log.ssl.append(dict(ts=t, uid=uid, s=ws, sp=sp, d=ip, dp=443, sni=name, ja3="", ja3s=""))
            else:
                uid, sp = _out(log, t, ws, ip, 80, "web-browsing", svc="http", ob=rng.randint(700, 1200), rb=rb)
                log.http.append(dict(ts=t, uid=uid, s=ws, sp=sp, d=ip, dp=80, host=name, uri="/xmlrpc.php",
                                     status=200 if hit else 405, rb=rb))
            if hit:
                log.threat(t + timedelta(seconds=1), ws, ip, 80, "Gootloader JavaScript Downloader Payload Retrieval",
                           "high", app="web-browsing")
                return

    poll(T0 + timedelta(minutes=2))
    t = T0 + timedelta(minutes=2)
    while True:
        t += timedelta(minutes=rng.uniform(35, 55))
        if t >= PAYLOAD - timedelta(minutes=5):
            break
        poll(t)
    poll(PAYLOAD - timedelta(seconds=20), payload=True)


def _beacon(log, rng, host, start, stop, first_alert=True):
    """Cobalt Strike HTTPS beacon to the published C2: sleep 22 s with 37% jitter while the operator
    works, 5 minutes during the quiet hours."""
    t, n = start, 0
    while t < stop:
        uid, sp = _out(log, t, host, CS_C2, 443, "ssl", ob=rng.randint(380, 900), rb=rng.randint(250, 1400),
                       dur=rng.uniform(0.2, 1.5))
        if n % 15 == 0:   # Zeek logs every TLS session; keep a sample of them in ssl.log to stay small
            log.ssl.append(dict(ts=t, uid=uid, s=host, sp=sp, d=CS_C2, dp=443, sni="", ja3=CS_JA3, ja3s=CS_JA3S))
        if first_alert and n == 0:
            log.threat(t + timedelta(seconds=1), host, CS_C2, 443, "Cobalt Strike Beacon Command and Control Traffic",
                       "critical")
        n += 1
        sleep = 300 if QUIET <= t < DAY2 else 22
        t += timedelta(seconds=sleep * rng.uniform(0.63, 1.37))


def _systembc(log, rng, host, start, stop):
    """SystemBC SOCKS5 to the published C2 on 4001; long-lived tunnel sessions carry the attacker's RDP."""
    log.ids(start + timedelta(seconds=2), host, SYSTEMBC_C2, 4001, "ET MALWARE SystemBC Powershell bot registration",
            9100008, "A Network Trojan was detected", sev=1, app="")
    t = start
    while t < stop:
        busy = t < QUIET or t >= DAY2
        _out(log, t, host, SYSTEMBC_C2, 4001, "unknown-tcp", svc="socks",
             ob=rng.randint(2_000_000, 9_000_000) if busy else rng.randint(400, 900),
             rb=rng.randint(200_000, 900_000) if busy else rng.randint(300, 700),
             dur=rng.uniform(300, 900) if busy else 2.0)
        t += timedelta(seconds=rng.uniform(600, 900) if busy else 1800)


def _lateral(log, rng):
    ws = PATIENT0
    t = PAYLOAD + timedelta(minutes=2)
    _beacon(log, rng, ws, t, STOP + timedelta(minutes=10))

    # discovery: LDAP to both DCs, then a burst of SMB probes
    t = PAYLOAD + timedelta(minutes=10)
    for k in range(24):
        log.session(t + timedelta(seconds=k * 9), ws, DC1 if k % 2 else DC2, 3268 if k % 3 == 0 else 389,
                    svc="ldap", rb=rng.randint(40_000, 400_000))
    t += timedelta(minutes=5)
    targets = SERVERS + rng.sample(WORKSTATIONS, 45)
    for k, d in enumerate(targets):
        if d == ws:
            continue
        log.session(t + timedelta(seconds=k * 0.7), ws, d, 445, svc="smb" if d in SERVERS else "-",
                    state="SF" if d in SERVERS or k % 4 == 0 else "REJ", ob=200, rb=None if d in SERVERS else 0)
    log.ids(t + timedelta(seconds=20), ws, targets[3], 445,
            "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection", 9100001,
            "Misc activity", sev=3)

    # remote service + beacon copy to each target (Defender blocks the first try on dc01)
    t = PAYLOAD + timedelta(minutes=20)
    for i, (target, fname, md5, sha1, sha256) in enumerate(SMB_BEACONS):
        tries = 2 if target == DC1 else 1
        for attempt in range(tries):
            uid, sp = log.session(t, ws, target, 445, svc="smb,dce_rpc", ob=rng.randint(310_000, 330_000),
                                  rb=rng.randint(9_000, 20_000), dur=rng.uniform(4, 12))
            # one alert per signature and transfer; the full set only on the first (Defender switched off)
            sigs = [("ET RPC DCERPC SVCCTL - Remote Service Control Manager Access", 9100002, "Misc activity", 3)]
            if i == 0 and attempt == 0:
                sigs += [("ET POLICY Powershell Command With Encoded Argument Over SMB - Likely Lateral Movement",
                          9100006, PRIVACY, 2),
                         ("ET POLICY SMB2 NT Create AndX Request For an Executable File", 9100004, PRIVACY, 2)]
            elif i in (1, 2):
                extra = "Hidden Window" if i == 1 else "No Profile"
                sigs.append((f"ET POLICY Powershell Command With {extra} Argument Over SMB - Likely Lateral Movement",
                             9100009 + i, PRIVACY, 2))
            sigs.append(("ET POLICY SMB Executable File Transfer", 9100003, PRIVACY, 2))
            for k, (sig, sid, cat, sev) in enumerate(sigs):
                log.ids(t + timedelta(seconds=1 + 2 * k), ws, target, 445, sig, sid, cat, sev=sev)
            log.files.append(dict(ts=t + timedelta(seconds=5), uid=uid, s=ws, sp=sp, d=target, dp=445,
                                  name=f"\\\\{HOSTS[target][0].split('.')[0].upper()}\\ADMIN$\\{fname}",
                                  mime="application/x-dosexec", size=rng.randint(300_000, 320_000),
                                  md5=md5, sha1=sha1, sha256=sha256))
            t += timedelta(minutes=rng.uniform(3, 6) if attempt + 1 < tries else rng.uniform(5, 9))
        # SMB beacon: the parent keeps talking to the child over a named pipe on 445
        pipe_t = t - timedelta(minutes=3)
        for k in range(rng.randint(10, 18)):
            log.session(pipe_t + timedelta(minutes=k * rng.uniform(4, 9)), ws, target, 445, svc="smb",
                        ob=rng.randint(600, 4000), rb=rng.randint(600, 4000))
    dc1_beacon = PAYLOAD + timedelta(minutes=33)
    _beacon(log, rng, DC1, dc1_beacon, STOP)

    # SystemBC on the beachhead, then RDP through the tunnel to dc01
    sbc = PAYLOAD + timedelta(hours=1, minutes=33)
    _systembc(log, rng, ws, sbc, STOP)
    rdp = sbc + timedelta(minutes=4)
    for k in range(3):
        log.session(rdp + timedelta(minutes=k * 22), ws, DC1, 3389, svc="rdp", ob=rng.randint(400_000, 900_000),
                    rb=rng.randint(4_000_000, 15_000_000), dur=rng.uniform(600, 1300))

    # Advanced IP Scanner from dc01
    scan = rdp + timedelta(minutes=13)
    every = [ip for ip in HOSTS if ip != DC1]
    for k, d in enumerate(every):
        for j, port in enumerate((21, 80, 443, 445, 3389, 4899)):
            listening = (port == 445 and (d in SERVERS or d in WORKSTATIONS)) or \
                        (port == 3389 and d in SERVERS) or (port in (80, 443) and (d in PRINTERS or d in (APP, WSUS)))
            log.session(scan + timedelta(seconds=k * 1.3 + j * 0.15), DC1, d, port, svc="-",
                        state="SF" if listening else "REJ", ob=80 if listening else 0, rb=120 if listening else 0,
                        dur=0.01)
    # the attacker browses the file share and opens a Passwords file
    fs_t = scan + timedelta(minutes=12)
    uid, sp = log.session(fs_t, DC1, FS, 445, svc="smb", ob=9_000, rb=2_400_000, dur=340)
    log.files.append(dict(ts=fs_t + timedelta(seconds=40), uid=uid, s=FS, sp=445, d=DC1, dp=sp,
                          name="\\\\FS01\\IT$\\Passwords.xlsx", mime="application/vnd.openxmlformats-officedocument",
                          size=38_912, md5="", sha1="", sha256=""))

    # backup server: WinRM, then RDP, then SystemBC copied over SMB
    bk = fs_t + timedelta(minutes=14)
    for k in range(5):
        log.session(bk + timedelta(seconds=k * 40), DC1, BACKUP, 5985, svc="http", ob=rng.randint(3_000, 9_000),
                    rb=rng.randint(2_000, 12_000))
    log.session(bk + timedelta(minutes=4), DC1, BACKUP, 3389, svc="rdp", ob=600_000, rb=9_000_000, dur=1500)
    uid, sp = log.session(bk + timedelta(minutes=6), DC1, BACKUP, 445, svc="smb", ob=12_000, rb=3_000)
    for sig, sid in (("ET POLICY SMB2 NT Create AndX Request For a Powershell .ps1 File", 9100005),
                     ("ET HUNTING Possible Powershell .ps1 Script Use Over SMB", 9100007)):
        log.ids(bk + timedelta(minutes=6, seconds=1), DC1, BACKUP, 445, sig, sid, PRIVACY)
    log.files.append(dict(ts=bk + timedelta(minutes=6, seconds=1), uid=uid, s=DC1, sp=sp, d=BACKUP, dp=445,
                          name="\\\\BACKUP01\\C$\\Users\\svc-backup\\AppData\\Roaming\\s5.ps1", mime="text/plain",
                          size=10_884, md5="", sha1="", sha256=""))
    _systembc(log, rng, BACKUP, bk + timedelta(minutes=10), STOP)
    _beacon(log, rng, BACKUP, bk + timedelta(minutes=12), STOP)
    for k, d in enumerate(SERVERS):                        # a smaller scan from the backup server
        if d != BACKUP:
            log.session(bk + timedelta(minutes=20, seconds=k * 2), BACKUP, d, 445, svc="smb", ob=80, rb=120,
                        dur=0.02)

    # day 2: hands-on review of shares and backup settings over the tunnels
    t = DAY2 + timedelta(minutes=5)
    while t < STOP - timedelta(minutes=20):
        log.session(t, ws, DC1, 3389, svc="rdp", ob=rng.randint(300_000, 800_000),
                    rb=rng.randint(3_000_000, 12_000_000), dur=rng.uniform(900, 1700))
        log.session(t + timedelta(minutes=3), DC1, FS, 445, svc="smb", ob=rng.randint(6_000, 20_000),
                    rb=rng.randint(1_000_000, 30_000_000), dur=rng.uniform(60, 500))
        if rng.random() < 0.5:
            log.session(t + timedelta(minutes=8), DC1, BACKUP, 3389, svc="rdp", ob=rng.randint(200_000, 600_000),
                        rb=rng.randint(2_000_000, 8_000_000), dur=rng.uniform(300, 900))
        if rng.random() < 0.3:
            log.session(t + timedelta(minutes=10), DC1, SQL, 1433, svc="-", rb=rng.randint(10_000, 400_000))
        t += timedelta(minutes=rng.uniform(18, 30))


def _zeek(path, name, fields, types, rows):
    with open(path, "w") as fh:
        fh.write(f"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\t{name}\n"
                 f"#open\t{START.strftime('%Y-%m-%d-%H-%M-%S')}\n")
        fh.write("#fields\t" + "\t".join(fields) + "\n#types\t" + "\t".join(types) + "\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
        fh.write("#close\t" + END.strftime("%Y-%m-%d-%H-%M-%S") + "\n")


def _ts(t):
    return f"{t.timestamp():.6f}"


def _write(outdir, log, rng):
    paths = []
    by_ts = lambda r: (r["ts"], r.get("uid", ""))

    p = os.path.join(outdir, "conn.log")
    _zeek(p, "conn", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
                      "duration", "orig_bytes", "resp_bytes", "conn_state", "history"],
          ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
           "string", "string"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), r["proto"], r["svc"],
            f"{r['dur']:.3f}", str(r["ob"]), str(r["rb"]), r["state"],
            {"SF": "ShADadFf", "REJ": "Sr", "S0": "S"}.get(r["state"], "S")] for r in sorted(log.conn, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "dns.log")
    _zeek(p, "dns", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name",
                     "rcode_name", "answers"],
          ["time", "string", "addr", "port", "addr", "port", "enum", "string", "string", "string", "vector[string]"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], "53", "udp", r["q"], "A", "NOERROR", r["a"]]
           for r in sorted(log.dns, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "http.log")
    _zeek(p, "http", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "method", "host", "uri",
                      "user_agent", "status_code", "response_body_len"],
          ["time", "string", "addr", "port", "addr", "port", "string", "string", "string", "string", "count", "count"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), "GET", r["host"], r["uri"],
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", str(r["status"]), str(r["rb"])]
           for r in sorted(log.http, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "ssl.log")
    _zeek(p, "ssl", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "server_name",
                     "established", "ja3", "ja3s"],
          ["time", "string", "addr", "port", "addr", "port", "string", "string", "bool", "string", "string"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), "TLSv12", r["sni"] or "-", "T",
            r["ja3"] or "-", r["ja3s"] or "-"] for r in sorted(log.ssl, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "files.log")
    _zeek(p, "files", ["ts", "fuid", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "source",
                       "analyzers", "mime_type", "filename", "is_orig", "seen_bytes", "md5", "sha1", "sha256"],
          ["time", "string", "string", "addr", "port", "addr", "port", "string", "set[string]", "string", "string",
           "bool", "count", "string", "string", "string"],
          ([_ts(r["ts"]), f"F{i:08x}", r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), "SMB",
            "MD5,SHA1,SHA256" if r["md5"] else "(empty)", r["mime"], r["name"], "T", str(r["size"]),
            r["md5"] or "-", r["sha1"] or "-", r["sha256"] or "-"]
           for i, r in enumerate(sorted(log.files, key=by_ts))))
    paths.append(p)

    p = os.path.join(outdir, "suricata_eve.json")
    with open(p, "w") as fh:
        for i, r in enumerate(sorted(log.eve, key=lambda r: (r["ts"], r["sid"]))):
            ev = {"timestamp": r["ts"].strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000", "flow_id": 1_000_000 + i,
                  "event_type": "alert", "src_ip": r["s"], "src_port": rng.randint(49152, 65535), "dest_ip": r["d"],
                  "dest_port": r["dp"], "proto": "TCP",
                  "alert": {"action": "allowed", "gid": 1, "signature_id": r["sid"], "rev": 3,
                            "signature": r["sig"], "category": r["cat"], "severity": r["sev"]}}
            if r["app"]:
                ev["app_proto"] = r["app"]
            fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
    paths.append(p)

    p = os.path.join(outdir, "paloalto_traffic.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["Receive Time", "Serial #", "Type", "Threat/Content Type", "Source address",
                    "Destination address", "Rule", "Application", "Source Zone", "Destination Zone",
                    "Source Port", "Destination Port", "IP Protocol", "Action", "Bytes", "Bytes Sent",
                    "Bytes Received", "Start Time", "Threat/Content Name", "Severity"])
        rows = [("TRAFFIC", r) for r in log.pan] + [("THREAT", r) for r in log.threats]
        for kind, r in sorted(rows, key=lambda x: (x[1]["ts"], x[0], x[1]["s"], x[1]["d"])):
            ts = r["ts"].strftime("%Y/%m/%d %H:%M:%S")
            if kind == "THREAT":           # Start Time filled in, so the alert keeps its own time
                w.writerow([ts, "013201007781", "THREAT", r["kind"], r["s"], r["d"], "allow-web-out", r["app"],
                            r["fz"], r["tz"], rng.randint(49152, 65535), r["dp"], "tcp", r["action"], "", "", "",
                            ts, r["name"], r["sev"]])
                continue
            rule = "allow-web-out" if r["action"] == "allow" else "deny-direct-dns"
            # Receive Time is when the session ended; Start Time is when it began
            w.writerow([ts, "013201007781", "TRAFFIC", "end", r["s"], r["d"], rule, r["app"], r["fz"], r["tz"],
                        r["sp"], r["dp"], r["proto"], r["action"], r["sent"] + r["rcvd"], r["sent"], r["rcvd"],
                        ts, "", ""])
    paths.append(p)

    p = os.path.join(outdir, "domain_scan.nessus")
    _nessus(p)
    paths.append(p)

    p = os.path.join(outdir, "ioc_indicators.csv")
    _iocs(p)
    paths.append(p)

    p = os.path.join(outdir, "article_previews.json")
    with open(p, "w") as fh:
        json.dump({REPORT_URL: {
            "title": "SEO Poisoning to Domain Control: The Gootloader Saga Continues",
            "overview": "The DFIR Report follows an intrusion that began when a user downloaded a poisoned "
                        "search result: Gootloader JavaScript fetched a Cobalt Strike payload about nine hours "
                        "later, and the attacker moved over SMB, WinRM and RDP, used SystemBC as a SOCKS5 tunnel "
                        "and reached the domain controllers, file shares and backup server."}}, fh, indent=2)
        fh.write("\n")
    paths.append(p)
    return paths


def _nessus(path):
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name="Monthly domain scan")
    scan_start = START - timedelta(days=3, hours=-1)
    for k, (ip, (fqdn, os_name)) in enumerate(HOSTS.items()):
        rh = ET.SubElement(report, "ReportHost", name=ip)
        hp = ET.SubElement(rh, "HostProperties")
        t = scan_start + timedelta(seconds=20 * k)
        for key, val in (("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_name),
                         ("HOST_START_TIMESTAMP", str(int(t.timestamp()))),
                         ("HOST_END_TIMESTAMP", str(int(t.timestamp()) + 180))):
            ET.SubElement(hp, "tag", name=key).text = val
        ET.SubElement(rh, "ReportItem", port="0", svc_name="general", protocol="tcp", severity="0",
                      pluginID="19506", pluginName="Nessus Scan Information", pluginFamily="Settings")
        for v in VULNS:
            if v[0] != ip:
                continue
            _, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol = v
            it = ET.SubElement(rh, "ReportItem", port=str(port), svc_name=svc, protocol=proto,
                               severity=str(sev), pluginID=pid, pluginName=name, pluginFamily="Windows")
            ET.SubElement(it, "cvss3_base_score").text = str(cvss)
            for c in cves:
                ET.SubElement(it, "cve").text = c
            ET.SubElement(it, "exploit_available").text = "true" if expl else "false"
            if msf:
                ET.SubElement(it, "exploit_framework_metasploit").text = "true"
            ET.SubElement(it, "synopsis").text = syn
            ET.SubElement(it, "solution").text = sol
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def _iocs(path):
    """The report's published indicators, as data."""
    rows = []
    for name, _, https in GOOT_SITES:
        rows.append(("domain", name, "Gootloader compromised WordPress site"))
        rows.append(("url", f"{'https' if https else 'http'}://{name}/xmlrpc.php", "Gootloader stage-2 URL"))
    rows += [("ip", GOOT_SERVER, "Weaponized Gootloader server"), ("ip", CS_C2, "Cobalt Strike C2 (443)"),
             ("ip", SYSTEMBC_C2, "SystemBC C2 (4001)")]
    for _, fname, md5, sha1, sha256 in SMB_BEACONS:
        rows += [("hash", h, f"Cobalt Strike beacon {fname}") for h in (md5, sha1, sha256)]
    for fname, md5, sha1, sha256 in OTHER_HASHES:
        rows += [("hash", h, fname) for h in (md5, sha1, sha256)]
    seen = "2024-02-26T00:00:00.000Z"
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["indicatorType", "indicator", "disposition", "dispositionReason", "riskTags", "firstSeenAt",
                    "lastSeenAt", "sightingCount", "sources", "articleUrls", "extractionMethods", "confidences"])
        for kind, value, why in rows:
            w.writerow([kind, value, "Actionable", why, "gootloader", seen, seen, 1, "thedfirreport.com",
                        REPORT_URL, "ioc-table", ""])


def generate(outdir: str, seed: int = 26) -> list[str]:
    """Write the Gootloader sample folder."""
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(seed)
    log = _Log(rng)
    _background(log, rng)
    _gootloader(log, rng)
    _lateral(log, rng)
    for r in log.conn + log.pan:                 # every generated address must be a real address
        ipaddress.ip_address(r["s"]), ipaddress.ip_address(r["d"])
    return _write(outdir, log, rng)
