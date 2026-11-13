"""Generate the Compare sample: two fictional companies with remote sites, one report per site.

Ridgeline ("ridgeline.example") is the company in the Gootloader sample, and that sample is its head
office report. This module adds two branch offices that see the same intrusion from the other end of
the site-to-site VPN. The branches, and everything that happens in them, are invented: The DFIR Report
describes one site.

  Denver   dc01's Advanced IP Scanner sweep reaches the office right after it covers the head office.
           On day 2 the attacker, working from dc01, opens RDP to den-fs01, copies the same Cobalt
           Strike beacon dc01 received over SMB, and den-fs01 calls the report's published C2 through
           the office's own internet line until the activity stops. The file share is then browsed.
  Tampa    Only the sweep.

Corvane ("corvane.example"), a fictional semiconductor equipment supplier, follows the campaign in
Unit 42's "Attackers Use Autonomous AI to Target Semiconductor, Defense and Civil Society Sectors"
(2026-11-12): CL-STA-1238 ran a customized fork of the open-source Cairn AI penetration-testing
framework against at least 19 organizations. AI agents worked in Reason and Explore loops through
reconnaissance, web and service exploitation, credential collection and internal access. Against one
semiconductor company they brute-forced a production credential on a partner-integration application,
pulled application data, user lists and email lists, and created administrator accounts and a
persistent API token; the task for a semiconductor equipment supplier carried VPN gateway addresses,
group names and shared group passwords for several sites. The report publishes two addresses, the
Cairn server (154.44.31.4) and the staging and attack-egress node (82.29.129.54), and no other
indicators. Here every attack session comes from the egress node; the Cairn server is only in the IOC
list, since the report doesn't describe victims reaching it. Everything else (which site saw what,
timings, volumes, the bursts of machine-paced requests between pauses) is invented:

  HQ        01:40 port sweep and content discovery on the public servers; 02:10 brute force of the
            partner portal; 02:16 one credential works: user lists, email lists and application data
            are pulled, admin accounts and an API token created; the token is used every few hours after.
  Phoenix   03:05 VPN login with the leaked group password; scans the plant network, reads the
            directory and the file server for hours; back on day 2 for more files.
  Austin    04:55 VPN login; SSH to the build server, source code cloned from GitLab, tools fetched from
            the staging server; back on day 2 for more code. Separately, at 16:20 a user searching for
            an agreement template lands on two Gootloader sites, which the firewall blocks.
  Dresden   The group password was changed here: only failed VPN logins, on both days.

Both companies' sensors cover the Gootloader sample's two days. The six new site folders carry one IOC
list with both reports' indicators, the way a service provider runs one feed for every client, except
Dresden's: like the Gootloader sample's own list, it predates Unit 42's report, so only Compare's re-hunt
finds the egress address there. Internal addresses overlap on purpose: both head offices use
10.20.0.0/24 for servers.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import random
import shutil
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from . import sample_gootloader as goot

FOLDER = "compare_two_companies"
UNIT42_URL = "https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/"
CAIRN_SERVER = "154.44.31.4"      # published: Cairn hosting server (HK, AS979)
EGRESS = "82.29.129.54"           # published: staging server and attack egress (US, AS142036)
CORVANE = "corvane.example"
START, END, DAY2, STOP = goot.START, goot.END, goot.DAY2, goot.STOP
SWEEP = goot.PAYLOAD + timedelta(hours=1, minutes=50)   # when dc01's Advanced IP Scanner sweep starts
SWEEP_PORTS = (21, 80, 443, 445, 3389, 4899)
WIN11, WIN10 = "Microsoft Windows 11 Enterprise", "Microsoft Windows 10 Enterprise"
WS2016, WS2019, WS2022 = (f"Microsoft Windows Server {v} Standard" for v in (2016, 2019, 2022))
UBUNTU, ASA = "Ubuntu 22.04", "Cisco Adaptive Security Appliance"
PREVIEW = {UNIT42_URL: {
    "title": "Attackers Use Autonomous AI to Target Semiconductor, Defense and Civil Society Sectors",
    "overview": "Unit 42 describes CL-STA-1238, assessed with moderate confidence as China-nexus, running a "
                "customized fork of the open-source Cairn AI penetration-testing framework in 25 operations "
                "against at least 19 semiconductor, defense and civil society organizations in August and "
                "September 2026. AI agents mapped targets, exploited web applications and identity weaknesses, "
                "collected credentials and reached internal networks; the operators supplied extra "
                "intelligence such as VPN gateway addresses and shared group passwords."}}
# (folder, report name, network, description); Ridgeline's head office is the Gootloader sample
SITES = [
    (goot.FOLDER, "Ridgeline HQ", "Ridgeline",
     "Sample: Ridgeline's head office. The Gootloader intrusion from The DFIR Report, replayed."),
    ("ridgeline_denver", "Ridgeline Denver office", "Ridgeline",
     "Sample: dc01's scan reaches this office over the site VPN. On day 2 the attacker copies a Cobalt "
     "Strike beacon to den-fs01, which calls the C2 through the office's own internet line."),
    ("ridgeline_tampa", "Ridgeline Tampa office", "Ridgeline",
     "Sample: only dc01's scan reaches this office; nothing else from the intrusion."),
    ("corvane_hq", "Corvane HQ", "Corvane",
     "Sample: an AI agent (Cairn, CL-STA-1238 in Unit 42's report) maps the public servers, brute-forces "
     "the partner portal, pulls user and email lists, and comes back with an API token."),
    ("corvane_phoenix", "Corvane Phoenix plant", "Corvane",
     "Sample: the agent logs into the site VPN with a leaked group password, scans the plant network and "
     "reads the file server."),
    ("corvane_austin", "Corvane Austin design center", "Corvane",
     "Sample: VPN login with the leaked group password, SSH to the build server, source code pulled from "
     "GitLab, tools fetched from the staging server. A user also lands on two Gootloader sites (blocked)."),
    ("corvane_dresden", "Corvane Dresden service center", "Corvane",
     "Sample: the leaked group password no longer works here; only failed VPN logins. Analyzed with the IOC "
     "feed from before Unit 42's report, so only Compare's re-hunt finds the egress address."),
]
# (pluginID, name, severity, cvss3, cves, exploit, metasploit, synopsis, solution) by short name
V = {
    "smb": ("57608", "SMB Signing not required", 2, 5.3, [], False, False,
            "Signing is not required on the remote SMB server.", "Enforce message signing in the host's configuration."),
    "edge": ("207053", "Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities", 3, 8.8,
             ["CVE-2024-7965", "CVE-2024-7971"], True, False,
             "The browser installed on the remote host is affected by multiple vulnerabilities.",
             "Upgrade to Microsoft Edge version 129.0.2792.52 or later."),
    "7zip": ("189385", "7-Zip < 24.07 Code Execution", 3, 7.0, ["CVE-2024-11477"], False, False,
             "The archiver on the remote host is affected by a code execution vulnerability.",
             "Upgrade to 7-Zip 24.07 or later."),
    "spooler": ("151440", "Windows Print Spooler Service Enabled (PrintNightmare, CVE-2021-34527)", 4, 8.8,
                ["CVE-2021-34527"], True, True,
                "The Print Spooler service is affected by a remote code execution vulnerability.",
                "Apply the July 2021 security updates or disable the Print Spooler service."),
    "nla": ("58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", 2, 4.0, [], False, False,
            "The remote Terminal Services doesn't use NLA only.", "Enable Network Level Authentication."),
    "ldap": ("191001", "Active Directory LDAP Signing and Channel Binding Not Required", 2, 5.9, [], False, False,
             "The domain controller accepts unsigned LDAP binds.", "Require LDAP signing and channel binding."),
    "sql": ("73756", "Microsoft SQL Server Unsupported Version Detection", 4, 10.0, [], False, False,
            "The installed version of SQL Server is no longer supported.", "Upgrade to a supported version of SQL Server."),
    "kb2019": ("205440", "KB5041578: Windows Server 2019 Security Update (August 2024)", 4, 9.8, ["CVE-2024-38063"],
               False, False, "The remote Windows host is missing security update 5041578.",
               "Apply Security Update 5041578."),
    "ike": ("62694", "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key", 2, 5.3, ["CVE-2002-1623"],
            False, False,
            "The VPN gateway answers IKE Aggressive Mode with a pre-shared key: anyone who knows a group name "
            "gets a hash of its group password to crack offline.",
            "Disable Aggressive Mode, or use certificates; give every site its own strong group key."),
    "terrapin": ("187201", "OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin)", 2, 5.9, ["CVE-2023-48795"],
                 False, False, "The SSH server is affected by a prefix truncation weakness.",
                 "Upgrade to OpenSSH 9.6 or later."),
    "regresshion": ("201194", "OpenSSH < 9.8 Race Condition RCE (regreSSHion)", 4, 8.1, ["CVE-2024-6387"], True, False,
                    "The SSH server is affected by a signal handler race condition.", "Upgrade to OpenSSH 9.8 or later."),
    "tomcat": ("171340", "Apache Tomcat 9.0.x < 9.0.71 Information Disclosure", 2, 5.3, ["CVE-2023-28708"], False,
               False, "The Tomcat server is affected by an information disclosure vulnerability.",
               "Upgrade to Apache Tomcat 9.0.71 or later."),
    "nginx": ("200206", "nginx 1.25.x < 1.25.4 Multiple Vulnerabilities", 3, 7.5, ["CVE-2024-24989"], False, False,
              "The web server is affected by multiple denial of service vulnerabilities.",
              "Upgrade to nginx 1.25.4 or later."),
    "postfix": ("187315", "Postfix SMTP Smuggling", 2, 5.3, ["CVE-2023-51764"], False, False,
                "The mail server accepts smuggled SMTP commands.", "Upgrade Postfix and set smtpd_forbid_bare_newline."),
    "gitlab": ("187600", "GitLab 16.1 < 16.7.2 Account Takeover via Password Reset", 4, 10.0, ["CVE-2023-7028"],
               True, False, "The GitLab instance allows account takeover through the password reset flow.",
               "Upgrade to GitLab 16.7.2 or later and enable two-factor authentication."),
    "jenkins": ("189463", "Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897)", 4, 9.8, ["CVE-2024-23897"], True,
                True, "The Jenkins CLI allows unauthenticated reading of arbitrary files.",
                "Upgrade to Jenkins 2.442 or later."),
    "snmp": ("41028", "SNMP Agent Default Community Name (public)", 3, 7.5, ["CVE-1999-0517"], True, False,
             "The community name of the remote SNMP server can be guessed.",
             "Disable SNMP or change the default community string."),
    "telnet": ("42263", "Unencrypted Telnet Server", 2, 6.5, [], False, False,
               "The remote Telnet server transmits traffic in cleartext.", "Disable Telnet and use SSH instead."),
}
# Corvane's head office, as the remote sites see it over the site-to-site VPN
C_DC1, C_DC2, C_FS, C_SQL, C_ERP = "10.20.0.10", "10.20.0.11", "10.20.0.20", "10.20.0.40", "10.20.0.41"


def _utc(day, hour, minute=0, second=0):
    return datetime(2026, 10, day, hour, minute, second, tzinfo=timezone.utc)


class Site:
    """One site: its hosts and scan findings, and what its sensors recorded. Zeek taps the core
    switch, the site's own Palo Alto firewall logs every session to or from another zone, and
    Ridgeline also runs Suricata. Same interface as the Gootloader sample's log, so its beacon
    helper works here too."""

    def __init__(self, folder, domain, resolver, serial, seed, hours, prefix, scan_name):
        self.folder, self.domain, self.resolver, self.serial = folder, domain, resolver, serial
        self.rng = random.Random(seed)
        self.hours = hours                    # working day in UTC hours: (first, end); may wrap midnight
        self.prefix, self.scan_name = prefix, scan_name
        self.hosts: dict[str, tuple[str, str]] = {}      # ip -> (fqdn, os); everything here is scanned
        self.vulns: list[tuple] = []
        self.conn, self.pan, self.threats, self.dns, self.http, self.ssl, self.files, self.eve = ([] for _ in range(8))
        self.uid = 0

    def host(self, ip, name, os_name):
        self.hosts[ip] = (f"{name}.{self.domain}", os_name)
        return ip

    def vuln(self, ip, port, svc, key, proto="tcp"):
        self.vulns.append((ip, port, proto, svc) + V[key])

    def _uid(self):
        self.uid += 1
        return f"{self.prefix}{self.uid:09x}"

    def work_ts(self, rng=None):
        """A time in the site's working day (08:00-18:00 local), now and then outside it."""
        rng = rng or self.rng
        first, end = self.hours
        span = (END - START).total_seconds()
        while True:
            t = START + timedelta(seconds=rng.uniform(0, span))
            inside = first <= t.hour < end if first < end else (t.hour >= first or t.hour < end)
            if inside or rng.random() < 0.12:
                return t

    def session(self, ts, s, d, dp, svc="-", proto="tcp", state="SF", ob=None, rb=None, dur=None,
                app=None, fz=None, tz=None, action="allow", zeek=True, rule=None):
        """One session: in Zeek when allowed, and in the firewall log when it crosses a zone (``app``)."""
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
            self.pan.append(dict(ts=ts, s=s, sp=sp, d=d, dp=dp, app=app, fz=fz, tz=tz, action=action, rule=rule,
                                 sent=ob if action == "allow" else rng.randint(60, 200),
                                 rcvd=rb if action == "allow" else 0, proto=proto))
        return uid, sp

    def lookup(self, ts, client, query, answer):
        self.dns.append(dict(ts=ts, uid=self._uid(), s=client, sp=self.rng.randint(49152, 65535), d=self.resolver,
                             q=query, a=answer))

    def threat(self, ts, s, d, dp, name, sev, action="alert", kind="spyware", app="ssl", fz="trust", tz="untrust"):
        self.threats.append(dict(ts=ts, s=s, d=d, dp=dp, name=name, sev=sev, action=action, kind=kind,
                                 app=app, fz=fz, tz=tz))

    def ids(self, ts, s, d, dp, sig, sid, category, sev=2, app="smb"):
        self.eve.append(dict(ts=ts, s=s, d=d, dp=dp, sig=sig, sid=sid, cat=category, sev=sev, app=app))


def _bursts(rng, start, count, size=(8, 30), gap=(0.15, 0.6), pause=(20, 90)):
    """``count`` timestamps the way an AI agent works: a quick burst of requests, then a pause
    while the model reads the results and decides what to do next."""
    t, out = start, []
    while len(out) < count:
        for _ in range(min(rng.randint(*size), count - len(out))):
            out.append(t)
            t += timedelta(seconds=rng.uniform(*gap))
        t += timedelta(seconds=rng.uniform(*pause))
    return out


def _workstations(s, net, first, names, os_pick=None):
    """Workstations numbered from ``net``.``first``: ``names`` is [(prefix, count)]."""
    out, n = [], first
    for prefix, count in names:
        for k in range(1, count + 1):
            out.append(s.host(f"{net}.{n}", f"{prefix}-{k:02}", (os_pick or (lambda i: WIN11 if i % 3 else WIN10))(n)))
            n += 1
    return out


def _office(s, workstations, dcs, file_servers, apps, printers=(), print_server=None):
    """Everyday traffic: logons, file shares, business apps, cloud services, printing."""
    rng = s.rng
    for ws in workstations:
        for _ in range(rng.randint(4, 7)):
            s.session(s.work_ts(), ws, rng.choice(dcs), 88, svc="krb", ob=rng.randint(1200, 1800))
        for _ in range(rng.randint(2, 4)):
            s.session(s.work_ts(), ws, rng.choice(dcs), 389, svc="ldap")
        for _ in range(rng.randint(3, 6)):
            s.session(s.work_ts(), ws, rng.choice(file_servers), 445, svc="smb", rb=rng.randint(20_000, 2_000_000))
        for _ in range(rng.randint(1, 3)):
            ip, port, svc = rng.choice(apps)
            s.session(s.work_ts(), ws, ip, port, svc=svc)
        for _ in range(rng.randint(3, 6)):
            name, ip = rng.choice(goot.SAAS)
            t = s.work_ts()
            if rng.random() < 0.25:
                s.lookup(t - timedelta(seconds=1), ws, name, ip)
            goot._out(s, t, ws, ip, 443, "ssl")
    for h in range(0, 48, 2):                        # the site's resolver forwards upstream
        s.session(START + timedelta(hours=h, minutes=rng.randint(0, 119)), s.resolver, goot.UPSTREAM_DNS, 53,
                  svc="dns", proto="udp", app="dns", fz="trust", tz="untrust", ob=rng.randint(60, 90),
                  rb=rng.randint(90, 300))
    for p in printers:
        for _ in range(rng.randint(3, 6)):
            s.session(s.work_ts(), print_server or rng.choice(workstations), p, 9100, ob=rng.randint(30_000, 600_000),
                      rb=200)
    for ws in rng.sample(workstations, min(6, len(workstations))):      # direct outside DNS is blocked
        s.session(s.work_ts(), ws, "8.8.8.8", 53, svc="dns", proto="udp", app="dns", fz="trust", tz="untrust",
                  action="deny", rule="deny-direct-dns")


def _windows(s, servers, workstations, edge=0.35, zip7=0.15):
    for ip in servers + workstations:
        s.vuln(ip, 445, "cifs", "smb")
    for ip in workstations:
        if s.rng.random() < edge:
            s.vuln(ip, 0, "general", "edge")
        if s.rng.random() < zip7:
            s.vuln(ip, 0, "general", "7zip")


# -- Ridgeline's offices ---------------------------------------------------------------------------

def _branch(folder, net, prefix, seed, hours, uid, ws_count, scan_name):
    """A Ridgeline office: a file server (and in Denver a read-only DC), workstations, printers;
    logons go to the head office's DCs over the site-to-site VPN, nightly backups come from backup01."""
    s = Site(folder, goot.DOMAIN, f"{net}.0.53", "0132010077" + seed[-2:], int(seed), hours, uid, scan_name)
    rng = s.rng
    servers = []
    dc = None
    if prefix == "den":
        dc = s.host(f"{net}.0.10", "den-dc03", WS2019)            # read-only DC
        servers.append(dc)
    fs = s.host(f"{net}.0.20", f"{prefix}-fs01", WS2016)
    servers.append(fs)
    ws = _workstations(s, f"{net}.10", 21, [(f"{prefix}-ws", ws_count)])
    printers = [s.host(f"{net}.30.{i}", f"{prefix}-prn-{i}", "HP LaserJet") for i in (10, 11)]
    dcs = [dc, dc, goot.DC1, goot.DC2] if dc else [goot.DC1, goot.DC2]
    _office(s, ws, dcs, [fs, fs, fs, goot.FS], [(goot.APP, 443, "ssl"), (goot.SQL, 1433, "-")], printers, fs)
    if dc:
        for k in range(24):                               # replication with the head office
            s.session(START + timedelta(hours=2 * k, minutes=rng.randint(0, 50)), dc, goot.DC1,
                      rng.choice([135, 389, 445]), rb=rng.randint(5_000, 300_000))
    for night in (2, 26):                                 # backup01 pulls the file share every night
        s.session(START + timedelta(hours=night, minutes=rng.randint(5, 50)), goot.BACKUP, fs, 445, svc="smb",
                  ob=4000, rb=rng.randint(80_000_000, 300_000_000), dur=rng.uniform(300, 1500))
    _windows(s, servers, ws)
    s.vuln(fs, 445, "cifs", "spooler")
    s.vuln(fs, 3389, "msrdp", "nla")
    if dc:
        s.vuln(dc, 389, "ldap", "ldap")
        s.vuln(dc, 445, "cifs", "spooler")
    return s, servers, ws, printers


def _sweep(s, start, servers, workstations, printers):
    """dc01's Advanced IP Scanner sweep, after the head office: every host, six ports each."""
    rng = s.rng
    every = servers + workstations + printers
    for k, d in enumerate(every):
        for j, port in enumerate(SWEEP_PORTS):
            listening = (port == 445 and d not in printers) or (port == 3389 and d in servers) or \
                        (port in (80, 443) and d in printers)
            s.session(start + timedelta(seconds=k * 1.3 + j * 0.15), goot.DC1, d, port,
                      state="SF" if listening else "REJ", ob=80 if listening else 0, rb=120 if listening else 0,
                      dur=0.01)
    s.ids(start + timedelta(seconds=20), goot.DC1, servers[-1], 445,
          "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection", 9100001, "Misc activity", sev=3)
    return start + timedelta(seconds=len(every) * 1.3)


def _ridgeline():
    den, d_srv, d_ws, d_prn = _branch("ridgeline_denver", "10.21", "den", "2101", (14, 24), "D", 40,
                                      "Monthly scan - Denver office")
    tpa, t_srv, t_ws, t_prn = _branch("ridgeline_tampa", "10.22", "tpa", "2102", (12, 22), "T", 30,
                                      "Monthly scan - Tampa office")
    hq_sweep = len(goot.HOSTS) - 1                         # hosts the sweep covers at the head office first
    after = _sweep(den, SWEEP + timedelta(seconds=hq_sweep * 1.3 + 2), d_srv, d_ws, d_prn)
    _sweep(tpa, after + timedelta(seconds=2), t_srv, t_ws, t_prn)
    _denver_beacon(den, d_srv[-1])
    return [den, tpa]


def _denver_beacon(s, fs):
    """Day 2: from dc01, RDP to den-fs01, the beacon dc01 received copied over SMB and started as a
    service, then the file share browsed. den-fs01 reaches the C2 through the office's internet line."""
    rng = s.rng
    t = _utc(27, 7, 20)
    s.session(t, goot.DC1, fs, 3389, svc="rdp", ob=rng.randint(300_000, 700_000), rb=rng.randint(3_000_000, 9_000_000),
              dur=rng.uniform(600, 1100))
    t += timedelta(minutes=4)
    _, fname, md5, sha1, sha256 = goot.SMB_BEACONS[0]
    uid, sp = s.session(t, goot.DC1, fs, 445, svc="smb,dce_rpc", ob=rng.randint(310_000, 330_000),
                        rb=rng.randint(9_000, 20_000), dur=rng.uniform(4, 12))
    for k, (sig, sid, cat, sev) in enumerate((
            ("ET RPC DCERPC SVCCTL - Remote Service Control Manager Access", 9100002, "Misc activity", 3),
            ("ET POLICY SMB2 NT Create AndX Request For an Executable File", 9100004, goot.PRIVACY, 2),
            ("ET POLICY SMB Executable File Transfer", 9100003, goot.PRIVACY, 2))):
        s.ids(t + timedelta(seconds=1 + 2 * k), goot.DC1, fs, 445, sig, sid, cat, sev=sev)
    s.files.append(dict(ts=t + timedelta(seconds=5), uid=uid, s=goot.DC1, sp=sp, d=fs, dp=445,
                        name=f"\\\\DEN-FS01\\ADMIN$\\{fname}", mime="application/x-dosexec",
                        size=rng.randint(300_000, 320_000), md5=md5, sha1=sha1, sha256=sha256))
    goot._beacon(s, rng, fs, t + timedelta(minutes=2), STOP)
    t = _utc(27, 8, 10)
    while t < STOP - timedelta(minutes=20):
        s.session(t, goot.DC1, fs, 445, svc="smb", ob=rng.randint(6_000, 20_000), rb=rng.randint(1_000_000, 25_000_000),
                  dur=rng.uniform(60, 400))
        t += timedelta(minutes=rng.uniform(22, 35))


# -- Corvane --------------------------------------------------------------------------------------

def _vpn_users(s, vpn, pool, targets, users):
    """Employees on the remote-access VPN in the evening: IKE from home, then work over the tunnel."""
    rng = s.rng
    apps = {443: "ssl", 445: "ms-ds-smb", 389: "ldap"}
    for k in range(users):
        home = f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        inner = f"{pool}.{11 + k}"
        for day in (26, 27):
            t = _utc(day, 0) + timedelta(hours=s.hours[1] + rng.uniform(1, 3))
            if t > END - timedelta(hours=2):
                continue
            s.session(t, home, vpn, 500, proto="udp", app="ike", fz="untrust", tz="dmz", ob=rng.randint(900, 1400),
                      rb=rng.randint(700, 1100), dur=rng.uniform(0.3, 1.2), rule="allow-vpn-gateway")
            s.session(t + timedelta(seconds=2), home, vpn, 4500, proto="udp", app="ipsec-esp-udp", fz="untrust",
                      tz="dmz", ob=rng.randint(2_000_000, 30_000_000), rb=rng.randint(5_000_000, 90_000_000),
                      dur=rng.uniform(1800, 5400), rule="allow-vpn-gateway")
            for j in range(rng.randint(4, 9)):
                d, port, svc = rng.choice(targets)
                s.session(t + timedelta(minutes=2 + j * rng.uniform(4, 12)), inner, d, port, svc=svc, app=apps[port],
                          fz="vpn", tz="trust", rule="ra-vpn-users", rb=rng.randint(10_000, 3_000_000))


def _agent_vpn(s, vpn, tunnel):
    """The agent logs into the site's VPN with the leaked group name and password (IKE Aggressive
    Mode on 500, then the tunnel on 4500). ``tunnel`` is [(start, stop, megabytes in, megabytes out)]."""
    rng = s.rng
    for start, stop, mb_in, mb_out in tunnel:
        s.session(start, EGRESS, vpn, 500, proto="udp", app="ike", fz="untrust", tz="dmz", ob=rng.randint(900, 1400),
                  rb=rng.randint(700, 1100), dur=rng.uniform(0.3, 1.2), rule="allow-vpn-gateway")
        pieces = max(1, int((stop - start).total_seconds() // 900))
        for k in range(pieces):
            s.session(start + timedelta(seconds=3 + k * 900), EGRESS, vpn, 4500, proto="udp", app="ipsec-esp-udp",
                      fz="untrust", tz="dmz", ob=int(mb_in * 1e6 / pieces * rng.uniform(0.7, 1.3)),
                      rb=int(mb_out * 1e6 / pieces * rng.uniform(0.7, 1.3)), dur=900, rule="allow-vpn-gateway")


def _agent_scan(s, src, start, targets, ports, open_on):
    """Machine-paced internal scan from the agent's VPN address, burst by burst."""
    rng = s.rng
    probes = [(d, p) for d in targets for p in ports]
    for ts, (d, port) in zip(_bursts(rng, start, len(probes), size=(30, 80), gap=(0.02, 0.08), pause=(15, 60)), probes):
        listening = port in open_on(d)
        s.session(ts, src, d, port, state="SF" if listening else "REJ", ob=60 if listening else 0,
                  rb=90 if listening else 0, dur=0.01, app="incomplete", fz="vpn", tz="trust", rule="ra-vpn-users")
    s.threat(start + timedelta(seconds=40), src, targets[0], ports[0], "TCP Port Scan", "medium", kind="scan",
             app="not-applicable", fz="vpn", tz="trust")


def _windows_ports(servers, workstations, extra=None):
    def open_on(d):
        ports = {135, 139, 445} if d in servers or d in workstations else set()
        if d in servers:
            ports |= {3389, 5985}
        return ports | (extra or {}).get(d, set())
    return open_on


def _corvane_hq():
    s = Site("corvane_hq", CORVANE, "10.20.0.53", "016401002210", 4201, (15, 1), "H", "Quarterly scan - HQ")
    rng = s.rng
    www = s.host("172.16.10.10", "www01", UBUNTU)
    portal = s.host("172.16.10.20", "partners01", UBUNTU)        # the partner-integration application
    mail = s.host("172.16.10.25", "mail01", UBUNTU)
    dc1, dc2 = s.host(C_DC1, "dc01", WS2022), s.host(C_DC2, "dc02", WS2022)
    fs = s.host(C_FS, "fs01", WS2019)
    sql = s.host(C_SQL, "sql01", WS2016)
    erp = s.host(C_ERP, "erp01", WS2019)
    pdb = s.host("10.20.0.45", "partnerdb01", UBUNTU)
    adm = s.host("10.20.0.60", "it-adm01", WS2022)
    servers = [dc1, dc2, fs, sql, erp, adm]
    ws = _workstations(s, "10.20.10", 21, [("eng-ws", 20), ("fin-ws", 8), ("ops-ws", 12), ("sales-ws", 10),
                                           ("hr-ws", 4), ("it-ws", 6)])
    printers = [s.host(f"10.20.30.{i}", f"prn-{i}", "HP LaserJet") for i in (10, 11, 12)]
    _office(s, ws, [dc1, dc2], [fs], [(erp, 443, "ssl"), (sql, 1433, "-")], printers, fs)
    for _ in range(260):                                           # the public website
        t = START + timedelta(seconds=rng.uniform(0, (END - START).total_seconds()))
        s.session(t, f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}", www, 443, svc="ssl", app="ssl",
                  fz="untrust", tz="dmz", ob=rng.randint(600, 3000), rb=rng.randint(5_000, 400_000),
                  rule="allow-dmz-inbound")
    for partner in ("192.0.2.201", "192.0.2.202", "192.0.2.203"):    # partners' systems call the portal API
        t = START + timedelta(minutes=rng.randint(0, 40))
        while t < END:
            uid, sp = s.session(t, partner, portal, 443, svc="ssl", app="ssl", fz="untrust", tz="dmz",
                                ob=rng.randint(900, 6000), rb=rng.randint(2_000, 60_000), rule="allow-dmz-inbound")
            s.session(t + timedelta(seconds=1), portal, pdb, 5432, svc="postgresql", ob=rng.randint(400, 2000),
                      rb=rng.randint(2_000, 50_000))
            t += timedelta(minutes=rng.uniform(40, 80))
    for _ in range(90):                                            # mail in and out
        t = s.work_ts()
        s.session(t, f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}", mail, 25, svc="smtp", app="smtp",
                  fz="untrust", tz="dmz", ob=rng.randint(4_000, 400_000), rb=rng.randint(300, 900),
                  rule="allow-dmz-inbound")
        s.session(t + timedelta(minutes=rng.uniform(1, 30)), mail, f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                  25, svc="smtp", app="smtp", fz="dmz", tz="untrust", ob=rng.randint(4_000, 300_000), rb=600,
                  rule="allow-dmz-outbound")
    for _ in range(30):                                            # administration of the DMZ
        s.session(s.work_ts(), adm, rng.choice([www, portal, mail]), 22, svc="ssh", app="ssh", fz="trust",
                  tz="dmz", rb=rng.randint(5_000, 200_000), rule="allow-admin-dmz")
    _windows(s, servers, ws)
    s.vuln(dc1, 389, "ldap", "ldap")
    s.vuln(dc2, 389, "ldap", "ldap")
    for ip in (dc1, dc2, adm):
        s.vuln(ip, 3389, "msrdp", "nla")
    for ip in (dc1, fs):
        s.vuln(ip, 445, "cifs", "spooler")
    s.vuln(sql, 1433, "mssql", "sql")
    for ip in (fs, erp):
        s.vuln(ip, 0, "general", "kb2019")
    s.vuln(portal, 443, "www", "tomcat")
    s.vuln(www, 443, "www", "nginx")
    s.vuln(mail, 25, "smtp", "postfix")
    for ip in (www, portal, mail):
        s.vuln(ip, 22, "ssh", "terrapin")
    _cairn_hq(s, www, portal, mail, pdb)
    return s


def _cairn_hq(s, www, portal, mail, pdb):
    rng = s.rng
    # recon: a sweep of the public addresses (most ports dropped), then content discovery
    ports = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
             8000, 8080, 8443, 9200)
    open_on = {www: {80, 443}, portal: {443}, mail: {25, 465, 587}}
    probes = [(d, p) for d in (www, portal, mail) for p in ports]
    for ts, (d, port) in zip(_bursts(rng, _utc(26, 1, 40), len(probes), size=(20, 40), gap=(0.05, 0.2)), probes):
        if port in open_on[d]:
            s.session(ts, EGRESS, d, port, ob=80, rb=120, dur=0.02, app="incomplete", fz="untrust", tz="dmz",
                      rule="allow-dmz-inbound")
        else:
            s.session(ts, EGRESS, d, port, app="incomplete", fz="untrust", tz="dmz", action="deny", rule="default-deny")
    s.threat(_utc(26, 1, 40, 30), EGRESS, www, 443, "TCP Port Scan", "medium", kind="scan", app="not-applicable",
             fz="untrust", tz="dmz")
    for target, count, sni, t in ((www, 140, "www.corvane.example", _utc(26, 1, 44)),
                                  (portal, 170, "partners.corvane.example", _utc(26, 1, 52))):
        for k, ts in enumerate(_bursts(rng, t, count)):
            uid, sp = s.session(ts, EGRESS, target, 443, svc="ssl", app="ssl", fz="untrust", tz="dmz",
                                ob=rng.randint(500, 1100), rb=rng.randint(300, 2_500), dur=rng.uniform(0.05, 0.4),
                                rule="allow-dmz-inbound")
            if k % 20 == 0:
                s.ssl.append(dict(ts=ts, uid=uid, s=EGRESS, sp=sp, d=target, dp=443, sni=sni, ja3="", ja3s=""))
    # brute force of the partner portal's login API
    times = _bursts(rng, _utc(26, 2, 10), 380, size=(20, 60), gap=(0.2, 0.9), pause=(5, 30))
    for k, ts in enumerate(times):
        uid, sp = s.session(ts, EGRESS, portal, 443, svc="ssl", app="ssl", fz="untrust", tz="dmz",
                            ob=rng.randint(700, 1300), rb=rng.randint(400, 900), dur=rng.uniform(0.1, 0.6),
                            rule="allow-dmz-inbound")
        if k % 25 == 0:
            s.ssl.append(dict(ts=ts, uid=uid, s=EGRESS, sp=sp, d=portal, dp=443, sni="partners.corvane.example",
                              ja3="", ja3s=""))
        if k in (40, 140, 240, 340):
            s.threat(ts + timedelta(seconds=1), EGRESS, portal, 443, "HTTP: User Authentication Brute-force Attempt",
                     "high", kind="vulnerability", app="ssl", fz="untrust", tz="dmz")
    # a credential that works: email lists, user lists and application data, then admin accounts and a token
    t = times[-1] + timedelta(seconds=40)
    for k, (rb, dur) in enumerate(((2_400_000, 20), (6_100_000, 45), (38_500_000, 260))):
        ts = t + timedelta(minutes=3 * k)
        s.session(ts, EGRESS, portal, 443, svc="ssl", app="ssl", fz="untrust", tz="dmz", ob=rng.randint(3_000, 9_000),
                  rb=rb, dur=dur, rule="allow-dmz-inbound")
        for j in range(3):
            s.session(ts + timedelta(seconds=1 + j), portal, pdb, 5432, svc="postgresql", ob=rng.randint(800, 3_000),
                      rb=rb // 3, dur=dur / 3)
    for k in range(4):
        s.session(t + timedelta(minutes=12, seconds=20 * k), EGRESS, portal, 443, svc="ssl", app="ssl", fz="untrust",
                  tz="dmz", ob=rng.randint(1_500, 4_000), rb=rng.randint(800, 2_000), rule="allow-dmz-inbound")
    # the persistent API token, used every few hours
    t = _utc(26, 6, 5)
    while t < _utc(27, 10):
        s.session(t, EGRESS, portal, 443, svc="ssl", app="ssl", fz="untrust", tz="dmz", ob=rng.randint(1_000, 3_000),
                  rb=rng.randint(40_000, 900_000), dur=rng.uniform(1, 8), rule="allow-dmz-inbound")
        t += timedelta(hours=rng.uniform(2.5, 4))


def _corvane_site(folder, net, prefix, seed, hours, uid, scan_name, ws_count, servers_spec):
    """A Corvane site: a VPN gateway that takes group logins, servers, workstations, a printer;
    logons go to the head office's DCs over the site-to-site VPN."""
    s = Site(folder, CORVANE, f"{net}.0.53", "0164010022" + seed[-2:], int(seed), hours, uid, scan_name)
    vpn = s.host(f"{net}.1.5", f"vpn-{prefix}", ASA)
    srv = {name: s.host(f"{net}.0.{last}", name, os_name) for name, last, os_name in servers_spec}
    ws = _workstations(s, f"{net}.10", 21, [(f"{prefix}-ws", ws_count)])
    printers = [s.host(f"{net}.30.10", f"{prefix}-prn-10", "HP LaserJet")]
    s.vuln(vpn, 500, "ike", "ike", proto="udp")
    return s, vpn, srv, ws, printers


def _corvane_phoenix():
    s, vpn, srv, ws, printers = _corvane_site(
        "corvane_phoenix", "10.31", "phx", "4231", (15, 1), "P", "Quarterly scan - Phoenix plant", 40,
        [("phx-dc03", 10, WS2019), ("phx-fs01", 20, WS2016), ("phx-mes01", 30, WS2019), ("phx-hist01", 31, WS2019)])
    rng = s.rng
    dc, fs, mes, hist = srv["phx-dc03"], srv["phx-fs01"], srv["phx-mes01"], srv["phx-hist01"]
    tools = [s.host(f"10.31.20.{i}", f"phx-tool-{i}", "Linux Kernel 4.19") for i in range(11, 19)]
    _office(s, ws, [dc, dc, C_DC1], [fs], [(mes, 443, "ssl"), (C_ERP, 443, "ssl")], printers)
    for tool in tools:                                  # the historian polls the tool controllers (OPC UA)
        t = START + timedelta(minutes=rng.randint(0, 29))
        while t < END:
            s.session(t, hist, tool, 4840, ob=rng.randint(200, 600), rb=rng.randint(2_000, 12_000), dur=rng.uniform(0.1, 1))
            t += timedelta(minutes=rng.uniform(25, 35))
        for _ in range(6):
            s.session(s.work_ts(), mes, tool, 8080, svc="http", rb=rng.randint(5_000, 80_000))
    for k in range(12):                                 # the MES reports to the head office's ERP
        s.session(START + timedelta(hours=4 * k, minutes=rng.randint(0, 59)), mes, C_ERP, 443, svc="ssl",
                  rb=rng.randint(20_000, 400_000))
    _vpn_users(s, vpn, "10.31.250", [(fs, 445, "smb"), (mes, 443, "ssl"), (dc, 389, "ldap")], 3)
    _windows(s, list(srv.values()), ws)
    s.vuln(dc, 389, "ldap", "ldap")
    for ip in (fs, dc):
        s.vuln(ip, 445, "cifs", "spooler")
    s.vuln(mes, 3389, "msrdp", "nla")
    for tool in tools:
        s.vuln(tool, 161, "snmp", "snmp", proto="udp")
    s.vuln(tools[0], 23, "telnet", "telnet")
    # the agent: VPN on day 1 and day 2, a scan, the directory, the file server, an RDP try
    pool = "10.31.250.23"
    _agent_vpn(s, vpn, [(_utc(26, 3, 5), _utc(26, 6, 55), 30, 1_100), (_utc(27, 1, 10), _utc(27, 4, 30), 12, 420)])
    servers = list(srv.values())
    _agent_scan(s, pool, _utc(26, 3, 8), servers + ws + tools, (22, 80, 135, 139, 443, 445, 1433, 3389, 5985, 8080),
                _windows_ports(servers, ws, {mes: {443}, hist: {443}, **{t: {22, 8080} for t in tools}}))
    spray = _bursts(rng, _utc(26, 3, 22), 64, size=(16, 24), gap=(0.3, 0.8), pause=(25, 50))
    for k, ts in enumerate(spray):                      # passwords tried against the file server
        s.session(ts, pool, fs, 445, svc="smb", ob=rng.randint(900, 1_400), rb=rng.randint(500, 800),
                  dur=rng.uniform(0.05, 0.3), app="ms-ds-smb", fz="vpn", tz="trust", rule="ra-vpn-users")
        if k in (20, 50):
            s.threat(ts + timedelta(seconds=1), pool, fs, 445, "SMB: User Password Brute-force Attempt", "high",
                     kind="vulnerability", app="ms-ds-smb", fz="vpn", tz="trust")
    for k in range(6):
        s.session(_utc(26, 3, 40) + timedelta(minutes=4 * k), pool, dc, 389, svc="ldap", ob=rng.randint(4_000, 9_000),
                  rb=rng.randint(2_000_000, 9_000_000), dur=rng.uniform(5, 40), app="ldap", fz="vpn", tz="trust",
                  rule="ra-vpn-users")
    for k in range(3):
        s.session(_utc(26, 4, 15) + timedelta(seconds=40 * k), pool, mes, 3389, svc="rdp", ob=rng.randint(2_000, 4_000),
                  rb=rng.randint(3_000, 6_000), dur=rng.uniform(2, 6), app="ms-rdp", fz="vpn", tz="trust",
                  rule="ra-vpn-users")
    for day_start, day_stop, mb in ((_utc(26, 3, 30), _utc(26, 6, 50), (15, 60)), (_utc(27, 1, 15), _utc(27, 4, 20), (10, 45))):
        t = day_start
        while t < day_stop:
            s.session(t, pool, fs, 445, svc="smb", ob=rng.randint(20_000, 90_000), rb=int(rng.uniform(*mb) * 1e6),
                      dur=rng.uniform(60, 400), app="ms-ds-smb", fz="vpn", tz="trust", rule="ra-vpn-users")
            t += timedelta(minutes=rng.uniform(7, 14))
    return s


def _corvane_austin():
    s, vpn, srv, ws, printers = _corvane_site(
        "corvane_austin", "10.32", "aus", "4232", (13, 23), "A", "Quarterly scan - Austin design center", 30,
        [("aus-fs01", 20, WS2019), ("git01", 25, UBUNTU), ("build01", 26, "Ubuntu 20.04"), ("lic01", 27, UBUNTU)])
    rng = s.rng
    fs, git, build, lic = srv["aus-fs01"], srv["git01"], srv["build01"], srv["lic01"]
    eng = _workstations(s, "10.32.20", 21, [("aus-eng", 20)], os_pick=lambda i: UBUNTU)
    _office(s, ws, [C_DC1, C_DC2], [fs], [(git, 443, "ssl"), (C_ERP, 443, "ssl")], printers)
    for e in eng:                                       # engineers: code, builds, licenses
        for _ in range(rng.randint(6, 10)):
            port, svc = rng.choice([(22, "ssh"), (443, "ssl")])
            s.session(s.work_ts(), e, git, port, svc=svc, ob=rng.randint(2_000, 900_000), rb=rng.randint(20_000, 30_000_000))
        for _ in range(rng.randint(2, 4)):
            s.session(s.work_ts(), e, build, 8080, svc="http", rb=rng.randint(10_000, 2_000_000))
        for _ in range(rng.randint(2, 4)):
            s.session(s.work_ts(), e, lic, 27000, ob=400, rb=900)
    for _ in range(70):                                 # CI fetches code and packages
        t = s.work_ts()
        s.session(t, build, git, 443, svc="ssl", rb=rng.randint(1_000_000, 60_000_000))
        if rng.random() < 0.3:
            goot._out(s, t + timedelta(seconds=30), build, "198.18.30.10", 443, "ssl", rb=rng.randint(2_000_000, 80_000_000))
    _vpn_users(s, vpn, "10.32.250", [(git, 443, "ssl"), (fs, 445, "smb"), (C_DC1, 389, "ldap")], 2)
    _windows(s, [fs], ws)
    s.vuln(fs, 445, "cifs", "spooler")
    s.vuln(git, 443, "www", "gitlab")
    s.vuln(build, 8080, "www", "jenkins")
    s.vuln(build, 22, "ssh", "regresshion")
    for ip in [git, lic] + eng[::4]:
        s.vuln(ip, 22, "ssh", "terrapin")
    # the agent: VPN, a scan, SSH to the build server, code from GitLab, tools from the staging server
    pool = "10.32.250.41"
    _agent_vpn(s, vpn, [(_utc(26, 4, 55), _utc(26, 8, 10), 25, 1_500), (_utc(27, 6, 30), _utc(27, 7, 25), 4, 640)])
    servers = list(srv.values())
    _agent_scan(s, pool, _utc(26, 5, 0), servers + eng, (22, 80, 443, 445, 3389, 5432, 8080),
                lambda d: {22} | ({443} if d == git else {8080} if d == build else {445, 3389} if d == fs else set()))
    for k, ts in enumerate(_bursts(rng, _utc(26, 5, 12), 24, size=(6, 12), gap=(0.4, 1.5), pause=(20, 60))):
        s.session(ts, pool, build, 8080, svc="http", ob=rng.randint(600, 2_000), rb=rng.randint(2_000, 60_000),
                  dur=rng.uniform(0.1, 1), app="jenkins", fz="vpn", tz="trust", rule="ra-vpn-users")
        if k == 3:                                      # the Jenkins CLI reads files: keys and credentials
            s.threat(ts + timedelta(seconds=1), pool, build, 8080,
                     "Jenkins Arbitrary File Read Vulnerability (CVE-2024-23897)", "critical", kind="vulnerability",
                     app="jenkins", fz="vpn", tz="trust")
    for k in range(9):
        s.session(_utc(26, 5, 20) + timedelta(minutes=7 * k), pool, build, 22, svc="ssh", ob=rng.randint(20_000, 90_000),
                  rb=rng.randint(60_000_000, 180_000_000) if k > 1 else rng.randint(4_000, 30_000),
                  dur=rng.uniform(60, 400), app="ssh", fz="vpn", tz="trust", rule="ra-vpn-users")
    for k in range(12):
        s.session(_utc(26, 5, 25) + timedelta(minutes=6 * k), build, git, 443, svc="ssl", ob=rng.randint(4_000, 12_000),
                  rb=rng.randint(40_000_000, 120_000_000), dur=rng.uniform(30, 240))
    for t in (_utc(26, 5, 41), _utc(26, 6, 2)):                 # tools from the staging server
        goot._out(s, t, build, EGRESS, 443, "ssl", ob=rng.randint(1_000, 3_000), rb=rng.randint(4_000_000, 12_000_000),
                  dur=rng.uniform(5, 20))
    for k in range(8):                                  # day 2: straight to GitLab over the VPN
        s.session(_utc(27, 6, 33) + timedelta(minutes=6 * k), pool, git, 443, svc="ssl", ob=rng.randint(5_000, 20_000),
                  rb=rng.randint(40_000_000, 110_000_000), dur=rng.uniform(40, 300), app="ssl", fz="vpn", tz="trust",
                  rule="ra-vpn-users")
    _gootloader_blocked(s, ws[13])
    return s


def _gootloader_blocked(s, ws):
    """A user searching for an agreement template follows a poisoned result to two of the Gootloader
    sites; URL filtering blocks both, so no script arrives."""
    rng = s.rng
    t = _utc(26, 16, 20)
    s.lookup(t - timedelta(seconds=40), ws, "www.bing.com", goot.SEARCH)
    goot._out(s, t - timedelta(seconds=39), ws, goot.SEARCH, 443, "ssl", ob=2400, rb=86_000)
    lure, lure_ip = "nda-template-hub.example", "198.51.100.47"     # fictional poisoned result
    s.lookup(t - timedelta(seconds=5), ws, lure, lure_ip)
    uid, sp = goot._out(s, t, ws, lure_ip, 443, "ssl", ob=3_000, rb=240_000, dur=4.1)
    s.ssl.append(dict(ts=t, uid=uid, s=ws, sp=sp, d=lure_ip, dp=443, sni=lure, ja3="", ja3s=""))
    for name, ip, _https in (goot.GOOT_SITES[4], goot.GOOT_SITES[6]):
        t += timedelta(seconds=rng.uniform(20, 40))
        s.lookup(t, ws, name, ip)
        uid, sp = goot._out(s, t + timedelta(seconds=1), ws, ip, 443, "ssl", state="RSTR", ob=rng.randint(500, 700),
                            rb=rng.randint(60, 120), dur=0.3)
        s.ssl.append(dict(ts=t + timedelta(seconds=1), uid=uid, s=ws, sp=sp, d=ip, dp=443, sni=name, ja3="", ja3s="",
                          established="F"))
        s.threat(t + timedelta(seconds=1), ws, ip, 443, f"URL filtering: malware ({name})", "medium",
                 action="block-url", kind="url")


def _corvane_dresden():
    s, vpn, srv, ws, printers = _corvane_site(
        "corvane_dresden", "10.33", "dre", "4233", (7, 17), "R", "Quarterly scan - Dresden service center", 18,
        [("dre-fs01", 20, WS2019)])
    rng = s.rng
    fs = srv["dre-fs01"]
    _office(s, ws, [C_DC1, C_DC2], [fs], [(C_ERP, 443, "ssl")], printers)
    _vpn_users(s, vpn, "10.33.250", [(fs, 445, "smb"), (C_ERP, 443, "ssl")], 1)
    _windows(s, [fs], ws)
    s.vuln(fs, 445, "cifs", "spooler")
    for start, tries in ((_utc(26, 5, 30), 26), (_utc(27, 2, 10), 8)):   # the group password was changed here
        for ts in _bursts(rng, start, tries, size=(3, 6), gap=(1, 4), pause=(30, 120)):
            s.session(ts, EGRESS, vpn, 500, proto="udp", app="ike", fz="untrust", tz="dmz", ob=rng.randint(600, 1_200),
                      rb=rng.randint(300, 700), dur=rng.uniform(0.2, 0.8), rule="allow-vpn-gateway")
    return s


# -- writing -------------------------------------------------------------------------------------

ZONE_RULES = {("trust", "untrust"): "allow-internet", ("untrust", "dmz"): "allow-dmz-inbound",
              ("dmz", "untrust"): "allow-dmz-outbound", ("vpn", "trust"): "ra-vpn-users",
              ("trust", "dmz"): "allow-admin-dmz"}


def _rule(r):
    if r.get("rule"):
        return r["rule"]
    if r["action"] not in ("allow", "alert", "block-url"):
        return "default-deny"
    return ZONE_RULES.get((r["fz"], r["tz"]), f"allow-{r['tz']}")


def _write(s: Site, outdir: str, iocs: list[list]) -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    rng = s.rng
    paths = []
    by_ts = lambda r: (r["ts"], r.get("uid", ""))

    def zeek(name, fields, types, rows):
        p = os.path.join(outdir, f"{name}.log")
        goot._zeek(p, name, fields, types, rows)
        paths.append(p)

    zeek("conn", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
                  "orig_bytes", "resp_bytes", "conn_state", "history"],
         ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count", "string",
          "string"],
         ([goot._ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), r["proto"], r["svc"],
           f"{r['dur']:.3f}", str(r["ob"]), str(r["rb"]), r["state"],
           {"SF": "ShADadFf", "REJ": "Sr", "S0": "S", "RSTR": "ShADr"}.get(r["state"], "S")]
          for r in sorted(s.conn, key=by_ts)))
    if s.dns:
        zeek("dns", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name",
                     "rcode_name", "answers"],
             ["time", "string", "addr", "port", "addr", "port", "enum", "string", "string", "string", "vector[string]"],
             ([goot._ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], "53", "udp", r["q"], "A", "NOERROR", r["a"]]
              for r in sorted(s.dns, key=by_ts)))
    if s.ssl:
        zeek("ssl", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "server_name",
                     "established", "ja3", "ja3s"],
             ["time", "string", "addr", "port", "addr", "port", "string", "string", "bool", "string", "string"],
             ([goot._ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), "TLSv12", r["sni"] or "-",
               r.get("established", "T"), r["ja3"] or "-", r["ja3s"] or "-"] for r in sorted(s.ssl, key=by_ts)))
    if s.files:
        zeek("files", ["ts", "fuid", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "source", "analyzers",
                       "mime_type", "filename", "is_orig", "seen_bytes", "md5", "sha1", "sha256"],
             ["time", "string", "string", "addr", "port", "addr", "port", "string", "set[string]", "string", "string",
              "bool", "count", "string", "string", "string"],
             ([goot._ts(r["ts"]), f"F{s.prefix}{i:07x}", r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), "SMB",
               "MD5,SHA1,SHA256" if r["md5"] else "(empty)", r["mime"], r["name"], "T", str(r["size"]),
               r["md5"] or "-", r["sha1"] or "-", r["sha256"] or "-"] for i, r in enumerate(sorted(s.files, key=by_ts))))
    if s.eve:
        p = os.path.join(outdir, "suricata_eve.json")
        with open(p, "w") as fh:
            for i, r in enumerate(sorted(s.eve, key=lambda r: (r["ts"], r["sid"]))):
                ev = {"timestamp": r["ts"].strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000", "flow_id": 2_000_000 + i,
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
        rows = [("TRAFFIC", r) for r in s.pan] + [("THREAT", r) for r in s.threats]
        for kind, r in sorted(rows, key=lambda x: (x[1]["ts"], x[0], x[1]["s"], x[1]["d"], x[1]["dp"])):
            ts = r["ts"].strftime("%Y/%m/%d %H:%M:%S")
            if kind == "THREAT":
                w.writerow([ts, s.serial, "THREAT", r["kind"], r["s"], r["d"], _rule(r), r["app"], r["fz"],
                            r["tz"], rng.randint(49152, 65535), r["dp"], "tcp", r["action"], "", "", "", ts, r["name"],
                            r["sev"]])
                continue
            w.writerow([ts, s.serial, "TRAFFIC", "end", r["s"], r["d"], _rule(r), r["app"], r["fz"], r["tz"], r["sp"],
                        r["dp"], r["proto"], r["action"], r["sent"] + r["rcvd"], r["sent"], r["rcvd"], ts, "", ""])
    paths.append(p)

    p = os.path.join(outdir, f"{s.folder.split('_', 1)[1]}_scan.nessus")
    _nessus(s, p)
    paths.append(p)

    p = os.path.join(outdir, "ioc_indicators.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(goot.IOC_HEADER)
        w.writerows(iocs)
    paths.append(p)

    p = os.path.join(outdir, "article_previews.json")
    with open(p, "w") as fh:
        json.dump({**goot.PREVIEW, **PREVIEW}, fh, indent=2)
        fh.write("\n")
    paths.append(p)
    return paths


def ioc_rows() -> list[list]:
    """One feed for every client: The DFIR Report's Gootloader indicators and Unit 42's two Cairn addresses."""
    seen = "2026-11-12T00:00:00.000Z"
    cairn = [["ip", ip, "Actionable", why, "cl-sta-1238;cairn", seen, seen, 1, "unit42.paloaltonetworks.com",
              UNIT42_URL, "ioc-table", ""]
             for ip, why in ((CAIRN_SERVER, "Cairn hosting server (HK, AS979)"),
                             (EGRESS, "Cairn staging server and attack egress (US, AS142036)"))]
    return goot.ioc_rows() + cairn


def _nessus(s: Site, path: str):
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name=s.scan_name)
    scan_start = START - timedelta(days=4, hours=-2)
    for k, (ip, (fqdn, os_name)) in enumerate(s.hosts.items()):
        rh = ET.SubElement(report, "ReportHost", name=ip)
        hp = ET.SubElement(rh, "HostProperties")
        t = scan_start + timedelta(seconds=20 * k)
        for key, val in (("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_name),
                         ("HOST_START_TIMESTAMP", str(int(t.timestamp()))),
                         ("HOST_END_TIMESTAMP", str(int(t.timestamp()) + 180))):
            ET.SubElement(hp, "tag", name=key).text = val
        ET.SubElement(rh, "ReportItem", port="0", svc_name="general", protocol="tcp", severity="0",
                      pluginID="19506", pluginName="Nessus Scan Information", pluginFamily="Settings")
        for v in s.vulns:
            if v[0] != ip:
                continue
            _, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol = v
            it = ET.SubElement(rh, "ReportItem", port=str(port), svc_name=svc, protocol=proto, severity=str(sev),
                               pluginID=pid, pluginName=name, pluginFamily="General")
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


def generate(outdir: str) -> list[str]:
    """Write the six new site folders (Ridgeline's head office is the Gootloader sample)."""
    paths = []
    for s in _ridgeline() + [_corvane_hq(), _corvane_phoenix(), _corvane_austin(), _corvane_dresden()]:
        for r in s.conn + s.pan:              # every generated address must be a real address
            ipaddress.ip_address(r["s"]), ipaddress.ip_address(r["d"])
        # Dresden's folder keeps the feed from before Unit 42 published: only Compare's re-hunt finds the egress node
        paths += _write(s, os.path.join(outdir, s.folder), goot.ioc_rows() if s.folder == "corvane_dresden" else ioc_rows())
    return paths


# -- loading the sites into the upload page --------------------------------------------------------

def load(data_dir: str, again: bool = False, log=print) -> tuple[list[str], str | None]:
    """Analyze every site into its own run in the upload page's data folder, named and with its
    network set, so Compare reports lists them, and save a comparison of all seven there too.
    Returns the run ids and the comparison id; when the seven reports are already there (and not
    ``again``), returns theirs and None without adding a second set."""
    from . import compare, pipeline, runname
    from .web import compare_page
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    have = {r.title: r.key for r in compare.server_reports(data_dir) if r.network in ("Ridgeline", "Corvane")}
    if not again and all(name in have for _, name, _, _ in SITES):
        return [have[name] for _, name, _, _ in SITES], None
    runs = []
    with tempfile.TemporaryDirectory() as tmp:
        goot.generate(os.path.join(tmp, goot.FOLDER))
        generate(os.path.join(tmp, FOLDER))
        for folder, name, network, description in SITES:
            src = os.path.join(tmp, folder if folder == goot.FOLDER else os.path.join(FOLDER, folder))
            run_id = runname.new_run(data_dir, name)
            root = os.path.join(data_dir, run_id)
            shutil.copytree(src, os.path.join(root, "in"))          # like an upload: the inputs stay with the run
            files = [f for f in pipeline.input_files([os.path.join(root, "in")], os.path.join(root, "out"))
                     if os.path.basename(f) != "article_previews.json"]     # passed as the preview cache instead
            log(f"Analyzing {name}…")
            pipeline.run(files, os.path.join(root, "out"), workdir=root,
                         article_preview_cache=os.path.join(root, "in", "article_previews.json"),
                         report=runname.clean(name, description, network))
            runs.append(run_id)
    reports = [r for r in compare.server_reports(data_dir) if r.key in runs]
    cid, out = compare_page.new_comparison(data_dir)
    log("Comparing the seven reports…")
    compare_page.save(out, reports, [], crosscheck=True)
    return runs, cid
