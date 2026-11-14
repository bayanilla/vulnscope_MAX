"""Generate the CyberStrike AI sample: an AI-assisted FortiGate and web-shell intrusion at a fictional
logistics company.

The behaviour follows public reporting on CyberStrikeAI and the FortiGate campaign it was linked to
(Amazon Threat Intelligence, Team Cymru, Cyber and Ramen, Elastic Security Labs, Cisco Talos, Unit 42,
Brandefense). The company ("tallmast.example"), its hosts, users and every internal address are invented,
and so are the times. The four operator addresses are published indicators (212.11.64.250 and
185.196.11.225 from Amazon; 146.190.195.154 and 64.176.48.93 from Team Cymru's CyberStrikeAI server list);
what each one does here is fictional. Proxies and the Tor exit are documentation addresses.

The firewall's SSL-VPN and admin interfaces sit on a DMZ address (172.16.10.1) behind the provider's
router; the Zeek and Suricata sensor watches the DMZ and the core, so it sees traffic to the FortiGate,
the web server and everything the VPN pool does inside.

Data window 2026-11-02 and 11-03 (UTC):
  00:40  Two CyberStrikeAI servers fingerprint the FortiGate's management ports (443, 8443, 10443, 4443)
         and the web server at machine-even intervals.
  01:20  Three 15-minute SSL-VPN login bursts from 212.11.64.250, one attempt every 1.5 s, no jitter.
  04:52  A VPN login with stolen credentials from 185.196.11.225: no exploit, just valid credentials.
  05:01  From the VPN address (10.30.250.23): service discovery (gogo) across the server and user
         subnets, then Nuclei against domain controllers and SMB hosts.
  05:48  Veeam Backup & Replication: CVE-2023-27532 (credential disclosure, 9401), then CVE-2024-40711
         (deserialization, 8000).
  06:30  DCSync against dc01, then pass-the-hash over SMB and WMI to fs01, sql01, erp01, jump01.
  07:10  The backup server sends ~1.8 GB to 185.196.11.225.
  09:00  A second track: Nuclei and sqlmap against the public tracking portal (web01) from 212.11.64.250.
  09:14  The IPS blocks it. The skill set's ban workaround switches to a proxy and a new User-Agent,
         then to a free proxy in the victim's country, then to Tor.
  09:52  Through Tor: an anonymous file upload drops an .aspx page; the CyberStrikeAI WebShell manager
         talks to it (User-Agent "CyberStrikeAI-WebShell/1.0", a 'pass' field, an OSPROBE echo).
  10:02  An implant on web01 calls 212.11.64.250:8443 every 5 seconds with no jitter, then web01
         reaches sql01, dc01 and fs01, which it had never talked to.
  16:00  The implant stops; a 'SystemUpdate' scheduled task restarts it at 06:00 on day 2 for two hours.
"""
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone

from . import sample_kit as kit

FOLDER = "cyberstrike_ai_fortigate_intrusion"
DOMAIN = "tallmast.example"
START = datetime(2026, 11, 2, tzinfo=timezone.utc)
END = START + timedelta(days=2)
T_FP = datetime(2026, 11, 2, 0, 40, tzinfo=timezone.utc)
T_BRUTE = datetime(2026, 11, 2, 1, 20, tzinfo=timezone.utc)
T_VPN = datetime(2026, 11, 2, 4, 52, tzinfo=timezone.utc)
T_DISC = datetime(2026, 11, 2, 5, 1, tzinfo=timezone.utc)
T_VEEAM = datetime(2026, 11, 2, 5, 48, tzinfo=timezone.utc)
T_DCSYNC = datetime(2026, 11, 2, 6, 30, tzinfo=timezone.utc)
T_EXFIL = datetime(2026, 11, 2, 7, 10, tzinfo=timezone.utc)
T_WEB = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)
T_BLOCK = datetime(2026, 11, 2, 9, 14, tzinfo=timezone.utc)
T_SHELL = datetime(2026, 11, 2, 9, 52, tzinfo=timezone.utc)
T_IMPLANT = datetime(2026, 11, 2, 10, 2, tzinfo=timezone.utc)
T_IMPLANT_STOP = datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc)
T_RESTART = datetime(2026, 11, 3, 6, 0, tzinfo=timezone.utc)

SOURCES = {
    "brandefense": ("https://brandefense.io/security-news/cyberstrikeai-attacks-explained/",
                    "CyberStrikeAI attacks explained",
                    "Brandefense explains how the open-source CyberStrikeAI platform, which chains 100+ security "
                    "tools under an LLM agent, was tied to AI-assisted attacks on FortiGate appliances."),
    "elastic": ("https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex",
                "Detecting agentic offensive frameworks: ARTEX and friends",
                "Elastic Security Labs lists CyberStrikeAI's operator console, implant builder and WebShell "
                "manager: User-Agent 'Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)' with a 'pass' field, "
                "an OSPROBE echo, 'SystemUpdate' persistence, five-second check-ins without jitter, and proxy, "
                "User-Agent and Tor fallbacks when blocked."),
    "talos": ("https://blog.talosintelligence.com/artex-and-beyond/",
              "ARTEX and beyond",
              "Cisco Talos saw CyberStrikeAI co-deployed with ARTEX on the same infrastructure, alongside "
              "scanners such as Fscan and C2 such as VShell and AdaptixC2."),
    "unit42": ("https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/",
               "ARTEX and AI-powered red teaming tools",
               "Unit 42 counted 1,323 internet-facing CyberStrikeAI hosts in October 2026 and describes agent "
               "timing such as short request bursts and fast retries."),
    "amazon": ("https://aws.amazon.com/blogs/security/ai-augmented-threat-actor-accesses-fortigate-devices-at-scale/",
               "AI-augmented threat actor accesses FortiGate devices at scale",
               "Amazon Threat Intelligence reports 600+ FortiGate devices in 55 countries reached through "
               "exposed management ports (443, 8443, 10443, 4443) and weak or stolen credentials, followed by "
               "gogo, Nuclei, DCSync, pass-the-hash and attacks on Veeam (CVE-2023-27532, CVE-2024-40711)."),
    "cymru": ("https://www.team-cymru.com/post/tracking-cyberstrikeai-usage",
              "Tracking CyberStrikeAI usage",
              "Team Cymru tied the FortiGate campaign address 212.11.64.250 to a 'CyberStrikeAI' banner on port "
              "8080 and tracked 21 CyberStrikeAI server addresses between January and February 2026."),
}

# -- outside addresses -------------------------------------------------------------------------------
CSAI = "212.11.64.250"           # Amazon + Team Cymru (CyberStrikeAI banner on 8080)
CAMPAIGN = "185.196.11.225"      # Amazon campaign address
FP_A, FP_B = "146.190.195.154", "64.176.48.93"    # Team Cymru CyberStrikeAI servers
OPERATORS = [CSAI, CAMPAIGN, FP_A, FP_B]
PROXY = "198.51.100.201"         # fictional commercial proxy
COUNTRY_PROXY = "203.0.113.45"   # fictional free proxy in the victim's country
TOR_EXIT = "192.0.2.199"         # fictional Tor exit
UPSTREAM_DNS = "192.0.2.53"
SAAS = [("outlook.office365.example", "198.18.10.31"), ("teams.collab.example", "198.18.10.44"),
        ("tms.carrier.example", "198.18.20.12"), ("edi.partner.example", "198.18.20.57"),
        ("updates.vendor.example", "192.0.2.120"), ("fortiguard.example", "192.0.2.130")]
CUSTOMERS = [f"203.0.113.{i}" for i in range(60, 120)] + [f"198.18.50.{i}" for i in range(10, 50)]
HOME_USERS = [f"198.18.60.{i}" for i in range(10, 22)]      # staff connecting to the VPN from home

# -- internal estate ---------------------------------------------------------------------------------
HOSTS: dict[str, tuple[str, str]] = {}
FW, WEB, MAIL = "172.16.10.1", "172.16.10.20", "172.16.10.25"
DC1, DC2, FS, SQL, ERP, BACKUP, WSUS, JUMP = ("10.30.0.10", "10.30.0.11", "10.30.0.20", "10.30.0.30",
                                               "10.30.0.31", "10.30.0.40", "10.30.0.50", "10.30.0.60")
RESOLVER = "10.30.0.53"
VPN_ATTACKER = "10.30.250.23"
VPN_USERS = [f"10.30.250.{i}" for i in range(11, 19)]
for ip, name, os_name in (
        (FW, "fw01", "Fortinet FortiOS 7.2.6"),
        (WEB, "web01", "Microsoft Windows Server 2016 Standard"),
        (MAIL, "mail01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (DC1, "dc01", "Microsoft Windows Server 2019 Standard"),
        (DC2, "dc02", "Microsoft Windows Server 2019 Standard"),
        (FS, "fs01", "Microsoft Windows Server 2019 Standard"),
        (SQL, "sql01", "Microsoft Windows Server 2016 Standard"),
        (ERP, "erp01", "Microsoft Windows Server 2019 Standard"),
        (BACKUP, "backup01", "Microsoft Windows Server 2019 Standard"),
        (WSUS, "wsus01", "Microsoft Windows Server 2019 Standard"),
        (JUMP, "jump01", "Microsoft Windows Server 2022 Standard")):
    HOSTS[ip] = (f"{name}.{DOMAIN}", os_name)
WORKSTATIONS: list[str] = []
_n = 21
for dept, count in (("disp", 18), ("wh", 16), ("fin", 10), ("ops", 12), ("it", 4)):
    for k in range(1, count + 1):
        ip = f"10.30.20.{_n}"
        HOSTS[ip] = (f"{dept}-ws-{k:02}.{DOMAIN}", "Microsoft Windows 11 Enterprise" if _n % 4 else
                     "Microsoft Windows 10 Enterprise")
        WORKSTATIONS.append(ip)
        _n += 1
SCANNERS = [f"10.30.30.{i}" for i in range(10, 18)]           # warehouse handhelds' print/label stations
for ip in SCANNERS:
    HOSTS[ip] = (f"label-{ip.split('.')[-1]}.{DOMAIN}", "Zebra Link-OS")
SERVERS = [DC1, DC2, FS, SQL, ERP, BACKUP, WSUS, JUMP]

UA_WEBSHELL = "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"
UA_SQLMAP = "sqlmap/1.8.4#stable (https://sqlmap.org)"
UA_NUCLEI = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
UA_ROTATE = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
             "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
             "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"]
UA_BROWSERS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
               "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"]

SIG = {
    "fp": ("ET SCAN FortiOS Version Fingerprinting via /remote/fgt_lang", 9300001, "Attempted Information Leak", 2),
    "mgmt": ("ET SCAN Fortinet Management Interface Probe on Non-Standard Ports (8443/10443/4443)", 9300002, "Attempted Information Leak", 3),
    "brute": ("ET SCAN FortiGate SSL-VPN Login Brute Force - Fixed-Interval Attempts", 9300003, "Attempted User Privilege Gain", 2),
    "gogo": ("ET SCAN Internal Service Discovery Sweep (gogo-style) From VPN Pool", 9300004, "Attempted Information Leak", 2),
    "nuclei": ("ET SCAN Nuclei SMB/LDAP Template Probes Against Domain Controller", 9300005, "Attempted Information Leak", 2),
    "veeam1": ("ET EXPLOIT Veeam Backup & Replication Credential Disclosure Attempt (CVE-2023-27532)", 9300006, "Attempted Administrator Privilege Gain", 1),
    "veeam2": ("ET EXPLOIT Veeam Backup & Replication Deserialization RCE Attempt (CVE-2024-40711)", 9300007, "Attempted Administrator Privilege Gain", 1),
    "dcsync": ("ET POLICY DRSUAPI DsGetNCChanges Request From Non-DC (Possible DCSync)", 9300008, "Attempted Administrator Privilege Gain", 1),
    "pth": ("ET POLICY SMB Remote Service Creation via svcctl From VPN Pool (Possible psexec/wmiexec)", 9300009, "Attempted Administrator Privilege Gain", 1),
    "sqlmap": ("ET SCAN Sqlmap SQL Injection Scan", 9300010, "Attempted Information Leak", 2),
    "nucleiweb": ("ET SCAN Nuclei Web Template Scan", 9300011, "Attempted Information Leak", 3),
    "tor": ("ET POLICY Inbound HTTP From Known Tor Exit Node", 9300012, "Misc activity", 3),
    "upload": ("ET WEB_SERVER ASPX File Upload to Anonymous Upload Handler", 9300013, "Web Application Attack", 1),
    "webshell": ("ET WEB_SERVER CyberStrikeAI WebShell User-Agent Inbound", 9300014, "A Network Trojan was detected", 1),
    "osprobe": ("ET WEB_SERVER WebShell OS Probe Marker (:OSPROBE_..:END) in HTTP Response", 9300015, "A Network Trojan was detected", 1),
    "beacon": ("ET MALWARE Possible CyberStrikeAI Implant Check-in - 5 s Fixed Interval TLS", 9300016, "A Network Trojan was detected", 1),
}

V = kit.vuln
VULNS = [
    V(FW, 10443, "www", "190020", "Fortinet FortiOS SSL-VPN Out-of-Bounds Write (CVE-2024-21762)", 4, 9.8,
      ("CVE-2024-21762",), True, True, "The FortiOS SSL-VPN on the remote device is affected by an out-of-bounds "
      "write that allows remote code execution.", "Upgrade FortiOS to 7.2.7 or later.", family="Firewalls"),
    V(FW, 10443, "www", "910201", "SSL-VPN Portal Accepts Single-Factor Logins", 3, 7.5, (), False, False,
      "The SSL-VPN portal authenticates with a password alone.", "Require MFA for every VPN user.",
      family="Firewalls"),
    V(FW, 443, "www", "910202", "FortiOS Administrative Interface Reachable From Untrusted Network", 3, 7.3, (), False,
      False, "The FortiGate administrative GUI answers on its internet-facing interface.",
      "Restrict administrative access to a management network and trusted hosts.", family="Firewalls"),
    V(FW, 8443, "www", "910202", "FortiOS Administrative Interface Reachable From Untrusted Network", 3, 7.3, (), False,
      False, "The FortiGate administrative GUI answers on its internet-facing interface.",
      "Restrict administrative access to a management network and trusted hosts.", family="Firewalls"),
    V(WEB, 80, "www", "910203", "Anonymous File Upload Allowed (Tracking Portal Upload Handler)", 4, 9.8, (), True,
      False, "The upload handler accepts files of any type from unauthenticated users into a web-served folder.",
      "Require authentication, store uploads outside the web root and allow-list file types.", family="CGI abuses"),
    V(WEB, 80, "www", "42479", "CGI Generic SQL Injection (blind)", 3, 8.6, (), True, False,
      "A CGI application hosted on the remote web server is potentially prone to SQL injection.",
      "Modify the affected CGI scripts so that they properly escape arguments.", family="CGI abuses"),
    V(WEB, 0, "general", "910204", "Microsoft IIS 10.0 / Windows Server 2016 Missing Security Updates", 3, 8.1, (),
      False, False, "The web server is missing several monthly security updates.",
      "Apply the latest cumulative update.", family="Windows"),
    V(BACKUP, 9401, "www", "173380", "Veeam Backup & Replication Credential Disclosure (CVE-2023-27532)", 4, 7.5,
      ("CVE-2023-27532",), True, True,
      "The backup service lets an unauthenticated user request encrypted credentials from the configuration database.",
      "Upgrade Veeam Backup & Replication to a fixed build.", family="Windows"),
    V(BACKUP, 8000, "www", "206174", "Veeam Backup & Replication Deserialization RCE (CVE-2024-40711)", 4, 9.8,
      ("CVE-2024-40711",), True, True, "The backup server deserializes untrusted data, allowing remote code execution.",
      "Upgrade Veeam Backup & Replication to 12.2 or later.", family="Windows"),
    V(SQL, 1433, "mssql", "73756", "Microsoft SQL Server Unsupported Version Detection", 4, 10.0, (), False, False,
      "The installed version of SQL Server is no longer supported.", "Upgrade to a supported version of SQL Server.",
      family="Databases"),
]
for dc in (DC1, DC2):
    VULNS += [V(dc, 389, "ldap", "191001", "Active Directory LDAP Signing and Channel Binding Not Required", 2, 5.9,
                (), False, False, "The domain controller accepts unsigned LDAP binds.",
                "Require LDAP signing and channel binding.", family="Windows"),
              V(dc, 5355, "llmnr", "53513", "Link-Local Multicast Name Resolution (LLMNR) Detection", 1, 0.0, (),
                False, False, "LLMNR is enabled, which allows name-resolution poisoning.", "Disable LLMNR.",
                family="Service detection", proto="udp")]
for ip in (FS, SQL, ERP, BACKUP, WSUS, JUMP) + tuple(WORKSTATIONS):
    VULNS.append(V(ip, 445, "cifs", "57608", "SMB Signing not required", 2, 5.3, (), False, False,
                   "Signing is not required on the remote SMB server.",
                   "Enforce message signing in the host's configuration.", family="Misc."))


def _background(log: kit.Log, rng):
    span = (END - START).total_seconds()

    def work_ts():
        while True:                            # Tallmast works 06:00-18:00 US Central (12:00-24:00 UTC)
            t = START + timedelta(seconds=rng.uniform(0, span))
            if 12 <= t.hour or rng.random() < 0.15:
                return t

    for ws in WORKSTATIONS:
        for _ in range(rng.randint(6, 10)):
            log.session(work_ts(), ws, rng.choice([DC1, DC2]), 88, svc="krb", ob=rng.randint(1200, 1800))
        for _ in range(rng.randint(3, 6)):
            log.session(work_ts(), ws, rng.choice([DC1, DC2]), 389, svc="ldap")
        for _ in range(rng.randint(4, 8)):
            log.session(work_ts(), ws, FS, 445, svc="smb", rb=rng.randint(20_000, 2_000_000))
        for _ in range(rng.randint(2, 5)):
            log.session(work_ts(), ws, ERP, 443, svc="ssl", rb=rng.randint(20_000, 900_000))
        for _ in range(rng.randint(5, 9)):
            name, ip = rng.choice(SAAS)
            t = work_ts()
            if rng.random() < 0.3:
                log.lookup(t - timedelta(seconds=1), ws, name, ip)
            log.tls(t, ws, ip, 443, sni=name, log_ssl=rng.random() < 0.3)
    for st in SCANNERS:
        for _ in range(8):
            log.session(work_ts(), st, ERP, 9100, ob=200, rb=rng.randint(5_000, 60_000))
    for _ in range(700):                              # customers track shipments
        t = work_ts()
        log.web(t, rng.choice(CUSTOMERS), WEB, 80, "GET", "track.tallmast.example",
                rng.choice(["/", f"/track.aspx?id=TM{rng.randint(1000000, 9999999)}", "/css/site.css",
                            "/js/track.js", "/contact.aspx"]), rng.choice(UA_BROWSERS), 200,
                rb=rng.randint(2_000, 60_000))
    for _ in range(60):                               # the tracking portal reads the ERP API
        log.session(work_ts(), WEB, ERP, 443, svc="ssl", rb=rng.randint(4_000, 200_000))
    # staff on the VPN: home address -> FortiGate, then the VPN address works inside
    for k, vip in enumerate(VPN_USERS):
        home = HOME_USERS[k]
        for day in (0, 1):
            t = START + timedelta(days=day, hours=rng.uniform(13, 16))
            dur = rng.uniform(3, 6) * 3600
            log.tls(t, home, FW, 10443, ob=rng.randint(20_000_000, 90_000_000), rb=rng.randint(60_000_000, 300_000_000),
                    dur=dur, log_ssl=day == 0)
            for _ in range(rng.randint(8, 16)):
                ts = t + timedelta(seconds=rng.uniform(60, dur))
                log.session(ts, vip, rng.choice([FS, ERP, DC1]), rng.choice([445, 443, 389]),
                            rb=rng.randint(10_000, 4_000_000))
    for t in (START + timedelta(hours=h, minutes=rng.randint(0, 59)) for h in range(48)):
        log.session(t, RESOLVER, UPSTREAM_DNS, 53, svc="dns", proto="udp", ob=rng.randint(60, 90),
                    rb=rng.randint(90, 300))
    for k in range(6):
        log.session(START + timedelta(hours=4 + 8 * k), WSUS, "192.0.2.120", 80, svc="http",
                    rb=rng.randint(2_000_000, 40_000_000))
        log.tls(START + timedelta(hours=5 + 8 * k), FW, "192.0.2.130", 443, sni="fortiguard.example", log_ssl=False)
    for _ in range(30):
        log.session(work_ts(), JUMP, rng.choice(SERVERS), rng.choice([3389, 5985, 445]), rb=rng.randint(10_000, 900_000))
    for _ in range(24):                               # nightly backups
        log.session(START + timedelta(hours=rng.choice([2, 3, 26, 27]), minutes=rng.randint(0, 59)), BACKUP,
                    rng.choice([FS, SQL, ERP, DC1]), 445, svc="smb", ob=4000, rb=rng.randint(50_000_000, 400_000_000),
                    dur=rng.uniform(300, 1800))


def _edge(log, rng):
    """Fingerprinting and the SSL-VPN login bursts."""
    t = T_FP
    for src, offset in ((FP_A, 0), (FP_B, 31)):
        ts = t + timedelta(minutes=offset)
        for k, port in enumerate((443, 8443, 10443, 4443, 443, 10443, 8443, 4443) * 3):
            state = "SF" if port in (443, 8443, 10443) else "REJ"
            log.tls(ts + timedelta(seconds=2 * k), src, FW, port, ob=rng.randint(500, 900) if state == "SF" else 0,
                    rb=rng.randint(1_500, 6_000) if state == "SF" else 0, dur=0.3 if state == "SF" else 0.001,
                    log_ssl=state == "SF" and k < 4, state=state)
        for k, uri in enumerate(("/", "/aspnet_client/", "/web.config", "/track.aspx?id=1", "/admin/", "/upload/")):
            log.web(ts + timedelta(seconds=50 + 2 * k), src, WEB, 80, "GET", "track.tallmast.example", uri, UA_NUCLEI,
                    200 if k in (0, 3) else (403 if k in (2, 4) else 404))
        log.alert(ts + timedelta(seconds=6), src, FW, 10443, *SIG["fp"], app="tls")
        log.alert(ts + timedelta(seconds=8), src, FW, 8443, *SIG["mgmt"], app="tls")
    # three 15-minute bursts, one attempt every 1.5 s, no jitter
    n = 0
    for b, start in enumerate((T_BRUTE, T_BRUTE + timedelta(minutes=45), T_BRUTE + timedelta(minutes=90))):
        ts = start
        while ts < start + timedelta(minutes=15):
            log.tls(ts, CSAI, FW, 10443, ob=rng.randint(1_100, 1_300), rb=rng.randint(1_900, 2_100), dur=0.4,
                    log_ssl=n % 120 == 0)
            n += 1
            ts += timedelta(seconds=1.5)
        log.alert(start + timedelta(seconds=30), CSAI, FW, 10443, *SIG["brute"], app="tls")
        log.note(start + timedelta(minutes=15), CSAI, FW, 10443, "SSL::Fixed_Interval_Short_Sessions",
                 "212.11.64.250 opened 600 short TLS sessions to the SSL-VPN in 15 min at exactly 1.5 s "
                 "(consistent with sslvpn-login-fail on the FortiGate)")
    # the real way in: stolen credentials, one long tunnel
    log.tls(T_VPN, CAMPAIGN, FW, 10443, ob=310_000_000, rb=95_000_000, dur=4.2 * 3600, log_ssl=True)


def _inside(log, rng):
    """What the VPN address does once the tunnel is up."""
    a = VPN_ATTACKER
    # gogo: servers subnet on 13 ports, user subnet on 3
    t = T_DISC
    live_srv = set(SERVERS) | {RESOLVER}
    k = 0
    for last in range(1, 81):
        d = f"10.30.0.{last}"
        for port in (21, 22, 80, 135, 139, 443, 445, 1433, 3389, 5985, 8000, 9401, 9392):
            open_ = d in live_srv and (port in (135, 139, 445, 3389, 5985) or
                                       (d == SQL and port == 1433) or (d == BACKUP and port in (8000, 9401, 9392)) or
                                       (d in (ERP, WSUS) and port in (80, 443)))
            log.session(t + timedelta(seconds=k * 0.02), a, d, port, state="SF" if open_ else "REJ",
                        ob=60 if open_ else 0, rb=120 if open_ else 0, dur=0.01)
            k += 1
    t2 = t + timedelta(minutes=4)
    for k, d in enumerate(WORKSTATIONS + SCANNERS):
        for j, port in enumerate((135, 445, 3389)):
            open_ = d in WORKSTATIONS and port in (135, 445)
            log.session(t2 + timedelta(seconds=k * 0.3 + j * 0.05), a, d, port, state="SF" if open_ else "REJ",
                        ob=60 if open_ else 0, rb=120 if open_ else 0, dur=0.01)
    log.alert(t + timedelta(seconds=10), a, DC1, 445, *SIG["gogo"], app="")
    # Nuclei against the DCs and SMB hosts
    t = T_DISC + timedelta(minutes=24)
    for k, ts in enumerate(kit.bursts(rng, t, 160, per=(6, 30), pause=(3, 20))):
        d = (DC1, DC2, FS, SQL, ERP)[k % 5]
        port = (445, 389, 88, 445, 135)[k % 5] if d in (DC1, DC2) else 445
        log.session(ts, a, d, port, ob=rng.randint(200, 1_200), rb=rng.randint(200, 2_000), dur=0.05)
    log.alert(t + timedelta(seconds=20), a, DC1, 389, *SIG["nuclei"], app="")
    log.alert(t + timedelta(seconds=40), a, DC2, 445, *SIG["nuclei"], app="smb")
    # Veeam
    t = T_VEEAM
    for k in range(4):
        log.session(t + timedelta(seconds=k * 7), a, BACKUP, 9401, ob=rng.randint(800, 2_000), rb=rng.randint(2_000, 12_000))
    log.alert(t + timedelta(seconds=1), a, BACKUP, 9401, *SIG["veeam1"], app="")
    t += timedelta(minutes=14)
    for k in range(3):
        log.session(t + timedelta(seconds=k * 9), a, BACKUP, 8000, ob=rng.randint(4_000, 9_000), rb=rng.randint(500, 2_000))
    log.alert(t + timedelta(seconds=1), a, BACKUP, 8000, *SIG["veeam2"], app="")
    for k in range(6):                                 # the operator works on the backup server
        log.session(t + timedelta(minutes=2 + k * 3), a, BACKUP, 3389 if k % 2 else 5985, svc="rdp" if k % 2 else "http",
                    ob=rng.randint(100_000, 600_000), rb=rng.randint(500_000, 6_000_000), dur=rng.uniform(60, 400))
    # DCSync, then pass-the-hash
    t = T_DCSYNC
    log.session(t, a, DC1, 135, svc="dce_rpc", ob=1_200, rb=900, dur=0.1)
    log.session(t + timedelta(seconds=1), a, DC1, 49668, svc="dce_rpc", ob=52_000, rb=4_100_000, dur=16)
    log.alert(t + timedelta(seconds=2), a, DC1, 49668, *SIG["dcsync"], app="dcerpc")
    t += timedelta(minutes=15)
    for k, d in enumerate((FS, SQL, ERP, JUMP)):
        ts = t + timedelta(seconds=k * rng.uniform(15, 40))
        log.session(ts, a, d, 445, svc="smb,dce_rpc", ob=rng.randint(8_000, 30_000), rb=rng.randint(4_000, 20_000))
        log.session(ts + timedelta(seconds=2), a, d, 135, svc="dce_rpc", ob=900, rb=700)
        log.alert(ts + timedelta(seconds=1), a, d, 445, *SIG["pth"], app="smb")
    # the backup server sends its credential store and configs out
    for k, size in enumerate((900_000_000, 620_000_000, 310_000_000)):
        log.tls(T_EXFIL + timedelta(minutes=k * 7), BACKUP, CAMPAIGN, 443, ob=size, rb=rng.randint(40_000, 90_000),
                dur=rng.uniform(300, 480), log_ssl=k == 0)


def _web(log, rng):
    host = "track.tallmast.example"
    t = T_WEB
    for k, ts in enumerate(kit.bursts(rng, t, 120, per=(5, 25), pause=(3, 15))):
        log.web(ts, CSAI, WEB, 80, "GET", host, rng.choice(
            ["/.env", "/web.config.bak", "/aspnet_client/", "/elmah.axd", "/trace.axd", "/upload/upload.aspx",
             "/tracking/upload.aspx", "/api/swagger", "/backup.zip", "/admin/login.aspx"]), UA_NUCLEI,
            rng.choice([404, 404, 404, 403, 200]))
    log.alert(t + timedelta(seconds=5), CSAI, WEB, 80, *SIG["nucleiweb"], app="http")
    t = T_WEB + timedelta(minutes=7)
    for k, ts in enumerate(kit.bursts(rng, t, 260, per=(8, 30), pause=(2, 8))):
        if ts >= T_BLOCK:
            break
        log.web(ts, CSAI, WEB, 80, "GET", host, f"/track.aspx?id=TM{rng.randint(1000000, 9999999)}"
                + rng.choice(["%27", "%27%20AND%201%3D1--", "%22", "%29%20OR%20SLEEP%285%29--", ""]),
                UA_SQLMAP, rng.choice([200, 500, 200]))
    log.alert(t + timedelta(seconds=3), CSAI, WEB, 80, *SIG["sqlmap"], app="http")
    # the IPS blocks; the ban-workaround skill rotates source and User-Agent each time
    steps = ((CSAI, UA_SQLMAP, T_BLOCK, T_BLOCK + timedelta(seconds=40)),
             (PROXY, UA_ROTATE[0], T_BLOCK + timedelta(seconds=40), T_BLOCK + timedelta(minutes=17)),
             (COUNTRY_PROXY, UA_ROTATE[1], T_BLOCK + timedelta(minutes=18), T_BLOCK + timedelta(minutes=30)),
             (TOR_EXIT, UA_ROTATE[2], T_BLOCK + timedelta(minutes=31), T_SHELL))
    for i, (src, ua, a, b) in enumerate(steps):
        if i == 0:
            for k in range(8):
                ts = a + timedelta(seconds=k * 4)
                log.session(ts, src, WEB, 80, state="REJ", ob=0, rb=0)
                log.alert(ts, src, WEB, 80, *SIG["sqlmap"], app="http", blocked=True)
            continue
        ts = a
        hits = 0
        while ts < b:
            log.web(ts, src, WEB, 80, "GET", host, f"/track.aspx?id=TM{rng.randint(1000000, 9999999)}"
                    + rng.choice(["%27", "%29%20OR%20SLEEP%285%29--", ""]), ua, rng.choice([200, 500]))
            hits += 1
            ts += timedelta(seconds=rng.uniform(1.5, 6))
        if src != TOR_EXIT:
            log.alert(b - timedelta(seconds=30), src, WEB, 80, *SIG["sqlmap"], app="http", blocked=True)
            for k in range(3):
                log.session(b - timedelta(seconds=20 - k * 5), src, WEB, 80, state="REJ", ob=0, rb=0)
        else:
            log.alert(a + timedelta(seconds=2), src, WEB, 80, *SIG["tor"], app="http")
    # the upload and the web shell, through Tor
    t = T_SHELL
    log.web(t, TOR_EXIT, WEB, 80, "GET", host, "/tracking/upload.aspx", UA_ROTATE[2], 200)
    log.web(t + timedelta(seconds=6), TOR_EXIT, WEB, 80, "POST", host, "/tracking/upload.aspx", UA_ROTATE[2], 200,
            ob=rng.randint(3_000, 5_000), rb=180)
    log.alert(t + timedelta(seconds=7), TOR_EXIT, WEB, 80, *SIG["upload"], app="http")
    t += timedelta(seconds=30)
    for k in range(18):
        ts = t + timedelta(seconds=k * rng.uniform(2, 9))
        log.web(ts, TOR_EXIT, WEB, 80, "POST", host, "/uploads/SystemUpdate.aspx", UA_WEBSHELL, 200,
                ob=rng.randint(300, 900), rb=rng.randint(40, 4_000))
    log.alert(t, TOR_EXIT, WEB, 80, *SIG["webshell"], app="http")
    log.alert(t + timedelta(seconds=1), WEB, TOR_EXIT, 80, *SIG["osprobe"], app="http")
    log.note(t + timedelta(seconds=2), TOR_EXIT, WEB, 80, "HTTP::Webshell_UA",
             "POST /uploads/SystemUpdate.aspx with User-Agent CyberStrikeAI-WebShell/1.0 and form field 'pass'; "
             "response contains :OSPROBE_WINDOWS:END")
    # implant: every 5 s, no jitter
    first = True
    for start, stop in ((T_IMPLANT, T_IMPLANT_STOP), (T_RESTART, T_RESTART + timedelta(hours=2))):
        ts = start
        n = 0
        while ts < stop:
            log.tls(ts, WEB, CSAI, 8443, ob=rng.randint(220, 260), rb=rng.randint(90, 140), dur=0.08,
                    log_ssl=n % 240 == 0)
            if n == 0:
                log.alert(ts + timedelta(seconds=30), WEB, CSAI, 8443, *SIG["beacon"], app="tls")
            n += 1
            ts += timedelta(seconds=5)
        if first:
            log.note(start + timedelta(minutes=10), WEB, CSAI, 8443, "SSL::Fixed_Interval_Beacon",
                     "172.16.10.20 contacted 212.11.64.250:8443 120 times in 10 min at exactly 5.0 s (no jitter)")
            first = False
    # web01 reaches inside for the first time
    t = T_IMPLANT + timedelta(minutes=18)
    for k, (d, port, svc) in enumerate(((SQL, 1433, "-"), (DC1, 389, "ldap"), (DC1, 88, "krb"), (FS, 445, "smb"),
                                        (SQL, 445, "smb"))):
        for j in range(rng.randint(2, 5)):
            log.session(t + timedelta(seconds=k * 20 + j * 3), WEB, d, port, svc=svc, rb=rng.randint(2_000, 900_000))


def ioc_rows() -> list[list]:
    seen = "2026-11-05T00:00:00.000Z"
    amazon, cymru = SOURCES["amazon"][0], SOURCES["cymru"][0]
    brand = SOURCES["brandefense"][0]
    rows = [
        ["ip", CSAI, "Actionable", "FortiGate campaign address; CyberStrikeAI banner on 8080 (Amazon, Team Cymru)",
         "cyberstrikeai;fortigate", seen, seen, 1, "aws.amazon.com;team-cymru.com", f"{amazon};{cymru};{brand}",
         "ioc-table", ""],
        ["ip", CAMPAIGN, "Actionable", "FortiGate campaign address (Amazon)", "cyberstrikeai;fortigate", seen, seen, 1,
         "aws.amazon.com", f"{amazon};{brand}", "ioc-table", ""],
        ["ip", FP_A, "Actionable", "CyberStrikeAI server (Team Cymru)", "cyberstrikeai", seen, seen, 1,
         "team-cymru.com", cymru, "ioc-table", ""],
        ["ip", FP_B, "Actionable", "CyberStrikeAI server (Team Cymru)", "cyberstrikeai", seen, seen, 1,
         "team-cymru.com", cymru, "ioc-table", ""],
        ["cve", "CVE-2023-27532", "Actionable", "Veeam credential disclosure used in the campaign (Amazon)",
         "cyberstrikeai;veeam", seen, seen, 1, "aws.amazon.com", amazon, "article-text", ""],
        ["cve", "CVE-2024-40711", "Actionable", "Veeam deserialization RCE used in the campaign (Amazon)",
         "cyberstrikeai;veeam", seen, seen, 1, "aws.amazon.com", amazon, "article-text", ""],
    ]
    return rows


def generate(outdir: str, seed: int = 1102) -> list[str]:
    """Write the CyberStrike AI sample folder."""
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(seed)
    log = kit.Log(rng, RESOLVER, prefix="S")
    _background(log, rng)
    _edge(log, rng)
    _inside(log, rng)
    _web(log, rng)
    kit.check_addresses(log)
    paths = kit.write_zeek(outdir, log, START, END)
    paths.append(kit.write_eve(os.path.join(outdir, "suricata_eve.json"), log, rng))
    paths.append(kit.write_nessus(os.path.join(outdir, "tallmast_scan.nessus"), "Tallmast quarterly scan", HOSTS,
                                  VULNS, START - timedelta(days=4, hours=-3)))
    paths.append(kit.write_iocs(os.path.join(outdir, "ioc_indicators.csv"), ioc_rows()))
    paths.append(kit.write_previews(os.path.join(outdir, "article_previews.json"),
                                    {url: {"title": title, "overview": text} for url, title, text in SOURCES.values()}))
    return paths
