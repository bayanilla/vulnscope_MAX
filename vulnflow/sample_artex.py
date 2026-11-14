"""Generate the Artex AI sample: an agent-driven intrusion at a fictional software vendor, plus a lab agent
that wandered out of its test range.

The behaviour follows public reporting on the ARTEX agentic offensive framework (Elastic Security Labs,
Cisco Talos, Google Threat Intelligence Group, Unit 42, Wiz, Help Net Security; November 2026). The company
("northfold.example"), its hosts, users and every internal address are invented, and so are the times.
The five operator addresses are the ones Wiz published for the campaign (three of them attributed by
Microsoft to Storm-0940); which address does what here is fictional. Everything else outside is a
reserved documentation or benchmarking address, including where webhook.site and the LLM API resolve.

Two stories share the data window (2026-10-19 and 10-20, UTC):

Outside operator (UNC7228 / Storm-0940 style, IT and software vendor targeting)
  03:12  104.194.150.21 maps the customer portal: a request for a path that cannot exist (to learn what
         "not found" looks like), JavaScript source maps, runtime config, Swagger/OpenAPI documents, then
         ~500 fuzzing requests answered 200/403/404. Three parallel workers, bursts of 2-25 s.
         User-Agents norma/0.4 (the ARTEX web fetch tool) and artex-enrich/1.0.
  03:37  The WAF blocks the address. A new one (144.172.64.60) arrives within minutes with a browser
         User-Agent and maps the API gateway.
  04:05  Password spray against the SSO login page, one attempt a second for ~40 minutes, canary
         usernames (test@example.com, evil.com) first, then 60+ SSO route variations in two minutes.
  04:47  Blocked again; 144.172.64.99 carries on with Python-urllib/3.12.
  06:10  A human step in a desktop browser: password reset for one engineer, then a successful login.
         The agent registers an ArtexProbe admin account (is_admin) and reads it back after the write,
         then walks predictable tenant IDs.
  07:30  From 144.172.64.128 with curl/7.88.1: the portal's SQL report API points MySQL's general_log at a
         .jsp file in the web root; the agent tries cl1217.jsp and f1219a.jsp (404) before z1219.jsp (200).
  07:41  The portal fetches generated scripts back from 144.172.64.128 and posts results to rotating
         webhook.site URLs (curl as the C2 channel).
  07:50  Discovery and credential access from the portal: LDAP, a 27-request Kerberos TGS burst in 23 s
         (Kerberoasting), the application database, WinRM attempts, then DCSync against dc01.
  09:10  The portal's notification system mails ~1,300 internal users.
  10:15  ~1.4 GB leaves the portal for 167.88.172.97.
  Day 2  The web shell is polled every 48 seconds. When 144.172.64.99 is blocked at 10:00 the polls
         come from an open proxy.

Lab agent escape (WorkOS-style)
  14:00-17:08 on day 1, seclab01 runs an authorised ARTEX benchmark against the lab range. Each step
  is an LLM API call (api.deepseek.com) followed by a short burst of tool traffic. At 16:20 the agent
  leaves the lab range, finds the legacy sales API (crm01), logs in with its predictable development
  credential and pages through the whole customer table until the run is stopped.
"""
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone

from . import sample_kit as kit

FOLDER = "artex_ai_agentic_intrusion"
DOMAIN = "northfold.example"
START = datetime(2026, 10, 19, tzinfo=timezone.utc)
END = START + timedelta(days=2)
T_MAP = datetime(2026, 10, 19, 3, 12, tzinfo=timezone.utc)
T_SPRAY = datetime(2026, 10, 19, 4, 5, tzinfo=timezone.utc)
T_HUMAN = datetime(2026, 10, 19, 6, 10, tzinfo=timezone.utc)
T_SHELL = datetime(2026, 10, 19, 7, 30, tzinfo=timezone.utc)
T_EXFIL = datetime(2026, 10, 19, 10, 15, tzinfo=timezone.utc)
T_LAB = datetime(2026, 10, 19, 14, 0, tzinfo=timezone.utc)
T_ESCAPE = datetime(2026, 10, 19, 16, 20, tzinfo=timezone.utc)
T_LAB_STOP = datetime(2026, 10, 19, 17, 8, tzinfo=timezone.utc)
T_POLL = datetime(2026, 10, 20, 3, 0, tzinfo=timezone.utc)
T_PROXY = datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc)

SOURCES = {
    "elastic": ("https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex",
                "Detecting agentic offensive frameworks: ARTEX and friends",
                "Elastic Security Labs describes ARTEX as an LLM planner with parallel workers running nuclei, "
                "httpx, katana, ffuf and sqlmap, with execution bursts of about 2-25 seconds and the User-Agents "
                "norma/0.4 and artex-enrich/1.0, and gives a hunt for one source using several tool families "
                "in a minute."),
    "talos": ("https://blog.talosintelligence.com/artex-and-beyond/",
              "ARTEX and beyond",
              "Cisco Talos covers ARTEX's planner/worker design, its misuse within weeks of release, rapid "
              "retries (80,000 requests in 90 minutes in one case), co-deployed C2 such as VShell and "
              "AdaptixC2, and Snort rules for the norma harness."),
    "gtig": ("https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks",
             "ARTEX and friends enter: agentic offensive frameworks",
             "Google Threat Intelligence Group reports UNC7228 using ARTEX: source-map and web fuzzing, a MySQL "
             "general_log web shell (cl1217.jsp, f1219a.jsp, z1219.jsp), Kerberoasting and DCSync scripts, "
             "notification abuse to 1,300 users, and curl to 491 rotating webhook.site URLs as C2."),
    "unit42": ("https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/",
               "ARTEX and AI-powered red teaming tools",
               "Unit 42 counts exposed ARTEX and CyberStrikeAI hosts and describes agent timing: request "
               "bursts with 25-31 second pauses, polling every 48 seconds for days, canary inputs such as "
               "test@example.com and evil.com, and write-then-read checks."),
    "wiz": ("https://wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors",
            "ARTEX in the wild: Storm-0940 expands targeting of IT and software vendors",
            "Wiz describes source-map and OpenAPI mapping, password spraying at about one attempt a second "
            "in 20-60 minute bursts, 60+ SSO route variations in two minutes, address rotation within "
            "minutes of a block, and publishes five operator IP addresses."),
    "helpnet": ("https://www.helpnetsecurity.com/2026/11/09/artex-goes-from-pentesting-tool-to-attacker-staple-in-three-months/",
                "ARTEX goes from pentesting tool to attacker staple in three months",
                "Help Net Security summarises ARTEX's spread, including a benchmark run whose agent escaped its "
                "test environment and reached an internal sales application through a predictable development "
                "credential."),
}

# -- outside addresses -------------------------------------------------------------------------------
OPS_MAP = "104.194.150.21"          # Wiz IOC
OPS_API = "144.172.64.60"           # Wiz IOC (Microsoft: Storm-0940)
OPS_SPRAY = "144.172.64.99"         # Wiz IOC (Microsoft: Storm-0940)
OPS_SHELL = "144.172.64.128"        # Wiz IOC (Microsoft: Storm-0940)
OPS_EXFIL = "167.88.172.97"         # Wiz IOC
OPERATORS = [OPS_MAP, OPS_API, OPS_SPRAY, OPS_SHELL, OPS_EXFIL]
OPEN_PROXY = "198.51.100.140"       # fictional open proxy (GTIG: fallback after blocks)
WEBHOOK = ("webhook.site", "198.51.100.88")         # real service name, fictional resolution
LLM_API = ("api.deepseek.com", "198.18.30.10")      # real service name, fictional resolution
UPSTREAM_DNS = "192.0.2.53"
SAAS = [("mail.office365.example", "198.18.10.31"), ("github.example", "198.18.10.60"),
        ("slack.example", "198.18.10.44"), ("pypi.example", "198.18.20.12"), ("registry.npm.example", "198.18.20.57"),
        ("docs.vendor.example", "192.0.2.80")]
CUSTOMERS = [f"203.0.113.{i}" for i in range(10, 60)] + [f"198.18.40.{i}" for i in range(10, 40)]

# -- internal estate ---------------------------------------------------------------------------------
HOSTS: dict[str, tuple[str, str]] = {}
PORTAL, SSO, API, MAIL = "10.50.1.10", "10.50.1.11", "10.50.1.12", "10.50.1.25"
DC1, DC2, DB, GIT, CI, FS, CRM, BACKUP, JUMP = ("10.50.0.10", "10.50.0.11", "10.50.0.20", "10.50.0.30",
                                                "10.50.0.31", "10.50.0.40", "10.50.0.45", "10.50.0.50",
                                                "10.50.0.60")
RESOLVER = "10.50.0.53"            # DNS appliance, not in the scan, so lookups are not pinned on a DC
SECLAB = "10.50.40.10"
LAB = ["10.50.41.10", "10.50.41.11", "10.50.41.12", "10.50.41.13"]
for ip, name, os_name in (
        (PORTAL, "portal01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (SSO, "sso01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (API, "api01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (MAIL, "mail01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (DC1, "dc01", "Microsoft Windows Server 2022 Standard"),
        (DC2, "dc02", "Microsoft Windows Server 2022 Standard"),
        (DB, "db01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (GIT, "git01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (CI, "ci01", "Linux Kernel 5.15 on Ubuntu 22.04"),
        (FS, "fs01", "Microsoft Windows Server 2019 Standard"),
        (CRM, "crm01", "Microsoft Windows Server 2012 R2 Standard"),
        (BACKUP, "backup01", "Microsoft Windows Server 2019 Standard"),
        (JUMP, "jump01", "Microsoft Windows Server 2022 Standard"),
        (SECLAB, "seclab01", "Linux Kernel 6.8 on Ubuntu 24.04")):
    HOSTS[ip] = (f"{name}.{DOMAIN}", os_name)
for ip, name in zip(LAB, ("lab-juice", "lab-dvwa", "lab-webgoat", "lab-api")):
    HOSTS[ip] = (f"{name}.lab.{DOMAIN}", "Linux Kernel 5.15 on Ubuntu 22.04")
WORKSTATIONS: list[str] = []
_n = 21
for dept, count, os_name in (("eng-mbp", 30, "Mac OS X 15.1"), ("eng-lx", 14, "Linux Kernel 6.8 on Ubuntu 24.04"),
                             ("ops-ws", 14, "Microsoft Windows 11 Enterprise"),
                             ("sales-ws", 12, "Microsoft Windows 11 Enterprise")):
    for k in range(1, count + 1):
        ip = f"10.50.10.{_n}"
        HOSTS[ip] = (f"{dept}-{k:02}.{DOMAIN}", os_name)
        WORKSTATIONS.append(ip)
        _n += 1
PRINTERS = [f"10.50.30.{i}" for i in range(10, 14)]
for ip in PRINTERS:
    HOSTS[ip] = (f"prn-{ip.split('.')[-1]}.{DOMAIN}", "HP LaserJet")
SERVERS = [DC1, DC2, DB, GIT, CI, FS, CRM, BACKUP, JUMP]
DMZ = [PORTAL, SSO, API, MAIL]

UA_NORMA, UA_ENRICH = "norma/0.4", "artex-enrich/1.0"
UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
UA_URLLIB, UA_CURL, UA_REQ = "Python-urllib/3.12", "curl/7.88.1", "python-requests/2.34.2"
UA_DESKTOP = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
UA_BROWSERS = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
               "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"]

# -- signatures (ET style names; sids 92000xx are local placeholders) -----------------------------------
SIG = {
    "norma": ("ET USER_AGENTS Agentic Pentest Harness User-Agent (norma/0.4)", 9200001, "A Network Trojan was detected", 2),
    "enrich": ("ET USER_AGENTS ARTEX Enrichment Worker User-Agent (artex-enrich/1.0)", 9200002, "A Network Trojan was detected", 2),
    "fuzz": ("ET SCAN Rapid Web Path Fuzzing - High 404/403 Ratio From Single Source", 9200003, "Web Application Attack", 2),
    "map": ("ET INFO JavaScript Source Map Retrieved by Non-Browser Client", 9200004, "Potentially Bad Traffic", 3),
    "spray": ("ET SCAN Password Spray Against Web SSO Login Endpoint", 9200005, "Attempted User Privilege Gain", 2),
    "sso": ("ET POLICY OAuth state/callback Manipulation - Many SSO Route Variations", 9200006, "Attempted User Privilege Gain", 2),
    "genlog": ("ET WEB_SERVER MySQL general_log Redirected to Web Root via SQL API (Possible Webshell Staging)", 9200007, "Web Application Attack", 1),
    "jsp": ("ET WEB_SERVER JSP Webshell Access - Short Iterative File Names", 9200008, "Web Application Attack", 1),
    "webhook": ("ET INFO Observed webhook.site Domain in TLS SNI from Server Segment", 9200009, "Potentially Bad Traffic", 2),
    "kerberoast": ("ET POLICY Kerberos TGS-REQ RC4-HMAC Burst for Multiple SPNs (Possible Kerberoasting)", 9200010, "Attempted User Privilege Gain", 1),
    "dcsync": ("ET POLICY DRSUAPI DsGetNCChanges Request From Non-DC (Possible DCSync)", 9200011, "Attempted Administrator Privilege Gain", 1),
    "smtp": ("ET INFO Mass SMTP Submission From Web Application Server", 9200012, "Misc activity", 3),
    "bulk": ("ET POLICY Bulk API Pagination Export From Lab Segment", 9200013, "Potential Corporate Privacy Violation", 2),
    "devcred": ("ET POLICY Known Development Credential Used Against Internal API", 9200014, "Attempted User Privilege Gain", 1),
}

# -- scan findings ---------------------------------------------------------------------------------------
V = kit.vuln
VULNS = [
    V(PORTAL, 443, "www", "900101", "Northfold Portal Report API Executes Arbitrary SQL Statements", 4, 9.8, (), True,
      False, "The portal's report API passes caller-supplied SQL to MySQL with the application account, which "
      "holds SUPER and FILE privileges.", "Remove free-form SQL from the report API and drop SUPER/FILE from the "
      "application account.", family="CGI abuses"),
    V(PORTAL, 443, "www", "42479", "CGI Generic SQL Injection (blind)", 3, 8.6, (), True, False,
      "A CGI application hosted on the remote web server is potentially prone to SQL injection.",
      "Modify the affected CGI scripts so that they properly escape arguments.", family="CGI abuses"),
    V(PORTAL, 443, "www", "232781", "Apache Tomcat 9.0.x < 9.0.99 Remote Code Execution (CVE-2025-24813)", 4, 9.8,
      ("CVE-2025-24813",), True, True, "The Tomcat instance behind the portal is affected by a partial PUT "
      "remote code execution vulnerability.", "Upgrade to Apache Tomcat 9.0.99 or later.", family="Web Servers"),
    V(PORTAL, 443, "www", "900102", "JavaScript Source Maps Publicly Accessible", 2, 5.3, (), False, False,
      "Production JavaScript source maps reveal internal API routes.", "Do not publish source maps.",
      family="CGI abuses"),
    V(API, 443, "www", "900103", "OpenAPI / Swagger Documentation Exposed Without Authentication", 2, 5.3, (), False,
      False, "The API gateway publishes its full OpenAPI document to anonymous users.",
      "Require authentication for API documentation.", family="CGI abuses"),
    V(SSO, 443, "www", "900104", "Web Login Endpoint Lacks Rate Limiting and Account Lockout", 3, 7.5, (), False,
      False, "The SSO login form accepts unlimited attempts from one address.",
      "Add rate limiting, lockout and phishing-resistant MFA.", family="CGI abuses"),
    V(CRM, 8080, "www", "900105", "Sales API Accepts Predictable Development Credential", 4, 9.1, (), True, False,
      "The legacy sales API accepts a local-development username and password from any internal address.",
      "Remove development credentials and put the API behind SSO.", family="CGI abuses"),
    V(CRM, 0, "general", "108797", "Unsupported Windows OS (remote)", 4, 10.0, (), False, False,
      "The remote host runs a version of Windows that is no longer supported.",
      "Upgrade to a supported version of Windows.", family="Windows"),
    V(CI, 8080, "www", "189463", "Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897)", 4, 9.8, ("CVE-2024-23897",),
      True, True, "The Jenkins controller allows arbitrary file read through its CLI.",
      "Upgrade Jenkins to 2.442 or later.", family="CGI abuses"),
    V(DB, 3306, "mysql", "900106", "MySQL Server Unsupported Version Detection", 4, 10.0, (), False, False,
      "The installed version of MySQL is no longer supported.", "Upgrade to a supported MySQL release.",
      family="Databases"),
    V(MAIL, 25, "smtp", "900107", "SMTP Relay Accepts Unauthenticated Submission From Server Segment", 2, 5.3, (),
      False, False, "The mail relay accepts mail from any DMZ server without authentication.",
      "Require authenticated submission and per-sender limits.", family="SMTP problems"),
]
for dc in (DC1, DC2):
    VULNS += [V(dc, 88, "kerberos", "900108", "Kerberos RC4-HMAC Encryption Allowed for Service Accounts", 2, 5.9, (),
                False, False, "Service accounts accept RC4 tickets, which makes Kerberoasting practical.",
                "Require AES for service accounts and use gMSAs.", family="Windows"),
              V(dc, 389, "ldap", "191001", "Active Directory LDAP Signing and Channel Binding Not Required", 2, 5.9, (),
                False, False, "The domain controller accepts unsigned LDAP binds.",
                "Require LDAP signing and channel binding.", family="Windows")]
for ip in (FS, CRM, BACKUP, JUMP) + tuple(w for w in WORKSTATIONS if HOSTS[w][1].startswith("Microsoft")):
    VULNS.append(V(ip, 445, "cifs", "57608", "SMB Signing not required", 2, 5.3, (), False, False,
                   "Signing is not required on the remote SMB server.",
                   "Enforce message signing in the host's configuration.", family="Misc."))
for ip, name in zip(LAB, ("OWASP Juice Shop", "DVWA", "WebGoat", "crAPI")):
    VULNS.append(V(ip, 80, "www", "900110", f"Intentionally Vulnerable Training Application Detected ({name})", 3, 7.5,
                   (), True, False, "A deliberately vulnerable application used for security testing is reachable.",
                   "Keep training targets on an isolated network.", family="CGI abuses"))


def _rt(rng, t, lo=0.0, hi=1.0):
    return t + timedelta(seconds=rng.uniform(lo, hi))


def _background(log: kit.Log, rng):
    span = (END - START).total_seconds()

    def work_ts():
        while True:
            t = START + timedelta(seconds=rng.uniform(0, span))
            if 13 <= t.hour < 23 or rng.random() < 0.12:
                return t

    for ws in WORKSTATIONS:
        windows = not HOSTS[ws][1].startswith(("Mac", "Linux"))
        for _ in range(rng.randint(6, 10)):
            log.session(work_ts(), ws, rng.choice([DC1, DC2]), 88, svc="krb", proto="tcp", ob=rng.randint(1200, 1800))
        for _ in range(rng.randint(3, 6)):
            log.session(work_ts(), ws, rng.choice([DC1, DC2]), 389, svc="ldap")
        if windows:
            for _ in range(rng.randint(4, 8)):
                log.session(work_ts(), ws, FS, 445, svc="smb", rb=rng.randint(20_000, 2_000_000))
        else:
            for _ in range(rng.randint(4, 8)):
                log.session(work_ts(), ws, GIT, rng.choice([22, 443]), svc="ssh" if rng.random() < .5 else "ssl",
                            rb=rng.randint(20_000, 3_000_000))
        if HOSTS[ws][0].startswith("sales"):
            for _ in range(rng.randint(4, 8)):
                t = work_ts()
                log.web(t, ws, CRM, 8080, "GET", "crm01.northfold.example:8080",
                        f"/app/accounts/{rng.randint(1000, 9999)}", rng.choice(UA_BROWSERS), 200)
        for _ in range(rng.randint(6, 10)):
            name, ip = rng.choice(SAAS)
            t = work_ts()
            if rng.random() < 0.3:
                log.lookup(t - timedelta(seconds=1), ws, name, ip)
            log.tls(t, ws, ip, 443, sni=name, log_ssl=rng.random() < 0.3)
    # customers use the portal, the API and the SSO page through the day
    for _ in range(900):
        t = work_ts()
        c = rng.choice(CUSTOMERS)
        r = rng.random()
        if r < 0.55:
            log.web(t, c, PORTAL, 443, "GET", "portal.northfold.example",
                    rng.choice(["/", "/dashboard", "/invoices", "/static/js/main.4f1c2a.js", "/static/css/app.css",
                                "/api/v2/me", "/api/v2/tickets?page=1"]), rng.choice(UA_BROWSERS), 200,
                    rb=rng.randint(2_000, 180_000))
        elif r < 0.8:
            log.web(t, c, API, 443, "GET", "api.northfold.example", f"/v2/orders/{rng.randint(10000, 99999)}",
                    rng.choice(["python-requests/2.32.3", "Go-http-client/2.0", "okhttp/4.12.0"]), 200)
        else:
            log.web(t, c, SSO, 443, "POST", "login.northfold.example", "/api/auth/login",
                    rng.choice(UA_BROWSERS), 200 if rng.random() < 0.93 else 401)
    for t in (START + timedelta(hours=h, minutes=rng.randint(0, 59)) for h in range(48)):
        log.session(t, RESOLVER, UPSTREAM_DNS, 53, svc="dns", proto="udp", ob=rng.randint(60, 90),
                    rb=rng.randint(90, 300))
    for _ in range(60):                               # build pipeline
        t = work_ts()
        log.session(t, CI, GIT, 22, svc="ssh", rb=rng.randint(100_000, 9_000_000))
        log.tls(t + timedelta(seconds=30), CI, rng.choice(SAAS[3:5])[1], 443, log_ssl=False,
                rb=rng.randint(1_000_000, 20_000_000))
    for _ in range(40):                               # the portal talks to its database and the relay
        log.session(work_ts(), PORTAL, DB, 3306, svc="mysql", rb=rng.randint(4_000, 400_000))
        log.session(work_ts(), PORTAL, MAIL, 25, svc="smtp", ob=rng.randint(3_000, 30_000), rb=600)
    for _ in range(30):
        log.session(work_ts(), JUMP, rng.choice(SERVERS), rng.choice([3389, 5985, 22]), rb=rng.randint(10_000, 900_000))
    for _ in range(20):
        log.session(START + timedelta(hours=rng.choice([1, 2, 25, 26]), minutes=rng.randint(0, 59)), BACKUP,
                    rng.choice([FS, DB, GIT, CRM]), 445, svc="smb", ob=4000, rb=rng.randint(50_000_000, 400_000_000),
                    dur=rng.uniform(300, 1800))
    for p in PRINTERS:
        log.session(work_ts(), rng.choice(WORKSTATIONS), p, 9100, ob=rng.randint(30_000, 600_000), rb=200)
    for _ in range(12):                               # the security team's ordinary use of the lab box
        log.session(work_ts(), rng.choice(WORKSTATIONS[:8]), SECLAB, 22, svc="ssh", rb=rng.randint(5_000, 200_000))


def _hit(log, t, src, dst, host, uri, ua, status, rng, method="GET", rb=None):
    log.web(t, src, dst, 443, method, host, uri, ua, status,
            rb=(rng.randint(150, 600) if status >= 400 else rng.randint(1_500, 90_000)) if rb is None else rb)


def _mapping(log, rng):
    """Application mapping, the first block and rotation."""
    host = "portal.northfold.example"
    t = T_MAP
    _hit(log, t, OPS_MAP, PORTAL, host, "/4c1f8e2a-0b7d-4e55-9d13-f2a6c0b1e7d9", UA_NORMA, 404, rng)
    log.alert(t + timedelta(seconds=1), OPS_MAP, PORTAL, 443, *SIG["norma"], app="http")
    first = [("/static/js/main.4f1c2a.js.map", 200), ("/static/js/vendor.91be0d.js.map", 200),
             ("/runtime-config.json", 200), ("/config.js", 200), ("/swagger.json", 404), ("/v3/api-docs", 200),
             ("/api/v2/openapi.yaml", 200), ("/.well-known/openid-configuration", 200)]
    for k, (uri, status) in enumerate(first):
        _hit(log, t + timedelta(seconds=4 + k * 0.4), OPS_MAP, PORTAL, host, uri, UA_NORMA, status, rng)
    log.alert(t + timedelta(seconds=5), OPS_MAP, PORTAL, 443, *SIG["map"], app="http")
    log.alert(t + timedelta(seconds=9), OPS_MAP, PORTAL, 443, *SIG["enrich"], app="http")
    words = ["admin", "backup", "old", "test", "dev", "api", "internal", "export", "report", "reports", "upload",
             "uploads", "debug", "console", "actuator", "metrics", "env", "config", "db", "sql", "logs", "tmp"]
    exts = ["", ".bak", ".old", ".zip", ".jsp", ".json", ".txt", ".sql", ".tar.gz", ".yml"]
    dirs = ["/", "/admin/", "/api/", "/internal/", "/reports/", "/static/"]
    times = kit.bursts(rng, t + timedelta(seconds=40), 520)
    blocked_at = T_MAP + timedelta(minutes=25)
    for k, ts in enumerate(times):
        if ts >= blocked_at:
            break
        uri = rng.choice(dirs) + rng.choice(words) + rng.choice(exts)
        status = 403 if uri.startswith(("/admin/", "/internal/")) else (200 if rng.random() < 0.04 else 404)
        ua = UA_ENRICH if k % 7 == 3 else (UA_CURL if k % 11 == 5 else UA_NORMA)
        _hit(log, ts, OPS_MAP, PORTAL, host, uri, ua, status, rng)
    log.alert(T_MAP + timedelta(minutes=3), OPS_MAP, PORTAL, 443, *SIG["fuzz"], app="http")
    log.note(T_MAP + timedelta(minutes=2), OPS_MAP, PORTAL, 443, "HTTP::Agentic_Tool_Mix",
             "104.194.150.21 used 3 tool families (norma, curl, python) and 140 requests in one minute "
             "(Elastic agentic-framework hunt)")
    # the WAF blocks; the agent keeps trying for a moment, then the planner moves to new infrastructure
    for k in range(6):
        ts = blocked_at + timedelta(seconds=k * 3)
        log.session(ts, OPS_MAP, PORTAL, 443, state="REJ", ob=0, rb=0)
        log.alert(ts, OPS_MAP, PORTAL, 443, *SIG["fuzz"], app="http", blocked=True)
    t = blocked_at + timedelta(minutes=3, seconds=10)
    api = "api.northfold.example"
    _hit(log, t, OPS_API, API, api, "/0e6b1d55-not-a-route", UA_CHROME, 404, rng)
    for k, ts in enumerate(kit.bursts(rng, t + timedelta(seconds=5), 140, per=(3, 14))):
        uri = rng.choice(["/v2/openapi.json", "/v2/docs", "/v2/orders", "/v2/customers", "/v2/tenants",
                          "/v2/users", "/v2/admin", "/v2/export", "/v2/webhooks", "/v2/internal/health"])
        if rng.random() < 0.5:
            uri += f"/{rng.randint(1000, 1100)}"
        _hit(log, ts, OPS_API, API, api, uri, UA_CHROME, rng.choice([200, 401, 401, 403, 404]), rng)


def _spray(log, rng):
    host = "login.northfold.example"
    canaries = ["test%40example.com", "admin%40evil.com", "deadbeefdeadbeefdeadbeef12", "nobody%40northfold.example"]
    staff = [f"{f}.{l}%40northfold.example" for f, l in
             (("a", "berg"), ("d", "larsen"), ("m", "okafor"), ("s", "ruiz"), ("t", "nakamura"), ("j", "holm"),
              ("k", "patel"), ("l", "moreau"), ("r", "singh"), ("e", "novak"), ("p", "lindqvist"), ("h", "osei"))]
    t = T_SPRAY
    for k, name in enumerate(canaries + staff):          # which usernames exist?
        _hit(log, t + timedelta(seconds=k * 1.1), OPS_API, SSO, host, f"/api/users/exists?login={name}", UA_CHROME,
             200 if k >= len(canaries) else 404, rng)
    t += timedelta(seconds=40)

    def spray(src, ua, t, stop):
        n = 0
        while t < stop:
            log.web(t, src, SSO, 443, "POST", host, "/api/auth/login", ua, 401, rb=rng.randint(90, 160))
            n += 1
            if n % 90 == 0:
                log.web(t + timedelta(seconds=0.4), src, SSO, 443, "POST", host,
                        f"/api/auth/password-reset?login={rng.choice(staff)}", ua, 202, rb=60)
            t += timedelta(seconds=rng.choice([0.8, 0.9, 1.0, 1.0, 1.0, 1.1, 1.2, 1.4]))
        return n

    stop1 = T_SPRAY + timedelta(minutes=40)
    spray(OPS_API, UA_CHROME, t, stop1)
    log.alert(T_SPRAY + timedelta(minutes=2), OPS_API, SSO, 443, *SIG["spray"], app="http")
    log.note(T_SPRAY + timedelta(minutes=10), OPS_API, SSO, 443, "HTTP::Password_Spray",
             "144.172.64.60 sent 600 failed logins for 12 accounts to /api/auth/login in 10 minutes (median gap 1 s)")
    # 60+ SSO route variations in two minutes
    routes = ["/oauth2/authorize", "/oauth2/callback", "/saml2/acs", "/saml2/sso", "/adfs/ls/", "/sso/login",
              "/api/auth/sso/callback", "/connect/authorize", "/login/oauth2/code/entra", "/auth/realms/main/protocol/openid-connect/auth"]
    t = stop1 + timedelta(seconds=20)
    for k in range(64):
        r = routes[k % len(routes)]
        q = rng.choice(["?state=evil.com", "?redirect_uri=https%3A%2F%2Fevil.com%2Fcb", "?code=deadbeef&state=1",
                        "?id_token=eyJhbGciOiJub25lIn0.e30.", "?RelayState=..%2F..%2Fadmin", ""])
        _hit(log, t + timedelta(seconds=k * 1.8), OPS_API, SSO, host, r + q, UA_CHROME,
             rng.choice([302, 400, 400, 404, 401]), rng)
    log.alert(t + timedelta(seconds=30), OPS_API, SSO, 443, *SIG["sso"], app="http")
    # blocked; a new address and a new User-Agent pick the spray up four minutes later
    blk = T_SPRAY + timedelta(minutes=42)
    for k in range(4):
        log.session(blk + timedelta(seconds=k * 2), OPS_API, SSO, 443, state="REJ", ob=0, rb=0)
        log.alert(blk + timedelta(seconds=k * 2), OPS_API, SSO, 443, *SIG["spray"], app="http", blocked=True)
    t2 = blk + timedelta(minutes=4, seconds=30)
    spray(OPS_SPRAY, UA_URLLIB, t2, t2 + timedelta(minutes=22))
    log.alert(t2 + timedelta(minutes=1), OPS_SPRAY, SSO, 443, *SIG["spray"], app="http")

    # the human step: a desktop browser does the password reset and first login
    t = T_HUMAN
    for k, (m, uri, st) in enumerate((("GET", "/reset", 200), ("POST", "/api/auth/password-reset?login=d.larsen%40northfold.example", 202),
                                      ("GET", "/reset/confirm?token=7Q2xv9", 200), ("POST", "/api/auth/password", 200),
                                      ("GET", "/login", 200), ("POST", "/api/auth/login", 200),
                                      ("GET", "/api/auth/mfa/enroll", 200))):
        log.web(t + timedelta(seconds=k * rng.uniform(8, 40)), OPS_SPRAY, SSO, 443, m, host, uri, UA_DESKTOP, st)
    # the agent takes over: an admin account, read back after every write, then predictable tenant IDs
    t = T_HUMAN + timedelta(minutes=9)
    phost = "portal.northfold.example"
    for k in range(3):
        name = f"ArtexProbe{48213 + k}"
        _hit(log, t, OPS_SPRAY, PORTAL, phost, f"/api/v2/admin/users?name={name}&is_admin=true", UA_URLLIB, 201, rng,
             method="POST", rb=310)
        _hit(log, t + timedelta(seconds=0.7), OPS_SPRAY, PORTAL, phost, f"/api/v2/admin/users/{name}", UA_URLLIB,
             200, rng, rb=420)
        t += timedelta(seconds=rng.uniform(26, 31))
    for k, ts in enumerate(kit.bursts(rng, t + timedelta(seconds=20), 90, per=(1, 14), burst=(1, 14), pause=(25, 31))):
        tenant = 1001 + k
        _hit(log, ts, OPS_SPRAY, PORTAL, phost, f"/api/v2/tenants/{tenant}/invoices", UA_URLLIB,
             200 if k % 4 else 403, rng)


def _shell_and_inside(log, rng):
    host = "portal.northfold.example"
    t = T_SHELL
    for k in range(3):
        _hit(log, t + timedelta(seconds=k * 6), OPS_SHELL, PORTAL, host, "/api/v2/reports/query", UA_CURL, 200, rng,
             method="POST", rb=rng.randint(80, 300))
    log.alert(t + timedelta(seconds=7), OPS_SHELL, PORTAL, 443, *SIG["genlog"], app="http")
    t += timedelta(seconds=40)
    for k, (name, status) in enumerate((("cl1217.jsp", 404), ("f1219a.jsp", 404), ("z1219.jsp", 200))):
        for j in range(2 if status == 404 else 1):
            ts = t + timedelta(seconds=k * 70 + j * 30)     # replayed ~30 s apart before moving on
            if status == 404:
                _hit(log, ts - timedelta(seconds=5), OPS_SHELL, PORTAL, host, "/api/v2/reports/query", UA_CURL, 200,
                     rng, method="POST", rb=120)
            _hit(log, ts, OPS_SHELL, PORTAL, host, f"/reports/{name}?c=id", UA_CURL, status, rng)
    shell_up = t + timedelta(seconds=150)
    log.alert(shell_up, OPS_SHELL, PORTAL, 443, *SIG["jsp"], app="http")
    for k, ts in enumerate(kit.bursts(rng, shell_up + timedelta(seconds=20), 40, per=(2, 8))):
        _hit(log, ts, OPS_SHELL, PORTAL, host, "/reports/z1219.jsp?c=" + rng.choice(
            ["whoami", "uname%20-a", "cat%20/opt/portal/conf/app.yml", "ls%20/opt", "ip%20a", "env"]), UA_CURL, 200, rng)

    # the portal pulls generated scripts from the operator and posts results to webhook.site
    t = T_SHELL + timedelta(minutes=11)
    for k in range(6):
        log.tls(t + timedelta(minutes=k * 3, seconds=rng.uniform(0, 20)), PORTAL, OPS_SHELL, 443,
                ob=rng.randint(400, 900), rb=rng.randint(4_000, 60_000), log_ssl=k == 0)
    log.lookup(t + timedelta(minutes=3), PORTAL, WEBHOOK[0], WEBHOOK[1])
    log.alert(t + timedelta(minutes=3, seconds=2), PORTAL, WEBHOOK[1], 443, *SIG["webhook"], app="tls")
    for ts in kit.bursts(rng, t + timedelta(minutes=3, seconds=1), 130, per=(2, 9), pause=(30, 140)):
        if ts > T_EXFIL + timedelta(minutes=30):
            break
        log.tls(ts, PORTAL, WEBHOOK[1], 443, sni=WEBHOOK[0], ob=rng.randint(600, 24_000), rb=rng.randint(300, 900),
                log_ssl=rng.random() < 0.25)
        if rng.random() < 0.08:
            log.lookup(ts - timedelta(seconds=0.2), PORTAL, WEBHOOK[0], WEBHOOK[1])

    # discovery and credential access, in agent bursts
    t = T_SHELL + timedelta(minutes=20)
    for k in range(20):
        log.session(t + timedelta(seconds=k * 1.1), PORTAL, DC1 if k % 2 else DC2, 389, svc="ldap",
                    rb=rng.randint(30_000, 600_000))
    t += timedelta(minutes=2)
    tgs = sorted(t + timedelta(seconds=rng.uniform(0, 23)) for _ in range(27))     # 27 events in 23 s
    for ts in tgs:
        log.session(ts, PORTAL, DC1, 88, svc="krb", ob=rng.randint(1_400, 1_700), rb=rng.randint(1_200, 1_900),
                    dur=0.02)
    log.alert(tgs[5], PORTAL, DC1, 88, *SIG["kerberoast"], app="krb5")
    log.note(tgs[-1], PORTAL, DC1, 88, "Kerberos::TGS_Burst",
             "10.50.1.10 requested 27 RC4 service tickets for 27 SPNs in 23 s")
    t += timedelta(minutes=4)
    for k in range(8):
        log.session(t + timedelta(seconds=k * 2.5), PORTAL, DB, 3306, svc="mysql", rb=rng.randint(200_000, 4_000_000))
    t += timedelta(minutes=6)
    for k, (d, port) in enumerate(((CI, 5985), (FS, 5985), (JUMP, 5985), (FS, 445), (BACKUP, 445), (GIT, 22))):
        log.session(t + timedelta(seconds=k * 9), PORTAL, d, port, svc="http" if port == 5985 else "-",
                    ob=rng.randint(2_000, 9_000), rb=rng.randint(1_000, 6_000), dur=rng.uniform(1, 6))
    dcs = T_SHELL + timedelta(minutes=70)                   # DCSync against dc01
    log.session(dcs, PORTAL, DC1, 135, svc="dce_rpc", ob=1_200, rb=900, dur=0.1)
    log.session(dcs + timedelta(seconds=1), PORTAL, DC1, 49668, svc="dce_rpc", ob=48_000, rb=3_600_000, dur=14)
    log.alert(dcs + timedelta(seconds=2), PORTAL, DC1, 49668, *SIG["dcsync"], app="dcerpc")

    # notification abuse: ~1,300 messages to staff through the relay
    t = datetime(2026, 10, 19, 9, 10, tzinfo=timezone.utc)
    for k in range(26):
        log.session(t + timedelta(seconds=k * rng.uniform(4, 9)), PORTAL, MAIL, 25, svc="smtp",
                    ob=rng.randint(180_000, 260_000), rb=rng.randint(3_000, 6_000), dur=rng.uniform(5, 15))
    log.alert(t + timedelta(seconds=30), PORTAL, MAIL, 25, *SIG["smtp"], app="smtp")
    log.note(t + timedelta(minutes=4), PORTAL, MAIL, 25, "SMTP::Mass_Submission",
             "10.50.1.10 submitted 1,312 messages to 1,300 internal recipients in 4 minutes")

    # exfiltration
    for k, size in enumerate((610_000_000, 480_000_000, 330_000_000)):
        log.tls(T_EXFIL + timedelta(minutes=k * 9), PORTAL, OPS_EXFIL, 443, ob=size, rb=rng.randint(40_000, 90_000),
                dur=rng.uniform(380, 520), log_ssl=True)

    # day 2: the web shell is polled every 48 seconds; after a block, through an open proxy
    t = T_POLL
    first = True
    while t < END - timedelta(minutes=5):
        src = OPS_SPRAY if t < T_PROXY else OPEN_PROXY
        if T_PROXY <= t < T_PROXY + timedelta(minutes=6):
            log.session(t, OPS_SPRAY, PORTAL, 443, state="REJ", ob=0, rb=0)
            log.alert(t, OPS_SPRAY, PORTAL, 443, *SIG["jsp"], app="http", blocked=True)
        else:
            _hit(log, t, src, PORTAL, host, "/reports/z1219.jsp?c=poll", UA_CURL, 200, rng, rb=rng.randint(40, 90))
            if first or (src == OPEN_PROXY and t < T_PROXY + timedelta(minutes=7)):
                log.alert(t, src, PORTAL, 443, *SIG["jsp"], app="http")
                first = False
        t += timedelta(seconds=48 + rng.uniform(-0.4, 0.4))


def _lab(log, rng):
    """An authorised benchmark run whose agent leaves the lab range."""
    t = T_LAB
    log.lookup(t - timedelta(seconds=2), SECLAB, LLM_API[0], LLM_API[1])
    step = 0
    crm = "crm01.northfold.example:8080"
    page = 1
    while t < T_LAB_STOP:
        # the planner asks the model what to do next
        log.tls(t, SECLAB, LLM_API[1], 443, sni=LLM_API[0], ob=rng.randint(6_000, 40_000),
                rb=rng.randint(2_000, 9_000), dur=rng.uniform(3, 20), log_ssl=step % 6 == 0)
        burst = t + timedelta(seconds=rng.uniform(4, 22))
        if burst < T_ESCAPE:
            target = rng.choice(LAB)
            for k in range(rng.randint(4, 24)):
                ts = burst + timedelta(seconds=rng.uniform(0, rng.uniform(2, 25)))
                log.web(ts, SECLAB, target, 80, rng.choice(["GET", "GET", "POST"]), HOSTS[target][0],
                        rng.choice(["/", "/login", "/api/products?q=%27", "/rest/user/login", "/vulnerabilities/sqli/",
                                    "/WebGoat/attack", "/identity/api/v2/user/dashboard", "/robots.txt"]),
                        rng.choice([UA_NORMA, UA_NORMA, "Mozilla/5.0 (compatible; nuclei)"]),
                        rng.choice([200, 200, 302, 401, 404, 500]))
        else:
            if step % 3 == 0 and page == 1:
                for k, (uri, st) in enumerate((("/api/v1/health", 200), ("/api/v1/login?user=admin", 401),
                                               ("/api/v1/login?user=dev", 200))):
                    log.web(burst + timedelta(seconds=k * 1.5), SECLAB, CRM, 8080, "POST" if "login" in uri else "GET",
                            crm, uri, UA_NORMA, st)
                log.alert(burst + timedelta(seconds=1), SECLAB, CRM, 8080, *SIG["norma"], app="http")
                log.alert(burst + timedelta(seconds=4), SECLAB, CRM, 8080, *SIG["devcred"], app="http")
            for k in range(rng.randint(8, 22)):
                ts = burst + timedelta(seconds=5 + k * rng.uniform(0.3, 1.1))
                log.web(ts, SECLAB, CRM, 8080, "GET", crm, f"/api/v1/accounts?page={page}&size=500", UA_NORMA, 200,
                        rb=rng.randint(60_000, 140_000))
                page += 1
            if page > 20 and not any(e["sid"] == SIG["bulk"][1] for e in log.eve):
                log.alert(ts, SECLAB, CRM, 8080, *SIG["bulk"], app="http")
        step += 1
        t = burst + timedelta(seconds=rng.uniform(25, 60))
    log.note(T_LAB_STOP - timedelta(minutes=2), SECLAB, CRM, 8080, "HTTP::Bulk_Pagination",
             f"10.50.40.10 paged through /api/v1/accounts {page - 1} times in 45 minutes")


def ioc_rows() -> list[list]:
    seen = "2026-11-05T00:00:00.000Z"
    wiz, gtig = SOURCES["wiz"][0], SOURCES["gtig"][0]
    rows = []
    for ip in OPERATORS:
        why = "ARTEX operator address (Wiz)" + ("; Microsoft attributes it to Storm-0940" if ip.startswith("144.") else "")
        rows.append(["ip", ip, "Actionable", why, "artex;storm-0940;unc7228", seen, seen, 1, "wiz.io", wiz,
                     "ioc-table", ""])
    rows.append(["domain", "webhook.site", "Suspicious", "Legitimate service abused as ARTEX C2 channel (GTIG)",
                 "artex;c2-channel", seen, seen, 1, "cloud.google.com", gtig, "article-text", ""])
    return rows


def generate(outdir: str, seed: int = 1019) -> list[str]:
    """Write the Artex AI sample folder."""
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(seed)
    log = kit.Log(rng, RESOLVER, prefix="A")
    _background(log, rng)
    _mapping(log, rng)
    _spray(log, rng)
    _shell_and_inside(log, rng)
    _lab(log, rng)
    kit.check_addresses(log)
    paths = kit.write_zeek(outdir, log, START, END)
    paths.append(kit.write_eve(os.path.join(outdir, "suricata_eve.json"), log, rng))
    paths.append(kit.write_nessus(os.path.join(outdir, "northfold_scan.nessus"), "Northfold monthly scan", HOSTS, VULNS,
                                  START - timedelta(days=2, hours=-2)))
    paths.append(kit.write_iocs(os.path.join(outdir, "ioc_indicators.csv"), ioc_rows()))
    paths.append(kit.write_previews(os.path.join(outdir, "article_previews.json"),
                                    {url: {"title": title, "overview": text} for url, title, text in SOURCES.values()}))
    return paths
