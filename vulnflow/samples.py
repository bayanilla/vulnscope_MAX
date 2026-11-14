"""Generate a synthetic 250-host environment that exercises every code path.

The estate: a DMZ (web, mail, VPN, proxy), a server subnet, ~190 Windows workstations and
VPN laptops, printers and cameras. Background traffic covers both directions: clients
using file, directory, proxy and app servers, backups, monitoring and software pushes
(east/west), plus customers, mail, VPN users, browsing through the proxy, IoT cloud
check-ins and blocked internet scanning (north/south).

Story: web01 (DMZ) runs a vulnerable Apache. An outside address trips the firewall's
IPS signature for that CVE (alert only), web01 then connects back to it, uploads data
and starts probing internal SMB/RDP. BlueKeep probes against ws-031 are reset by the IPS. Meanwhile
the scanner missed the domain controller and a new file server.

A small synthetic packaging line reuses five scanned host slots. A remote engineer's laptop
reuses an existing VPN-pool slot and has allowed OT access through a synthetic GlobalProtect
VPN policy. Outbound HTTPS from it and the OT engineering workstation is an investigation lead,
while HMI/PLC Modbus reads are routine.
"""
from __future__ import annotations

import csv
import json
import os
import random
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

START = datetime(2026, 10, 12, tzinfo=timezone.utc)
ATTACK = datetime(2026, 10, 16, 3, 12, tzinfo=timezone.utc)
ATTACKER = "203.0.113.45"
OT_ACTIVITY = datetime(2026, 10, 17, 2, 10, tzinfo=timezone.utc)
OT_EXTERNAL = "198.51.100.77"  # reserved documentation address; a suspicious contact, not attributed C2

HOSTS = {  # ip: (hostname, os)
    "10.10.1.10": ("web01.corp.example", "Linux Kernel 5.4 on Ubuntu 20.04"),
    "10.10.1.20": ("app01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04"),
    "10.10.2.20": ("db01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04"),
    "10.10.2.25": ("fs01.corp.example", "Microsoft Windows Server 2012 R2"),
    "10.10.3.5": ("jump01.corp.example", "Microsoft Windows Server 2019"),
    "10.10.3.31": ("ws-031.corp.example", "Microsoft Windows 7 Professional"),
    "10.10.4.50": ("prn-4f.corp.example", "HP LaserJet"),
    "10.10.5.60": ("ups-mgmt.corp.example", "Embedded Linux"),
}
WORKSTATIONS = [f"10.10.3.{i}" for i in range(40, 48)]
for ip in WORKSTATIONS:
    HOSTS[ip] = (f"ws-{ip.split('.')[-1]:0>3}.corp.example", "Microsoft Windows 10 Enterprise")

# (ip, port, proto, svc, pluginID, name, sev, cvss3, cves, exploit, metasploit, synopsis, solution)
VULNS = [
    ("10.10.1.10", 443, "tcp", "www", "153884", "Apache 2.4.49 < 2.4.51 Path Traversal and RCE", 4, 9.8,
     ["CVE-2021-41773", "CVE-2021-42013"], True, True,
     "The remote web server is affected by a path traversal vulnerability that can lead to remote code execution.",
     "Upgrade to Apache version 2.4.51 or later."),
    ("10.10.1.10", 22, "tcp", "ssh", "187201", "OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin)", 2, 5.9,
     ["CVE-2023-48795"], False, False,
     "The SSH server is affected by a prefix truncation weakness.", "Upgrade to OpenSSH 9.6 or later."),
    ("10.10.1.20", 8009, "tcp", "ajp13", "134862", "Apache Tomcat AJP Connector Request Injection (Ghostcat)", 4, 9.8,
     ["CVE-2020-1938"], True, True,
     "An AJP connector is listening and is affected by a file read/inclusion vulnerability.",
     "Update Tomcat to 9.0.31 / 8.5.51 / 7.0.100 or later, or disable the AJP connector."),
    ("10.10.2.20", 5432, "tcp", "postgresql", "183965", "PostgreSQL 13.x < 13.13 Multiple Vulnerabilities", 3, 8.8,
     ["CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870"], False, False,
     "The database server is affected by multiple vulnerabilities including an integer overflow.",
     "Upgrade to PostgreSQL 13.13 or later."),
    ("10.10.2.25", 445, "tcp", "cifs", "97833", "MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)", 4, 8.1,
     ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"], True, True,
     "The remote Windows host is affected by multiple remote code execution vulnerabilities in SMBv1.",
     "Apply MS17-010 and disable SMBv1."),
    ("10.10.3.31", 3389, "tcp", "msrdp", "125313", "Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)", 4, 9.8,
     ["CVE-2019-0708"], True, True,
     "The remote host is affected by a remote code execution vulnerability in Remote Desktop Services.",
     "Apply the May 2019 security update and enable Network Level Authentication."),
    ("10.10.3.5", 3389, "tcp", "msrdp", "58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", 2, 4.0,
     [], False, False, "The remote Terminal Services doesn't use NLA only.", "Enable Network Level Authentication."),
    ("10.10.4.50", 23, "tcp", "telnet", "42263", "Unencrypted Telnet Server", 2, 6.5, [], False, False,
     "The remote Telnet server transmits traffic in cleartext.", "Disable Telnet and use SSH instead."),
    ("10.10.5.60", 161, "udp", "snmp", "41028", "SNMP Agent Default Community Name (public)", 3, 7.5,
     ["CVE-1999-0517"], True, False, "The community name of the remote SNMP server can be guessed.",
     "Disable SNMP or change the default community string."),
]
for ip in WORKSTATIONS:
    VULNS.append((ip, 0, "tcp", "general", "207053", "Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities",
                  3, 8.8, ["CVE-2024-7965", "CVE-2024-7971"], True, False,
                  "The browser installed on the remote host is affected by multiple vulnerabilities.",
                  "Upgrade to Microsoft Edge version 129.0.2792.52 or later."))


# -- the rest of the estate (250 scanned hosts in total) ---------------------------------
_E = random.Random(2026)        # fixed, so the scan and hostnames never change between runs
DMZ_WEB = [f"10.10.1.{i}" for i in range(11, 15)]
MAIL, VPN, PROXY = "10.10.1.25", "10.10.1.30", "10.10.1.40"
APPS = [f"10.10.2.{i}" for i in range(30, 38)]
DBS = ["10.10.2.21", "10.10.2.22", "10.10.2.23"]
SQL, FS02 = "10.10.2.24", "10.10.2.26"
SCCM, BACKUP, MON, PRINTSRV, GIT, CI = (f"10.10.2.{i}" for i in range(40, 46))
JUMP02 = "10.10.3.6"
PRINTERS = [f"10.10.4.{i}" for i in range(51, 59)]
CAMERAS = [f"10.10.4.{i}" for i in range(60, 70)]
OFFICE = [f"10.10.3.{i}" for i in range(48, 195)]
LAPTOPS = [f"10.10.7.{i}" for i in range(10, 47)]   # VPN address pool
REMOTE_ENG = LAPTOPS[-1]
CLIENTS = WORKSTATIONS + OFFICE + LAPTOPS
HMI, ENG, HIST, PLC1, PLC2 = (f"10.10.6.{i}" for i in (10, 11, 12, 13, 14))
NEW_SERVERS = APPS + DBS + [SQL, FS02, SCCM, BACKUP, MON, PRINTSRV, GIT, CI]

for i, ip in enumerate(DMZ_WEB, 2):
    HOSTS[ip] = (f"web0{i}.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
HOSTS[MAIL] = ("mail01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
HOSTS[VPN] = ("vpn01.corp.example", "Ivanti Connect Secure 22.3")
HOSTS[PROXY] = ("proxy01.corp.example", "Linux Kernel 4.18 on Red Hat Enterprise Linux 8")
for i, ip in enumerate(APPS, 2):
    HOSTS[ip] = (f"app0{i}.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
for i, ip in enumerate(DBS, 2):
    HOSTS[ip] = (f"db0{i}.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
HOSTS[SQL] = ("sql01.corp.example", "Microsoft Windows Server 2016")
HOSTS[FS02] = ("fs02.corp.example", "Microsoft Windows Server 2019")
HOSTS[SCCM] = ("sccm01.corp.example", "Microsoft Windows Server 2019")
HOSTS[BACKUP] = ("backup01.corp.example", "Microsoft Windows Server 2019")
HOSTS[MON] = ("mon01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
HOSTS[PRINTSRV] = ("print01.corp.example", "Microsoft Windows Server 2016")
HOSTS[GIT] = ("git01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
HOSTS[CI] = ("jenkins01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04")
HOSTS[JUMP02] = ("jump02.corp.example", "Microsoft Windows Server 2022")
for ip in PRINTERS:
    HOSTS[ip] = (f"prn-{ip.split('.')[-1]}.corp.example", _E.choice(["HP LaserJet", "Xerox VersaLink", "Ricoh MP"]))
for ip in CAMERAS:
    HOSTS[ip] = (f"cam-{ip.split('.')[-1]}.corp.example", "Hikvision IP Camera")
for ip in OFFICE:
    HOSTS[ip] = (f"ws-{ip.split('.')[-1]:0>3}.corp.example",
                 _E.choice(["Microsoft Windows 10 Enterprise"] * 3 + ["Microsoft Windows 11 Enterprise"] * 2))
for ip in LAPTOPS:
    HOSTS[ip] = (f"lt-{ip.split('.')[-1]:0>3}.corp.example", "Microsoft Windows 11 Enterprise")
HOSTS[REMOTE_ENG] = ("eng-lt01.corp.example", "Microsoft Windows 11 Enterprise")
HOSTS[HMI] = ("hmi01.plant.example", "Windows 10 IoT Enterprise")
HOSTS[ENG] = ("eng01.plant.example", "Windows 10 Engineering Workstation")
HOSTS[HIST] = ("hist01.plant.example", "Linux Process Historian")
HOSTS[PLC1] = ("plc01.plant.example", "Modbus TCP PLC")
HOSTS[PLC2] = ("plc02.plant.example", "Modbus TCP PLC")


def _v(ip, port, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol, proto="tcp"):
    VULNS.append((ip, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol))


CLIENT_VULNS = [  # plugins a typical client fleet carries, picked per host
    (0, "general", "207053", "Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities", 3, 8.8,
     ["CVE-2024-7965", "CVE-2024-7971"], True, False,
     "The browser installed on the remote host is affected by multiple vulnerabilities.",
     "Upgrade to Microsoft Edge version 129.0.2792.52 or later."),
    (0, "general", "206722", "Google Chrome < 128.0.6613.84 Multiple Vulnerabilities", 3, 8.8,
     ["CVE-2024-7965"], True, False, "The browser installed on the remote host is affected by multiple vulnerabilities.",
     "Upgrade to Google Chrome version 128.0.6613.84 or later."),
    (0, "general", "205440", "KB5041580: Windows 10 Version 22H2 Security Update (August 2024)", 4, 9.8,
     ["CVE-2024-38063"], False, False, "The remote Windows host is missing security update 5041580.",
     "Apply Security Update 5041580."),
    (0, "general", "192951", "Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)", 3, 7.8,
     ["CVE-2024-30284"], False, False, "The PDF reader on the remote host is affected by multiple vulnerabilities.",
     "Upgrade to Adobe Acrobat Reader 24.002.20687 or later."),
    (0, "general", "189385", "7-Zip < 24.07 Code Execution", 3, 7.0, ["CVE-2024-11477"], False, False,
     "The archiver on the remote host is affected by a code execution vulnerability.", "Upgrade to 7-Zip 24.07 or later."),
    (0, "general", "201084", "Zoom Client < 6.0.2 Privilege Escalation", 2, 6.5, ["CVE-2024-27240"], False, False,
     "The Zoom client on the remote host is affected by a privilege escalation vulnerability.",
     "Upgrade to Zoom Client 6.0.2 or later."),
    (445, "cifs", "57608", "SMB Signing not required", 2, 5.3, [], False, False,
     "Signing is not required on the remote SMB server.", "Enforce message signing in the host's configuration."),
]
for ip in OFFICE + LAPTOPS:
    for c in _E.sample(CLIENT_VULNS, _E.randint(1, 3)):
        _v(ip, *c)

for ip in DMZ_WEB:
    _v(ip, 443, "www", "200206", "nginx 1.25.x < 1.25.4 Multiple Vulnerabilities", 3, 7.5, ["CVE-2024-24989"],
       False, False, "The web server is affected by multiple denial of service vulnerabilities.",
       "Upgrade to nginx 1.25.4 or later.")
_v(MAIL, 25, "smtp", "187315", "Postfix SMTP Smuggling", 2, 5.3, ["CVE-2023-51764"], False, False,
   "The mail server is affected by an SMTP smuggling vulnerability.", "Upgrade Postfix and set smtpd_forbid_bare_newline.")
_v(VPN, 443, "www", "189987", "Ivanti Connect Secure Command Injection (CVE-2024-21887)", 4, 9.1,
   ["CVE-2023-46805", "CVE-2024-21887"], True, True,
   "The VPN appliance is affected by authentication bypass and command injection vulnerabilities.",
   "Apply the vendor patch and run the integrity checker.")
_v(PROXY, 3128, "http_proxy", "182251", "Squid < 6.4 Multiple Vulnerabilities", 3, 7.5, ["CVE-2023-46846"],
   False, False, "The proxy is affected by request smuggling and denial of service vulnerabilities.",
   "Upgrade to Squid 6.4 or later.")
for ip in APPS[:3]:
    _v(ip, 8080, "www", "156057", "Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)", 4, 10.0,
       ["CVE-2021-44228"], True, True, "The application uses a Log4j version affected by remote code execution.",
       "Upgrade to Apache Log4j 2.17.1 or later.")
for ip in APPS[3:]:
    _v(ip, 8080, "www", "171340", "Apache Tomcat 9.0.x < 9.0.71 Information Disclosure", 2, 5.3, ["CVE-2023-28708"],
       False, False, "The Tomcat server is affected by an information disclosure vulnerability.",
       "Upgrade to Apache Tomcat 9.0.71 or later.")
for ip in DBS:
    _v(ip, 5432, "postgresql", "183965", "PostgreSQL 13.x < 13.13 Multiple Vulnerabilities", 3, 8.8,
       ["CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870"], False, False,
       "The database server is affected by multiple vulnerabilities including an integer overflow.",
       "Upgrade to PostgreSQL 13.13 or later.")
_v(SQL, 1433, "mssql", "73756", "Microsoft SQL Server Unsupported Version Detection", 4, 10.0, [], False, False,
   "The installed version of SQL Server is no longer supported.", "Upgrade to a supported version of SQL Server.")
_v(FS02, 445, "cifs", "57608", "SMB Signing not required", 2, 5.3, [], False, False,
   "Signing is not required on the remote SMB server.", "Enforce message signing in the host's configuration.")
_v(SCCM, 0, "general", "205440", "KB5041578: Windows Server 2019 Security Update (August 2024)", 4, 9.8,
   ["CVE-2024-38063"], False, False, "The remote Windows host is missing security update 5041578.",
   "Apply Security Update 5041578.")
_v(BACKUP, 9401, "veeam", "173914", "Veeam Backup & Replication Credential Disclosure (CVE-2023-27532)", 4, 7.5,
   ["CVE-2023-27532"], True, True, "The backup service exposes encrypted credentials to unauthenticated users.",
   "Upgrade to Veeam Backup & Replication 12.0.0.1420 P20230223 or later.")
_v(MON, 161, "snmp", "41028", "SNMP Agent Default Community Name (public)", 3, 7.5, ["CVE-1999-0517"], True, False,
   "The community name of the remote SNMP server can be guessed.", "Disable SNMP or change the default community string.",
   proto="udp")
_v(PRINTSRV, 0, "general", "151440", "Windows Print Spooler Service Enabled (PrintNightmare)", 4, 8.8,
   ["CVE-2021-34527"], True, True, "The Print Spooler service on the remote host is affected by remote code execution.",
   "Apply the July 2021 updates and restrict Point and Print.")
_v(GIT, 443, "www", "187600", "GitLab 16.1 < 16.7.2 Account Takeover via Password Reset", 4, 10.0, ["CVE-2023-7028"],
   True, False, "The GitLab instance allows account takeover through the password reset flow.",
   "Upgrade to GitLab 16.7.2 or later and enable two-factor authentication.")
_v(CI, 8080, "www", "189463", "Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897)", 4, 9.8, ["CVE-2024-23897"],
   True, True, "The Jenkins CLI allows unauthenticated reading of arbitrary files.", "Upgrade to Jenkins 2.442 or later.")
_v(JUMP02, 3389, "msrdp", "58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", 2, 4.0,
   [], False, False, "The remote Terminal Services doesn't use NLA only.", "Enable Network Level Authentication.")
for ip in PRINTERS:
    _v(ip, 161, "snmp", "41028", "SNMP Agent Default Community Name (public)", 3, 7.5, ["CVE-1999-0517"], True, False,
       "The community name of the remote SNMP server can be guessed.",
       "Disable SNMP or change the default community string.", proto="udp")
for ip in CAMERAS:
    _v(ip, 80, "www", "153600", "Hikvision IP Camera Command Injection (CVE-2021-36260)", 4, 9.8, ["CVE-2021-36260"],
       True, True, "The camera's web server is affected by an unauthenticated command injection vulnerability.",
       "Upgrade the camera firmware to the vendor's fixed release.")


def _nessus(path):
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name="Quarterly internal scan")
    for ip, (fqdn, os_name) in HOSTS.items():
        rh = ET.SubElement(report, "ReportHost", name=ip)
        hp = ET.SubElement(rh, "HostProperties")
        for k, v in (("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_name)):
            ET.SubElement(hp, "tag", name=k).text = v
        ET.SubElement(rh, "ReportItem", port="0", svc_name="general", protocol="tcp", severity="0",
                      pluginID="19506", pluginName="Nessus Scan Information", pluginFamily="Settings")
        for v in VULNS:
            if v[0] != ip:
                continue
            _, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol = v
            it = ET.SubElement(rh, "ReportItem", port=str(port), svc_name=svc, protocol=proto,
                               severity=str(sev), pluginID=pid, pluginName=name, pluginFamily="General")
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


def _flows(rng):
    """Return (zeek_rows, pan_rows, netflow_rows) as dicts."""
    zeek, pan, nf, threats = [], [], [], []
    span = (ATTACK + timedelta(days=2) - START).total_seconds()

    def t(lo=START, hi=None):
        hi = hi or START + timedelta(seconds=span)
        return lo + timedelta(seconds=rng.uniform(0, (hi - lo).total_seconds()))

    def z(ts, s, d, dp, proto="tcp", svc="-", state="SF", ob=None, rb=None):
        zeek.append(dict(ts=ts, s=s, sp=rng.randint(49152, 65535), d=d, dp=dp, proto=proto, svc=svc,
                         state=state, ob=rng.randint(200, 5000) if ob is None else ob,
                         rb=rng.randint(500, 40000) if rb is None else rb))

    def p(ts, s, d, dp, app, action="allow", fz="untrust", tz="dmz", sent=None, rcvd=None, rule=None):
        pan.append(dict(ts=ts, s=s, sp=rng.randint(1024, 65535), d=d, dp=dp, app=app, action=action,
                        fz=fz, tz=tz, rule=rule, sent=rng.randint(400, 3000) if sent is None else sent,
                        rcvd=(rng.randint(2000, 90000) if action == "allow" else 0) if rcvd is None else rcvd))

    # internet -> web01:443 (normal customers), seen by the firewall
    for _ in range(220):
        p(t(), f"198.51.100.{rng.randint(2, 250)}", "10.10.1.10", 443, "ssl")
    # attacker: exploit, callback, staging upload, then internal probing
    for k in range(4):
        p(ATTACK + timedelta(seconds=k * 7), ATTACKER, "10.10.1.10", 443, "web-browsing")
    threats.append(dict(ts=ATTACK + timedelta(seconds=14), s=ATTACKER, d="10.10.1.10", dp=443, fz="untrust", tz="dmz",
                        name="Apache HTTP Server Path Traversal Vulnerability CVE-2021-41773(91694)",
                        sev="critical", action="alert"))
    p(ATTACK + timedelta(minutes=1), "10.10.1.10", ATTACKER, 4444, "unknown-tcp", fz="dmz", tz="untrust")
    p(ATTACK + timedelta(minutes=40), "10.10.1.10", ATTACKER, 443, "ssl", fz="dmz", tz="untrust",
      sent=62_000_000, rcvd=4000)
    for k, dst in enumerate(["10.10.2.25", "10.10.3.31", "10.10.6.70"]):
        dp = 445 if dst != "10.10.3.31" else 3389
        z(ATTACK + timedelta(minutes=55 + k), "10.10.1.10", dst, dp, svc="smb" if dp == 445 else "rdp")
    # internet scanning noise against RDP and SSH, blocked at the perimeter
    for _ in range(60):
        p(t(), f"192.0.2.{rng.randint(2, 250)}", "10.10.3.31", 3389, "incomplete", action="deny", tz="trust")
    for _ in range(3):  # IPS saw BlueKeep probes and reset them
        threats.append(dict(ts=t(), s=f"192.0.2.{rng.randint(2, 250)}", d="10.10.3.31", dp=3389, fz="untrust", tz="trust",
                            name="Microsoft RDP Remote Code Execution Vulnerability CVE-2019-0708(55188)",
                            sev="critical", action="reset-both"))
    for _ in range(25):
        p(t(), f"192.0.2.{rng.randint(2, 250)}", "10.10.1.10", 22, "incomplete", action="deny")
    # workstations browsing out
    for _ in range(150):
        p(t(), rng.choice(WORKSTATIONS), f"93.184.{rng.randint(0, 255)}.{rng.randint(1, 254)}", 443, "ssl",
          fz="trust", tz="untrust")
    # Synthetic OT lead: periodic external contact from the engineering station.
    for k in range(3):
        p(OT_ACTIVITY - timedelta(minutes=15 - 5 * k), ENG, OT_EXTERNAL, 443, "ssl",
          fz="ot", tz="untrust", sent=1500 + k * 120, rcvd=800 + k * 80)
    for k in range(2):
        p(OT_ACTIVITY - timedelta(minutes=35 - 10 * k), REMOTE_ENG, OT_EXTERNAL, 443, "ssl",
          fz="vpn", tz="untrust", sent=1100 + k * 90, rcvd=650 + k * 50)
    # Authorized remote engineer access through a synthetic GlobalProtect VPN policy.
    for k in range(2):
        p(OT_ACTIVITY - timedelta(minutes=20 - 5 * k), REMOTE_ENG, ENG, 3389, "ms-rdp",
          fz="vpn", tz="ot", rule="GlobalProtect-Engineer-VPN")

    # east-west, seen by Zeek on the core switch
    for _ in range(120):
        z(t(), "10.10.1.10", "10.10.1.20", 8009, svc="ajp")
    for _ in range(40):
        z(t(), "10.10.1.10", "10.10.0.53", 53, proto="udp", svc="dns")
    for _ in range(140):
        z(t(), "10.10.1.20", "10.10.2.20", 5432, svc="postgresql")
    # Small, synthetic packaging line: HMI polls PLCs and the historian collects data.
    for plc in (PLC1, PLC2):
        for k in range(4):
            z(START + timedelta(days=3, minutes=5 * k), HMI, plc, 502, svc="modbus")
    for k in range(3):
        z(START + timedelta(days=3, minutes=7 * k), HMI, HIST, 4840, svc="opcua")
    for ws in WORKSTATIONS:
        for _ in range(25):
            z(t(), ws, "10.10.2.25", 445, svc="smb")
        for _ in range(10):
            z(t(), ws, "10.10.0.10", 88, svc="krb")
            z(t(), ws, "10.10.0.10", 389, svc="ldap")
        for _ in range(6):
            z(t(), ws, "10.10.0.53", 53, proto="udp", svc="dns")
    for _ in range(30):
        z(t(), "10.10.3.5", "10.10.3.31", 3389, svc="rdp")
        z(t(), "10.10.3.5", "10.10.2.20", 22, svc="ssh")
    for _ in range(8):  # SYNs to the printer's web UI, never answered
        z(t(), "10.10.3.42", "10.10.4.50", 80, svc="-", state="S0", rb=0)
    z(t(), "10.10.3.41", "10.10.3.31", 445, state="REJ", ob=0, rb=0)
    # one malformed row to show cleaning
    zeek.append(dict(ts=t(), s="not-an-ip", sp=1, d="10.10.2.25", dp=445, proto="tcp", svc="-",
                     state="SF", ob=1, rb=1))

    # a segment only covered by NetFlow
    for _ in range(80):
        nf.append(dict(ts=t(), s=rng.choice(WORKSTATIONS), d="10.10.6.70", sp=rng.randint(49152, 65535),
                       dp=rng.choice([445, 3389]), bytes=rng.randint(1000, 90000)))
    for _ in range(30):
        nf.append(dict(ts=t(), s="10.10.2.20", d="10.10.6.71", sp=rng.randint(49152, 65535), dp=8443,
                       bytes=rng.randint(1000, 90000)))
    nf.append(dict(ts=t(), s="10.10.3.40", d="10.10.6.71", sp=50000, dp=8443, bytes=500))
    nf.append(nf[-1])  # exact duplicate, removed during cleaning
    _estate_flows(random.Random(rng.random()), t, zeek, pan)
    return zeek, pan, nf, threats


def _estate_flows(rng, t, zeek, pan):
    """Background traffic for the rest of the estate. Nothing here is suspicious on purpose."""
    def z(s, d, dp, n, proto="tcp", svc="-", state="SF"):
        for _ in range(n):
            zeek.append(dict(ts=t(), s=s, sp=rng.randint(49152, 65535), d=d, dp=dp, proto=proto, svc=svc,
                             state=state, ob=0 if state != "SF" else rng.randint(200, 6000),
                             rb=0 if state != "SF" else rng.randint(500, 60000)))

    def p(s, d, dp, app, n, action="allow", fz="trust", tz="untrust", big=False):
        for _ in range(n):
            ok = action == "allow"
            pan.append(dict(ts=t(), s=s() if callable(s) else s, sp=rng.randint(1024, 65535),
                            d=d() if callable(d) else d, dp=dp, app=app, action=action, fz=fz, tz=tz,
                            sent=rng.randint(400, 3000), rcvd=rng.randint(2000, 400000 if big else 90000) if ok else 0))

    # an outside address under `prefix`; a two-part prefix such as 93.184 also needs a third octet,
    # which comes from its own generator so the rest of the sample is unchanged
    mid = random.Random(4096)

    def ext(prefix):
        missing = 2 - prefix.count(".")
        return lambda: prefix + "".join(f".{mid.randint(0, 255)}" for _ in range(missing)) + f".{rng.randint(1, 254)}"

    # east/west: every client logs on, resolves names, maps drives, prints and uses the proxy and apps
    for ws in OFFICE + LAPTOPS:
        z(ws, "10.10.0.10", 88, rng.randint(2, 5), svc="krb")
        z(ws, "10.10.0.10", 389, rng.randint(2, 5), svc="ldap")
        z(ws, "10.10.0.53", 53, rng.randint(2, 6), proto="udp", svc="dns")
        z(ws, rng.choice(["10.10.2.25", FS02, FS02]), 445, rng.randint(3, 10), svc="smb")
        z(ws, PROXY, 3128, rng.randint(4, 12), svc="http")
        z(ws, rng.choice(APPS), 8080, rng.randint(1, 4), svc="http")
        z(ws, SCCM, 8530, rng.randint(1, 2), svc="http")
        if rng.random() < 0.5:
            z(ws, PRINTSRV, 445, rng.randint(1, 2), svc="smb")
        if rng.random() < 0.12:     # developers
            z(ws, GIT, 443, rng.randint(2, 6), svc="ssl")
            z(ws, GIT, 22, rng.randint(1, 3), svc="ssh")
            z(ws, CI, 8080, rng.randint(1, 3), svc="http")
    for ws in OFFICE[::9]:          # software pushes from SCCM to a slice of the fleet
        z(SCCM, ws, 445, 2, svc="smb")
        z(SCCM, ws, 135, 1, svc="dce_rpc")
    for k, web in enumerate(DMZ_WEB):
        z(web, APPS[k], 8080, rng.randint(60, 90), svc="http")
        z(web, "10.10.0.53", 53, 10, proto="udp", svc="dns")
    for app in APPS:
        z(app, rng.choice(DBS), 5432, rng.randint(40, 80), svc="postgresql")
        z(app, "10.10.0.10", 389, 4, svc="ldap")
    for app in APPS[::2]:
        z(app, SQL, 1433, rng.randint(20, 40), svc="tds")
    z(DBS[0], DBS[1], 5432, 30, svc="postgresql")      # replication
    z(CI, GIT, 22, 40, svc="ssh")
    z(CI, APPS[5], 22, 12, svc="ssh")                   # deployments
    z(MAIL, "10.10.0.10", 389, 20, svc="ldap")
    z(PROXY, "10.10.0.53", 53, 60, proto="udp", svc="dns")
    z(PRINTSRV, "10.10.0.10", 389, 6, svc="ldap")
    for prn in PRINTERS:
        z(PRINTSRV, prn, 9100, rng.randint(10, 30), svc="-")
        z(MON, prn, 161, 6, proto="udp", svc="snmp")
    for cam in CAMERAS:
        z(MON, cam, 80, 4, svc="http")
        z(MON, cam, 554, 6, svc="rtsp")
    for srv in NEW_SERVERS + DMZ_WEB + [MAIL, PROXY, VPN]:
        if srv != MON:
            z(MON, srv, 161, 3, proto="udp", svc="snmp")
        if srv not in (BACKUP, MON, VPN):
            z(BACKUP, srv, 445 if srv in (SQL, FS02, SCCM, PRINTSRV) else 22, 2,
              svc="smb" if srv in (SQL, FS02, SCCM, PRINTSRV) else "ssh")
    for srv in [SQL, FS02, SCCM, BACKUP, PRINTSRV]:
        z(JUMP02, srv, 3389, rng.randint(3, 8), svc="rdp")
    for srv in APPS + DBS + [GIT, CI, MON]:
        z(JUMP02, srv, 22, rng.randint(2, 6), svc="ssh")
    z(SCCM, BACKUP, 9401, 4, svc="-")                   # backup console
    z(OFFICE[3], "10.10.3.90", 445, 3, state="REJ")     # peer-to-peer SMB refused
    z(OFFICE[7], CAMERAS[2], 80, 4, state="S0")         # a user poking at a camera's web UI

    # north/south through the firewall
    for web in DMZ_WEB:
        p(ext("198.51.100"), web, 443, "ssl", rng.randint(60, 120), fz="untrust", tz="dmz")
    p(ext("209.85.220"), MAIL, 25, "smtp", 90, fz="untrust", tz="dmz")          # inbound mail
    p(MAIL, ext("40.107.22"), 25, "smtp", 70, fz="dmz", tz="untrust")           # outbound mail
    p(ext("73.162"), VPN, 443, "ssl", 160, fz="untrust", tz="dmz")              # staff on VPN
    p(ext("24.18"), VPN, 443, "ssl", 90, fz="untrust", tz="dmz")
    p(PROXY, ext("93.184"), 443, "ssl", 380, fz="dmz", big=True)                # browsing via the proxy
    p(PROXY, ext("151.101"), 443, "ssl", 160, fz="dmz", big=True)
    p(PROXY, ext("142.250"), 80, "web-browsing", 60, fz="dmz")
    p(SCCM, ext("13.107.4"), 443, "ms-update", 40, big=True)
    p(GIT, ext("140.82.112"), 443, "github", 25)
    p(CI, ext("104.16.24"), 443, "ssl", 30)                                     # package mirrors
    for cam in CAMERAS:                                                         # IoT cloud check-ins
        p(cam, ext("47.88.59"), 443, "ssl", rng.randint(3, 8))
    p(lambda: rng.choice(OFFICE), ext("93.184"), 443, "ssl", 120, action="deny")  # direct browsing blocked
    p(lambda: rng.choice(OFFICE), "8.8.8.8", 53, "dns", 40, action="deny")        # outside DNS blocked
    p(ext("192.0.2"), VPN, 22, "incomplete", 45, action="deny", fz="untrust", tz="dmz")
    p(ext("192.0.2"), MAIL, 3389, "incomplete", 30, action="deny", fz="untrust", tz="dmz")
    p(ext("198.18.0"), lambda: rng.choice(DMZ_WEB), 8080, "incomplete", 50, action="deny",
      fz="untrust", tz="dmz")


def generate(outdir: str, seed: int = 7) -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(seed)
    zeek, pan, nf, threats = _flows(rng)
    paths = []

    p = os.path.join(outdir, "zeek_conn.log")
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
              "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
    with open(p, "w") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        fh.write("#fields\t" + "\t".join(fields) + "\n")
        for i, r in enumerate(sorted(zeek, key=lambda r: r["ts"])):
            fh.write("\t".join([f"{r['ts'].timestamp():.6f}", f"C{i:08x}", r["s"], str(r["sp"]), r["d"],
                                str(r["dp"]), r["proto"], r["svc"], f"{rng.uniform(0.01, 30):.3f}",
                                str(r["ob"]), str(r["rb"]), r["state"], "ShADadFf" if r["state"] == "SF" else "S"]) + "\n")
        fh.write("#close\t2026-10-18-23-59-59\n")
    paths.append(p)

    p = os.path.join(outdir, "modbus.log")
    with open(p, "w") as fh:
        for i, plc in enumerate((PLC1, PLC2)):
            for k in range(2):
                event = {"ts": (START + timedelta(days=3, minutes=10 * k + i)).timestamp(),
                         "uid": f"OT{i}{k}", "id.orig_h": HMI, "id.orig_p": 51000 + i * 10 + k,
                         "id.resp_h": plc, "id.resp_p": 502, "is_orig": True,
                         "func": "READ_HOLDING_REGISTERS" if k == 0 else "READ_INPUT_REGISTERS"}
                fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    paths.append(p)

    p = os.path.join(outdir, "paloalto_traffic.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["Receive Time", "Serial #", "Type", "Threat/Content Type", "Source address",
                    "Destination address", "Rule", "Application", "Source Zone", "Destination Zone",
                    "Source Port", "Destination Port", "IP Protocol", "Action", "Bytes", "Bytes Sent",
                    "Bytes Received", "Start Time", "Threat/Content Name", "Severity"])
        rows = [("TRAFFIC", r) for r in pan] + [("THREAT", r) for r in threats]
        for kind, r in sorted(rows, key=lambda x: x[1]["ts"]):
            ts = r["ts"].strftime("%Y/%m/%d %H:%M:%S")
            if kind == "THREAT":
                w.writerow([ts, "016401000001", "THREAT", "vulnerability", r["s"], r["d"], "allow-web", "web-browsing",
                            r["fz"], r["tz"], rng.randint(1024, 65535), r["dp"], "tcp", r["action"], "", "", "", "",
                            r["name"], r["sev"]])
                continue
            w.writerow([ts, "016401000001", "TRAFFIC", "end", r["s"], r["d"],
                        r.get("rule") or ("allow-web" if r["action"] == "allow" else "default-deny"),
                        r["app"], r["fz"], r["tz"],
                        r["sp"], r["dp"], "tcp", r["action"], r["sent"] + r["rcvd"], r["sent"], r["rcvd"], ts, "", ""])
    paths.append(p)

    p = os.path.join(outdir, "netflow_segment6.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["ts", "sa", "da", "sp", "dp", "pr", "ibyt"])
        for r in nf:
            w.writerow([r["ts"].strftime("%Y-%m-%d %H:%M:%S"), r["s"], r["d"], r["sp"], r["dp"], "TCP", r["bytes"]])
    paths.append(p)

    p = os.path.join(outdir, "quarterly_scan.nessus")
    _nessus(p)
    paths.append(p)
    return paths


def generate_bundles(outdir: str, seed: int = 7) -> list[str]:
    """Write the scan-backed example, a matching network-only example, the large
    4,324-host on-prem + AWS example, the Gootloader intrusion replay and the two-company
    Compare sample (whose Ridgeline head office is the Gootloader replay)."""
    from . import sample_compare, sample_gootloader, sample_hosts
    full = generate(os.path.join(outdir, "scan_and_telemetry"), seed)
    telemetry_dir = os.path.join(outdir, "telemetry_only")
    os.makedirs(telemetry_dir, exist_ok=True)
    copied = []
    for path in full:
        if path.endswith(".nessus"):
            continue
        target = os.path.join(telemetry_dir, os.path.basename(path))
        shutil.copy2(path, target)
        copied.append(target)
    hosts = sample_hosts.generate(os.path.join(outdir, sample_hosts.FOLDER))
    goot = sample_gootloader.generate(os.path.join(outdir, sample_gootloader.FOLDER))
    two = sample_compare.generate(os.path.join(outdir, sample_compare.FOLDER))
    return full + copied + hosts + goot + two
