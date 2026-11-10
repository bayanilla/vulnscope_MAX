"""Generate the large host sample: a fictional 4,324-host company whose network extends into AWS.

On premises (10.40.0.0/16, "hq.example"): core network and identity services, a server room with
VMware, SQL and an on-prem Kubernetes cluster, 2,400 Windows desktops, 400 Macs, Linux developer
machines, VoIP phones, printers, Wi-Fi access points, cameras and building systems.

AWS extension, reached over a site-to-site VPN that lands on the Palo Alto firewall's "aws" zone:
  - prod VPC 10.60.0.0/16 in us-east-2: web, API and worker instances, EKS nodes, RDS, cache, Kafka.
  - dev VPC 10.61.0.0/16 in us-west-2: developer instances, EKS nodes, CI runners and a sandbox.
Cloud traffic comes from VPC Flow Logs (default version 2 format). Every one of the 4,324 internal
hosts is in the Nessus scan, and every one appears in at least one log, so the run shows exactly
4,324 hosts. Outside addresses come from full /24 prefixes, so every generated address is valid.

Investigation leads (fictional, for demonstration only):
  - fw01's GlobalProtect portal trips IPS signatures for CVE-2024-3400 from outside (reset).
  - web-prod-07 (Log4Shell on 443 in the scan) is reached by 203.0.113.66, then connects back to it
    on 4444 and later sends it ~46 MB: a return-connection and large-upload lead (no IPS in AWS).
  - sbx-dev-03 has SSH open to the internet; a burst of attempts, a few accepted.
  - Workstations reach ESXi OpenSLP (427/udp) on hosts the scan flags for CVE-2021-21974.
"""
from __future__ import annotations

import csv
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
import os

START = datetime(2026, 10, 19, tzinfo=timezone.utc)
END = START + timedelta(days=2)
TOTAL_HOSTS = 4324
FOLDER = "hosts_onprem_and_aws"
ACCOUNT = {"prod": "111122223333", "dev": "444455556666"}      # documentation-style account ids

# Outside addresses: whole /24 prefixes only (reserved documentation ranges where it matters).
GP_SCANNER = "192.0.2"           # probes against the GlobalProtect portal
C2_LIKE = "203.0.113.66"         # outbound lead from web-prod-07
SSH_BRUTE = "198.51.100"         # SSH attempts against the dev sandbox
CUSTOMERS = ["198.18.4", "198.18.9", "198.19.20", "198.19.77"]   # benchmarking range, used as "customers"
STAFF_HOME = ["198.18.30", "198.18.31", "198.19.60"]
SAAS = ["151.101.65", "142.250.72", "13.107.42", "140.82.113", "104.16.24", "52.96.40"]
AWS_PUBLIC = ["52.219.100", "52.95.150", "3.5.140"]           # S3 / service endpoints seen from the VPCs
VPN_PEER_PROD, VPN_PEER_DEV = "52.15.20.10", "54.70.33.20"     # AWS side of the site-to-site tunnels
HQ_PUBLIC = "203.0.113.10"

# ip -> (fqdn, os, role, place)
HOSTS: dict[str, tuple[str, str, str, str]] = {}
VULNS: list[tuple] = []


def _ip(net, i):
    """Spread index i over a /20-ish block: net='10.40.32' -> 10.40.(32 + i//250).(i%250 + 2)."""
    a, b, c = net.split(".")
    return f"{a}.{b}.{int(c) + i // 250}.{i % 250 + 2}"


def _add(ip, name, os_name, role, place="onprem"):
    assert ip not in HOSTS, ip
    HOSTS[ip] = (name, os_name, role, place)
    return ip


def _build(rng: random.Random):
    HOSTS.clear()
    VULNS.clear()
    d = "hq.example"
    # -- core network and identity ----------------------------------------------------------
    g = {}
    g["dc"] = [_add(f"10.40.0.{10 + i}", f"dc0{i + 1}.{d}", "Microsoft Windows Server 2022", "dc") for i in range(4)]
    g["dns"] = [_add(f"10.40.0.{20 + i}", f"dns0{i + 1}.{d}", "Linux Kernel 5.14 on Red Hat Enterprise Linux 9", "dns")
                for i in range(2)]
    g["dhcp"] = [_add(f"10.40.0.{25 + i}", f"dhcp0{i + 1}.{d}", "Microsoft Windows Server 2019", "dhcp") for i in range(2)]
    g["ntp"] = [_add("10.40.0.30", f"ntp01.{d}", "Linux Kernel 5.15 on Ubuntu 22.04", "ntp")]
    g["pki"] = [_add("10.40.0.31", f"pki01.{d}", "Microsoft Windows Server 2019", "pki")]
    g["radius"] = [_add("10.40.0.32", f"nps01.{d}", "Microsoft Windows Server 2022", "radius")]
    g["fw"] = [_add(f"10.40.0.{1 + i}", f"fw0{i + 1}.{d}", "Palo Alto Networks PAN-OS 11.1", "fw") for i in range(2)]
    g["core"] = [_add(f"10.40.0.{3 + i}", f"core-sw0{i + 1}.{d}", "Cisco IOS XE 17.6", "switch") for i in range(2)]
    g["dist"] = [_add(f"10.40.0.{40 + i}", f"dist-sw{i + 1:02}.{d}", "Cisco IOS XE 17.9", "switch") for i in range(12)]
    g["wlc"] = [_add(f"10.40.0.{60 + i}", f"wlc0{i + 1}.{d}", "Aruba Mobility Conductor 8.10", "wlc") for i in range(2)]

    # -- server room: 360 servers --------------------------------------------------------------
    srv = iter(range(400))
    nxt = lambda: _ip("10.40.8", next(srv))
    def many(key, n, pat, os_choices, role):
        g[key] = [_add(nxt(), pat.format(i + 1) + "." + d, rng.choice(os_choices), role) for i in range(n)]
    many("esx", 24, "esx{:02}", ["VMware ESXi 7.0.3"], "esxi")
    many("vc", 1, "vcenter{:02}", ["VMware vCenter Server Appliance 7.0"], "vcenter")
    many("nas", 4, "nas{:02}", ["Synology DiskStation Manager 7.1"], "nas")
    many("sql", 12, "sql{:02}", ["Microsoft Windows Server 2016", "Microsoft Windows Server 2019"], "sql")
    many("ora", 4, "ora{:02}", ["Linux Kernel 4.18 on Oracle Linux 8"], "oracle")
    many("web", 20, "intranet{:02}", ["Linux Kernel 5.15 on Ubuntu 22.04", "Microsoft Windows Server 2019"], "web")
    many("app", 60, "app{:02}", ["Linux Kernel 5.14 on Red Hat Enterprise Linux 9", "Linux Kernel 5.15 on Ubuntu 22.04",
                                 "Microsoft Windows Server 2022"], "app")
    many("fs", 8, "fs{:02}", ["Microsoft Windows Server 2019", "Microsoft Windows Server 2022"], "file")
    many("prt", 4, "print{:02}", ["Microsoft Windows Server 2016"], "printsrv")
    many("bk", 6, "backup{:02}", ["Microsoft Windows Server 2019"], "backup")
    many("mon", 4, "mon{:02}", ["Linux Kernel 5.15 on Ubuntu 22.04"], "monitoring")
    many("siem", 3, "siem{:02}", ["Linux Kernel 5.14 on Red Hat Enterprise Linux 9"], "siem")
    many("dev", 4, "git{:02}", ["Linux Kernel 5.15 on Ubuntu 22.04"], "devtools")
    many("k8s", 30, "k8s-node{:02}", ["Linux Kernel 5.15 on Ubuntu 22.04"], "k8s")
    many("wsus", 2, "wsus{:02}", ["Microsoft Windows Server 2019"], "wsus")
    rest = 360 - sum(len(v) for k, v in g.items() if k in
                     "esx vc nas sql ora web app fs prt bk mon siem dev k8s wsus".split())
    many("misc", rest, "srv{:03}", ["Microsoft Windows Server 2016", "Microsoft Windows Server 2019",
                                    "Microsoft Windows Server 2022", "Linux Kernel 5.14 on Red Hat Enterprise Linux 9",
                                    "Linux Kernel 3.10 on CentOS Linux 7"], "server")

    # -- clients and devices ------------------------------------------------------------------
    g["ws"] = [_add(_ip("10.40.32", i), f"ws-{i + 1:04}.{d}",
                    rng.choice(["Microsoft Windows 10 Enterprise"] * 2 + ["Microsoft Windows 11 Enterprise"] * 3),
                    "workstation") for i in range(2400)]
    g["mac"] = [_add(_ip("10.40.48", i), f"mac-{i + 1:03}.{d}", rng.choice(["macOS 14.6", "macOS 15.1", "macOS 13.6"]),
                     "mac") for i in range(400)]
    g["lnx"] = [_add(_ip("10.40.52", i), f"dev-{i + 1:03}.{d}",
                     rng.choice(["Linux Kernel 6.8 on Ubuntu 24.04", "Linux Kernel 6.11 on Fedora 41"]), "linux-desktop")
                for i in range(120)]
    g["phone"] = [_add(_ip("10.40.64", i), f"sep-{i + 1:03}.{d}", rng.choice(["Cisco IP Phone 8845", "Poly VVX 450"]),
                       "phone") for i in range(300)]
    g["printer"] = [_add(_ip("10.40.70", i), f"prn-{i + 1:02}.{d}", rng.choice(["HP LaserJet", "Xerox VersaLink",
                                                                               "Ricoh IM C3000"]), "printer")
                    for i in range(60)]
    g["ap"] = [_add(_ip("10.40.72", i), f"ap-{i + 1:02}.{d}", "Aruba AP-535 (ArubaOS 8.10)", "ap") for i in range(80)]
    g["cam"] = [_add(_ip("10.40.74", i), f"cam-{i + 1:02}.{d}", "Axis Network Camera (AXIS OS 10.12)", "camera")
                for i in range(90)]
    iot = [("badge", 30, "badge-{:02}", "HID VertX EVO V2000"), ("hvac", 12, "hvac-{:02}", "Tridium Niagara 4 JACE"),
           ("ups", 10, "ups-{:02}", "APC Network Management Card 2"), ("screen", 20, "screen-{:02}", "Android TV 11")]
    k = 0
    for key, n, pat, os_name in iot:
        g[key] = [_add(_ip("10.40.76", k + i), pat.format(i + 1) + "." + d, os_name, "iot") for i in range(n)]
        k += n

    # -- AWS ------------------------------------------------------------------------------------
    def ec2(key, vpc, n, pat, os_choices, role, region):
        base = "10.60" if vpc == "prod" else "10.61"
        start = len([h for h in HOSTS.values() if h[3] == f"aws-{vpc}"])
        out = []
        for i in range(n):
            j = start + i
            ip = f"{base}.{j // 200 + (1 if vpc == 'prod' else 1)}.{j % 200 + 10}"
            out.append(_add(ip, f"{pat.format(i + 1)}.{region}.aws.example", rng.choice(os_choices), role, f"aws-{vpc}"))
        g[key] = out
    al = ["Amazon Linux 2023", "Amazon Linux 2"]
    ec2("w_prod", "prod", 40, "web-prod-{:02}", al, "ec2-web", "use2")
    ec2("api_prod", "prod", 80, "api-prod-{:02}", al + ["Linux Kernel 6.8 on Ubuntu 24.04"], "ec2-api", "use2")
    ec2("wrk_prod", "prod", 60, "worker-prod-{:02}", al, "ec2-worker", "use2")
    ec2("eks_prod", "prod", 60, "eks-prod-{:02}", ["Bottlerocket OS 1.20"], "eks", "use2")
    ec2("bast_prod", "prod", 2, "bastion-prod-{:02}", ["Amazon Linux 2023"], "bastion", "use2")
    ec2("rds_prod", "prod", 6, "rds-prod-{:02}", ["Amazon RDS for PostgreSQL 15"], "rds", "use2")
    ec2("cache_prod", "prod", 6, "cache-prod-{:02}", ["Amazon ElastiCache for Redis 7"], "cache", "use2")
    ec2("kafka_prod", "prod", 6, "kafka-prod-{:02}", ["Amazon MSK (Kafka 3.6)"], "kafka", "use2")
    ec2("batch_prod", "prod", 20, "batch-prod-{:02}", al, "ec2-batch", "use2")
    ec2("ad_dev", "dev", 2, "adc-dev-{:02}", ["Microsoft Windows Server 2022"], "dc", "usw2")
    ec2("bast_dev", "dev", 1, "bastion-dev-{:02}", ["Amazon Linux 2023"], "bastion", "usw2")
    ec2("box_dev", "dev", 60, "dev-box-{:02}", al + ["Linux Kernel 6.8 on Ubuntu 24.04", "Microsoft Windows Server 2022"],
        "ec2-dev", "usw2")
    ec2("eks_dev", "dev", 40, "eks-dev-{:02}", ["Bottlerocket OS 1.20"], "eks", "usw2")
    ec2("ci_dev", "dev", 20, "ci-runner-dev-{:02}", al, "ci", "usw2")
    ec2("sbx_dev", "dev", 10, "sbx-dev-{:02}", ["Linux Kernel 5.15 on Ubuntu 22.04", "Linux Kernel 5.4 on Ubuntu 20.04"],
        "sandbox", "usw2")
    assert len(HOSTS) == TOTAL_HOSTS, len(HOSTS)
    return g


def _v(ip, port, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol, proto="tcp"):
    VULNS.append((ip, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol))


def _vulns(g, rng):
    win_client = [
        (0, "general", "205440", "KB5041580: Windows 10 Version 22H2 Security Update (August 2024)", 4, 9.8,
         ["CVE-2024-38063"], False, False, "The remote Windows host is missing security update 5041580.",
         "Apply Security Update 5041580."),
        (0, "general", "207053", "Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities", 3, 8.8,
         ["CVE-2024-7965", "CVE-2024-7971"], True, False,
         "The browser installed on the remote host is affected by multiple vulnerabilities.",
         "Upgrade to Microsoft Edge version 129.0.2792.52 or later."),
        (0, "general", "192951", "Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)", 3, 7.8,
         ["CVE-2024-30284"], False, False, "The PDF reader on the remote host is affected by multiple vulnerabilities.",
         "Upgrade to Adobe Acrobat Reader 24.002.20687 or later."),
        (0, "general", "189385", "7-Zip < 24.07 Code Execution", 3, 7.0, ["CVE-2024-11477"], False, False,
         "The archiver on the remote host is affected by a code execution vulnerability.", "Upgrade to 7-Zip 24.07 or later."),
        (445, "cifs", "57608", "SMB Signing not required", 2, 5.3, [], False, False,
         "Signing is not required on the remote SMB server.", "Enforce message signing in the host's configuration."),
    ]
    for ip in g["ws"]:
        if rng.random() < 0.7:                       # 30% of desktops are fully patched
            for c in rng.sample(win_client, rng.randint(1, 3)):
                _v(ip, *c)
    for ip in g["mac"]:
        if rng.random() < 0.45:
            _v(ip, 0, "general", "209260", "macOS 14.x < 14.7.1 Multiple Vulnerabilities", 3, 7.8, ["CVE-2024-44236"],
               False, False, "The remote macOS host is missing a security update.", "Upgrade to macOS 14.7.1 or later.")
        if rng.random() < 0.2:
            _v(ip, 0, "general", "206722", "Google Chrome < 128.0.6613.84 Multiple Vulnerabilities", 3, 8.8,
               ["CVE-2024-7965"], True, False, "The browser installed on the remote host is affected by multiple vulnerabilities.",
               "Upgrade to Google Chrome version 128.0.6613.84 or later.")
    for ip in g["lnx"]:
        if rng.random() < 0.3:
            _v(ip, 22, "ssh", "187201", "OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin)", 2, 5.9, ["CVE-2023-48795"],
               False, False, "The SSH server is affected by a prefix truncation weakness.", "Upgrade to OpenSSH 9.6 or later.")
    _v(g["fw"][0], 443, "www", "193237", "Palo Alto GlobalProtect OS Command Injection (CVE-2024-3400)", 4, 10.0,
       ["CVE-2024-3400"], True, True, "The GlobalProtect gateway is affected by an unauthenticated command injection.",
       "Upgrade PAN-OS to 11.1.2-h3 or later.")
    for ip in g["core"] + g["dist"][:4]:
        _v(ip, 443, "www", "182913", "Cisco IOS XE Web UI Privilege Escalation (CVE-2023-20198)", 4, 10.0,
           ["CVE-2023-20198"], True, True, "The web UI allows an unauthenticated attacker to create an account.",
           "Disable the HTTP server feature or upgrade to a fixed release.")
    for ip in g["esx"][:16]:
        _v(ip, 427, "slp", "171354", "VMware ESXi OpenSLP Heap Overflow (CVE-2021-21974)", 4, 8.8, ["CVE-2021-21974"],
           True, True, "The ESXi host is affected by a heap overflow in OpenSLP.",
           "Apply VMSA-2021-0002 and disable the SLP service.", proto="udp")
    _v(g["vc"][0], 443, "www", "146825", "VMware vCenter Server RCE (CVE-2021-21972)", 4, 9.8, ["CVE-2021-21972"],
       True, True, "The vSphere Client plugin allows remote code execution.", "Apply VMSA-2021-0002.")
    for ip in g["nas"]:
        _v(ip, 5001, "www", "190451", "Synology DSM < 7.2.1 Multiple Vulnerabilities", 3, 7.5, ["CVE-2023-52941"],
           False, False, "The NAS is affected by multiple vulnerabilities.", "Upgrade to DSM 7.2.1 or later.")
    for ip in g["sql"][:5]:
        _v(ip, 1433, "mssql", "73756", "Microsoft SQL Server Unsupported Version Detection", 4, 10.0, [], False, False,
           "The installed version of SQL Server is no longer supported.", "Upgrade to a supported version of SQL Server.")
    for ip in g["app"][:9]:
        _v(ip, 8080, "www", "156057", "Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)", 4, 10.0,
           ["CVE-2021-44228"], True, True, "The application uses a Log4j version affected by remote code execution.",
           "Upgrade to Apache Log4j 2.17.1 or later.")
    for ip in g["misc"]:
        if "CentOS Linux 7" in HOSTS[ip][1]:
            _v(ip, 0, "general", "201352", "CentOS 7 End of Life", 4, 10.0, [], False, False,
               "The remote host runs an operating system that is no longer supported.", "Migrate to a supported OS.")
    for ip in g["prt"]:
        _v(ip, 0, "general", "151440", "Windows Print Spooler Service Enabled (PrintNightmare)", 4, 8.8,
           ["CVE-2021-34527"], True, True, "The Print Spooler service is affected by remote code execution.",
           "Apply the July 2021 updates and restrict Point and Print.")
    _v(g["bk"][0], 9401, "veeam", "173914", "Veeam Backup & Replication Credential Disclosure (CVE-2023-27532)", 4, 7.5,
       ["CVE-2023-27532"], True, True, "The backup service exposes encrypted credentials to unauthenticated users.",
       "Upgrade to Veeam Backup & Replication 12.0.0.1420 P20230223 or later.")
    for ip in g["printer"]:
        _v(ip, 161, "snmp", "41028", "SNMP Agent Default Community Name (public)", 3, 7.5, ["CVE-1999-0517"], True, False,
           "The community name of the remote SNMP server can be guessed.",
           "Disable SNMP or change the default community string.", proto="udp")
    for ip in g["phone"][::3]:
        _v(ip, 5060, "sip", "64585", "SIP Server Cleartext Signaling", 2, 5.3, [], False, False,
           "The phone accepts SIP signaling without TLS.", "Enable SIP over TLS and SRTP.", proto="udp")
    for ip in g["cam"][:30]:
        _v(ip, 80, "www", "45411", "Web Server Uses Basic Authentication Without HTTPS", 2, 5.3, [], False, False,
           "The camera's web interface sends credentials in cleartext.", "Enable HTTPS and disable HTTP.")
    for ip in g["hvac"]:
        _v(ip, 47808, "bacnet", "142710", "BACnet Device Allows Unauthenticated Writes", 3, 8.2, [], False, False,
           "The building controller accepts BACnet write requests without authentication.",
           "Restrict BACnet to the building management network and enable BACnet/SC.", proto="udp")
    for ip in g["badge"]:
        _v(ip, 23, "telnet", "42263", "Unencrypted Telnet Server", 2, 6.5, [], False, False,
           "The remote Telnet server transmits traffic in cleartext.", "Disable Telnet and use SSH instead.")
    # AWS
    for ip in g["w_prod"][:10]:
        _v(ip, 443, "www", "156057", "Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)", 4, 10.0,
           ["CVE-2021-44228"], True, True, "The application uses a Log4j version affected by remote code execution.",
           "Upgrade to Apache Log4j 2.17.1 or later.")
    for ip in g["api_prod"][::4]:
        _v(ip, 0, "general", "183513", "Amazon Linux 2 : kernel (ALAS2-2024-2450)", 3, 7.8, ["CVE-2024-1086"], True, False,
           "The remote Amazon Linux 2 host is missing a kernel security update.", "Run 'yum update kernel' and reboot.")
    for ip in g["box_dev"][::5]:
        _v(ip, 22, "ssh", "201194", "OpenSSH < 9.8 Race Condition RCE (regreSSHion)", 4, 8.1, ["CVE-2024-6387"], True, False,
           "The SSH server is affected by a signal handler race condition.", "Upgrade to OpenSSH 9.8 or later.")
    for ip in g["sbx_dev"]:
        if "20.04" in HOSTS[ip][1]:
            _v(ip, 22, "ssh", "201194", "OpenSSH < 9.8 Race Condition RCE (regreSSHion)", 4, 8.1, ["CVE-2024-6387"], True,
               False, "The SSH server is affected by a signal handler race condition.", "Upgrade to OpenSSH 9.8 or later.")
    _v(g["sbx_dev"][2], 22, "ssh", "10862", "SSH Password Authentication Accepted From the Internet", 3, 7.5, [],
       False, False, "The SSH server allows password logins and is reachable from the internet.",
       "Require keys, close port 22 in the security group and use Session Manager.")
    for ip in g["rds_prod"][:2]:
        _v(ip, 5432, "postgresql", "183965", "PostgreSQL 15.x < 15.5 Multiple Vulnerabilities", 3, 8.8,
           ["CVE-2023-5868", "CVE-2023-5869"], False, False,
           "The database server is affected by multiple vulnerabilities including an integer overflow.",
           "Upgrade the RDS engine to 15.5 or later.")


def _nessus(path):
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name="Estate-wide scan (on-prem and AWS)")
    by_ip: dict[str, list] = {}
    for v in VULNS:
        by_ip.setdefault(v[0], []).append(v)
    for ip, (fqdn, os_name, _role, place) in HOSTS.items():
        rh = ET.SubElement(report, "ReportHost", name=ip)
        hp = ET.SubElement(rh, "HostProperties")
        for k, v in (("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_name)):
            ET.SubElement(hp, "tag", name=k).text = v
        if place.startswith("aws"):
            ET.SubElement(hp, "tag", name="aws-vpc").text = "vpc-0prod0example" if place == "aws-prod" else "vpc-0dev0example"
        ET.SubElement(rh, "ReportItem", port="0", svc_name="general", protocol="tcp", severity="0",
                      pluginID="19506", pluginName="Nessus Scan Information", pluginFamily="Settings")
        for v in by_ip.get(ip, []):
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


def _traffic(g, rng):
    zeek, pan, threats = [], [], []
    vpc = {"prod": [], "dev": []}
    span = (END - START).total_seconds()
    t = lambda: START + timedelta(seconds=rng.uniform(0, span))
    pick = lambda xs: (lambda: rng.choice(xs))
    ext = lambda prefixes: (lambda: f"{rng.choice(prefixes)}.{rng.randint(1, 254)}")
    val = lambda x: x() if callable(x) else x

    def z(s, d, dp, n=1, proto="tcp", svc="-", state="SF", ts=None):
        for _ in range(n):
            ok = state == "SF"
            zeek.append(dict(ts=ts or t(), s=val(s), sp=rng.randint(49152, 65535), d=val(d), dp=dp, proto=proto,
                             svc=svc, state=state, ob=rng.randint(200, 6000) if ok else 0,
                             rb=rng.randint(500, 60000) if ok else 0))

    def p(s, d, dp, app, n=1, action="allow", fz="trust", tz="untrust", big=False, ts=None, sent=None):
        for _ in range(n):
            ok = action == "allow"
            pan.append(dict(ts=ts or t(), s=val(s), sp=rng.randint(1024, 65535), d=val(d), dp=dp, app=app,
                            action=action, fz=fz, tz=tz, sent=sent or rng.randint(400, 3000),
                            rcvd=rng.randint(2000, 400000 if big else 90000) if ok else 0))

    def f(which, s, d, dp, n=1, proto=6, action="ACCEPT", ts=None, nbytes=None):
        for _ in range(n):
            start = ts or t()
            vpc[which].append(dict(ts=start, s=val(s), d=val(d), sp=rng.randint(32768, 60999), dp=dp, proto=proto,
                                   bytes=nbytes or (rng.randint(800, 250000) if action == "ACCEPT" else 60),
                                   action=action))

    dcs, dns, fs, prt = g["dc"], g["dns"], g["fs"], g["prt"]
    clients = g["ws"] + g["mac"] + g["lnx"]
    # every client: logon, DNS, DHCP, file shares, browsing out through the firewall
    for c in clients:
        win = c in g["ws"] or rng.random() < 0.6
        if win:
            z(c, pick(dcs), 88, rng.randint(1, 3), svc="krb")
            z(c, pick(dcs), 389, rng.randint(1, 2), svc="ldap")
            z(c, pick(fs), 445, rng.randint(1, 4), svc="smb")
        z(c, pick(dns), 53, rng.randint(1, 3), proto="udp", svc="dns")
        if rng.random() < 0.3:
            z(c, pick(g["dhcp"]), 67, 1, proto="udp", svc="dhcp")
        if rng.random() < 0.35:
            z(c, pick(prt), 445, 1, svc="smb")
        if rng.random() < 0.25:
            z(c, pick(g["web"]), 443, rng.randint(1, 3), svc="ssl")
        if rng.random() < 0.5:
            p(c, ext(SAAS), 443, "ssl", rng.randint(1, 2), big=True)
    for c in rng.sample(g["ws"], 300):            # SCCM-style pushes and WSUS
        z(pick(g["wsus"]), c, 445, 1, svc="smb")
    for c in g["ws"][::4]:
        z(c, pick(g["wsus"]), 8530, 1, svc="http")
    # developers use git, on-prem k8s and the AWS dev VPC over the VPN
    for c in g["lnx"] + g["mac"][::4]:
        z(c, pick(g["dev"]), 22, rng.randint(1, 3), svc="ssh")
        p(c, pick(g["box_dev"] + g["bast_dev"]), 22, "ssh", rng.randint(1, 2), tz="aws")
    # servers
    for s in g["app"]:
        z(s, pick(g["sql"] + g["ora"]), rng.choice([1433, 1521]), rng.randint(10, 30), svc="tds")
        z(s, pick(dcs), 389, 2, svc="ldap")
    for s in g["web"]:
        z(s, pick(g["app"]), 8080, rng.randint(20, 40), svc="http")
    for s in g["k8s"]:
        z(s, pick(g["k8s"][:3]), 6443, rng.randint(5, 10), svc="ssl")
        z(s, pick(g["nas"]), 2049, 3, svc="nfs")
    for s in g["esx"]:
        z(g["vc"][0], s, 443, rng.randint(10, 20), svc="ssl")
        z(s, pick(g["nas"]), 2049, rng.randint(5, 10), svc="nfs")
    for c in g["ws"][::40]:                       # admins' desktops still reach ESXi SLP (lead)
        z(c, pick(g["esx"][:16]), 427, 1, proto="udp", svc="-")
    for bk in g["bk"]:
        for s in rng.sample(g["sql"] + g["fs"] + g["app"], 20):
            z(bk, s, 445, 2, svc="smb")
    server_like = [ip for ip, h in HOSTS.items() if h[3] == "onprem" and h[2] not in
                   ("workstation", "mac", "linux-desktop", "phone")]
    for i, s in enumerate(server_like):           # monitoring polls every on-prem device and server
        z(g["mon"][i % 4], s, 161, rng.randint(1, 3), proto="udp", svc="snmp")
        z(s, g["siem"][i % 3], 514, rng.randint(1, 4), proto="udp", svc="syslog")
        if s != g["ntp"][0]:
            z(s, g["ntp"][0], 123, 1, proto="udp", svc="ntp")
    for s in g["misc"]:
        z(s, pick(dcs), 88, rng.randint(1, 2), svc="krb")
    for d_ in dcs:
        for o in dcs:
            if o != d_:
                z(d_, o, 135, 3, svc="dce_rpc")
    # phones, printers, Wi-Fi, cameras, building systems
    for ph in g["phone"]:
        z(ph, pick(dns), 53, 1, proto="udp", svc="dns")
        p(ph, ext(["198.18.200"]), 5061, "sip", rng.randint(1, 3))            # cloud calling provider
    for pr in g["printer"]:
        z(pick(prt), pr, 9100, rng.randint(5, 15), svc="-")
    for ap in g["ap"]:
        z(ap, pick(g["wlc"]), 4343, rng.randint(3, 8), svc="ssl")
        z(ap, g["radius"][0], 1812, rng.randint(2, 6), proto="udp", svc="radius")
    for cam in g["cam"]:
        z(cam, pick(g["nas"]), 554, rng.randint(4, 10), svc="rtsp")
    for h in g["hvac"]:
        p(h, ext(["198.19.140"]), 443, "ssl", rng.randint(2, 5))               # vendor cloud
    for b in g["badge"]:
        z(b, g["misc"][0], 4070, rng.randint(2, 6), svc="-")
    for u in g["ups"]:
        z(u, g["mon"][0], 162, 1, proto="udp", svc="snmp")
    for sc in g["screen"]:
        p(sc, ext(SAAS), 443, "ssl", rng.randint(1, 3))

    # perimeter
    p(ext(STAFF_HOME), g["fw"][0], 443, "panos-global-protect", 600, fz="untrust", tz="trust")
    p(ext(CUSTOMERS), pick(g["web"][:4]), 443, "ssl", 300, fz="untrust", tz="dmz")
    p(ext([GP_SCANNER]), g["fw"][0], 443, "incomplete", 80, action="deny", fz="untrust", tz="trust")
    attack = START + timedelta(hours=30, minutes=12)
    for k in range(4):                              # GlobalProtect exploit attempts, reset by the IPS
        src = f"{GP_SCANNER}.{rng.randint(2, 250)}"
        ts = attack + timedelta(minutes=k * 9)
        p(src, g["fw"][0], 443, "panos-global-protect", 1, fz="untrust", tz="trust", ts=ts)
        threats.append(dict(ts=ts + timedelta(seconds=2), s=src, d=g["fw"][0], dp=443, fz="untrust", tz="trust",
                            name="Palo Alto Networks GlobalProtect Command Injection Vulnerability CVE-2024-3400(95187)",
                            sev="critical", action="reset-both"))
    # site-to-site VPN to AWS: on-prem <-> VPCs through the firewall's aws zone
    p(g["fw"][0], VPN_PEER_PROD, 500, "ipsec-esp-udp", 40, tz="untrust")
    p(g["fw"][0], VPN_PEER_DEV, 500, "ipsec-esp-udp", 40, tz="untrust")
    for s in g["ws"][::8]:
        p(s, pick(g["w_prod"]), 443, "ssl", 1, tz="aws")                       # staff use the internal app
    for s in g["app"][:20]:
        p(s, pick(g["api_prod"]), 443, "ssl", rng.randint(5, 12), tz="aws")
    for s in g["siem"]:
        p(pick(g["api_prod"] + g["eks_prod"]), s, 6514, "syslog", 40, fz="aws", tz="trust")
    for s in g["ad_dev"]:
        p(s, pick(dcs), 389, "ldap", 20, fz="aws", tz="trust")
        p(s, pick(dcs), 88, "kerberos", 20, fz="aws", tz="trust")
    p(pick(g["ci_dev"]), pick(g["dev"]), 22, "ssh", 120, fz="aws", tz="trust")

    # inside AWS (VPC Flow Logs): every instance talks to something, and the leads
    P = g
    for w in P["w_prod"]:
        f("prod", ext(CUSTOMERS), w, 443, rng.randint(15, 40))
        f("prod", w, pick(P["api_prod"]), 8080, rng.randint(10, 25))
        f("prod", w, pick(P["cache_prod"]), 6379, rng.randint(5, 15))
    for a in P["api_prod"]:
        f("prod", a, pick(P["rds_prod"]), 5432, rng.randint(10, 30))
        f("prod", a, pick(P["kafka_prod"]), 9092, rng.randint(5, 15))
        f("prod", a, ext(AWS_PUBLIC), 443, rng.randint(1, 4))
    for w in P["wrk_prod"] + P["batch_prod"]:
        f("prod", w, pick(P["kafka_prod"]), 9092, rng.randint(5, 15))
        f("prod", w, ext(AWS_PUBLIC), 443, rng.randint(2, 6), nbytes=rng.randint(10**6, 4 * 10**7))
        f("prod", w, pick(P["rds_prod"]), 5432, rng.randint(2, 8))
    for e in P["eks_prod"]:
        f("prod", e, pick(P["api_prod"]), 8080, rng.randint(5, 15))
        f("prod", e, pick(P["eks_prod"][:3]), 443, rng.randint(2, 6))
    for b in P["bast_prod"]:
        for s in rng.sample(P["api_prod"], 10):
            f("prod", b, s, 22, 2)
    for r in P["rds_prod"][1:]:
        f("prod", P["rds_prod"][0], r, 5432, 6)                                 # replication
    f("prod", ext(["198.19.33"]), pick(P["w_prod"]), 22, 60, action="REJECT")  # internet SSH noise, blocked by SGs
    lead = P["w_prod"][6]                         # web-prod-07: repeated outbound to a non-customer address
    for k in range(3):                            # it first reaches the vulnerable web service
        f("prod", C2_LIKE, lead, 443, ts=START + timedelta(hours=31, seconds=20 * k), nbytes=1200)
    for k in range(9):
        f("prod", lead, C2_LIKE, 4444, ts=START + timedelta(hours=31, minutes=5 + 17 * k),
          nbytes=1800 + rng.randint(0, 600))
    f("prod", lead, C2_LIKE, 443, ts=START + timedelta(hours=33, minutes=2), nbytes=48_000_000)
    for dv in P["box_dev"]:
        f("dev", dv, pick(P["eks_dev"]), 443, rng.randint(2, 6))
        f("dev", dv, ext(SAAS + AWS_PUBLIC), 443, rng.randint(2, 6))
    for e in P["eks_dev"]:
        f("dev", e, pick(P["eks_dev"][:3]), 443, rng.randint(2, 6))
    for c in P["ci_dev"]:
        f("dev", c, ext(["140.82.113", "104.16.24"]), 443, rng.randint(5, 15))
        f("dev", c, pick(P["eks_dev"]), 443, rng.randint(2, 6))
    for s in P["sbx_dev"]:
        f("dev", P["bast_dev"][0], s, 22, 3)
        f("dev", s, ext(SAAS), 443, rng.randint(1, 3))
    for a in P["ad_dev"]:
        f("dev", pick(P["box_dev"]), a, 389, 20)
    sbx = P["sbx_dev"][2]                         # SSH open to the internet: many tries, a few accepted
    burst = START + timedelta(hours=40)
    for k in range(120):
        f("dev", f"{SSH_BRUTE}.{rng.randint(2, 250)}", sbx, 22, ts=burst + timedelta(seconds=k * 11),
          action="ACCEPT" if k % 40 == 39 else "REJECT")
    return zeek, pan, threats, vpc


def _write(outdir, zeek, pan, threats, vpc, rng):
    paths = []
    p = os.path.join(outdir, "zeek_conn.log")
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
              "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
    with open(p, "w") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        fh.write("#fields\t" + "\t".join(fields) + "\n")
        for i, r in enumerate(sorted(zeek, key=lambda r: r["ts"])):
            fh.write("\t".join([f"{r['ts'].timestamp():.6f}", f"H{i:08x}", r["s"], str(r["sp"]), r["d"], str(r["dp"]),
                                r["proto"], r["svc"], f"{rng.uniform(0.01, 30):.3f}", str(r["ob"]), str(r["rb"]),
                                r["state"], "ShADadFf" if r["state"] == "SF" else "S"]) + "\n")
        fh.write("#close\t" + END.strftime("%Y-%m-%d-%H-%M-%S") + "\n")
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
            if kind == "THREAT":            # Start Time filled in so the alert keeps its time
                w.writerow([ts, "016401009999", "THREAT", "vulnerability", r["s"], r["d"], "allow-gp-portal",
                            "panos-global-protect", r["fz"], r["tz"], rng.randint(1024, 65535), r["dp"], "tcp",
                            r["action"], "", "", "", ts, r["name"], r["sev"]])
                continue
            rule = ("site-to-site-aws" if "aws" in (r["fz"], r["tz"]) else
                    "allow-out" if r["action"] == "allow" else "default-deny")
            udp = r["app"] in ("ipsec-esp-udp", "sip") and r["dp"] in (500,)
            w.writerow([ts, "016401009999", "TRAFFIC", "end", r["s"], r["d"], rule, r["app"], r["fz"], r["tz"],
                        r["sp"], r["dp"], "udp" if udp else "tcp", r["action"], r["sent"] + r["rcvd"], r["sent"],
                        r["rcvd"], ts, "", ""])
    paths.append(p)

    for which, region in (("prod", "us-east-2"), ("dev", "us-west-2")):
        p = os.path.join(outdir, f"aws_vpcflow_{which}_{region}.log")
        eni = f"eni-0{which}{region.replace('-', '')}"
        with open(p, "w") as fh:
            fh.write("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes "
                     "start end action log-status\n")
            for r in sorted(vpc[which], key=lambda r: r["ts"]):
                s = int(r["ts"].timestamp())
                fh.write(f"2 {ACCOUNT[which]} {eni} {r['s']} {r['d']} {r['sp']} {r['dp']} {r['proto']} "
                         f"{max(1, r['bytes'] // 900)} {r['bytes']} {s} {s + 60} {r['action']} OK\n")
        paths.append(p)

    p = os.path.join(outdir, "network_map.csv")         # optional: names the ranges so AWS stands out
    with open(p, "w", newline="") as fh:
        fh.write("cidr,name,type\n10.40.0.0/16,HQ on-prem,on-prem\n"
                 "10.60.0.0/16,AWS prod (us-east-2),aws\n10.61.0.0/16,AWS dev (us-west-2),aws\n")
    paths.append(p)

    p = os.path.join(outdir, "estate_scan.nessus")
    _nessus(p)
    paths.append(p)

    return paths


def generate(outdir: str, seed: int = 11) -> list[str]:
    """Write the 4,324-host on-prem + AWS sample folder."""
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(seed)
    g = _build(random.Random(4324))
    _vulns(g, random.Random(43240))
    zeek, pan, threats, vpc = _traffic(g, rng)
    return _write(outdir, zeek, pan, threats, vpc, rng)


def write_inventory(path: str) -> str:
    """A plain host list (ip, hostname, os, role, location) for people. Kept out of the sample
    folder so the analyzer does not try to read it as a flow file."""
    if not HOSTS:
        _build(random.Random(4324))
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["ip", "hostname", "os", "role", "location"])
        for ip, (name, os_name, role, place) in HOSTS.items():
            loc = {"onprem": "on-prem (hq)", "aws-prod": "AWS us-east-2 prod VPC",
                   "aws-dev": "AWS us-west-2 dev VPC"}[place]
            w.writerow([ip, name, os_name, role, loc])
    return path
