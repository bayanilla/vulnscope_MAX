# Múcaro VulnScope: Technical Analysis

Generated 2026-10-30T22:59:36Z. Telemetry window 2026-10-12T00:01:19Z to 2026-10-18T03:11:38Z.

## 1. Inputs and data quality

| File | Format | Records read | Kept | Dropped | Notes |
|---|---|---|---|---|---|
| netflow_segment6.csv | generic | 112 | 112 | 0 |  |
| paloalto_traffic.csv | paloalto | 2285 | 1315 | 970 missing or invalid IP | firewall timestamps are assumed to be UTC; 4 IPS/IDS alert(s) used as exploitation evidence |
| quarterly_scan.nessus | nessus | 697 | 697 | 0 |  |
| zeek_conn.log | zeek | 8343 | 8342 | 1 missing or invalid IP |  |
| dns.log | zeek | 7 | 7 | 0 | Zeek stream records preserved as events; only conn sessions and notice alerts affect scoring |
| flows.csv | generic | 13 | 13 | 0 |  |
| notice.log | zeek | 1 | 1 | 0 | 1 IPS/IDS alert(s) used as exploitation evidence |
| scan.csv | nessus_csv | 1 | 1 | 0 | Nessus CSV exports usually omit exploit availability; prefer the .nessus file |
| large_mucaro_archive.csv | mucaro_ioc_archive | 14 | 14 | 0 |  |

Exact duplicate sessions removed: 1. Duplicate findings merged across scans: 0. IPS/IDS alerts loaded: 5. Internal address space: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, fc00::/7, fe80::/10, ::1/128.

Zeek stream events preserved (separate from connection sessions and alerts): dns 7.

## 2. Method

Each finding is scored 0-100 as `CVSS x 10 x Exploit x Exposure x BlastRadius`, capped at 100, then multiplied by 1.25 with corroborated exploitation evidence or 1.1 with investigation leads.

- **Exploit**: 1.0 if a public exploit exists (1.1 if in Metasploit/CANVAS/Core), otherwise 0.65.
- **Exposure** (from telemetry): 1.0 service reached from the internet; 0.85 reached internally by 5+ hosts; 0.75 reached internally; 0.45 attempts only; 0.35 blocked by firewall; 0.3 service not observed in use; 0.5 host absent from telemetry (unknown). Host-level findings (port 0, e.g. missing patches or client software) use 0.7 / 0.5 / 0.35 for internet-facing / active / quiet hosts.
- **Blast radius**: 1.0 to 1.5 from the number of internal hosts this host has completed sessions with (walked 2 hops), how many of those carry High/Critical findings, and use of lateral-movement protocols (SMB, RDP, SSH, WinRM, database ports).
- **Indicators** are leads, not proof. *Lead*: the host connects back to an outside address that reached the vulnerable service; new lateral connections or >20 MB uploaded to the internet after that contact; an IPS/IDS alert on the service that was not blocked; a flagged host newly connecting to this vulnerable service. *Corroborated*: an unblocked IPS/IDS alert on the service plus post-contact behaviour from the host. Confirming a compromise still needs host evidence (EDR, logs, forensics), which this tool does not see.
- **Priority**: P1 score >= 75 or corroborated evidence; P2 >= 50 or any lead; P3 >= 25; P4 below.

## 3. Prioritized findings

| Pri | Score | Host | Vulnerability | Port | CVSS | Exploit | Exposure | Blast | Likelihood |
|---|---|---|---|---|---|---|---|---|---|
| P1 | 100 | web01.corp.example (10.10.1.10) | Apache 2.4.49 < 2.4.51 Path Traversal and RCE (153884) | 443/tcp (www) | 9.8 | Yes | Vulnerable service reached from the internet | x1.5 | High |
| P1 | 100 | web02.corp.example (10.10.1.11) | Synthetic Magento StyleSmuggler finding (990001) | 443/tcp | 10.0 | No | Vulnerable service reached from the internet | x1.38 | Medium |
| P1 | 100 | app01.corp.example (10.10.1.20) | Apache Tomcat AJP Connector Request Injection (Ghostcat) (134862) | 8009/tcp (ajp13) | 9.8 | Yes | Vulnerable service reached internally | x1.24 | High |
| P1 | 100 | app02.corp.example (10.10.2.30) | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (156057) | 8080/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.48 | High |
| P1 | 100 | app03.corp.example (10.10.2.31) | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (156057) | 8080/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.26 | High |
| P1 | 100 | app04.corp.example (10.10.2.32) | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (156057) | 8080/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.38 | High |
| P1 | 100 | jenkins01.corp.example (10.10.2.45) | Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897) (189463) | 8080/tcp (www) | 9.8 | Yes | Vulnerable service reached internally by many hosts | x1.38 | High |
| P1 | 93 | backup01.corp.example (10.10.2.41) | Veeam Backup & Replication Credential Disclosure (CVE-2023-27532) (173914) | 9401/tcp (veeam) | 7.5 | Yes | Vulnerable service reached internally | x1.5 | High |
| P1 | 89 | ws-031.corp.example (10.10.3.31) | Microsoft RDP RCE (CVE-2019-0708) (BlueKeep) (125313) | 3389/tcp (msrdp) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 85 | git01.corp.example (10.10.2.44) | GitLab 16.1 < 16.7.2 Account Takeover via Password Reset (187600) | 443/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.0 | High |
| P1 | 84 | web02.corp.example (10.10.1.11) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.38 | Medium |
| P1 | 83 | fs01.corp.example (10.10.2.25) | MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE) (97833) | 445/tcp (cifs) | 8.1 | Yes | Vulnerable service reached internally by many hosts | x1.0 | High |
| P1 | 81 | cam-60.corp.example (10.10.4.60) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-61.corp.example (10.10.4.61) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-62.corp.example (10.10.4.62) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-63.corp.example (10.10.4.63) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-64.corp.example (10.10.4.64) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-65.corp.example (10.10.4.65) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-66.corp.example (10.10.4.66) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-67.corp.example (10.10.4.67) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-68.corp.example (10.10.4.68) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-69.corp.example (10.10.4.69) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 73 | print01.corp.example (10.10.2.43) | Windows Print Spooler Service Enabled (PrintNightmare) (151440) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 67 | web04.corp.example (10.10.1.13) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.38 | Medium |
| P2 | 66 | ws-102.corp.example (10.10.3.102) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-103.corp.example (10.10.3.103) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-105.corp.example (10.10.3.105) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-106.corp.example (10.10.3.106) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-108.corp.example (10.10.3.108) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-113.corp.example (10.10.3.113) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-114.corp.example (10.10.3.114) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-118.corp.example (10.10.3.118) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-119.corp.example (10.10.3.119) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-121.corp.example (10.10.3.121) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-122.corp.example (10.10.3.122) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-124.corp.example (10.10.3.124) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-125.corp.example (10.10.3.125) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-128.corp.example (10.10.3.128) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-129.corp.example (10.10.3.129) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-130.corp.example (10.10.3.130) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-131.corp.example (10.10.3.131) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-132.corp.example (10.10.3.132) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-133.corp.example (10.10.3.133) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-135.corp.example (10.10.3.135) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-136.corp.example (10.10.3.136) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-140.corp.example (10.10.3.140) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-140.corp.example (10.10.3.140) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-147.corp.example (10.10.3.147) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-148.corp.example (10.10.3.148) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-149.corp.example (10.10.3.149) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-150.corp.example (10.10.3.150) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-153.corp.example (10.10.3.153) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-155.corp.example (10.10.3.155) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-157.corp.example (10.10.3.157) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-158.corp.example (10.10.3.158) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-158.corp.example (10.10.3.158) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-160.corp.example (10.10.3.160) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-161.corp.example (10.10.3.161) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-166.corp.example (10.10.3.166) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-167.corp.example (10.10.3.167) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-170.corp.example (10.10.3.170) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-171.corp.example (10.10.3.171) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-174.corp.example (10.10.3.174) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-176.corp.example (10.10.3.176) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-179.corp.example (10.10.3.179) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-179.corp.example (10.10.3.179) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-180.corp.example (10.10.3.180) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-180.corp.example (10.10.3.180) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-182.corp.example (10.10.3.182) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-183.corp.example (10.10.3.183) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-184.corp.example (10.10.3.184) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-186.corp.example (10.10.3.186) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-186.corp.example (10.10.3.186) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-187.corp.example (10.10.3.187) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-188.corp.example (10.10.3.188) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-189.corp.example (10.10.3.189) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-192.corp.example (10.10.3.192) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-193.corp.example (10.10.3.193) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-197.corp.example (10.10.3.197) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-048.corp.example (10.10.3.48) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-049.corp.example (10.10.3.49) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-050.corp.example (10.10.3.50) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-052.corp.example (10.10.3.52) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-053.corp.example (10.10.3.53) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-054.corp.example (10.10.3.54) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-055.corp.example (10.10.3.55) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-057.corp.example (10.10.3.57) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-059.corp.example (10.10.3.59) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-061.corp.example (10.10.3.61) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-062.corp.example (10.10.3.62) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-065.corp.example (10.10.3.65) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-066.corp.example (10.10.3.66) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-067.corp.example (10.10.3.67) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-067.corp.example (10.10.3.67) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-069.corp.example (10.10.3.69) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-069.corp.example (10.10.3.69) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-071.corp.example (10.10.3.71) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-075.corp.example (10.10.3.75) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-076.corp.example (10.10.3.76) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-077.corp.example (10.10.3.77) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-079.corp.example (10.10.3.79) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-081.corp.example (10.10.3.81) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-082.corp.example (10.10.3.82) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-083.corp.example (10.10.3.83) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-084.corp.example (10.10.3.84) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-087.corp.example (10.10.3.87) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-088.corp.example (10.10.3.88) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-090.corp.example (10.10.3.90) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-093.corp.example (10.10.3.93) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-095.corp.example (10.10.3.95) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-096.corp.example (10.10.3.96) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-097.corp.example (10.10.3.97) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-098.corp.example (10.10.3.98) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-098.corp.example (10.10.3.98) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-099.corp.example (10.10.3.99) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-010.corp.example (10.10.7.10) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-012.corp.example (10.10.7.12) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-015.corp.example (10.10.7.15) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-017.corp.example (10.10.7.17) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-018.corp.example (10.10.7.18) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-020.corp.example (10.10.7.20) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-021.corp.example (10.10.7.21) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-025.corp.example (10.10.7.25) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-027.corp.example (10.10.7.27) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-033.corp.example (10.10.7.33) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-033.corp.example (10.10.7.33) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-034.corp.example (10.10.7.34) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-037.corp.example (10.10.7.37) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-040.corp.example (10.10.7.40) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-043.corp.example (10.10.7.43) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-044.corp.example (10.10.7.44) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-045.corp.example (10.10.7.45) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 62 | web03.corp.example (10.10.1.12) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.28 | Medium |
| P2 | 61 | ws-040.corp.example (10.10.3.40) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.38 | Medium |
| P2 | 59 | ws-041.corp.example (10.10.3.41) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-042.corp.example (10.10.3.42) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-043.corp.example (10.10.3.43) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-044.corp.example (10.10.3.44) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-045.corp.example (10.10.3.45) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-046.corp.example (10.10.3.46) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-047.corp.example (10.10.3.47) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 58 | web05.corp.example (10.10.1.14) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.2 | Medium |
| P2 | 56 | prn-51.corp.example (10.10.4.51) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-52.corp.example (10.10.4.52) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-53.corp.example (10.10.4.53) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-54.corp.example (10.10.4.54) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-55.corp.example (10.10.4.55) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-56.corp.example (10.10.4.56) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-57.corp.example (10.10.4.57) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-58.corp.example (10.10.4.58) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 52 | db02.corp.example (10.10.2.21) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.22 | Medium |
| P3 | 49 | sql01.corp.example (10.10.2.24) | Microsoft SQL Server Unsupported Version Detection (73756) | 1433/tcp (mssql) | 10.0 | No | Vulnerable service reached internally | x1.0 | Medium |
| P3 | 48 | sccm01.corp.example (10.10.2.40) | KB5041578: Windows Server 2019 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-100.corp.example (10.10.3.100) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-101.corp.example (10.10.3.101) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-102.corp.example (10.10.3.102) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-104.corp.example (10.10.3.104) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-107.corp.example (10.10.3.107) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-109.corp.example (10.10.3.109) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-115.corp.example (10.10.3.115) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-116.corp.example (10.10.3.116) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-118.corp.example (10.10.3.118) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-119.corp.example (10.10.3.119) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-122.corp.example (10.10.3.122) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-128.corp.example (10.10.3.128) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-129.corp.example (10.10.3.129) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-134.corp.example (10.10.3.134) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-138.corp.example (10.10.3.138) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-142.corp.example (10.10.3.142) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-143.corp.example (10.10.3.143) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-149.corp.example (10.10.3.149) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-150.corp.example (10.10.3.150) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-151.corp.example (10.10.3.151) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-153.corp.example (10.10.3.153) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-156.corp.example (10.10.3.156) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-158.corp.example (10.10.3.158) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-163.corp.example (10.10.3.163) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-169.corp.example (10.10.3.169) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-170.corp.example (10.10.3.170) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-172.corp.example (10.10.3.172) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-173.corp.example (10.10.3.173) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-177.corp.example (10.10.3.177) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-179.corp.example (10.10.3.179) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-183.corp.example (10.10.3.183) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-188.corp.example (10.10.3.188) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-189.corp.example (10.10.3.189) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-192.corp.example (10.10.3.192) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-193.corp.example (10.10.3.193) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-195.corp.example (10.10.3.195) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-199.corp.example (10.10.3.199) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-056.corp.example (10.10.3.56) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-058.corp.example (10.10.3.58) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-059.corp.example (10.10.3.59) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-063.corp.example (10.10.3.63) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-076.corp.example (10.10.3.76) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-077.corp.example (10.10.3.77) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-082.corp.example (10.10.3.82) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-085.corp.example (10.10.3.85) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-092.corp.example (10.10.3.92) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-093.corp.example (10.10.3.93) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-094.corp.example (10.10.3.94) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-098.corp.example (10.10.3.98) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-010.corp.example (10.10.7.10) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-013.corp.example (10.10.7.13) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-018.corp.example (10.10.7.18) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-019.corp.example (10.10.7.19) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-021.corp.example (10.10.7.21) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-023.corp.example (10.10.7.23) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-026.corp.example (10.10.7.26) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-031.corp.example (10.10.7.31) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-033.corp.example (10.10.7.33) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-034.corp.example (10.10.7.34) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-040.corp.example (10.10.7.40) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-042.corp.example (10.10.7.42) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-043.corp.example (10.10.7.43) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-046.corp.example (10.10.7.46) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 45 | db01.corp.example (10.10.2.20) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.04 | Medium |
| P3 | 43 | proxy01.corp.example (10.10.1.40) | Squid < 6.4 Multiple Vulnerabilities (182251) | 3128/tcp (http_proxy) | 7.5 | No | Vulnerable service reached internally by many hosts | x1.04 | Medium |
| P3 | 43 | db03.corp.example (10.10.2.22) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.0 | Medium |
| P3 | 43 | db04.corp.example (10.10.2.23) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.0 | Medium |
| P3 | 43 | app06.corp.example (10.10.2.34) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.48 | Medium |
| P3 | 40 | app05.corp.example (10.10.2.33) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.36 | Medium |
| P3 | 40 | app07.corp.example (10.10.2.35) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.36 | Medium |
| P3 | 40 | app08.corp.example (10.10.2.36) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.38 | Medium |
| P3 | 39 | mail01.corp.example (10.10.1.25) | Postfix SMTP Smuggling (187315) | 25/tcp (smtp) | 5.3 | No | Vulnerable service reached from the internet | x1.14 | Medium |
| P3 | 39 | ws-111.corp.example (10.10.3.111) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-120.corp.example (10.10.3.120) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-138.corp.example (10.10.3.138) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-165.corp.example (10.10.3.165) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-075.corp.example (10.10.3.75) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 38 | ws-110.corp.example (10.10.3.110) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-112.corp.example (10.10.3.112) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-114.corp.example (10.10.3.114) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-118.corp.example (10.10.3.118) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-120.corp.example (10.10.3.120) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-128.corp.example (10.10.3.128) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-129.corp.example (10.10.3.129) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-130.corp.example (10.10.3.130) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-134.corp.example (10.10.3.134) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-137.corp.example (10.10.3.137) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-146.corp.example (10.10.3.146) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-148.corp.example (10.10.3.148) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-151.corp.example (10.10.3.151) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-152.corp.example (10.10.3.152) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-155.corp.example (10.10.3.155) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-157.corp.example (10.10.3.157) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-164.corp.example (10.10.3.164) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-174.corp.example (10.10.3.174) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-176.corp.example (10.10.3.176) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-187.corp.example (10.10.3.187) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-188.corp.example (10.10.3.188) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-190.corp.example (10.10.3.190) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-192.corp.example (10.10.3.192) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-198.corp.example (10.10.3.198) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-199.corp.example (10.10.3.199) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-049.corp.example (10.10.3.49) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-051.corp.example (10.10.3.51) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-053.corp.example (10.10.3.53) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-058.corp.example (10.10.3.58) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-060.corp.example (10.10.3.60) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-062.corp.example (10.10.3.62) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-063.corp.example (10.10.3.63) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-065.corp.example (10.10.3.65) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-068.corp.example (10.10.3.68) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-069.corp.example (10.10.3.69) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-073.corp.example (10.10.3.73) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-074.corp.example (10.10.3.74) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-078.corp.example (10.10.3.78) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-079.corp.example (10.10.3.79) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-080.corp.example (10.10.3.80) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-096.corp.example (10.10.3.96) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ups-mgmt.corp.example (10.10.5.60) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | No telemetry for this host (unknown) | x1.0 | Medium |
| P3 | 38 | lt-017.corp.example (10.10.7.17) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-019.corp.example (10.10.7.19) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-024.corp.example (10.10.7.24) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-025.corp.example (10.10.7.25) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-026.corp.example (10.10.7.26) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-030.corp.example (10.10.7.30) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-032.corp.example (10.10.7.32) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-036.corp.example (10.10.7.36) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 37 | app09.corp.example (10.10.2.37) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.26 | Medium |
| P3 | 34 | mon01.corp.example (10.10.2.42) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Service not observed in use | x1.5 | Low |
| P3 | 34 | ws-100.corp.example (10.10.3.100) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-109.corp.example (10.10.3.109) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-111.corp.example (10.10.3.111) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-113.corp.example (10.10.3.113) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-115.corp.example (10.10.3.115) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-121.corp.example (10.10.3.121) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-122.corp.example (10.10.3.122) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-126.corp.example (10.10.3.126) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-127.corp.example (10.10.3.127) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-133.corp.example (10.10.3.133) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-134.corp.example (10.10.3.134) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-137.corp.example (10.10.3.137) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-140.corp.example (10.10.3.140) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-143.corp.example (10.10.3.143) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-148.corp.example (10.10.3.148) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-149.corp.example (10.10.3.149) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-152.corp.example (10.10.3.152) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-153.corp.example (10.10.3.153) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-159.corp.example (10.10.3.159) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-161.corp.example (10.10.3.161) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-163.corp.example (10.10.3.163) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-165.corp.example (10.10.3.165) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-166.corp.example (10.10.3.166) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-169.corp.example (10.10.3.169) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-171.corp.example (10.10.3.171) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-173.corp.example (10.10.3.173) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-176.corp.example (10.10.3.176) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-177.corp.example (10.10.3.177) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-181.corp.example (10.10.3.181) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-184.corp.example (10.10.3.184) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-185.corp.example (10.10.3.185) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-191.corp.example (10.10.3.191) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-198.corp.example (10.10.3.198) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-048.corp.example (10.10.3.48) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-050.corp.example (10.10.3.50) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-051.corp.example (10.10.3.51) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-060.corp.example (10.10.3.60) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-062.corp.example (10.10.3.62) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-063.corp.example (10.10.3.63) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-065.corp.example (10.10.3.65) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-067.corp.example (10.10.3.67) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-071.corp.example (10.10.3.71) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-074.corp.example (10.10.3.74) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-080.corp.example (10.10.3.80) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-081.corp.example (10.10.3.81) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-086.corp.example (10.10.3.86) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-089.corp.example (10.10.3.89) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-090.corp.example (10.10.3.90) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-091.corp.example (10.10.3.91) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-092.corp.example (10.10.3.92) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-093.corp.example (10.10.3.93) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-094.corp.example (10.10.3.94) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-099.corp.example (10.10.3.99) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-014.corp.example (10.10.7.14) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-016.corp.example (10.10.7.16) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-020.corp.example (10.10.7.20) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-022.corp.example (10.10.7.22) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-024.corp.example (10.10.7.24) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-029.corp.example (10.10.7.29) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-035.corp.example (10.10.7.35) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-042.corp.example (10.10.7.42) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-044.corp.example (10.10.7.44) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-111.corp.example (10.10.3.111) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-117.corp.example (10.10.3.117) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-123.corp.example (10.10.3.123) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-125.corp.example (10.10.3.125) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-127.corp.example (10.10.3.127) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-131.corp.example (10.10.3.131) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-133.corp.example (10.10.3.133) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-139.corp.example (10.10.3.139) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-141.corp.example (10.10.3.141) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-142.corp.example (10.10.3.142) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-143.corp.example (10.10.3.143) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-144.corp.example (10.10.3.144) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-145.corp.example (10.10.3.145) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-154.corp.example (10.10.3.154) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-157.corp.example (10.10.3.157) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-159.corp.example (10.10.3.159) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-160.corp.example (10.10.3.160) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-166.corp.example (10.10.3.166) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-168.corp.example (10.10.3.168) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-171.corp.example (10.10.3.171) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-175.corp.example (10.10.3.175) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-178.corp.example (10.10.3.178) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-182.corp.example (10.10.3.182) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-189.corp.example (10.10.3.189) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-193.corp.example (10.10.3.193) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-196.corp.example (10.10.3.196) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-048.corp.example (10.10.3.48) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-056.corp.example (10.10.3.56) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-058.corp.example (10.10.3.58) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-061.corp.example (10.10.3.61) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-064.corp.example (10.10.3.64) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-070.corp.example (10.10.3.70) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-072.corp.example (10.10.3.72) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-085.corp.example (10.10.3.85) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-086.corp.example (10.10.3.86) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-089.corp.example (10.10.3.89) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-092.corp.example (10.10.3.92) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-094.corp.example (10.10.3.94) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-099.corp.example (10.10.3.99) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-012.corp.example (10.10.7.12) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-016.corp.example (10.10.7.16) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-017.corp.example (10.10.7.17) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-026.corp.example (10.10.7.26) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-027.corp.example (10.10.7.27) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-028.corp.example (10.10.7.28) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-029.corp.example (10.10.7.29) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-031.corp.example (10.10.7.31) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-034.corp.example (10.10.7.34) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-035.corp.example (10.10.7.35) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-036.corp.example (10.10.7.36) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-038.corp.example (10.10.7.38) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-039.corp.example (10.10.7.39) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-043.corp.example (10.10.7.43) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-044.corp.example (10.10.7.44) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 30 | vpn01.corp.example (10.10.1.30) | Ivanti Connect Secure Command Injection (CVE-2024-21887) (189987) | 443/tcp (www) | 9.1 | Yes | Service not observed in use | x1.0 | Low |
| P3 | 29 | fs02.corp.example (10.10.2.26) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.0 | Medium |
| P4 | 20 | web01.corp.example (10.10.1.10) | OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin) (187201) | 22/tcp (ssh) | 5.9 | No | Connections to service blocked by firewall | x1.5 | Low |
| P4 | 18 | ws-090.corp.example (10.10.3.90) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Connections to service blocked by firewall | x1.5 | Low |
| P4 | 16 | ws-103.corp.example (10.10.3.103) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-104.corp.example (10.10.3.104) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-105.corp.example (10.10.3.105) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-109.corp.example (10.10.3.109) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-110.corp.example (10.10.3.110) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-114.corp.example (10.10.3.114) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-115.corp.example (10.10.3.115) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-116.corp.example (10.10.3.116) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-119.corp.example (10.10.3.119) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-125.corp.example (10.10.3.125) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-142.corp.example (10.10.3.142) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-152.corp.example (10.10.3.152) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-161.corp.example (10.10.3.161) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-162.corp.example (10.10.3.162) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-163.corp.example (10.10.3.163) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-180.corp.example (10.10.3.180) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-182.corp.example (10.10.3.182) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-186.corp.example (10.10.3.186) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-190.corp.example (10.10.3.190) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-194.corp.example (10.10.3.194) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-195.corp.example (10.10.3.195) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-196.corp.example (10.10.3.196) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-199.corp.example (10.10.3.199) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-050.corp.example (10.10.3.50) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-052.corp.example (10.10.3.52) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-053.corp.example (10.10.3.53) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-055.corp.example (10.10.3.55) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-061.corp.example (10.10.3.61) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-071.corp.example (10.10.3.71) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-078.corp.example (10.10.3.78) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-082.corp.example (10.10.3.82) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-088.corp.example (10.10.3.88) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-011.corp.example (10.10.7.11) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-013.corp.example (10.10.7.13) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-014.corp.example (10.10.7.14) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-015.corp.example (10.10.7.15) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-021.corp.example (10.10.7.21) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-025.corp.example (10.10.7.25) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-028.corp.example (10.10.7.28) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-029.corp.example (10.10.7.29) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-036.corp.example (10.10.7.36) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-037.corp.example (10.10.7.37) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-041.corp.example (10.10.7.41) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 13 | prn-4f.corp.example (10.10.4.50) | Unencrypted Telnet Server (42263) | 23/tcp (telnet) | 6.5 | No | Service not observed in use | x1.0 | Low |
| P4 | 12 | jump02.corp.example (10.10.3.6) | Terminal Services Doesn't Use Network Level Authentication (NLA) Only (58453) | 3389/tcp (msrdp) | 4.0 | No | Service not observed in use | x1.5 | Low |
| P4 | 11 | jump01.corp.example (10.10.3.5) | Terminal Services Doesn't Use Network Level Authentication (NLA) Only (58453) | 3389/tcp (msrdp) | 4.0 | No | Service not observed in use | x1.36 | Low |

## 4. Host details

### web01.corp.example (10.10.1.10) - P1 - act now

- Operating system: Linux Kernel 5.4 on Ubuntu 20.04
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (249 inbound, 165 outbound sessions)
- Internet-exposed vulnerable service: yes

**Exploitation indicators** (leads unless marked corroborated)

- [lead] IPS/IDS alerted 1 time(s) on traffic to this service and did not block it: Apache HTTP Server Path Traversal Vulnerability CVE-2021-41773(91694) (from 203.0.113.45), matching CVE-2021-41773. An alert shows an attempt, not that it succeeded.
- [lead] 10.10.1.10 opened 2 outbound connection(s) to 203.0.113.45 (port 443, 4444) after 203.0.113.45 connected to the vulnerable service. This is consistent with an exploit callback, but on its own it can also be legitimate traffic; confirm with IPS/threat logs, payload or application logs, or host evidence.
- [lead] After the flagged inbound contact at 2026-10-16T03:12:00Z, 10.10.1.10 began connecting to 3 internal host(s) it had not talked to before, over RDP, SMB.
- [lead] 10.10.1.10 sent 59.1 MB to external address 203.0.113.45 after the flagged inbound contact at 2026-10-16T03:12:00Z.
- [corroborated] Independent signals agree: the IPS/IDS alerted on traffic to this vulnerable service from 203.0.113.45, the same address the host then connected back to, and the host then showed exfil, new lateral, return connection. Treat this as likely exploitation and start incident response; host forensics is still needed to confirm a compromise.

**Findings and exposure evidence**

#### P1 (100) Apache 2.4.49 < 2.4.51 Path Traversal and RCE

- Plugin 153884, Critical, CVSS 9.8, port 443/tcp (www), CVE-2021-41773, CVE-2021-42013
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached from the internet - 224 completed sessions from 154 external and 0 internal sources. Blast radius: the host talks to 5 internal host(s) directly and 6 within 2 hops, including 4 with High/Critical findings. Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.
- Traffic to service: 224 completed, 0 attempts, 0 blocked; first 2026-10-12T00:02:03Z, last 2026-10-18T02:50:10Z; top sources: 198.51.100.65 (ext) x6, 198.51.100.38 (ext) x5, 198.51.100.176 (ext) x4, 198.51.100.102 (ext) x4, 198.51.100.20 (ext) x4, 203.0.113.45 (ext) x4, 198.51.100.131 (ext) x3, 198.51.100.10 (ext) x3
- Synopsis: The remote web server is affected by a path traversal vulnerability that can lead to remote code execution.
- Remediation: Upgrade to Apache version 2.4.51 or later.

#### P4 (20) OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin)

- Plugin 187201, Medium, CVSS 5.9, port 22/tcp (ssh), CVE-2023-48795
- Why this score: Base severity: CVSS v3 5.9 (Medium). No public exploit is known to the scanner. Exposure: connections to service blocked by firewall. 25 connection(s) to it were blocked by a firewall. Blast radius: the host talks to 5 internal host(s) directly and 6 within 2 hops, including 4 with High/Critical findings.
- Traffic to service: 0 completed, 0 attempts, 25 blocked; first 2026-10-12T09:38:38Z, last 2026-10-17T20:49:02Z
- Synopsis: The SSH server is affected by a prefix truncation weakness.
- Remediation: Upgrade to OpenSSH 9.6 or later.

**Blast radius**

Completed sessions to 5 internal host(s) directly, 6 within 2 hops.
Lateral-movement protocols used: SMB (2), RDP (1).
Reachable hosts with High/Critical findings: 10.10.1.20, 10.10.2.25, 10.10.3.31, 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.1.20 | 1 | 8009/tcp | Critical |
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.3.31 | 1 | 3389/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 445/tcp | - |
| 10.10.2.20 | 2 |  | High |

Outbound to 1 external address(es); top: 203.0.113.45 x2.

### web02.corp.example (10.10.1.11) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (110 inbound, 83 outbound sessions)
- Internet-exposed vulnerable service: yes

**Exploitation indicators** (leads unless marked corroborated)

- [lead] IPS/IDS alerted 1 time(s) on traffic to this service and did not block it: Intel::Notice - Synthetic StyleSmuggler exploitation alert on the web service (from 209.73.130.148). An alert shows an attempt, not that it succeeded.
- [lead] 10.10.1.11 sent 24.8 MB to external address 99.84.67.186 after the flagged inbound contact at 2026-10-17T08:00:00Z.
- [corroborated] Independent signals agree: the IPS/IDS alerted on traffic to this vulnerable service, and the host then showed exfil. Treat this as likely exploitation and start incident response; host forensics is still needed to confirm a compromise.

**Findings and exposure evidence**

#### P1 (100) Synthetic Magento StyleSmuggler finding

- Plugin 990001, Critical, CVSS 10.0, port 443/tcp, CVE-2026-75650
- Why this score: Base severity: CVSS v3 10.0 (Critical). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 92 completed sessions from 79 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 5 within 2 hops, including 3 with High/Critical findings. Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.
- Traffic to service: 92 completed, 0 attempts, 0 blocked; first 2026-10-12T00:10:42Z, last 2026-10-18T02:34:27Z; top sources: 198.51.100.229 (ext) x3, 198.51.100.153 (ext) x2, 198.51.100.124 (ext) x2, 198.51.100.146 (ext) x2, 198.51.100.202 (ext) x2, 198.51.100.24 (ext) x2, 198.51.100.252 (ext) x2, 198.51.100.149 (ext) x2
- Synopsis: Fabricated scan finding for the source-linked web server storyline.
- Remediation: Apply the vendor hotfix and review host evidence.

#### P1 (84) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 92 completed sessions from 79 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 5 within 2 hops, including 3 with High/Critical findings. Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.
- Traffic to service: 92 completed, 0 attempts, 0 blocked; first 2026-10-12T00:10:42Z, last 2026-10-18T02:34:27Z; top sources: 198.51.100.229 (ext) x3, 198.51.100.153 (ext) x2, 198.51.100.124 (ext) x2, 198.51.100.146 (ext) x2, 198.51.100.202 (ext) x2, 198.51.100.24 (ext) x2, 198.51.100.252 (ext) x2, 198.51.100.149 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 5 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.24, 10.10.2.21.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

Outbound to 3 external address(es); top: 99.84.67.186 x3, 185.157.160.251 x2, 209.141.43.95 x1.

### app01.corp.example (10.10.1.20) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (120 inbound, 140 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Tomcat AJP Connector Request Injection (Ghostcat)

- Plugin 134862, Critical, CVSS 9.8, port 8009/tcp (ajp13), CVE-2020-1938
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 120 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 2 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 120 completed, 0 attempts, 0 blocked; first 2026-10-12T00:38:11Z, last 2026-10-18T02:46:28Z; top sources: 10.10.1.10 x120
- Synopsis: An AJP connector is listening and is affected by a file read/inclusion vulnerability.
- Remediation: Update Tomcat to 9.0.31 / 8.5.51 / 7.0.100 or later, or disable the AJP connector.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 2 within 2 hops.
Lateral-movement protocols used: PostgreSQL (140).
Reachable hosts with High/Critical findings: 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.20 | 1 | 5432/tcp | High |
| 10.10.6.71 | 2 |  | - |

### app02.corp.example (10.10.2.30) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (128 inbound, 113 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- Plugin 156057, Critical, CVSS 10.0, port 8080/tcp (www), CVE-2021-44228
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 118 completed sessions from 0 external and 22 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 4 within 2 hops, including 3 with High/Critical findings.
- Traffic to service: 118 completed, 0 attempts, 0 blocked; first 2026-10-12T01:05:57Z, last 2026-10-18T02:34:25Z; top sources: 10.10.1.11 x67, 10.10.3.128 x4, 10.10.7.37 x4, 10.10.3.166 x4, 10.10.7.40 x4, 10.10.3.180 x3, 10.10.3.130 x3, 10.10.3.191 x3
- Synopsis: The application uses a Log4j version affected by remote code execution.
- Remediation: Upgrade to Apache Log4j 2.17.1 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: PostgreSQL (77), MSSQL (32), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.21, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.21 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |
| 10.10.2.22 | 2 |  | High |

### app03.corp.example (10.10.2.31) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (153 inbound, 83 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- Plugin 156057, Critical, CVSS 10.0, port 8080/tcp (www), CVE-2021-44228
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 146 completed sessions from 0 external and 27 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 2 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 146 completed, 0 attempts, 0 blocked; first 2026-10-12T00:43:30Z, last 2026-10-17T23:27:13Z; top sources: 10.10.1.12 x81, 10.10.3.187 x4, 10.10.3.96 x4, 10.10.7.10 x4, 10.10.3.188 x4, 10.10.7.22 x4, 10.10.7.26 x4, 10.10.3.183 x3
- Synopsis: The application uses a Log4j version affected by remote code execution.
- Remediation: Upgrade to Apache Log4j 2.17.1 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 2 within 2 hops.
Lateral-movement protocols used: PostgreSQL (79), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.22 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### app04.corp.example (10.10.2.32) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (141 inbound, 100 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- Plugin 156057, Critical, CVSS 10.0, port 8080/tcp (www), CVE-2021-44228
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 132 completed sessions from 0 external and 29 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 132 completed, 0 attempts, 0 blocked; first 2026-10-12T04:14:00Z, last 2026-10-18T02:49:54Z; top sources: 10.10.1.13 x63, 10.10.3.121 x4, 10.10.3.62 x4, 10.10.3.124 x4, 10.10.3.54 x4, 10.10.3.84 x4, 10.10.3.151 x4, 10.10.3.53 x3
- Synopsis: The application uses a Log4j version affected by remote code execution.
- Remediation: Upgrade to Apache Log4j 2.17.1 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (62), MSSQL (34), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.22 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### jenkins01.corp.example (10.10.2.45) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (40 inbound, 82 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897)

- Plugin 189463, Critical, CVSS 9.8, port 8080/tcp (www), CVE-2024-23897
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 30 completed sessions from 0 external and 17 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 4 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 30 completed, 0 attempts, 0 blocked; first 2026-10-12T01:38:11Z, last 2026-10-18T02:14:35Z; top sources: 10.10.3.87 x3, 10.10.3.133 x3, 10.10.3.119 x3, 10.10.3.184 x3, 10.10.3.128 x2, 10.10.3.187 x2, 10.10.3.137 x2, 10.10.3.135 x2
- Synopsis: The Jenkins CLI allows unauthenticated reading of arbitrary files.
- Remediation: Upgrade to Jenkins 2.442 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SSH (52).
Reachable hosts with High/Critical findings: 10.10.2.44, 10.10.2.21.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.44 | 1 | 22/tcp | Critical |
| 10.10.2.35 | 1 | 22/tcp | Medium |
| 10.10.2.21 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

Outbound to 29 external address(es); top: 104.16.24.149 x2, 104.16.24.41 x1, 104.16.24.52 x1, 104.16.24.175 x1, 104.16.24.77 x1.

### backup01.corp.example (10.10.2.41) - P1 - act now

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Critical
- Seen in telemetry: yes (14 inbound, 46 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (93) Veeam Backup & Replication Credential Disclosure (CVE-2023-27532)

- Plugin 173914, Critical, CVSS 7.5, port 9401/tcp (veeam), CVE-2023-27532
- Why this score: Base severity: CVSS v3 7.5 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 23 internal host(s) directly and 50 within 2 hops, including 41 with High/Critical findings.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-15T05:34:49Z, last 2026-10-17T03:02:05Z; top sources: 10.10.2.40 x4
- Synopsis: The backup service exposes encrypted credentials to unauthenticated users.
- Remediation: Upgrade to Veeam Backup & Replication 12.0.0.1420 P20230223 or later.

**Blast radius**

Completed sessions to 23 internal host(s) directly, 50 within 2 hops.
Lateral-movement protocols used: SSH (38), SMB (8).
Reachable hosts with High/Critical findings: 10.10.1.11, 10.10.2.24, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.2.21, 10.10.2.22, 10.10.2.23, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.1.11 | 1 | 22/tcp | Critical |
| 10.10.2.24 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 22/tcp | Critical |
| 10.10.2.31 | 1 | 22/tcp | Critical |
| 10.10.2.32 | 1 | 22/tcp | Critical |
| 10.10.2.40 | 1 | 445/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp | Critical |
| 10.10.2.45 | 1 | 22/tcp | Critical |
| 10.10.1.12 | 1 | 22/tcp | High |
| 10.10.1.13 | 1 | 22/tcp | High |
| 10.10.1.14 | 1 | 22/tcp | High |
| 10.10.1.40 | 1 | 22/tcp | High |
| 10.10.2.21 | 1 | 22/tcp | High |
| 10.10.2.22 | 1 | 22/tcp | High |
| ... 35 more | | | |

### ws-031.corp.example (10.10.3.31) - P1 - act now

- Operating system: Microsoft Windows 7 Professional
- Findings: 1 Critical
- Seen in telemetry: yes (92 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Exploitation indicators** (leads unless marked corroborated)

- [lead] 10.10.1.10, which is flagged for investigation, newly connected to this vulnerable service at 2026-10-16T04:08:00Z. Check this host for signs of lateral movement.

**Findings and exposure evidence**

#### P1 (89) Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)

- Plugin 125313, Critical, CVSS 9.8, port 3389/tcp (msrdp), CVE-2019-0708
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 31 completed sessions from 0 external and 2 internal sources. 60 connection(s) to it were blocked by a firewall. The IPS/IDS blocked 3 alerted attempt(s) against it. Traffic gives leads worth investigating; nothing in the logs confirms exploitation.
- Traffic to service: 31 completed, 0 attempts, 60 blocked; first 2026-10-12T05:08:06Z, last 2026-10-18T03:11:38Z; top sources: 10.10.3.5 x30, 10.10.1.10 x1
- Synopsis: The remote host is affected by a remote code execution vulnerability in Remote Desktop Services.
- Remediation: Apply the May 2019 security update and enable Network Level Authentication.

**Blast radius**

No completed internal sessions from this host were observed.

### git01.corp.example (10.10.2.44) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (143 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (85) GitLab 16.1 < 16.7.2 Account Takeover via Password Reset

- Plugin 187600, Critical, CVSS 10.0, port 443/tcp (www), CVE-2023-7028
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available. Exposure: vulnerable service reached internally by many hosts - 62 completed sessions from 0 external and 17 internal sources.
- Traffic to service: 62 completed, 0 attempts, 0 blocked; first 2026-10-12T00:05:20Z, last 2026-10-18T03:05:06Z; top sources: 10.10.3.196 x6, 10.10.3.137 x6, 10.10.7.32 x6, 10.10.3.135 x5, 10.10.7.24 x5, 10.10.3.87 x5, 10.10.3.119 x4, 10.10.7.15 x3
- Synopsis: The GitLab instance allows account takeover through the password reset flow.
- Remediation: Upgrade to GitLab 16.7.2 or later and enable two-factor authentication.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 25 external address(es); top: 140.82.112.125 x1, 140.82.112.169 x1, 140.82.112.130 x1, 140.82.112.62 x1, 140.82.112.83 x1.

### fs01.corp.example (10.10.2.25) - P1 - act now

- Operating system: Microsoft Windows Server 2012 R2
- Findings: 1 Critical
- Seen in telemetry: yes (581 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Exploitation indicators** (leads unless marked corroborated)

- [lead] 10.10.1.10, which is flagged for investigation, newly connected to this vulnerable service at 2026-10-16T04:07:00Z. Check this host for signs of lateral movement.

**Findings and exposure evidence**

#### P1 (83) MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)

- Plugin 97833, Critical, CVSS 8.1, port 445/tcp (cifs), CVE-2017-0143, CVE-2017-0144, CVE-2017-0145
- Why this score: Base severity: CVSS v3 8.1 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 581 completed sessions from 0 external and 69 internal sources. Traffic gives leads worth investigating; nothing in the logs confirms exploitation.
- Traffic to service: 581 completed, 0 attempts, 0 blocked; first 2026-10-12T00:16:47Z, last 2026-10-18T02:56:33Z; top sources: 10.10.3.44 x25, 10.10.3.45 x25, 10.10.3.41 x25, 10.10.3.47 x25, 10.10.3.40 x25, 10.10.3.46 x25, 10.10.3.43 x25, 10.10.3.42 x25
- Synopsis: The remote Windows host is affected by multiple remote code execution vulnerabilities in SMBv1.
- Remediation: Apply MS17-010 and disable SMBv1.

**Blast radius**

No completed internal sessions from this host were observed.

### cam-60.corp.example (10.10.4.60) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 7 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-14T06:16:07Z, last 2026-10-17T18:05:15Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.89 x1, 47.88.59.142 x1, 47.88.59.128 x1, 47.88.59.29 x1, 47.88.59.165 x1.

### cam-61.corp.example (10.10.4.61) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 7 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-13T22:22:12Z, last 2026-10-16T13:27:08Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.164 x1, 47.88.59.210 x1, 47.88.59.92 x1, 47.88.59.221 x1, 47.88.59.84 x1.

### cam-62.corp.example (10.10.4.62) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (14 inbound, 3 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 4 attempts, 0 blocked; first 2026-10-12T13:28:33Z, last 2026-10-17T08:19:04Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 3 external address(es); top: 47.88.59.80 x1, 47.88.59.179 x1, 47.88.59.131 x1.

### cam-63.corp.example (10.10.4.63) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 4 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-13T23:36:27Z, last 2026-10-16T19:09:06Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 4 external address(es); top: 47.88.59.103 x1, 47.88.59.212 x1, 47.88.59.40 x1, 47.88.59.252 x1.

### cam-64.corp.example (10.10.4.64) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 5 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T05:42:25Z, last 2026-10-18T02:25:16Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 5 external address(es); top: 47.88.59.160 x1, 47.88.59.139 x1, 47.88.59.116 x1, 47.88.59.28 x1, 47.88.59.32 x1.

### cam-65.corp.example (10.10.4.65) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 4 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-13T13:13:20Z, last 2026-10-15T23:01:29Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 4 external address(es); top: 47.88.59.156 x1, 47.88.59.84 x1, 47.88.59.29 x1, 47.88.59.26 x1.

### cam-66.corp.example (10.10.4.66) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 7 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-16T13:03:56Z, last 2026-10-18T02:25:43Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.195 x1, 47.88.59.166 x1, 47.88.59.123 x1, 47.88.59.143 x1, 47.88.59.131 x1.

### cam-67.corp.example (10.10.4.67) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 5 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-13T05:41:03Z, last 2026-10-16T23:05:42Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 5 external address(es); top: 47.88.59.157 x1, 47.88.59.243 x1, 47.88.59.181 x1, 47.88.59.174 x1, 47.88.59.232 x1.

### cam-68.corp.example (10.10.4.68) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 8 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T23:15:28Z, last 2026-10-17T00:30:37Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 8 external address(es); top: 47.88.59.249 x1, 47.88.59.162 x1, 47.88.59.14 x1, 47.88.59.187 x1, 47.88.59.78 x1.

### cam-69.corp.example (10.10.4.69) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 6 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T20:40:32Z, last 2026-10-14T10:29:29Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 6 external address(es); top: 47.88.59.236 x1, 47.88.59.238 x1, 47.88.59.175 x1, 47.88.59.218 x1, 47.88.59.17 x1.

### print01.corp.example (10.10.2.43) - P2 - this cycle

- Operating system: Microsoft Windows Server 2016
- Findings: 1 Critical
- Seen in telemetry: yes (148 inbound, 180 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (73) Windows Print Spooler Service Enabled (PrintNightmare)

- Plugin 151440, Critical, CVSS 8.8, port host-level, CVE-2021-34527
- Why this score: Base severity: CVSS v3 8.8 (Critical). A public exploit is available (Metasploit). Exposure: host is active on the network - 148 completed sessions from 0 external and 97 internal sources. Blast radius: the host talks to 9 internal host(s) directly and 9 within 2 hops, including 8 with High/Critical findings.
- Traffic to host: 148 completed, 0 attempts, 0 blocked; first 2026-10-12T00:42:03Z, last 2026-10-18T02:45:30Z; top sources: 10.10.2.42 x3, 10.10.3.6 x3, 10.10.3.147 x2, 10.10.3.124 x2, 10.10.3.52 x2, 10.10.3.127 x2, 10.10.3.111 x2, 10.10.2.41 x2
- Synopsis: The Print Spooler service on the remote host is affected by remote code execution.
- Remediation: Apply the July 2021 updates and restrict Point and Print.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 9 within 2 hops.
Lateral-movement protocols used: LDAP (6).
Reachable hosts with High/Critical findings: 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.4.51 | 1 | 9100/tcp | High |
| 10.10.4.52 | 1 | 9100/tcp | High |
| 10.10.4.53 | 1 | 9100/tcp | High |
| 10.10.4.54 | 1 | 9100/tcp | High |
| 10.10.4.55 | 1 | 9100/tcp | High |
| 10.10.4.56 | 1 | 9100/tcp | High |
| 10.10.4.57 | 1 | 9100/tcp | High |
| 10.10.4.58 | 1 | 9100/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### web04.corp.example (10.10.1.13) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (93 inbound, 73 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P2 (67) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 79 completed sessions from 66 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 5 within 2 hops, including 3 with High/Critical findings.
- Traffic to service: 79 completed, 0 attempts, 0 blocked; first 2026-10-12T02:17:33Z, last 2026-10-17T21:30:17Z; top sources: 198.51.100.25 (ext) x2, 198.51.100.37 (ext) x2, 198.51.100.129 (ext) x2, 198.51.100.52 (ext) x2, 198.51.100.201 (ext) x2, 198.51.100.65 (ext) x2, 198.51.100.96 (ext) x2, 198.51.100.113 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 5 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.24, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

### ws-102.corp.example (10.10.3.102) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (3 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T13:55:46Z, last 2026-10-17T13:41:11Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T13:55:46Z, last 2026-10-17T13:41:11Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-103.corp.example (10.10.3.103) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-105.corp.example (10.10.3.105) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-106.corp.example (10.10.3.106) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-108.corp.example (10.10.3.108) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 23 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-113.corp.example (10.10.3.113) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-114.corp.example (10.10.3.114) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (5).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-118.corp.example (10.10.3.118) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-119.corp.example (10.10.3.119) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 43 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 34 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 34 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 34 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (5), LDAP (3), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| ... 23 more | | | |

### ws-121.corp.example (10.10.3.121) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-122.corp.example (10.10.3.122) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-124.corp.example (10.10.3.124) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-125.corp.example (10.10.3.125) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-128.corp.example (10.10.3.128) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: SMB (8), SSH (2), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 14 more | | | |

### ws-129.corp.example (10.10.3.129) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (3 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T02:31:21Z, last 2026-10-17T23:14:43Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T02:31:21Z, last 2026-10-17T23:14:43Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T02:31:21Z, last 2026-10-17T23:14:43Z; top sources: 10.10.2.40 x3
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-130.corp.example (10.10.3.130) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-131.corp.example (10.10.3.131) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-132.corp.example (10.10.3.132) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-133.corp.example (10.10.3.133) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 45 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), SSH (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 13 more | | | |

### ws-135.corp.example (10.10.3.135) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (7), SSH (3), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 13 more | | | |

### ws-136.corp.example (10.10.3.136) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 23 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (4), LDAP (4), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-140.corp.example (10.10.3.140) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-147.corp.example (10.10.3.147) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T18:08:11Z, last 2026-10-15T12:54:05Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 18 more | | | |

### ws-148.corp.example (10.10.3.148) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-149.corp.example (10.10.3.149) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-150.corp.example (10.10.3.150) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-153.corp.example (10.10.3.153) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: LDAP (5), Kerberos (5), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-155.corp.example (10.10.3.155) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-157.corp.example (10.10.3.157) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-158.corp.example (10.10.3.158) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-160.corp.example (10.10.3.160) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-161.corp.example (10.10.3.161) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 41 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 36 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 36 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 9 internal host(s) directly and 36 within 2 hops, including 32 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 36 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (4), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 21 more | | | |

### ws-166.corp.example (10.10.3.166) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (4), LDAP (3), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-167.corp.example (10.10.3.167) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-170.corp.example (10.10.3.170) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-171.corp.example (10.10.3.171) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-174.corp.example (10.10.3.174) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (3 inbound, 41 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 29 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-16T01:40:40Z, last 2026-10-17T10:47:13Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 29 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-16T01:40:40Z, last 2026-10-17T10:47:13Z; top sources: 10.10.2.40 x3
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (5), Kerberos (5).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 18 more | | | |

### ws-176.corp.example (10.10.3.176) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-179.corp.example (10.10.3.179) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-180.corp.example (10.10.3.180) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-182.corp.example (10.10.3.182) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-183.corp.example (10.10.3.183) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (3 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-15T21:19:49Z, last 2026-10-17T03:36:25Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-15T21:19:49Z, last 2026-10-17T03:36:25Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 18 more | | | |

### ws-184.corp.example (10.10.3.184) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 37 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (4), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 22 more | | | |

### ws-186.corp.example (10.10.3.186) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-187.corp.example (10.10.3.187) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), SSH (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 13 more | | | |

### ws-188.corp.example (10.10.3.188) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-189.corp.example (10.10.3.189) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-192.corp.example (10.10.3.192) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (3 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T04:18:11Z, last 2026-10-15T09:20:07Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T04:18:11Z, last 2026-10-15T09:20:07Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T04:18:11Z, last 2026-10-15T09:20:07Z; top sources: 10.10.2.40 x3
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 9 more | | | |

### ws-193.corp.example (10.10.3.193) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-197.corp.example (10.10.3.197) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 23 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-048.corp.example (10.10.3.48) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T19:12:40Z, last 2026-10-13T06:35:04Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T19:12:40Z, last 2026-10-13T06:35:04Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T19:12:40Z, last 2026-10-13T06:35:04Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 10 more | | | |

Outbound to 1 external address(es); top: 103.160.59.97 x2.

### ws-049.corp.example (10.10.3.49) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-050.corp.example (10.10.3.50) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (4), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-052.corp.example (10.10.3.52) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-053.corp.example (10.10.3.53) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-054.corp.example (10.10.3.54) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-055.corp.example (10.10.3.55) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-057.corp.example (10.10.3.57) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T12:55:25Z, last 2026-10-17T10:48:42Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 10 more | | | |

### ws-059.corp.example (10.10.3.59) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-061.corp.example (10.10.3.61) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-062.corp.example (10.10.3.62) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-065.corp.example (10.10.3.65) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-066.corp.example (10.10.3.66) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 20 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 20 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T04:25:13Z, last 2026-10-14T13:08:42Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 9 more | | | |

### ws-067.corp.example (10.10.3.67) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (3), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-069.corp.example (10.10.3.69) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-071.corp.example (10.10.3.71) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-075.corp.example (10.10.3.75) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T03:24:25Z, last 2026-10-17T09:25:21Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-12T20:35:01Z, last 2026-10-17T09:25:21Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 10 more | | | |

### ws-076.corp.example (10.10.3.76) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (5).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-077.corp.example (10.10.3.77) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-079.corp.example (10.10.3.79) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-081.corp.example (10.10.3.81) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-082.corp.example (10.10.3.82) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-083.corp.example (10.10.3.83) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-084.corp.example (10.10.3.84) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T05:39:16Z, last 2026-10-14T13:20:15Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 10 more | | | |

### ws-087.corp.example (10.10.3.87) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 41 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 34 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 37 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (4), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 22 more | | | |

### ws-088.corp.example (10.10.3.88) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-090.corp.example (10.10.3.90) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. 3 connection(s) to it were blocked by a firewall. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 0 completed, 0 attempts, 3 blocked; first 2026-10-12T15:56:48Z, last 2026-10-16T02:27:03Z
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. 3 connection(s) to it were blocked by a firewall. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 0 completed, 0 attempts, 3 blocked; first 2026-10-12T15:56:48Z, last 2026-10-16T02:27:03Z
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (18) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: connections to service blocked by firewall. 3 connection(s) to it were blocked by a firewall. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Traffic to service: 0 completed, 0 attempts, 3 blocked; first 2026-10-12T15:56:48Z, last 2026-10-16T02:27:03Z
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-093.corp.example (10.10.3.93) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (3 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 20 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T08:39:31Z, last 2026-10-18T01:35:42Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 20 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T08:39:31Z, last 2026-10-18T01:35:42Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 20 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T08:39:31Z, last 2026-10-18T01:35:42Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 9 more | | | |

### ws-095.corp.example (10.10.3.95) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-096.corp.example (10.10.3.96) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-097.corp.example (10.10.3.97) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-098.corp.example (10.10.3.98) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-099.corp.example (10.10.3.99) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-010.corp.example (10.10.7.10) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-012.corp.example (10.10.7.12) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-015.corp.example (10.10.7.15) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 34 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 34 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (2), SSH (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| ... 23 more | | | |

### lt-017.corp.example (10.10.7.17) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-018.corp.example (10.10.7.18) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-020.corp.example (10.10.7.20) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-021.corp.example (10.10.7.21) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-025.corp.example (10.10.7.25) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-027.corp.example (10.10.7.27) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-033.corp.example (10.10.7.33) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-034.corp.example (10.10.7.34) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-037.corp.example (10.10.7.37) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-040.corp.example (10.10.7.40) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### lt-043.corp.example (10.10.7.43) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### lt-044.corp.example (10.10.7.44) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### lt-045.corp.example (10.10.7.45) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### web03.corp.example (10.10.1.12) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (103 inbound, 91 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P2 (62) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 85 completed sessions from 74 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 4 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 85 completed, 0 attempts, 0 blocked; first 2026-10-12T01:00:38Z, last 2026-10-18T02:06:53Z; top sources: 198.51.100.232 (ext) x3, 198.51.100.92 (ext) x2, 198.51.100.102 (ext) x2, 198.51.100.40 (ext) x2, 198.51.100.16 (ext) x2, 198.51.100.94 (ext) x2, 198.51.100.237 (ext) x2, 198.51.100.19 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 4 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.22 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

### ws-040.corp.example (10.10.3.40) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 88 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (61) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 5 internal host(s) directly and 5 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 5 internal host(s) directly, 5 within 2 hops.
Lateral-movement protocols used: SMB (29), Kerberos (10), LDAP (10), RDP (9).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |
| 10.10.6.71 | 1 | 8443/tcp | - |

Outbound to 23 external address(es); top: 93.184.254.146 x1, 93.184.34.189 x1, 93.184.24.67 x1, 93.184.108.144 x1, 93.184.146.48 x1.

### ws-041.corp.example (10.10.3.41) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 81 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (27), LDAP (10), Kerberos (10), RDP (7).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 20 external address(es); top: 93.184.150.65 x1, 93.184.177.121 x1, 93.184.251.202 x1, 93.184.143.53 x1, 93.184.92.207 x1.

### ws-042.corp.example (10.10.3.42) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 98 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (35), Kerberos (10), LDAP (10), RDP (5).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 24 external address(es); top: 93.184.29.234 x1, 93.184.193.22 x1, 93.184.242.127 x1, 93.184.42.55 x1, 93.184.154.188 x1.

### ws-043.corp.example (10.10.3.43) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 73 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (28), Kerberos (10), LDAP (10), RDP (4).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 15 external address(es); top: 93.184.95.199 x1, 93.184.73.235 x1, 93.184.57.9 x1, 93.184.186.111 x1, 93.184.157.203 x1.

### ws-044.corp.example (10.10.3.44) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 76 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (32), LDAP (10), Kerberos (10), RDP (3).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 15 external address(es); top: 93.184.212.230 x1, 93.184.79.186 x1, 93.184.24.184 x1, 93.184.199.32 x1, 93.184.176.250 x1.

### ws-045.corp.example (10.10.3.45) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 81 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (30), Kerberos (10), LDAP (10), RDP (6).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 19 external address(es); top: 93.184.224.121 x1, 93.184.243.41 x1, 93.184.14.6 x1, 93.184.172.109 x1, 93.184.74.93 x1.

### ws-046.corp.example (10.10.3.46) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 76 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (25), Kerberos (10), LDAP (10), RDP (8).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp | - |

Outbound to 17 external address(es); top: 93.184.223.178 x1, 93.184.85.157 x1, 93.184.64.87 x1, 93.184.247.117 x1, 93.184.80.151 x1.

### ws-047.corp.example (10.10.3.47) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 75 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (30), LDAP (10), Kerberos (10), RDP (2).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 17 external address(es); top: 93.184.191.222 x1, 93.184.59.143 x1, 93.184.89.58 x1, 93.184.108.230 x1, 93.184.67.66 x1.

### web05.corp.example (10.10.1.14) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (140 inbound, 87 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P2 (58) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 120 completed sessions from 98 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 120 completed, 0 attempts, 0 blocked; first 2026-10-12T00:44:13Z, last 2026-10-18T01:58:31Z; top sources: 198.51.100.203 (ext) x3, 198.51.100.210 (ext) x3, 198.51.100.244 (ext) x3, 198.51.100.249 (ext) x2, 198.51.100.248 (ext) x2, 198.51.100.142 (ext) x2, 198.51.100.36 (ext) x2, 198.51.100.211 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 4 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.21.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.21 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

### prn-51.corp.example (10.10.4.51) - P2 - this cycle

- Operating system: HP LaserJet
- Findings: 1 High
- Seen in telemetry: yes (26 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T19:26:27Z, last 2026-10-17T22:53:02Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-52.corp.example (10.10.4.52) - P2 - this cycle

- Operating system: Xerox VersaLink
- Findings: 1 High
- Seen in telemetry: yes (33 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T02:11:51Z, last 2026-10-17T23:32:59Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-53.corp.example (10.10.4.53) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (18 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T11:55:33Z, last 2026-10-17T14:06:41Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-54.corp.example (10.10.4.54) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (30 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-15T04:30:50Z, last 2026-10-17T13:18:32Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-55.corp.example (10.10.4.55) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (25 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T17:35:11Z, last 2026-10-17T20:02:38Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-56.corp.example (10.10.4.56) - P2 - this cycle

- Operating system: HP LaserJet
- Findings: 1 High
- Seen in telemetry: yes (29 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T15:17:31Z, last 2026-10-16T12:45:54Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-57.corp.example (10.10.4.57) - P2 - this cycle

- Operating system: HP LaserJet
- Findings: 1 High
- Seen in telemetry: yes (35 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T07:43:47Z, last 2026-10-17T16:37:45Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-58.corp.example (10.10.4.58) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (26 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T10:11:31Z, last 2026-10-16T16:29:45Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### db02.corp.example (10.10.2.21) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (252 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (52) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 241 completed sessions from 0 external and 4 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 241 completed, 0 attempts, 0 blocked; first 2026-10-12T00:06:03Z, last 2026-10-18T02:45:03Z; top sources: 10.10.2.30 x77, 10.10.2.33 x65, 10.10.2.34 x50, 10.10.2.35 x49
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.
Lateral-movement protocols used: PostgreSQL (30).
Reachable hosts with High/Critical findings: 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.22 | 1 | 5432/tcp | High |

### sql01.corp.example (10.10.2.24) - P3 - scheduled

- Operating system: Microsoft Windows Server 2016
- Findings: 1 Critical
- Seen in telemetry: yes (123 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (49) Microsoft SQL Server Unsupported Version Detection

- Plugin 73756, Critical, CVSS 10.0, port 1433/tcp (mssql)
- Why this score: Base severity: CVSS v3 10.0 (Critical). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 111 completed sessions from 0 external and 4 internal sources.
- Traffic to service: 111 completed, 0 attempts, 0 blocked; first 2026-10-12T00:25:03Z, last 2026-10-18T02:16:27Z; top sources: 10.10.2.32 x34, 10.10.2.30 x32, 10.10.2.36 x24, 10.10.2.34 x21
- Synopsis: The installed version of SQL Server is no longer supported.
- Remediation: Upgrade to a supported version of SQL Server.

**Blast radius**

No completed internal sessions from this host were observed.

### sccm01.corp.example (10.10.2.40) - P3 - scheduled

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Critical
- Seen in telemetry: yes (284 inbound, 95 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041578: Windows Server 2019 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 284 completed sessions from 0 external and 192 internal sources. Blast radius: the host talks to 18 internal host(s) directly and 43 within 2 hops, including 34 with High/Critical findings.
- Traffic to host: 284 completed, 0 attempts, 0 blocked; first 2026-10-12T00:03:46Z, last 2026-10-18T03:00:57Z; top sources: 10.10.3.6 x4, 10.10.2.42 x3, 10.10.3.70 x2, 10.10.7.43 x2, 10.10.7.21 x2, 10.10.3.96 x2, 10.10.3.48 x2, 10.10.7.30 x2
- Synopsis: The remote Windows host is missing security update 5041578.
- Remediation: Apply Security Update 5041578.

**Blast radius**

Completed sessions to 18 internal host(s) directly, 43 within 2 hops.
Lateral-movement protocols used: SMB (34), RPC (17).
Reachable hosts with High/Critical findings: 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.1.11, 10.10.2.24, 10.10.2.25, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.2.21, 10.10.2.22, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.41 | 1 | 9401/tcp | Critical |
| 10.10.3.102 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.129 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.138 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.156 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.183 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.192 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.93 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.111 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.120 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.147 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.165 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.174 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.48 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.57 | 1 | 135/tcp, 445/tcp | High |
| ... 28 more | | | |

Outbound to 38 external address(es); top: 13.107.4.57 x2, 13.107.4.128 x2, 13.107.4.13 x1, 13.107.4.168 x1, 13.107.4.183 x1.

### ws-100.corp.example (10.10.3.100) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-101.corp.example (10.10.3.101) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (4), Kerberos (3), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-104.corp.example (10.10.3.104) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-107.corp.example (10.10.3.107) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-109.corp.example (10.10.3.109) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-115.corp.example (10.10.3.115) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-116.corp.example (10.10.3.116) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-134.corp.example (10.10.3.134) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 2 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-138.corp.example (10.10.3.138) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (3 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T17:08:20Z, last 2026-10-17T04:50:33Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-14T17:08:20Z, last 2026-10-16T15:08:47Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 9 more | | | |

### ws-142.corp.example (10.10.3.142) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 2 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-143.corp.example (10.10.3.143) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-151.corp.example (10.10.3.151) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 40 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (5).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-156.corp.example (10.10.3.156) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (3 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T11:41:47Z, last 2026-10-17T22:46:05Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-163.corp.example (10.10.3.163) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-169.corp.example (10.10.3.169) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-172.corp.example (10.10.3.172) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (5).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-173.corp.example (10.10.3.173) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-177.corp.example (10.10.3.177) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-195.corp.example (10.10.3.195) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-199.corp.example (10.10.3.199) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-056.corp.example (10.10.3.56) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-058.corp.example (10.10.3.58) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-063.corp.example (10.10.3.63) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 2 High
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-085.corp.example (10.10.3.85) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-092.corp.example (10.10.3.92) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-094.corp.example (10.10.3.94) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-013.corp.example (10.10.7.13) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### lt-019.corp.example (10.10.7.19) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-023.corp.example (10.10.7.23) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 22 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-026.corp.example (10.10.7.26) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-031.corp.example (10.10.7.31) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-042.corp.example (10.10.7.42) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### lt-046.corp.example (10.10.7.46) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### db01.corp.example (10.10.2.20) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (170 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (45) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 140 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops.
- Traffic to service: 140 completed, 0 attempts, 0 blocked; first 2026-10-12T00:34:43Z, last 2026-10-18T02:23:17Z; top sources: 10.10.1.20 x140
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.6.71 | 1 | 8443/tcp | - |

### proxy01.corp.example (10.10.1.40) - P3 - scheduled

- Operating system: Linux Kernel 4.18 on Red Hat Enterprise Linux 8
- Findings: 1 High
- Seen in telemetry: yes (1503 inbound, 60 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (43) Squid < 6.4 Multiple Vulnerabilities

- Plugin 182251, High, CVSS 7.5, port 3128/tcp (http_proxy), CVE-2023-46846
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 1498 completed sessions from 0 external and 189 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops.
- Traffic to service: 1498 completed, 0 attempts, 0 blocked; first 2026-10-12T00:01:19Z, last 2026-10-18T03:02:18Z; top sources: 10.10.3.127 x12, 10.10.3.193 x12, 10.10.3.176 x12, 10.10.3.124 x12, 10.10.3.80 x12, 10.10.3.59 x12, 10.10.3.147 x12, 10.10.3.156 x12
- Synopsis: The proxy is affected by request smuggling and denial of service vulnerabilities.
- Remediation: Upgrade to Squid 6.4 or later.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.0.53 | 1 | 53/udp | - |

### db03.corp.example (10.10.2.22) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (226 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (43) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 217 completed sessions from 0 external and 4 internal sources.
- Traffic to service: 217 completed, 0 attempts, 0 blocked; first 2026-10-12T00:56:13Z, last 2026-10-18T02:33:44Z; top sources: 10.10.2.31 x79, 10.10.2.32 x62, 10.10.2.37 x46, 10.10.2.21 x30
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

No completed internal sessions from this host were observed.

### db04.corp.example (10.10.2.23) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (71 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (43) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 60 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 60 completed, 0 attempts, 0 blocked; first 2026-10-12T02:31:00Z, last 2026-10-18T03:10:26Z; top sources: 10.10.2.36 x60
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

No completed internal sessions from this host were observed.

### app06.corp.example (10.10.2.34) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (68 inbound, 75 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (43) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 58 completed sessions from 0 external and 21 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 4 within 2 hops, including 3 with High/Critical findings.
- Traffic to service: 58 completed, 0 attempts, 0 blocked; first 2026-10-12T00:25:16Z, last 2026-10-18T00:49:19Z; top sources: 10.10.3.171 x4, 10.10.7.25 x4, 10.10.3.63 x4, 10.10.7.27 x4, 10.10.3.106 x4, 10.10.3.76 x4, 10.10.7.46 x4, 10.10.3.190 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: PostgreSQL (50), MSSQL (21), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.21, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.21 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |
| 10.10.2.22 | 2 |  | High |

### app05.corp.example (10.10.2.33) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (125 inbound, 69 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 115 completed sessions from 0 external and 16 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 115 completed, 0 attempts, 0 blocked; first 2026-10-12T01:55:26Z, last 2026-10-18T00:23:16Z; top sources: 10.10.1.14 x77, 10.10.7.43 x4, 10.10.7.14 x4, 10.10.3.59 x4, 10.10.3.196 x3, 10.10.3.149 x3, 10.10.3.186 x3, 10.10.3.134 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (65), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.21, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.21 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |
| 10.10.2.22 | 2 |  | High |

### app07.corp.example (10.10.2.35) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (73 inbound, 53 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 53 completed sessions from 0 external and 26 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 53 completed, 0 attempts, 0 blocked; first 2026-10-12T01:59:42Z, last 2026-10-18T01:26:57Z; top sources: 10.10.3.86 x4, 10.10.3.90 x4, 10.10.7.33 x4, 10.10.3.161 x3, 10.10.3.116 x3, 10.10.7.34 x3, 10.10.3.168 x3, 10.10.3.193 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (49), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.21, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.21 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |
| 10.10.2.22 | 2 |  | High |

### app08.corp.example (10.10.2.36) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (64 inbound, 88 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 53 completed sessions from 0 external and 22 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 53 completed, 0 attempts, 0 blocked; first 2026-10-12T01:37:50Z, last 2026-10-18T02:50:37Z; top sources: 10.10.3.52 x4, 10.10.3.132 x4, 10.10.3.139 x4, 10.10.3.49 x4, 10.10.3.199 x3, 10.10.3.61 x3, 10.10.3.169 x3, 10.10.7.29 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (60), MSSQL (24), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.23 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### mail01.corp.example (10.10.1.25) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (125 inbound, 90 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P3 (39) Postfix SMTP Smuggling

- Plugin 187315, Medium, CVSS 5.3, port 25/tcp (smtp), CVE-2023-51764
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 90 completed sessions from 77 external and 0 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops.
- Traffic to service: 90 completed, 0 attempts, 0 blocked; first 2026-10-12T01:55:58Z, last 2026-10-18T03:09:59Z; top sources: 209.85.220.199 (ext) x2, 209.85.220.107 (ext) x2, 209.85.220.197 (ext) x2, 209.85.220.54 (ext) x2, 209.85.220.201 (ext) x2, 209.85.220.130 (ext) x2, 209.85.220.22 (ext) x2, 209.85.220.133 (ext) x2
- Synopsis: The mail server is affected by an SMTP smuggling vulnerability.
- Remediation: Upgrade Postfix and set smtpd_forbid_bare_newline.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.
Lateral-movement protocols used: LDAP (20).

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.0.10 | 1 | 389/tcp | - |

Outbound to 64 external address(es); top: 40.107.22.167 x3, 40.107.22.64 x2, 40.107.22.69 x2, 40.107.22.70 x2, 40.107.22.62 x2.

### ws-111.corp.example (10.10.3.111) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 Medium, 1 High
- Seen in telemetry: yes (3 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-16T10:53:43Z, last 2026-10-17T06:13:55Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-15T11:28:26Z, last 2026-10-17T06:13:55Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-15T11:28:26Z, last 2026-10-17T06:13:55Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 19 more | | | |

### ws-120.corp.example (10.10.3.120) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium, 1 High
- Seen in telemetry: yes (3 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 22 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-15T03:17:42Z, last 2026-10-16T09:26:43Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 22 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-15T03:17:42Z, last 2026-10-16T09:26:43Z; top sources: 10.10.2.40 x3
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 9 more | | | |

### ws-165.corp.example (10.10.3.165) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium, 1 High
- Seen in telemetry: yes (3 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-16T00:45:34Z, last 2026-10-17T15:25:50Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 21 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T20:09:14Z, last 2026-10-17T15:25:50Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 9 more | | | |

### ws-110.corp.example (10.10.3.110) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 25 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (5), Kerberos (3), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 14 more | | | |

### ws-112.corp.example (10.10.3.112) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-137.corp.example (10.10.3.137) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 13 more | | | |

### ws-146.corp.example (10.10.3.146) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-152.corp.example (10.10.3.152) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-164.corp.example (10.10.3.164) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-190.corp.example (10.10.3.190) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-198.corp.example (10.10.3.198) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-051.corp.example (10.10.3.51) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-060.corp.example (10.10.3.60) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-068.corp.example (10.10.3.68) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (5), Kerberos (5).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-073.corp.example (10.10.3.73) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-074.corp.example (10.10.3.74) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-078.corp.example (10.10.3.78) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-080.corp.example (10.10.3.80) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ups-mgmt.corp.example (10.10.5.60) - P3 - scheduled

- Operating system: Embedded Linux
- Findings: 1 High
- Seen in telemetry: no (0 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: no telemetry for this host (unknown).
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### lt-024.corp.example (10.10.7.24) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: LDAP (4), SSH (3), SMB (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 13 more | | | |

### lt-030.corp.example (10.10.7.30) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 21 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (4), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### lt-032.corp.example (10.10.7.32) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 40 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| ... 23 more | | | |

### lt-036.corp.example (10.10.7.36) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### app09.corp.example (10.10.2.37) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (88 inbound, 50 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (37) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 77 completed sessions from 0 external and 30 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 2 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 77 completed, 0 attempts, 0 blocked; first 2026-10-12T00:37:26Z, last 2026-10-18T00:35:28Z; top sources: 10.10.3.112 x4, 10.10.3.97 x4, 10.10.3.165 x4, 10.10.3.117 x4, 10.10.3.99 x4, 10.10.3.114 x4, 10.10.3.192 x4, 10.10.3.179 x4
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 2 within 2 hops.
Lateral-movement protocols used: PostgreSQL (46), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.22 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### mon01.corp.example (10.10.2.42) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (2 inbound, 226 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: service not observed in use. Blast radius: the host talks to 43 internal host(s) directly and 62 within 2 hops, including 53 with High/Critical findings.
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

Completed sessions to 43 internal host(s) directly, 62 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.1.11, 10.10.1.30, 10.10.2.24, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.40, 10.10.2.41, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.4.60, 10.10.4.61, 10.10.4.62, 10.10.4.63, 10.10.4.64, 10.10.4.65, 10.10.4.66, 10.10.4.67, 10.10.4.68, 10.10.4.69, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.2.21, 10.10.2.22, 10.10.2.23, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.1.11 | 1 | 161/udp | Critical |
| 10.10.1.30 | 1 | 161/udp | Critical |
| 10.10.2.24 | 1 | 161/udp | Critical |
| 10.10.2.30 | 1 | 161/udp | Critical |
| 10.10.2.31 | 1 | 161/udp | Critical |
| 10.10.2.32 | 1 | 161/udp | Critical |
| 10.10.2.40 | 1 | 161/udp | Critical |
| 10.10.2.41 | 1 | 161/udp | Critical |
| 10.10.2.43 | 1 | 161/udp | Critical |
| 10.10.2.44 | 1 | 161/udp | Critical |
| 10.10.2.45 | 1 | 161/udp | Critical |
| 10.10.4.60 | 1 | 554/tcp, 80/tcp | Critical |
| 10.10.4.61 | 1 | 554/tcp, 80/tcp | Critical |
| 10.10.4.62 | 1 | 554/tcp, 80/tcp | Critical |
| 10.10.4.63 | 1 | 554/tcp, 80/tcp | Critical |
| ... 47 more | | | |

Outbound to 2 external address(es); top: 104.194.158.65 x2, 104.248.131.53 x1.

### ws-126.corp.example (10.10.3.126) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 22 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-127.corp.example (10.10.3.127) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-159.corp.example (10.10.3.159) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-181.corp.example (10.10.3.181) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-185.corp.example (10.10.3.185) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-191.corp.example (10.10.3.191) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-086.corp.example (10.10.3.86) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: LDAP (4), Kerberos (3), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-089.corp.example (10.10.3.89) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-091.corp.example (10.10.3.91) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### lt-014.corp.example (10.10.7.14) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 40 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-016.corp.example (10.10.7.16) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 40 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 37 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (4), SSH (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 22 more | | | |

### lt-022.corp.example (10.10.7.22) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 23 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: LDAP (5), Kerberos (5), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### lt-029.corp.example (10.10.7.29) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### lt-035.corp.example (10.10.7.35) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### ws-117.corp.example (10.10.3.117) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-123.corp.example (10.10.3.123) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-139.corp.example (10.10.3.139) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-141.corp.example (10.10.3.141) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-144.corp.example (10.10.3.144) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 31 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-145.corp.example (10.10.3.145) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### ws-154.corp.example (10.10.3.154) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-168.corp.example (10.10.3.168) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-175.corp.example (10.10.3.175) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 34 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (3), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| ... 23 more | | | |

### ws-178.corp.example (10.10.3.178) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### ws-196.corp.example (10.10.3.196) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 Medium
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 24 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (4), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 13 more | | | |

### ws-064.corp.example (10.10.3.64) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.22, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| ... 10 more | | | |

### ws-070.corp.example (10.10.3.70) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 23 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 22 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (3), SMB (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 11 more | | | |

### ws-072.corp.example (10.10.3.72) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-028.corp.example (10.10.7.28) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 33 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### lt-038.corp.example (10.10.7.38) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 32 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### lt-039.corp.example (10.10.7.39) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### vpn01.corp.example (10.10.1.30) - P3 - scheduled

- Operating system: Ivanti Connect Secure 22.3
- Findings: 1 Critical
- Seen in telemetry: yes (48 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (30) Ivanti Connect Secure Command Injection (CVE-2024-21887)

- Plugin 189987, Critical, CVSS 9.1, port 443/tcp (www), CVE-2023-46805, CVE-2024-21887
- Why this score: Base severity: CVSS v3 9.1 (Critical). A public exploit is available (Metasploit). Exposure: service not observed in use.
- Synopsis: The VPN appliance is affected by authentication bypass and command injection vulnerabilities.
- Remediation: Apply the vendor patch and run the integrity checker.

**Blast radius**

No completed internal sessions from this host were observed.

### fs02.corp.example (10.10.2.26) - P3 - scheduled

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Medium
- Seen in telemetry: yes (874 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (29) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 866 completed sessions from 0 external and 130 internal sources.
- Traffic to service: 866 completed, 0 attempts, 0 blocked; first 2026-10-12T00:21:37Z, last 2026-10-18T02:56:31Z; top sources: 10.10.7.12 x10, 10.10.3.145 x10, 10.10.3.167 x10, 10.10.3.71 x10, 10.10.3.111 x10, 10.10.7.25 x10, 10.10.3.189 x10, 10.10.3.94 x10
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

No completed internal sessions from this host were observed.

### ws-162.corp.example (10.10.3.162) - P4 - routine

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 24 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), SSH (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| ... 14 more | | | |

### ws-194.corp.example (10.10.3.194) - P4 - routine

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 31 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.23, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| ... 20 more | | | |

### lt-011.corp.example (10.10.7.11) - P4 - routine

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 30 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| ... 19 more | | | |

### lt-041.corp.example (10.10.7.41) - P4 - routine

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 21 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (5).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.2.21, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.102 | 2 |  | Critical |
| 10.10.3.129 | 2 |  | Critical |
| 10.10.3.138 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.183 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.93 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| ... 10 more | | | |

### prn-4f.corp.example (10.10.4.50) - P4 - routine

- Operating system: HP LaserJet
- Findings: 1 Medium
- Seen in telemetry: yes (8 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (13) Unencrypted Telnet Server

- Plugin 42263, Medium, CVSS 6.5, port 23/tcp (telnet)
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use.
- Synopsis: The remote Telnet server transmits traffic in cleartext.
- Remediation: Disable Telnet and use SSH instead.

**Blast radius**

No completed internal sessions from this host were observed.

### jump02.corp.example (10.10.3.6) - P4 - routine

- Operating system: Microsoft Windows Server 2022
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 89 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (12) Terminal Services Doesn't Use Network Level Authentication (NLA) Only

- Plugin 58453, Medium, CVSS 4.0, port 3389/tcp (msrdp)
- Why this score: Base severity: CVSS v3 4.0 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 19 internal host(s) directly and 62 within 2 hops, including 54 with High/Critical findings.
- Synopsis: The remote Terminal Services doesn't use NLA only.
- Remediation: Enable Network Level Authentication.

**Blast radius**

Completed sessions to 19 internal host(s) directly, 62 within 2 hops.
Lateral-movement protocols used: SSH (63), RDP (26).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.40, 10.10.2.41, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.2.21, 10.10.2.22, 10.10.2.23, 10.10.2.42, 10.10.1.11, 10.10.1.30, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.156, 10.10.3.183, 10.10.3.192, 10.10.3.93, 10.10.4.60, 10.10.4.61, 10.10.4.62, 10.10.4.63, 10.10.4.64, 10.10.4.65, 10.10.4.66, 10.10.4.67, 10.10.4.68, 10.10.4.69, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.3.111, 10.10.3.120, 10.10.3.147, 10.10.3.165, 10.10.3.174, 10.10.3.48, 10.10.3.57, 10.10.3.66, 10.10.3.75, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 3389/tcp | Critical |
| 10.10.2.30 | 1 | 22/tcp | Critical |
| 10.10.2.31 | 1 | 22/tcp | Critical |
| 10.10.2.32 | 1 | 22/tcp | Critical |
| 10.10.2.40 | 1 | 3389/tcp | Critical |
| 10.10.2.41 | 1 | 3389/tcp | Critical |
| 10.10.2.43 | 1 | 3389/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp | Critical |
| 10.10.2.45 | 1 | 22/tcp | Critical |
| 10.10.2.21 | 1 | 22/tcp | High |
| 10.10.2.22 | 1 | 22/tcp | High |
| 10.10.2.23 | 1 | 22/tcp | High |
| 10.10.2.42 | 1 | 22/tcp | High |
| 10.10.2.26 | 1 | 3389/tcp | Medium |
| 10.10.2.33 | 1 | 22/tcp | Medium |
| ... 47 more | | | |

### jump01.corp.example (10.10.3.5) - P4 - routine

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 60 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (11) Terminal Services Doesn't Use Network Level Authentication (NLA) Only

- Plugin 58453, Medium, CVSS 4.0, port 3389/tcp (msrdp)
- Why this score: Base severity: CVSS v3 4.0 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 2 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Synopsis: The remote Terminal Services doesn't use NLA only.
- Remediation: Enable Network Level Authentication.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: SSH (30), RDP (30).
Reachable hosts with High/Critical findings: 10.10.3.31, 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.3.31 | 1 | 3389/tcp | Critical |
| 10.10.2.20 | 1 | 22/tcp | High |
| 10.10.6.71 | 2 |  | - |

## 5. Coverage gaps

249 of 250 scanned hosts appear in telemetry; 253 internal addresses were seen in total.

**Scanned but not seen in telemetry** (exposure unknown; check sensor placement): 10.10.5.60

**Active internal servers not in the scan** (add to scan scope):

| Host | Services observed | Sessions |
|---|---|---|
| 10.10.0.10 | 389/tcp, 88/tcp | 1525 |
| 10.10.0.53 | 53/udp | 977 |
| 10.10.6.70 | 3389/tcp, 445/tcp | 81 |
| 10.10.6.71 | 8443/tcp | 31 |

## 6. Output files

- `executive_summary.md/.html`: leadership summary
- `technical_report.md/.html`: this report
- `correlated_findings.csv`: one row per finding with scores, for ticketing or spreadsheets
- `results.json`: full machine-readable result
- `hostile_activity.svg`: the hostile activity diagram as a standalone image
- `explorer.html`: interactive host explorer (who targets each host, and its internal blast radius)
- `normalized/flows.csv`, `normalized/findings.csv`: cleaned inputs in the common schema
- `normalized/zeek_events.jsonl`: other Zeek streams with stream identity and source fields
- `normalized/ot_events.jsonl`: industrial protocol records with operation and message direction

## Múcaro IOC matches

Exact matches to the imported IOC Archive are leads for review, not proof of malicious activity.

| Indicator | Type | Related hosts | Observed in | Source articles |
|---|---|---|---|---|
| 247.cdnflare.xyz | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| beraskencur.site | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| byveo.org | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| checkout-cdn.com | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| ntp.timesync.to | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| secure-dns-hub.com | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| solidmonpe.com | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 103.160.59.97 | ip | 10.10.3.48 | 2 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 104.194.158.65 | ip | 10.10.2.42 | 2 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 104.248.131.53 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 185.157.160.251 | ip | 10.10.1.11 | 2 network session | https://sansec.io/research/stylesmuggler-0day |
| 209.141.43.95 | ip | 10.10.1.11 | 1 network session | https://sansec.io/research/stylesmuggler-0day |
| 209.73.130.148 | ip | 10.10.1.11 | 1 IDS/IPS alert, 2 network session | https://sansec.io/research/stylesmuggler-0day |
| 99.84.67.186 | ip | 10.10.1.11 | 3 network session | https://sansec.io/research/stylesmuggler-0day |
