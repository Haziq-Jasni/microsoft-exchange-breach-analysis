##  Forensic Reconstruction & Telemetry Analysis: 2021 Microsoft Exchange Server Breach (HAFNIUM)

This project is an academic case study, completed as part of a group assignment, that reconstructs and documents the 2021 Microsoft Exchange Server (HAFNIUM/ProxyLogon) breach, using public incident reports, vendor threat-intelligence writeups, and the MITRE ATT&CK framework as source material. The goal was to practice the analytical workflow a digital forensics investigator would follow such as log analysis, attack-chain reconstruction, and legal/compliance review, rather than to perform a live investigation.

My contribution: I led the MITRE ATT&CK mapping of attacker behaviors, managed the digital forensics lifecycle documentation (evidence acquisition through analysis, with chain-of-custody records), and conducted the legal/compliance evaluation against PDPA guidelines (see Cross-Border Legal & Compliance Analysis below).

### 1. Command-Line Log Hunting (PowerShell)
Based on published indicators of compromise, this section documents the PowerShell text-filtering queries investigators used to sweep Exchange server logs (`HttpProxy`,` OABGeneratorLog`, and `ECP\Server`) for zero-day exploitation footprints:
* SSRF Entry (CVE-2021-26855): Internal request-routing anomalies where the AuthenticatedUser field was empty while the AnchorMailbox pattern contained unauthorized ServerInfo~*/* strings. This is a documented indicator of the SSRF exploit.
* Insecure Deserialization (CVE-2021-26857): Windows Application Event Log entries showing MSExchange Unified Messaging errors throwing System.InvalidCastException, a signature associated with SYSTEM-level remote code execution in public reporting.

### 2. Live Web Traffic Parsing (SIEM & Log Parsers)

This section documents how IIS logs were used (per published analyses) to identify unauthenticated XML SOAP POST requests targeting OWA directories (e.g., `/ecp/DDI/DDIService.svc/SetObject`), and how anomalous User-Agents like `python-requests/2.25.1` were flagged as threat-actor activity hidden in standard operational traffic.

### 3. Signature-Based Malware Scanning (YARA)

Documents the use of YARA rules, based on publicly released signatures, to identify malicious ASPX web shells (such as `help.aspx` and `shell.aspx`) matching known threat profiles like `webshell_aspx_reGeorgTunnel`.

### 4. Volatile Memory Forensics

Summarizes published memory-forensics findings describing credential-harvesting attempts. Specifically, unauthorized `SeDebugPrivilege` acquisition and handle access to the `lsass.exe` process initiated by the Exchange worker process (`w3wp.exe`) as reported in incident write-ups of the breach.

---
##  Reconstructed Attack Chain (ProxyLogon)

Based on public reporting, the HAFNIUM threat campaign executed a multi-stage exploitation chain from initial external probing to full enterprise compromise:

```mermaid
graph TD
    A[Internet-Facing Exchange Server Identified] --> B[Exploit CVE-2021-26855: SSRF]
    B --> C[Authentication Bypass Achieved]
    C --> D[Exploit CVE-2021-26858 & CVE-2021-27065: Arbitrary File Write]
    D --> E[Upload Malicious ASPX Web Shell]
    E --> F[Establish Persistent Remote Backdoor]
    F --> G[Exploit CVE-2021-26857: Insecure Deserialization]
    G --> H[Privilege Escalation to SYSTEM Level]
    H --> I[Credential Dumping via LSASS & Lateral Movement]
    I --> J[Full Enterprise Infrastructure Compromise]

    style B fill:#341212,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style D fill:#341212,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style G fill:#341212,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style J fill:#800c0c,stroke:#ff4d4d,stroke-width:2px,color:#fff
 ```
##  CCross-Border Legal & Compliance Analysis

A core part of this case study was auditing the incident against multiple legislative frameworks to assess liability and compliance implications:

US Computer Fraud and Abuse Act (CFAA): Analyzed potential violations under 18 U.S.C. § 1030 relating to unauthorized data theft and the transmission of malicious web shell code.
Malaysian Computer Crimes Act 1997: Mapped the server-side request forgery to Section 3(1)(a) (Unauthorized Access) and the web shell deployment to Section 5(1) (Unauthorized Modification).
Malaysian Personal Data Protection Act 2010 (PDPA): Assessed the victim organization's liability as a "Data User" under Section 9 (The Security Principle), and analyzed how delayed patch-management cycles for on-premises infrastructure could expose an organization to statutory fines of up to RM300,000.

## About This Project

This was completed as a group coursework case study for a Computer Crime & Digital Evidence module, intended to practice mapping a real-world breach to MITRE ATT&CK, reconstructing an attack chain from public sources, and evaluating legal/regulatory exposure and not as a live incident response engagement. See "My contribution" above for the specific parts of this analysis I was responsible for.
