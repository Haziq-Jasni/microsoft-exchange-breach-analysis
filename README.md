##  Advanced Forensic Toolkit & Telemetry Analysis

Rather than relying on automated alerts, this investigation utilized low-level log analysis, signature matching, and memory forensics to uncover the HAFNIUM attack chain:

### 1. Command-Line Log Hunting (PowerShell)
Used custom PowerShell text-filtering commands to sweep through raw Exchange server logs (`HttpProxy`, `OABGeneratorLog`, and `ECP\Server`) to detect zero-day exploitation footprints:
* **SSRF Entry (CVE-2021-26855):** Scanned for internal request routing anomalies where the `AuthenticatedUser` field was completely empty while the `AnchorMailbox` pattern contained unauthorized `ServerInfo~*/*` strings.
* **Insecure Deserialization (CVE-2021-26857):** Filtered Windows Application Event Logs for `MSExchange Unified Messaging` errors throwing specific `System.InvalidCastException` crashes, proving SYSTEM-level remote code execution.

### 2. Live Web Traffic Parsing (SIEM & Log Parsers)
Aggregated Internet Information Services (IIS) logs into a centralized dashboard to track unauthenticated XML SOAP POST requests targeting OWA directories (e.g., `/ecp/DDI/DDIService.svc/SetObject`). Identified threat actor activity hidden under standard operational traffic via anomalous User-Agents like `python-requests/2.25.1`.

### 3. Signature-Based Malware Scanning (YARA)
Deployed custom YARA rules to parse the server's directory byte-sequences. Successfully flagged malicious, disguised ASPX web shells (like `help.aspx` and `shell.aspx`) matching known threat profiles like `webshell_aspx_reGeorgTunnel` (SHA-256: `406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928`).

### 4. Volatile Memory Forensics
Analyzed volatile system memory images (VMEM) to identify credential-harvesting techniques. Detected unauthorized attempts to acquire `SeDebugPrivilege` and open handles on the `lsass.exe` process (PID 544) initiated by the Exchange worker process (`w3wp.exe`) to scrape plaintext administrative credentials.

---
##  Reconstructed Attack Chain (ProxyLogon)

The HAFNIUM threat campaign executed a sophisticated, multi-stage exploitation chain to progress from initial external probing to full enterprise-wide compromise:

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
##  Cross-Border Legal & Compliance Analysis

A major highlight of this investigation was auditing the incident against multiple legislative frameworks to establish liability and compliance metrics:
* **US Computer Fraud and Abuse Act (CFAA):** Evaluated violations under 18 U.S.C. § 1030 regarding unauthorized data theft and intentional transmission of malicious web shell code.
* **Malaysian Computer Crimes Act 1997:** Mapped the server-side request forgery to Section 3(1)(a) (Unauthorized Access) and the web shell deployment to Section 5(1) (Unauthorized Modification).
* **Malaysian Personal Data Protection Act 2010 (PDPA):** Audited the victim organization's liability as a "Data User" under Section 9 (The Security Principle). Analyzed how sluggish patch management cycles for on-premises infrastructure can result in statutory corporate fines up to RM300,000.
