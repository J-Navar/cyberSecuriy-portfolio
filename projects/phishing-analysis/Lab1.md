# Phishing Analysis Lab – SOC Incident Investigation

**Platform:** TryHackMe  
**Lab Type:** Phishing Simulator / SOC Investigation  
**Role:** Junior SOC Analyst (Simulated)  
**Tools Used:** SOC Dashboard, SIEM (Splunk)

---

## Lab Overview

This lab simulates a **live phishing attack occurring within a corporate environment**. As a SOC analyst, I monitored real-time alerts, analyzed suspicious activity across email, endpoint processes, and network traffic, and determined which events required escalation.

The primary goal was to **identify malicious behavior, reconstruct the attack chain, and document findings** in a clear and actionable incident report.

---

## Objectives

- Monitor and analyze real-time security alerts
- Identify phishing emails and malicious attachments
- Analyze endpoint process execution and command-line behavior
- Detect suspicious network activity and lateral movement
- Classify alerts as **True Positive** or **False Positive**
- Determine when escalation is required
- Document **Indicators of Activity (IOAs)** for SOC reporting

---

## Alert Categories

The investigation focused on three primary alert types:

1. **Suspicious Email Sender (Phishing)**
2. **Suspicious Parent–Child Process Relationships**
3. **Suspicious Network Activity (Mapped Network Drives)**

Each alert was analyzed using the SOC dashboard and Splunk SIEM logs.

---

## Phishing Alert Analysis

### Findings
- All phishing alerts were identified as **True Positives**
- Only a subset required escalation based on risk level

### True Positive Indicators
- External sender
- Malicious or unwanted email content
- Social engineering techniques (urgency, authority, fear)

### Escalation Indicators
- Malicious attachments
- Embedded links leading to credential harvesting
- Financial fraud or invoice scams
- Evidence of endpoint execution tied to the email

**Outcome:**  
Phishing emails without attachments or links were documented but not escalated. Emails containing payloads or credential theft attempts were escalated for further response.

---

## Process Alert Analysis

### Findings
- Most process alerts were **False Positives**
- Several alerts were **True Positives** due to abnormal execution behavior

### True Positive Indicators
- Processes running from suspicious locations (e.g., user `Downloads` folder)
- Unusual parent–child process relationships
- Suspicious command-line arguments (e.g., Base64-encoded PowerShell)
- Legitimate tools used in malicious contexts (PowerShell, `nslookup`)
- PowerShell execution following phishing interaction

### Escalation Indicators
- PowerShell execution from user-accessible directories
- Connections to external or untrusted domains
- Indicators associated with malware execution

**Outcome:**  
Processes were only escalated when execution context, behavior, and location indicated malicious intent.

---

## Network Alert Analysis

### Findings
- All network alerts were **True Positives**
- All required escalation

### True Positive Indicators
- Network utilities executed from user directories via PowerShell
- Signs of data access or potential exfiltration
- Example observed command:
```bash
net use Z: \FILESRV-01\SSF-FinancialRecords
```

### Escalation Indicators
- Potential access to sensitive financial data
- Evidence of lateral movement or reconnaissance
- Indicators of malware-related activity

**Outcome:**  
Network activity indicated post-compromise behavior and required immediate escalation.

---

## Incident Reporting & Escalation

For each alert, I documented:
- Alert description and severity
- True Positive vs False Positive classification
- Indicators of Activity (IOAs)
- Escalation decision with justification

Escalation was required when alerts showed:
- Endpoint execution of malicious code
- Credential harvesting attempts
- Lateral movement or sensitive data access
- Strong indicators of malware infection

---

## What I Learned

- How to triage phishing alerts based on risk rather than volume
- How attackers abuse legitimate tools (PowerShell, `net.exe`) for malicious purposes
- The importance of execution context (process location, parent-child relationships)
- How phishing emails can lead to endpoint compromise and internal network activity
- How to write clear, concise SOC-style incident reports
- When to escalate incidents to reduce false positives while maintaining security

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|----------|-------------|
| Initial Access | T1566 | Phishing emails with malicious links or attachments |
| Execution | T1059.001 | PowerShell execution |
| Defense Evasion | T1027 | Obfuscated / Base64-encoded commands |
| Credential Access | T1056 | Credential harvesting via phishing |
| Lateral Movement | T1021 | Accessing network shares |
| Discovery | T1087 / T1046 | Network and account discovery |
| Collection | T1005 | Access to sensitive internal data |

---

## Key Skills Demonstrated

- Phishing detection and analysis
- SIEM log analysis (Splunk)
- Endpoint and process investigation
- Network activity analysis
- Incident classification and escalation
- SOC documentation and reporting

---

## Disclaimer

This project was completed in a controlled lab environment for educational purposes.
