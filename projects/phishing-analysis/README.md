# Phishing Analysis  
### SOC-Focused Email Threat Investigation & Simulation

---

## Project Overview

This project demonstrates phishing detection, analysis, and mitigation in a Security Operations Center (SOC) context. The labs focus on both reactive incident investigation and proactive phishing simulation, emphasizing hands-on skills in email, endpoint, and network analysis.

Key objectives include:

- Triage phishing alerts and classify incidents  
- Analyze endpoint and network activity following phishing events  
- Evaluate email authentication protocols (SPF, DKIM, DMARC)  
- Identify detection gaps and propose defensive measures  
- Map observed techniques to MITRE ATT&CK  

This folder contains two labs:

1. **Phishing Analysis Lab – SOC Incident Investigation**  
2. **GoPhish Phishing Simulation & Email Authentication Analysis**  

---

## Project Contents

### 1 Phishing Analysis Lab – SOC Incident Investigation

**Platform:** TryHackMe  
**Role:** Junior SOC Analyst (Simulated)  
**Tools:** SOC Dashboard, Splunk SIEM  

**Lab Overview:**  
Simulates a live phishing attack in a corporate environment. Activities included monitoring real-time alerts, analyzing suspicious emails, endpoint processes, and network behavior, and documenting actionable findings.

**Key Focus Areas:**

- Monitor and analyze phishing alerts  
- Classify alerts as True Positive or False Positive  
- Identify malicious attachments, links, and credential harvesting attempts  
- Detect abnormal process execution and lateral movement  
- Document Indicators of Activity (IOAs) for escalation  

**Findings & Outcomes:**

- **Email Alerts:** True Positives for malicious emails; escalated if attachments or credential theft were present  
- **Process Alerts:** Mostly False Positives; escalated only when abnormal execution behavior and context suggested compromise  
- **Network Alerts:** True Positives requiring escalation for signs of lateral movement or sensitive data access  

**MITRE ATT&CK Mapping:**

| Tactic             | Technique ID | Description                                    |
|------------------|-------------|-----------------------------------------------|
| Initial Access    | T1566       | Phishing emails with malicious links/attachments |
| Execution         | T1059.001   | PowerShell execution                           |
| Defense Evasion   | T1027       | Obfuscated / Base64-encoded commands          |
| Credential Access | T1056       | Credential harvesting via phishing            |
| Lateral Movement  | T1021       | Accessing network shares                       |
| Discovery         | T1087/T1046 | Network and account discovery                  |
| Collection        | T1005       | Access to sensitive internal data             |

**Skills Demonstrated:**

- Phishing detection and analysis  
- SIEM log investigation (Splunk)  
- Endpoint and process monitoring  
- Network activity analysis  
- SOC documentation and incident reporting  
- Incident classification and escalation  

---

### 2 GoPhish Phishing Simulation & Email Authentication Analysis

**Platform:** GoPhish  
**Role:** Offensive/Defensive Security Research  
**Tools:** GoPhish, Kali Linux  

**Lab Overview:**  
Controlled phishing simulation testing how emails passing SPF, DKIM, and DMARC are handled by different email providers (Gmail, Outlook, Temporary Emails). Evaluated inbox vs spam delivery, detection gaps, and mitigation strategies.

**Lab Highlights:**

- **Email Authentication Analysis:** All campaigns passed SPF, DKIM, and DMARC for Gmail and Outlook  
- **Inbox vs Spam Observations:** Gmail delivered all emails to inbox; Outlook filtered some to spam depending on content  
- **Header & Routing Analysis:** X-Mailer headers (e.g., GoPhish) could be used for anomaly detection  
- **Campaign Variants:** Basic, IAR-themed, Personalized  

**Key Findings:**

- Authentication alone does not prevent phishing  
- Content-based filters vary by provider  
- Temporary email services offer minimal detection  
- Header inspection and behavioral analytics improve detection  

**MITRE ATT&CK Mapping:**

| Tactic               | Technique ID | Usage                                      |
|--------------------|-------------|--------------------------------------------|
| Initial Access       | T1566       | Phishing                                   |
| Initial Access       | T1566.002   | Spearphishing link delivery                 |
| Defense Evasion      | T1036       | Masquerading                                |
| Defense Evasion      | T1078       | Valid accounts (legitimate email abuse)    |
| Credential Access    | T1056.003   | Input capture via web forms                 |
| Command & Control    | T1071.001   | HTTP post-click communication               |
| Reconnaissance       | T1598       | Phishing for information                    |

**Detection & Mitigation Recommendations:**

1. Alert on authenticated emails containing risky content  
2. Detect X-Mailer anomalies for external senders  
3. Correlate content, authentication, and sender patterns  
4. Block or quarantine internal IP URLs in phishing emails  
5. Conduct user awareness campaigns emphasizing “authenticated ≠ safe”  
6. Implement post-click network monitoring for credential submissions  

**Skills Demonstrated:**

- Phishing campaign simulation  
- Email authentication analysis (SPF, DKIM, DMARC)  
- Behavioral and content-based detection logic  
- Correlation of email and network activity  
- Mitigation strategy development  

---

## Tools & Technologies Used

- Splunk SIEM  
- SOC Dashboard / Alerting Platforms  
- Wireshark (network monitoring for follow-up)  
- GoPhish  
- Kali Linux  
- Email Authentication Protocols (SPF, DKIM, DMARC)  

---

## Skills & Competencies Highlighted

- Phishing detection, triage, and escalation  
- Endpoint and process investigation  
- Network alert analysis  
- Email header and authentication analysis  
- SOC-style documentation and reporting  
- MITRE ATT&CK mapping and defensive reasoning  
- Red/Blue team simulation skills  

---

## Future Enhancements

- Attachment-based phishing campaigns (T1566.001)  
- SOAR automated response playbooks  
- SIEM-specific detection rule creation  
- Integration with user behavior analytics  
- MITRE D3FEND defensive mappings  

---

## Author

Jeremiah Navarrete  
Aspiring Cybersecurity Analyst | Focused on SOC & Threat Detection  

---

> Disclaimer: All labs were performed in controlled, educational environments. Email accounts, servers, and networks used were created for research and learning purposes only.

