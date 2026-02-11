# SOC Incident Response
Hands-On Incident Investigation & Response Simulations

## Project Overview
This folder demonstrates **SOC-focused incident response** for real-world cybersecurity scenarios. The labs emphasize detecting, analyzing, and mitigating threats across executive accounts and web infrastructure.  

Key objectives include:  

- Investigate anomalous user behavior and compromised accounts  
- Analyze web application and network-based attacks  
- Triage alerts and correlate across multiple data sources (UEBA, SIEM, audit logs)  
- Apply structured incident response following the **NIST framework**  
- Map observed techniques to **MITRE ATT&CK** for situational awareness  

This folder contains two labs:  

1. Executive Account Compromise – Financial Fraud Investigation  
2. Admin Portal Compromise – Web Exploitation & Lateral Movement  

---

## Project Contents

### 1. Executive Account Compromise – Financial Fraud Investigation
**Platform:** Blueteam Labs Online  
**Role:** Junior SOC Analyst (Simulated)  
**Tools:** Azure AD, Email Artifacts, UEBA  

**Lab Overview:**  
Simulates a real-world financial fraud scenario targeting a high-privilege executive email account (CFO). Activities included analyzing phishing emails, mailbox rule manipulations, and high-value bank transfers.  

**Key Focus Areas:**  
- Detect anomalous user behavior using UEBA alerts  
- Investigate compromised email accounts and suspicious inbox rules  
- Trace attacker IPs and destination accounts  
- Apply containment, eradication, and recovery actions  

**Findings & Outcomes:**  
- Malicious mailbox rules and hidden folders were used to divert security alerts  
- Multiple high-value transfers were attempted during the compromise window  
- MFA enforcement and credential resets mitigated further risk  

**MITRE ATT&CK Mapping:**  

| Tactic             | Technique ID | Description                               |
|------------------|-------------|-------------------------------------------|
| Initial Access     | T1566.001   | Spearphishing Attachment                  |
| Persistence        | T1078       | Valid Accounts                             |
| Credential Access  | T1098       | Account Manipulation                        |
| Collection         | T1114       | Email Collection                           |

**Skills Demonstrated:**  
- UEBA and SIEM alert triage  
- Email and mailbox rule forensics  
- Log correlation and attack reconstruction  
- Incident response using NIST framework  

---

### 2. Admin Portal Compromise – Web Exploitation & Lateral Movement
**Platform:** Blueteam Labs Online  
**Role:** Junior SOC Analyst (Simulated)  
**Tools:** Splunk SIEM, Web Logs, Network Logs  

**Lab Overview:**  
SOC monitoring detected suspicious traffic targeting the organization’s admin portal. Investigation revealed authentication bypass, remote code execution, and lateral movement within internal systems.  

**Key Focus Areas:**  
- Web application fingerprinting and framework vulnerability assessment  
- Detection of command execution and reverse shell activity  
- Monitoring lateral movement and SSH brute-force attempts  
- Applying containment, eradication, and recovery measures  

**Findings & Outcomes:**  
- Remote code execution achieved via malicious HTTP headers  
- Netcat reverse shells and lateral movement were identified  
- Blocking attacker IPs, patching vulnerable frameworks, and credential rotation prevented further compromise  

**MITRE ATT&CK Mapping:**  

| Tactic              | Technique ID | Description                                 |
|-------------------|-------------|---------------------------------------------|
| Reconnaissance     | T1592       | Gather Victim Host Information             |
| Initial Access      | T1190       | Exploit Public-Facing Application          |
| Execution           | T1059       | Command and Scripting Interpreter          |
| Command & Control   | T1105       | Ingress Tool Transfer                       |
| Lateral Movement    | T1021       | Remote Services                             |
| Credential Access   | T1110       | Brute Force                                 |

**Skills Demonstrated:**  
- SIEM log analysis and alert correlation  
- Web and network threat investigation  
- Detection of multi-stage attacks (RCE → Reverse Shell → Lateral Movement)  
- Incident response documentation and remediation  

---

## Tools & Technologies Used
- Azure AD / Audit Logs  
- Splunk SIEM  
- Email Artifacts & Mailbox Rule Analysis  
- UEBA Platforms  
- Network and Web Logs  

---

## Skills & Competencies Highlighted
- SOC monitoring, triage, and escalation  
- Multi-source log correlation and analysis  
- Email and web threat investigation techniques  
- Incident response execution (NIST framework)  
- Mapping attacks to MITRE ATT&CK  
- Documentation and reporting in a SOC context  

---

## Future Enhancements
- Integration with SOAR for automated containment  
- Advanced detection for mailbox rule abuse  
- Simulation of multi-vector attack scenarios combining web and email threats  
- Post-incident threat hunting and IOC enrichment  

---

**Author**  
Jeremiah Navarrete  
Aspiring Cybersecurity Analyst | Focused on SOC & Threat Detection  

**Disclaimer:** All labs were performed in controlled, educational environments. Systems, accounts, and networks were created solely for research and learning purposes.

