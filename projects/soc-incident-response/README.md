# SOC Incident Response Portfolio

## Overview
This folder contains hands-on SOC (Security Operations Center) incident response labs simulating real-world cybersecurity incidents. The exercises focus on **detecting, analyzing, and responding** to suspicious activity across user accounts, email systems, and web infrastructure.  

These labs highlight key skills in **log analysis, alert correlation, threat investigation, and incident response** following structured frameworks such as **NIST** and **MITRE ATT&CK**.  

The exercises are designed to demonstrate practical SOC capabilities for security analysts, especially in environments lacking prior professional experience.

---

## Labs Included

### 1. Executive Account Compromise
- **Scenario:** Financial fraud targeting the CFO’s email account  
- **Alert Type:** UEBA – User Behavior Anomaly  
- **Data Sources:** Azure AD Audit Logs, Email Artifacts  
- **Skills Demonstrated:**  
  - Phishing detection and investigation  
  - Mailbox rule analysis and mitigation  
  - UEBA alert correlation  
  - Incident containment and recovery  
- **MITRE ATT&CK Coverage:** T1566.001 (Spearphishing), T1078 (Valid Accounts), T1098 (Account Manipulation), T1114 (Email Collection)  


---

### 2. Admin Portal Compromise
- **Scenario:** Web application attack against administrative portal  
- **Alert Type:** Suspicious network activity / Web exploitation  
- **Data Sources:** SIEM (Splunk), Web Logs, Network Logs  
- **Skills Demonstrated:**  
  - Web application fingerprinting and vulnerability assessment  
  - Remote code execution detection  
  - Reverse shell and lateral movement analysis  
  - Incident containment, eradication, and recovery  
- **MITRE ATT&CK Coverage:** T1592 (Gather Host Info), T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), T1105 (Ingress Tool Transfer), T1021 (Remote Services), T1110 (Brute Force)  


---

## Skills Highlighted
- SOC monitoring and alert triage (UEBA, SIEM)  
- Log analysis across Azure, Splunk, and network sources  
- Email and web threat investigation techniques  
- Incident response following NIST framework: Preparation, Identification, Containment, Eradication, Recovery  
- Mapping real-world incidents to MITRE ATT&CK techniques  

---

## Key Takeaways
- Detecting subtle account misuse requires correlation across multiple data sources  
- Email and mailbox rule abuse are common persistence techniques for attackers  
- Web application vulnerabilities can lead to multi-stage attacks including remote code execution and lateral movement  
- Proactive monitoring, alerting, and incident response planning are critical to limit impact of attacks  


