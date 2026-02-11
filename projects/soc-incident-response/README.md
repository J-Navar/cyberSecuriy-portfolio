# SOC Incident Response

## Overview
This folder contains hands-on Security Operations Center (SOC) incident response labs designed to simulate **real-world cybersecurity incidents**. The exercises focus on detecting, investigating, and mitigating threats across executive accounts and web infrastructure.  

The labs demonstrate practical skills in **log analysis, alert correlation, threat investigation, and incident response**, following structured frameworks such as **NIST** and **MITRE ATT&CK**. These exercises are ideal for showcasing SOC capabilities to potential employers.

---

## Labs Included

### 1. Executive Account Compromise
- **Scenario:** Financial fraud targeting the CFO’s email account  
- **Alert Type:** UEBA – User Behavior Anomaly  
- **Data Sources:** Azure AD Audit Logs, Email Artifacts  
- **Summary:**  
  Over a 48-hour period, multiple high-value transfers were authorized from the CFO’s account, triggered by a phishing email. Investigation revealed malicious inbox rules and hidden folders designed to divert alerts. The lab emphasizes detecting account misuse, tracing attacker activity, and restoring secure access.  
- **Skills Demonstrated:**  
  - Phishing detection and analysis  
  - Email and mailbox rule forensics  
  - UEBA alert correlation  
  - Incident response: containment, eradication, and recovery  
- **MITRE ATT&CK Coverage:**  
  - T1566.001 – Spearphishing Attachment  
  - T1078 – Valid Accounts  
  - T1098 – Account Manipulation  
  - T1114 – Email Collection  

---

### 2. Admin Portal Compromise
- **Scenario:** Web application attack against an administrative portal  
- **Alert Type:** Suspicious Network Activity / Web Exploitation  
- **Data Sources:** SIEM (Splunk), Web Logs, Network Logs  
- **Summary:**  
  SOC monitoring detected unusual traffic to the admin portal. Investigation revealed authentication bypass, remote code execution via malicious headers, and lateral movement within the network. The lab emphasizes SIEM correlation, multi-stage attack detection, and web application security.  
- **Skills Demonstrated:**  
  - Web application fingerprinting and vulnerability assessment  
  - Detection of remote code execution and reverse shells  
  - Analysis of lateral movement and SSH brute-force activity  
  - Incident containment, eradication, and recovery  
- **MITRE ATT&CK Coverage:**  
  - T1592 – Gather Victim Host Information  
  - T1190 – Exploit Public-Facing Application  
  - T1059 – Command and Scripting Interpreter  
  - T1105 – Ingress Tool Transfer  
  - T1021 – Remote Services  
  - T1110 – Brute Force  

---

## Key Skills Highlighted
- SOC monitoring and alert triage (UEBA, SIEM)  
- Cross-source log analysis (Azure, Splunk, network logs)  
- Email and web-based threat investigation  
- Incident response processes using the NIST framework  
- Mapping attacks to MITRE ATT&CK techniques  

---

## Takeaways
- Multi-source correlation is critical for detecting subtle threats  
- Malicious mailbox rules and hidden folders are common attacker persistence methods  
- Web application vulnerabilities can lead to multi-stage attacks, including remote code execution and lateral movement  
- Rapid containment and remediation are essential to limit the impact of incidents  



