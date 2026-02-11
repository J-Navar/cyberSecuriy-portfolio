# Jeremiah Navarrete – Cybersecurity Portfolio
SOC | Threat Detection | Incident Response

## Overview
This portfolio demonstrates hands-on cybersecurity skills across **SOC operations, phishing analysis, network traffic investigation, and incident response**. All labs were completed in controlled environments and simulate real-world blue team workflows, including:

- Alert triage and escalation
- Endpoint, network, and email analysis
- Packet-level traffic investigation
- Detection logic development
- MITRE ATT&CK mapping
- SOC-style reporting and documentation

These projects showcase practical, job-ready skills for entry-level SOC Analyst, Threat Detection, and Cybersecurity Analyst roles.

---

## Portfolio Structure

### 1 Phishing Analysis
**SOC-Focused Email Threat Investigation & Simulation**

Focus: Phishing detection, email authentication analysis, incident escalation, and defensive detection development.

**Labs Included**

**1. Phishing Analysis Lab – SOC Incident Investigation**  
Platform: TryHackMe | Tools: Splunk SIEM, SOC Dashboard  
- Monitored real-time phishing alerts
- Classified incidents as True Positive or False Positive
- Investigated malicious attachments, links, and endpoint processes
- Detected lateral movement and network anomalies
- Documented IOAs for escalation

**2. GoPhish Phishing Simulation & Email Authentication Analysis**  
Platform: GoPhish | Tools: Kali Linux, SPF/DKIM/DMARC  
- Simulated phishing campaigns across Gmail, Outlook, and temporary email services
- Evaluated inbox vs spam delivery
- Analyzed email authentication headers
- Developed behavioral and content-based detection logic
- Proposed defensive mitigations

MITRE Techniques Covered:
- T1566 / T1566.002, T1036, T1078, T1056.003, T1071.001, T1598  

---

### 2 Network Traffic Analysis
**SOC-Focused Packet & DNS Investigation**

Focus: Packet inspection, protocol-based threat detection, and reducing false positives through contextual analysis.

**Labs Included**

**1. Wireshark Display Filter Playbook – SOC Traffic Analysis Reference**  
Platform: LabEx.io | Tools: Wireshark  
- Protocol filtering: HTTP, DNS, TCP, FTP, SSH
- Detection of port scanning, brute force, web exploitation
- Potential data exfiltration identification
- MITRE ATT&CK mapping and playbook creation

**2. DNS Traffic Analysis Lab – SOC / Blue Team Focus**  
Platform: Kali Linux (VMware NAT) | Tools: Wireshark  
- DNS query and response inspection
- Resolver identification and TTL interpretation
- Recognition of benign anomalies caused by NAT / split DNS
- Baseline DNS query volume analysis to reduce false positives

MITRE Techniques Covered:
- T1046, T1110, T1041, T1190  

---

### 3 SOC Incident Response
**Executive Account & Web Portal Compromise Simulations**

Focus: Log analysis, web exploitation detection, lateral movement investigation, containment, and recovery.

**Labs Included**

**1. Executive Account Compromise – Pension Fund Scenario**  
Platform: BlueTeamLabs.online | Tools: Azure Audit Logs, Email Artifacts, UEBA  
- Investigated phishing-based account compromise
- Detected malicious inbox rules and hidden folders
- High-value financial transfer analysis
- Incident response aligned with NIST framework
- MFA enforcement and containment

**2. Admin Portal Compromise – Web Exploitation & Lateral Movement**  
Platform: BlueTeamLabs.online | Tools: Splunk SIEM, Web Logs, Network Logs  
- Detected authentication bypass and remote code execution
- Identified reverse shell activity and lateral movement
- Multi-stage attack reconstruction
- Developed mitigation and response steps

MITRE Techniques Covered:
- T1566.001, T1078, T1098, T1114, T1592, T1190, T1059, T1105, T1021, T1110  

---

## Tools & Technologies Used

- **SIEM & Monitoring:** Splunk, UEBA, SOC Dashboards  
- **Network & Packet Analysis:** Wireshark, TCP/IP Suite, DNS Analysis  
- **Email & Phishing Security:** GoPhish, SPF/DKIM/DMARC  
- **Virtualization & Lab Platforms:** Kali Linux, VMware NAT, TryHackMe, BlueTeamLabs.online  
- **Cloud & Logging:** Azure Audit Logs, Email Artifacts, Web/Network Logs  

---

## Core Skills Demonstrated

- SOC alert triage and escalation  
- Phishing detection and analysis  
- Endpoint, process, and network investigation  
- Packet-level traffic inspection  
- Reverse shell and lateral movement detection  
- Incident response (NIST-aligned)  
- Detection logic and rule development  
- MITRE ATT&CK mapping  
- SOC-style documentation and reporting  
- False positive reduction through infrastructure context  

---

## Real-World Relevance

These labs mirror responsibilities in:

- Security Operations Centers (SOC)  
- Threat Detection & Monitoring  
- Incident Response Teams  
- Blue Team Operations  
- Detection Engineering  

They demonstrate not just technical ability, but structured thinking, escalation judgment, and reporting clarity — core skills for professional SOC environments.

---

## Future Development Goals

- SOAR automation and playbooks  
- Sigma / Suricata detection rules  
- DNS tunneling and C2 detection  
- Malicious PCAP and network traffic analysis  
- MITRE D3FEND defensive mappings  
- Cloud-focused incident response labs  

---

## Author

**Jeremiah Navarrete**  

Email: Jeremiah.navarrete@yahoo.com 

Aspiring Cybersecurity Analyst | Focused on SOC Operations, Threat Detection & Incident Response  

---

**Disclaimer:**  
All labs were completed in controlled, educational environments. Accounts, endpoints, and networks were created solely for learning and research purposes.
