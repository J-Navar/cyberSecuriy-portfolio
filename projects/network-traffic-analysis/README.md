# Network Traffic Analysis
SOC-Focused Packet & DNS Investigation Labs

## Project Overview
This folder demonstrates **hands-on network traffic analysis** from a Security Operations Center (SOC) perspective using Wireshark.  

The labs focus on:  

- Packet-level investigation and triage  
- Identifying suspicious network behavior  
- Applying structured detection logic  
- Understanding how network architecture impacts traffic visibility  

This folder contains two labs that reflect real-world blue team workflows:  

1. Wireshark Display Filter Playbook – SOC Traffic Analysis Reference  
2. DNS Traffic Analysis Lab – SOC / Blue Team Focus  

---

## Project Contents

### 1. Wireshark Display Filter Playbook – SOC Traffic Analysis Reference
**Platform:** LabEx.io  
**Role:** Junior SOC Analyst (Simulated)  
**Tools:** Wireshark  

**Lab Overview:**  
Provides a structured SOC reference for analyzing network traffic. Focuses on using **Wireshark display filters** to isolate traffic, detect threats, and document investigation procedures.  

**Key Focus Areas:**  
- Apply filters by protocol, IP, port, and time  
- Detect suspicious behaviors such as:  
  - Port scanning  
  - Brute force authentication attempts (FTP / SSH)  
  - Web exploitation attempts  
  - Potential data exfiltration  
- Correlate packet-level findings with SIEM and firewall logs  
- Build reusable detection playbooks for consistent triage  

**Findings & Outcomes:**  
- Multiple TCP SYN scans identified from a single source without ACK responses  
- Brute force attempts observed on FTP and SSH services  
- Web exploitation patterns identified through repeated HTTP errors  
- Data exfiltration attempts suggested by repeated outbound HTTP requests  

**MITRE ATT&CK Mapping:**  

| Tactic                  | Technique ID | Description                             |
|------------------------|-------------|-----------------------------------------|
| Discovery               | T1046       | Network Service Scanning                 |
| Credential Access       | T1110       | Brute Force                              |
| Command & Control       | T1041       | Exfiltration Over C2 Channel             |
| Initial Access           | T1190       | Exploit Public-Facing Application       |

**Skills Demonstrated:**  
- Network traffic triage and packet inspection  
- Wireshark display filter creation and refinement  
- SOC documentation and playbook creation  
- Threat detection across multiple protocols (HTTP, DNS, TCP, FTP, SSH)  

---

### 2. DNS Traffic Analysis Lab – SOC / Blue Team Focus
**Platform:** LabEx.io / Kali Linux VM  
**Role:** Junior SOC Analyst (Simulated)  
**Tools:** Wireshark  

**Lab Overview:**  
Simulates DNS traffic investigation to distinguish **legitimate network behavior from malicious activity**. Demonstrates baseline analysis, resolver identification, TTL interpretation, and anomaly detection in a virtualized network.  

**Key Focus Areas:**  
- Capture and analyze DNS queries and responses  
- Identify unusual patterns or suspicious domains  
- Correlate DNS activity with endpoint telemetry and network architecture  
- Reduce false positives by understanding NAT, split DNS, and internal resolvers  

**Findings & Outcomes:**  
- DNS queries for google.com, youtube.com, and openai.com resolved normally via internal resolvers  
- TTL and query volume were consistent with benign behavior  
- Lab highlights importance of network context in reducing false positives  
- Provides actionable methodology for SOC investigations  

**Skills Demonstrated:**  
- DNS traffic analysis for SOC monitoring  
- Packet-level investigation using Wireshark  
- Differentiating normal vs suspicious DNS behavior  
- Applying network context to reduce false positives  
- Mapping network behavior to MITRE ATT&CK techniques  

---

## Tools & Technologies Used
- Wireshark  
- Kali Linux VM / VMware NAT Networking  
- TCP/IP Protocol Suite  
- DNS over UDP  

---

## Skills & Competencies Highlighted
- SOC-style packet inspection and network triage  
- Threat detection for reconnaissance, brute force, exfiltration, and web exploitation attempts  
- DNS analysis and interpretation in enterprise environments  
- Translating packet-level findings into detection logic  
- Documentation and reporting for SOC workflows  

---

## Future Enhancements
- Analyze malicious PCAP samples for attack simulation  
- Correlate packet-level findings with SIEM alerts  
- Develop detection rules using Sigma / Suricata  
- Expand analysis to encrypted DNS (DoH/DoT)  
- Investigate DNS tunneling and C2 communication scenarios  

---

**Author**  
Jeremiah Navarrete  
Aspiring Cybersecurity Analyst | Focused on SOC & Threat Detection  

**Disclaimer:** All labs were performed in controlled, educational environments. Systems, endpoints, and network captures were created solely for research and learning purposes.
