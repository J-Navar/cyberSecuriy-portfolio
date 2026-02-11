# Network Traffic Analysis  
### SOC-Focused Packet Investigation & Threat Detection

---

## Project Overview

This project demonstrates hands-on network traffic analysis from a Security Operations Center (SOC) perspective using Wireshark.

The focus is on:

- Packet-level investigation  
- Identifying suspicious network behavior  
- Applying structured detection logic  
- Understanding how infrastructure impacts traffic visibility  

This folder contains both a **detection playbook** and a **guided DNS investigation lab**, reflecting real-world blue team workflows.

---

## Project Contents

### CheatSheet.md  
**Wireshark Display Filter Playbook**

A structured SOC-focused reference guide that includes:

- Common Wireshark display filters  
- Protocol-based traffic isolation techniques  
- Detection logic for:
  - Port scanning  
  - Brute force attempts  
  - Potential data exfiltration  
  - Web exploitation attempts  
- MITRE ATT&CK mapping  
- Detection engineering expansion ideas  

This document reflects how analysts build reusable investigative references for consistent triage and detection.

---

### Lab1.md  
**DNS Traffic Analysis – SOC / Blue Team Focus**

A hands-on DNS investigation performed in a virtualized lab environment using:

- Kali Linux (VMware NAT)  
- Wireshark  
- DNS over UDP  

This lab demonstrates:

- DNS request/response analysis  
- Resolver identification  
- TTL interpretation  
- Baseline query volume analysis  
- Identification of benign anomalies caused by NAT and split DNS  

The lab emphasizes distinguishing legitimate infrastructure behavior from malicious activity — a critical skill in real SOC environments.

---

## 🛠 Tools & Technologies Used

- Wireshark  
- Kali Linux  
- VMware (NAT Networking)  
- DNS over UDP  
- TCP/IP Protocol Suite  

---

## Skills Demonstrated

- Network traffic triage and packet inspection  
- Wireshark display filter creation and refinement  
- DNS investigation and resolution analysis  
- Identification of:
  - Port scanning behavior  
  - Brute force authentication attempts  
  - Suspicious HTTP activity  
  - Potential data exfiltration patterns  
- MITRE ATT&CK mapping  
- SOC-style documentation and reporting  
- False positive reduction through infrastructure awareness  

---

## Security & Detection Focus

This project simulates core SOC responsibilities, including:

- Investigating DNS activity during incident response  
- Validating suspicious traffic patterns  
- Mapping behavior to attack techniques  
- Translating packet analysis into detection logic  

It also demonstrates an understanding that:

> Not all anomalies are malicious — context and network architecture matter.

This mindset is critical for reducing alert fatigue and avoiding unnecessary escalations.

---

## Real-World Relevance

Network traffic analysis is foundational in:

- Security Operations Centers (SOC)  
- Incident Response  
- Threat Hunting  
- Detection Engineering  
- Network Security Monitoring  

The ability to interpret raw packet data and connect it to attack techniques is a core competency for entry-level cybersecurity analyst roles.

---

## Future Improvements

- Analyze malicious PCAP samples  
- Correlate packet findings with SIEM alerts  
- Develop Sigma / Suricata detection rules  
- Expand analysis to encrypted DNS (DoH/DoT)  
- Investigate DNS tunneling scenarios  

---

## Author  

Jeremiah Navarrete  
Aspiring Cybersecurity Analyst | Focused on Defensive Security & Threat Detection

