# Network Traffic Analysis – Wireshark Display Filter Playbook

## Overview
This document serves as a **SOC-focused network traffic analysis playbook** using **Wireshark display filters**. It provides a structured approach for **initial triage, threat detection, and investigation** by outlining commonly used filters, indicators of suspicious behavior, and investigative considerations.

This playbook is intended as a **reference guide**, not a single incident walkthrough, and reflects real-world SOC workflows.

---

## Lab Source
- **Platform:** LabEx.io  
- **Lab:** Analyze Network Traffic with Wireshark Display Filters

---

## Protocols Observed
- HTTP
- DNS
- TCP
- FTP
- SSH
- IP

---

## Network Context

### Source IP Addresses Observed
- `172.16.255.1`
- `206.108.207.163`

### Destination IP Addresses Observed
- `194.165.188.79`
- `192.168.3.131`

> These IPs were reviewed for suspicious patterns such as scanning behavior, authentication abuse, and abnormal request frequency.

---

## Wireshark Display Filters Used

### General Protocol Filters
- `http`
- `dns`
- `ftp`
- `ssh`

### IP Address Filtering
- `ip.addr == <IP_ADDRESS>`
- `ip.src == <IP_ADDRESS>`

### TCP & Port-Based Filtering
- `tcp.port == <PORT_NUMBER>`
- `tcp.flags.syn == 1`
- `tcp.flags.ack == 0`
- `tcp.len >= <SIZE>`

### HTTP-Specific Filters
- `http.request.method == "GET"`
- `http.host contains "<WEBSITE_NAME>"`
- `frame contains "login"`

### Authentication & Error Detection
- `ftp contains "530"`
- `ssh contains "Failed"`

### Time-Based Analysis
- `frame.time_delta <= <SECONDS>`

### Logical Operators
- `and`
- `or`
- `not`

---

## Indicators of Suspicious Activity
### Port Scanning
#### Indicators
- Repeated TCP SYN packets from a single source
- No corresponding ACK packets
- Attempts across multiple ports in short timeframes
#### Detection Filter
- `tcp.flags.syn == 1 and tcp.flags.ack == 0`

### Potential Data Exfiltration
#### Indicators
- Multiple outbound requests to the same external domain
- Abnormally large or frequent data transfers
- Consistent communication intervals
#### Detection Filters
- `http.host contains "<DOMAIN>"`
- `tcp.len >= <SIZE>`

### Brute Force Attempts (FTP / SSH)
#### Indicators
- Repeated authentication failures
- Identical error messages from the same source IP
#### Detection Filters
- `ftp contains "530"`
- `ssh contains "Failed"`

### Web Exploitation Attempts
#### Indicators
- Repeated HTTP 4xx or 5xx errors
- Requests targeting login pages or sensitive endpoints
- Suspicious or malformed request patterns
#### Detection Filters
- `frame contains "login"`
- `http.response.code >= 400`

---

## Findings Summary
- Port Scanning Detected: Multiple SYN packets from the same source IP without ACK responses
- Potential Data Exfiltration Activity: Repeated outbound requests to the same domain within short timeframes
- Brute Force Attempts Identified: FTP and SSH authentication failures originating from a single source IP
- Web Exploitation Attempts Observed: Repeated HTTP error responses triggered by the same source IP

---  

## SOC Analyst Considerations
- Validate whether source IPs belong to:
     - Vulnerability scanners
     - Internal security tools
     - Monitoring systems

- Correlate packet-level findings with:
     - SIEM alerts
     - Firewall logs
     - Endpoint telemetry
     - Establish baselines to reduce false positives

---

## Next Steps
### MITRE ATT&CK Mapping

- Map observed behaviors to MITRE techniques, such as:
     - T1046 – Network Service Scanning
     - T1110 – Brute Force
     - T1041 – Exfiltration Over C2 Channel
     - T1190 – Exploit Public-Facing Application

### SIEM Correlation
- Translate Wireshark indicators into SIEM detection logic
- Correlate DNS, firewall, and authentication logs
- Validate alerts across multiple data sources

### DNS & TLS Analysis Expansion
- Identify DNS tunneling indicators
- Analyze TLS handshake metadata
- Inspect SNI and certificate anomalies

### Visual Documentation
- Add annotated Wireshark screenshots
- Highlight key packet fields and flags
- Document investigation flow for training purposes

### Automation & Detection Engineering
- Convert filters into IDS/IPS rules
- Build detection logic using:
     - Sigma
     - Suricata
     - Zeek
- Create reusable detection templates

### Skills Demonstrated
- Network traffic triage and investigation
- Threat detection using packet analysis
- Understanding of common attack techniques
- SOC documentation and playbook creation
- Blue Team investigative methodology

