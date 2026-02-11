# DNS Traffic Analysis Lab – SOC / Blue Team Focus

## Overview
This lab demonstrates DNS traffic analysis from a **Security Operations Center (SOC)** perspective using **Wireshark**. The objective is to analyze DNS queries and responses to understand normal DNS behavior, identify infrastructure-related anomalies, and interpret how network architecture (NAT, virtualization, internal resolvers) affects traffic visibility.

This lab mirrors real-world SOC workflows such as:
- Investigating DNS activity
- Validating expected network behavior
- Distinguishing benign anomalies from suspicious activity

---

## Lab Environment
- **Operating System:** Kali Linux (VMware)
- **Packet Capture Tool:** Wireshark
- **Network Architecture:** Virtualized network with NAT
- **Protocols Observed:** DNS over UDP

---

## Traffic Generation
DNS traffic was intentionally generated to simulate user-driven name resolution activity:

```bash
dig google.com
dig youtube.com
dig openai.com
```

Analysis below focuses on google.com as a representative DNS transaction.

## DNS Investigation Results (google.com)
1. DNS Client (Request Origin)

- Source IP: 172.217.x.x

SOC Relevance:
Identifies the endpoint initiating the DNS request. In enterprise investigations, this IP would be mapped to a host, asset, or user account to determine intent and scope.


2. DNS Resolver (Destination)

- Resolver IP: 172.16.x.x

SOC Relevance:
Indicates the request was handled by an internal DNS resolver rather than directly querying public infrastructure. Internal resolvers are common in enterprise environments and may perform filtering, logging, or traffic inspection.


3. Transport Protocol

- Protocol: UDP

- Destination Port: 53

SOC Relevance:
Standard DNS behavior. Deviations such as:

- DNS over TCP (outside normal zone transfers)

- Non-standard ports

- Encrypted DNS (DoH/DoT) where not expected

may indicate tunneling, evasion, or policy violations.


4. Queried Domain

- Domain: google.com

- Record Type: A (IPv4)

SOC Relevance:
Domain reputation and context are critical in detecting:

- Phishing domains

- Command-and-control (C2) infrastructure

- Malware beaconing

Unusual record types (TXT, NULL, excessive MX queries) can also indicate data exfiltration or tunneling attempts.


5. DNS Response

- Resolved IP: 172.217.x.x

- TTL: 300 seconds

SOC Relevance:

- Returned IP addresses should be validated against expected infrastructure and threat intelligence sources.

- TTL values are important for detecting evasion techniques:

     - Extremely short TTLs may indicate fast-flux infrastructure.

     - Extremely long TTLs may indicate caching manipulation.

A TTL of 300 seconds is consistent with normal behavior.


6. DNS Query Volume

- Total Queries Observed: 3

- Filter Used:
``` bash
dns.flags.response == 0
```

SOC Relevance:
Query volume helps establish baseline behavior. Excessive or highly periodic DNS queries may indicate:

- Malware beaconing

- DNS tunneling

- Automated scripts

No abnormal frequency patterns were observed in this lab.


7. Recursion

- Recursion Desired (RD): 1

SOC Relevance:
Standard client behavior. Unexpected recursion patterns or open resolver behavior in production environments may indicate misconfiguration or abuse.


## Findings & Security Interpretation

### Observed Behavior
The DNS response resolved google.com to an IP address within the 172.x.x.x private address space, rather than a public Google IP.

### Root Cause Analysis

- The host operates within a VMware NAT environment
- DNS queries are handled by an internal DNS resolver or proxy
- Resolution is rewritten before reaching public DNS infrastructure

### SOC Implications

- This behavior represents split DNS, not malicious activity
- Highlights the importance of understanding:
     - Network topology
     - NAT behavior
     - Internal DNS infrastructure
-Prevents false positives during investigations involving “unexpected” IP ranges

## Detection & Monitoring Considerations

- Validate DNS destinations against known internal resolvers
- Correlate DNS queries with endpoint telemetry
- Monitor for:
     - Unusual record types (TXT, NULL)
     - Abnormal TTL patterns
     - High-frequency or periodic queries
     - Non-standard DNS ports or protocols

## Skills Demonstrated
- DNS traffic analysis for security monitoring
- Packet-level investigation using Wireshark
- Identifying benign vs suspicious DNS behavior
- Understanding enterprise DNS architecture
- Applying network context to reduce false positives

