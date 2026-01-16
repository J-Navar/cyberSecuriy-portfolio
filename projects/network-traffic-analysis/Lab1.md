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
-IP Address: 172.217.x.x
-SOC Relevance: Identifies the endpoint initiating the DNS request. In SOC investigations, this maps to a host, user, or asset.

2. DNS Resolver (Destination)
- IP Address: 172.16.x.x
- SOC Relevance: Confirms which DNS infrastructure is handling resolution. Internal resolvers are common in enterprise networks.

3. Transport Protocol
- Protocol: UDP
- SOC Relevance: Standard DNS behavior. Deviations (e.g., unexpected TCP or non-standard ports) may warrant investigation.

4. Destination Port
- Port: 53
- SOC Relevance: Confirms compliance with standard DNS port usage. Non-standard ports can indicate tunneling or evasion.

5. Queried Domain
- Domain: google.com
- SOC Relevance: Domain reputation and context are critical for detecting phishing, C2, or malware beaconing.

6. DNS Record Type
- Type: A record
- SOC Relevance: Normal IPv4 resolution. SOC analysts often flag unusual record types (TXT, NULL, excessive MX queries).

7. DNS Response IP Address
- Resolved IP: 172.217.x.x
- SOC Relevance: Returned IPs are evaluated for legitimacy, reputation, and whether they align with expected infrastructure.

8. Time To Live (TTL)
- TTL: 300 seconds
- SOC Relevance: Short TTLs can indicate fast-flux or evasion techniques. This value is consistent with normal behavior.

9. DNS Query Count
- Total Queries: 3
- Filter Used: dns.flags.response == 0
- SOC Relevance: Baselines query volume. Excessive or periodic queries may indicate automated beaconing.

10. Recursion Requested
- Status: Yes (RD = 1)
- SOC Relevance: Standard client behavior. Unexpected recursion patterns may indicate misconfiguration or abuse.

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

