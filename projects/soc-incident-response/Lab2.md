# Incident Overview

**Scenario:** MiddleMayhem (blueteamlabs.online) – Admin Portal Compromise

**Alert Type:** Suspicious network activity / Web exploitation

**Data Sources:** SIEM (Splunk) Web, Network Logs

The SOC team detected unusual traffic targeting the company’s administrative web portal. Although no breach 
was initially confirmed, log analysis revealed evidence of authentication bypass, remote code execution, 
and lateral movement within the environment.

---

## Initial Reconnaissance

The investigation began by identifying the web application’s underlying technologies.
- Parsed website source code and footer (“About Me” section)
- Identified JavaScript framework and version from client-side source
- Reviewed HTTP response headers for custom or framework-specific indicators
This information was used to assess potential known vulnerabilities affecting the application.

---

## SIEM Investigation (Splunk)

### Queries & Analysis Performed

- Searched web and SIEM logs for suspicious source IP activity:
```bash
index=* (field_name) ip_source=<suspicious_ip>
```
- Identified abnormal framework-related headers:
```bash
index=* | search x-middleware-subrequest
```
- Correlated observed headers with known CVEs affecting the framework
- Detected suspicious command execution patterns:
```bash
index=* | search "*nc*"
```
- Identified outbound connections associated with Netcat reverse shell activity:
```bash
index=* | search <ip_used_for_reverse_shell>
```
---

## Indicators of Compromise (IOCs)

- Suspicious external IP addresses targeting admin portal
- Presence of x-middleware-subrequest header associated with known vulnerabilities
- Netcat (nc) command usage indicating reverse shell execution
- Repeated SSH authentication attempts suggesting brute-force activity
- Evidence of lateral movement following initial compromise
- Targeted account identified as a database server user account

---

## Attack Chain Summary

1) Technology fingerprinting of the web application
2) Authentication bypass leveraging a vulnerable JavaScript framework
3) Remote code execution via malicious request headers
4) Reverse shell establishment using Netcat
5) Lateral movement across internal systems
6) SSH brute-force attempts against additional hosts

---

## Incident Response Actions (Recommended)

### Containment
- Block attacker IPs at firewall and WAF level
- Isolate compromised web and database servers

### Eradication
- Patch vulnerable JavaScript framework to latest version
- Remove unauthorized access mechanisms and reverse shells
- Audit user accounts and credentials used during the attack

### Recovery

- Rotate credentials for affected systems
- Restore systems from known-good backups
- Validate application integrity post-patching

### Lessons Learned
- Implement automated detection for suspicious headers
- Monitor for command execution indicators (nc, bash, sh)
- Harden admin portals with MFA and IP restrictions
- Maintain an asset inventory of application frameworks and versions

---

## MITRE ATT&CK Mapping

- T1592 – Gather Victim Host Information
- T1190 – Exploit Public-Facing Application
- T1059 – Command and Scripting Interpreter
- T1105 – Ingress Tool Transfer
- T1021 – Remote Services
- T1110 – Brute Force

---

## Key Takeaways

- Web application fingerprinting enables targeted exploitation
- Header-based attacks can bypass traditional authentication controls
- Reverse shells remain a common post-exploitation technique
- SIEM correlation is essential for detecting multi-stage attacks
