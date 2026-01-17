# Incident Overview

**Scenario:** Bec-ky (blueteamlabs.online) - Potential financial fraud involving company pension fund

**Alert Type:** UEBA – User Behavior Anomaly

**Data Sources:** Azure Audit Logs, Email Artifacts

A UEBA alert was triggered following anomalous user behavior associated with the CFO’s account. Over a 48-hour period, 
multiple high-value bank transfers were authorized and sent to both domestic and international accounts. The incident 
appeared to originate from a phishing-based email compromise.

---

## Logs & Artifacts Analyzed

- Azure AD Audit Logs
- Email message chain associated with CFO account
- Inbox rules and mailbox configuration changes

---

## Indicators of Compromise (IOCs)

- Suspicious source IP addresses
- Multiple failed login attempts from anomalous IPs
- Geo-location anomalies when correlated with timestamps
- Creation of malicious inbox rules from suspicious IPs
- Creation of a hidden inbox folder to divert security and financial alerts
- Inbox rule configuration designed to evade detection:

```bash
  subjectOrBodyContainsWords: withdrawal
  DeleteMessage: true
```

---

## Analysis & Investigation Steps

1) Identified the initial phishing email targeting the CFO
2) Confirmed email account compromise through login anomalies
3) Traced attacker IP addresses using Azure audit logs
4) Identified destination bank accounts receiving fraudulent transfers
5) Analyzed inbox rule creation and folder manipulation
6) Reviewed keyword-based filtering rules designed to suppress alerts

---

## Incident Response (NIST Framework)

1) Preparation
- Incident response team assembled
- Reviewed organizational policy requiring CFO authorization for transfers
- Referenced prior security awareness training related to phishing

2) Identification

- Detected abnormal surge in high-value transfers over a short timeframe
- Correlated UEBA alert with Azure logs and email artifacts
- Confirmed malicious inbox rule creation and account misuse

3) Containment

- Placed a temporary 48-hour hold on affected pension fund accounts
- Restricted CFO account access pending investigation

4) Eradication

- Removed all malicious inbox rules and folders
- Blacklisted attacker IP addresses and associated email accounts
- Verified no persistence mechanisms remained

5) Recovery

- Reset compromised email credentials
- Enforced MFA on executive email accounts
- Initiated bank account changes to prevent further unauthorized transfers

6. Lessons Learned

- Restrict inbox rule creation for high-privilege accounts
- Strengthen phishing awareness training (focus on sender verification)
- Implement IP allow-listing for banking and email services
- Improve monitoring for mailbox rule changes in SIEM

---

## MITRE ATT&CK Mapping 

- T1566.001 – Phishing: Spearphishing Attachment
- T1078 – Valid Accounts
- T1098 – Account Manipulation
- T1114 – Email Collection

---

## Key Takeaways

- UEBA alerts are effective for detecting subtle executive account misuse
- Mailbox rule abuse is a common persistence and evasion technique
- Financial fraud incidents require rapid containment to limit impact
