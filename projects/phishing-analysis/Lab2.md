# GoPhish Phishing Simulation & Email Authentication Analysis

## Overview
This project documents a controlled phishing simulation conducted using **GoPhish** to evaluate how modern email providers handle phishing emails that successfully pass **SPF, DKIM, and DMARC** authentication.

The objective of this lab was to:
- Analyze email authentication headers
- Observe inbox vs spam delivery behavior
- Identify detection gaps when authentication passes
- Map observed behavior to **MITRE ATT&CK**
- Propose practical detection logic and mitigations

This project is intended for **educational and defensive security research purposes only**.

---

## Lab Environment

### Tools & Infrastructure
- **Phishing Framework:** GoPhish
- **Attacker System:** Kali Linux
- **Landing Page:**  
  `http://172.16.81.128/24`
- **Mailer Identifier:** `X-Mailer: gophish`

### Sender Configuration
- **Sender Email:** `testeracc1030@gmail.com`
- **Email Platform:** Gmail SMTP
- **Authentication:** SPF, DKIM, DMARC enabled
- **Authentication Method:** App password

### Target Accounts
| Provider | Email Address |
|--------|---------------|
| Outlook | testeracc1000@outlook.com |
| Gmail | testeracc2040@gmail.com |
| Temporary Email | decata8281@coswz.com |

---

## Campaign Variants
Three phishing email variants were tested:
- **Basic**
- **IRA-themed**
- **Personalized**

Each campaign was sent to all three providers.

---

## Email Authentication Analysis

### SPF Results
All emails passed SPF validation for Outlook and Gmail.

| Campaign | Outlook | Gmail | Temp Email |
|--------|--------|-------|------------|
| Basic | Pass (74.125.224.53) | Pass (209.85.220.41) | Not Displayed |
| IRA | Pass (209.85.128.194) | Pass (209.85.220.65) | Not Displayed |
| Personal | Pass (74.125.224.50) | Pass (209.85.220.41) | Not Displayed |

---

### DKIM Results
DKIM signatures validated successfully.

| Campaign | Outlook | Gmail | Temp Email |
|--------|--------|-------|------------|
| Basic | Pass | Pass | Pass |
| IRA | Pass | Pass | Pass |
| Personal | Pass | Pass | Pass |

- **Algorithm:** rsa-sha256  
- **Canonicalization:** relaxed/relaxed  

---

### DMARC Results
DMARC passed for Outlook and Gmail.

| Campaign | Outlook | Gmail | Temp Email |
|--------|--------|-------|------------|
| Basic | Pass | Pass | Not Displayed |
| IRA | Pass | Pass | Not Displayed |
| Personal | Pass | Pass | Not Displayed |

- **Observed Policy:** `p=NONE`, `sp=QUARANTINE`

---

## Header & Routing Analysis

### Received Chain
- **Source System:** Kali Linux
- **Source IP:** `73.171.220.177`

| Provider | Observations |
|--------|--------------|
| Outlook | Only last hop visible |
| Gmail | Full sender routing visible |
| Temp Email | Minimal filtering and visibility |

---

## Inbox vs Spam Results

### Outlook
| Campaign | Folder | Notes |
|--------|-------|------|
| Basic | Inbox | Link functional |
| IRA | Spam | Link functional |
| Personal | Inbox | Link functional |

---

### Gmail
All campaigns landed in the **Inbox**.

- SPF: Pass  
- DKIM: Pass  
- DMARC: Pass  
- No warning banners displayed  

---

### Temporary Email Provider
All campaigns delivered to inbox.
- No authentication results displayed
- Minimal phishing detection observed

---

## Key Findings

1. **SPF, DKIM, and DMARC alone do not prevent phishing**
2. **Content-based filtering varies by provider**
3. **Legitimate consumer email platforms can be abused**
4. **Header indicators (X-Mailer) were not inspected**
5. **Temporary email providers offer minimal protection**

---

## MITRE ATT&CK Mapping

### Initial Access (TA0001)
| Technique ID | Name | Usage |
|-------------|------|------|
| **T1566** | Phishing | Primary attack vector |
| **T1566.002** | Spearphishing Link | Malicious landing page delivery |

---

### Defense Evasion (TA0005)
| Technique ID | Name | Usage |
|-------------|------|------|
| **T1036** | Masquerading | Impersonation of legitimate Gmail traffic |
| **T1078** | Valid Accounts | Abuse of legitimate Gmail account |

---

### Credential Access (TA0006)
| Technique ID | Name | Usage |
|-------------|------|------|
| **T1056.003** | Input Capture: Web Forms | Credential harvesting via landing page |

---

### Command and Control (TA0011)
| Technique ID | Name | Usage |
|-------------|------|------|
| **T1071.001** | Web Protocols | HTTP used for post-click communication |

---

### Reconnaissance (TA0043)
| Technique ID | Name | Usage |
|-------------|------|------|
| **T1598** | Phishing for Information | Credential collection |

---

## Detection Logic & Defensive Analytics

### 1. Authenticated Email + Risky Content
```bash
IF spf=pass AND dkim=pass AND dmarc=pass
AND email_body CONTAINS ("urgent","verify","account")
THEN alert authenticated_phish
```

### 2. X-Mailer Anomaly Detection
```bash
IF x_mailer IN ("gophish","phpmailer","sendmail")
AND sender_domain IS external
THEN alert mailer_anomaly
```

### 3. Consumer Email Abuse Detection
```bash
IF sender_domain IN ("gmail.com","outlook.com","yahoo.com")
AND subject MATCHES ("finance","tax","IRA","password")
THEN alert consumer_platform_abuse
```

### 4. Internal / RFC1918 URL Detection
```bash
IF url CONTAINS ("172.16.","10.","192.168.")
THEN block OR quarantine
```

### 5. Campaign Correlation Detection
```bash
IF COUNT(sender) > 3
WITHIN 30 minutes
AND subject_similarity > 80%
THEN alert phishing_campaign
```

### 6. Post-Click Network Detection
```bash
IF destination_ip IS unknown
AND http_method = POST
THEN alert possible_credential_submission
```

### 7. User Behavior Correlation
```bash
IF user_clicked_link
AND login_attempt FROM new_ip
WITHIN 10 minutes
THEN high_confidence_compromise
```

---

## Mitigation Recommendations
### Email Security
- Enforce DMARC policy = p=reject
- Monitor DMARC aggregate reports
- Block consumer email platforms for sensitive business actions

---

### Detection Improvements
- Inspect X-Mailer headers
- Correlate authentication + content
- Implement behavioral phishing analytics

---

### User Awareness
- Conduct regular phishing simulations
- Train users that “authenticated ≠ safe”

---

## Future Enhancements
- Attachment-based phishing (T1566.001)
- SOAR automated response playbooks
- MITRE D3FEND mapping
- SIEM-specific rules (Splunk / Sentinel / Elastic)

---

## Disclaimer
- This lab was performed in a controlled environment for educational and defensive security research only.
- All emails used were owned/created by me for educational and defensive security research purposes.

## Screenshots
<img width="2524" height="1536" alt="Screenshot from 2026-01-25 22-45-54" src="https://github.com/user-attachments/assets/42becf1c-6272-4227-8de4-f96b0aa18fd1" />

<img width="3044" height="1730" alt="Screenshot from 2026-01-25 20-44-20" src="https://github.com/user-attachments/assets/7a203946-705b-42d9-bc95-1413301a5e51" />

<img width="3659" height="1594" alt="Screenshot from 2026-01-25 20-38-56" src="https://github.com/user-attachments/assets/41ee9643-01a6-4277-b000-4bb512bffcd2" />

<img width="3692" height="1302" alt="Screenshot from 2026-01-25 20-51-07" src="https://github.com/user-attachments/assets/d636f2c1-bf8f-45ba-876d-0aad209b4d85" />





