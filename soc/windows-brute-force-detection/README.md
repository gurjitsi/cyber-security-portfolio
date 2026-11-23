# Windows Brute-Force Detection & Investigation

## Project Overview

This project demonstrates a Security Operations Centre (SOC) investigation of suspicious Windows authentication activity using Windows Security Event Logs and Splunk Search Processing Language (SPL).

The objective was to identify repeated authentication failures, investigate account-targeting behaviour, detect suspicious successful logins and map findings to MITRE ATT&CK.

## Technical Skills Demonstrated

- Windows Security Event Log analysis
- Authentication event investigation
- SPL detection engineering
- Python-based dataset analysis
- Brute-force and password-guessing detection
- Multi-account authentication correlation
- MITRE ATT&CK mapping
- Incident reporting and documentation

## Dataset

The project uses a Windows Security Event CSV containing:

- Event timestamps
- Computer names
- Windows Event IDs
- Target usernames
- Source IP addresses
- Logon types
- Authentication failure status codes

**Dataset statistics:**

| Event | Count |
|---|---:|
| Failed logins (4625) | 67 |
| Successful logins (4624) | 6 |
| Account lockouts (4740) | 1 |
| Total events | 74 |

## Detection Use Cases

| Detection | Objective |
|---|---|
| 01 | Repeated failed logins by source IP and username |
| 02 | Incorrect-password authentication attempts |
| 03 | One source IP targeting multiple accounts |
| 04 | Successful login following repeated failures against the same account |
| 05 | Successful login following multiple failed attempts from the same source IP |

## Key Investigation Findings

### 1. Repeated Authentication Failures

Identified 60 failed login attempts from `203.0.113.88` against four usernames on `NIMBUS-FS01`.

### 2. Password Guessing

Identified 40 failed attempts against the Administrator account with SubStatus `0xC000006A`, indicating incorrect passwords.

### 3. Account Lockout

Identified Windows Event ID 4740 for the Administrator account at 03:08:33 UTC.

### 4. Suspicious Successful Authentication

Identified seven failed authentication attempts against different accounts from `198.51.100.199`, followed by a successful login for `temp_intern` from the same IP.

The successful login used Logon Type 10, commonly associated with Remote Desktop.

This activity warrants investigation but does not independently prove account compromise.

## MITRE ATT&CK

Relevant techniques investigated:

- T1110 – Brute Force
- T1110.001 – Password Guessing
- T1078 – Valid Accounts (investigation hypothesis)
- T1021.001 – Remote Desktop Protocol (requires confirmation)

## Validation Method

The CSV and underlying detection logic were analysed using Python.

SPL queries were authored but have not yet been executed in Splunk. Therefore, this project distinguishes between Python-validated detection logic and unverified SPL runtime behaviour.

## Repository Structure

```text
windows-brute-force-detection/
├── README.md
├── dataset/
├── queries/
├── analysis/
├── screenshots/
├── mitre/
└── reports/
```

## Limitations

- The dataset is limited to Windows Security events.
- No endpoint process or network telemetry was supplied.
- Source IP addresses are reserved documentation addresses.
- Successful authentication does not automatically establish compromise.
- SPL runtime validation remains outstanding.

## Conclusion

This project demonstrates a structured investigation of suspicious Windows authentication activity, including detection development, evidence analysis, MITRE ATT&CK mapping and incident reporting.

The investigation identified multiple suspicious authentication patterns requiring further review.
