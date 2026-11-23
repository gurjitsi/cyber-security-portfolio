# Dataset Validation Results

Input: `windows_security.csv`
Records analysed: 74

- Event ID 4625: 67 failed logins
- Event ID 4624: 6 successful logins
- Event ID 4740: 1 account-lockout event
- SubStatus 0xC000006A: 43 events
- SubStatus 0xC0000064: 24 events

Cross-account, same-source-IP correlation (preceding 30 minutes, threshold >= 5):
- Successful login: 2026-10-15T19:37:23Z
- Source IP: 198.51.100.199
- Successful account: temp_intern
- Prior failed attempts: 7
- Distinct failed accounts: 7
- Logon type: 10

Validation was performed with Python against the supplied CSV. The SPL files have not been executed in Splunk.

