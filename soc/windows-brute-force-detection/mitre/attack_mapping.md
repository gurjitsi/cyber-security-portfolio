# MITRE ATT&CK Mapping
## Windows Brute-Force Detection & Investigation

**Project:** Windows Authentication Attack Analysis  
**Data source:** Windows Security Event Logs

## 1. Technique Mapping

| MITRE ID | Technique | Evidence | Assessment |
|---|---|---|---|
| T1110 | Brute Force | Repeated failed authentication attempts | Observed behaviour |
| T1110.001 | Password Guessing | 40 failed attempts against Administrator, with incorrect-password status | Strongly consistent |
| T1078 | Valid Accounts | Successful login for `temp_intern` after suspicious activity from the same source IP | Requires investigation |
| T1021.001 | Remote Desktop Protocol | Successful Event ID 4624 with Logon Type 10 | Possible; confirm the remote access method |

## 2. Evidence and Interpretation

### T1110 — Brute Force

The dataset contains 60 failed authentication attempts from `203.0.113.88`, targeting four usernames on `NIMBUS-FS01`.

This activity is consistent with brute-force behaviour.

### T1110.001 — Password Guessing

Forty failed attempts targeted the Administrator account. The associated SubStatus was `0xC000006A`, indicating an incorrect password.

This provides evidence consistent with password guessing.

### T1078 — Valid Accounts

A successful login was recorded for `temp_intern` from `198.51.100.199` following seven failed login attempts from that same IP against other accounts.

The successful authentication requires investigation. The dataset does not establish whether the account was compromised or whether the login was authorised.

### T1021.001 — Remote Desktop Protocol

The successful login recorded Logon Type 10, which indicates a Remote Interactive login.

This is commonly associated with Remote Desktop. Additional telemetry is required to confirm the exact remote access method.

## 3. Techniques Not Confirmed

The dataset does not prove password spraying. Although multiple accounts were targeted, it does not show whether the same password was tried against each account.

Account discovery or username enumeration is another possible explanation for attempts against nonexistent usernames, but the available events do not establish the attacker's intent.

## 4. Investigation Conclusion

The strongest evidence supports repeated password guessing against the Administrator account.

A separate sequence of multi-account targeting followed by successful authentication from the same source IP warrants further investigation.

These mappings represent observed behaviour and investigative hypotheses, not confirmed attribution or proof of compromise.
