# SOC Incident Investigation Report
## Windows Authentication Attack Analysis

**Project:** Windows Brute-Force Detection & Investigation  
**Environment:** Windows Security Event Logs  
**Dataset:** `windows_security.csv`  
**Analysis date:** 23 November 2026  
**Analyst:** SOC Analyst Trainee  
**Status:** Investigation completed — further validation recommended

---

## 1. Executive Summary

An analysis of 74 Windows Security events identified suspicious authentication activity against the system `NIMBUS-FS01`.

The investigation identified:

- 67 failed login attempts (Event ID 4625).
- 6 successful login events (Event ID 4624).
- 1 account-lockout event (Event ID 4740).
- 60 failed attempts originating from `203.0.113.88`, targeting four usernames.
- A separate sequence of seven failed attempts from `198.51.100.199`, followed by a successful Remote Interactive login from the same IP against a different account.

The findings indicate suspicious authentication activity consistent with brute-force and account-targeting behaviour.

The successful login following the second sequence requires further investigation. The available evidence does not establish that an account was compromised.

## 2. Investigation Scope

The investigation focused on:

- Repeated authentication failures.
- Incorrect-password attempts.
- Attempts against multiple usernames.
- Account-lockout events.
- Successful authentication following suspicious activity.

### Event distribution

| Windows Event ID | Description | Count |
|---|---|---:|
| 4625 | Failed login | 67 |
| 4624 | Successful login | 6 |
| 4740 | Account locked out | 1 |
| **Total** | | **74** |

## 3. Investigation Findings

### Finding 1: Repeated failed authentication attempts

**Source IP:** `203.0.113.88`  
**Target system:** `NIMBUS-FS01`  
**Workstation:** `kali`  
**Time:** 03:05:03–03:08:32 UTC  
**Total failed attempts:** 60

Account breakdown:

| Username | Failed attempts |
|---|---:|
| Administrator | 40 |
| admin | 8 |
| administrator1 | 6 |
| scanner | 6 |

The source generated repeated authentication failures against the Administrator account before attempting three additional usernames.

This activity is consistent with brute-force and account-targeting behaviour.

### Finding 2: Authentication failure reasons

The investigation identified two main SubStatus values:

| SubStatus | Description | Count |
|---|---|---:|
| 0xC000006A | Incorrect password | 43 |
| 0xC0000064 | User does not exist | 24 |

The results indicate that the activity included password guessing against an existing account and attempts involving usernames that did not exist.

### Finding 3: Administrator account lockout

**Event ID:** 4740  
**Account:** Administrator  
**Computer:** NIMBUS-FS01  
**Time:** 03:08:33 UTC

An account-lockout event was recorded immediately after the concentrated authentication failures.

This supports the need to investigate the earlier activity. However, the lockout event does not contain a source IP in this dataset, so direct attribution to the earlier IP cannot be confirmed from this event alone.

### Finding 4: Multiple account targeting followed by successful authentication

**Source IP:** `198.51.100.199`

Between 19:15:22 and 19:34:41 UTC, seven failed authentication attempts targeted seven different accounts.

The accounts included:

- bnguyen
- acarter
- backup_svc
- lgarcia
- kchen
- ekim
- dpatel

At 19:37:23 UTC, a successful login was recorded.

| Field | Value |
|---|---|
| Event ID | 4624 |
| Username | temp_intern |
| Source IP | 198.51.100.199 |
| Logon Type | 10 |
| Workstation | DESKTOP-7Q2X9 |
| Computer | NIMBUS-FS01 |

Logon Type 10 indicates a Remote Interactive login, commonly associated with Remote Desktop.

**Assessment:** The successful login came from the same source IP as the earlier failures, but targeted a different username. This is suspicious and warrants investigation. It does not prove that the successful account was compromised.

## 4. Detection Methodology

Four SPL detection queries were developed.

| Query | Detection objective |
|---|---|
| 01_brute_force_by_source_ip.spl | Identify repeated failed logins |
| 02_wrong_password_attempts.spl | Identify incorrect-password failures |
| 03_multiple_accounts_from_one_ip.spl | Identify sources targeting multiple accounts |
| 04_failed_then_successful_login.spl | Identify successful logins following failures |

The dataset was inspected using Python. The SPL files have been authored but have not yet been executed in Splunk.

## 5. MITRE ATT&CK Mapping

| Technique | Description | Relevance |
|---|---|---|
| T1110 | Brute Force | Repeated authentication failures |
| T1110.001 | Password Guessing | Repeated incorrect-password attempts |
| T1078 | Valid Accounts | Potential investigation area following successful authentication |

These are investigative mappings, not proof that a particular threat actor or technique was conclusively identified.

## 6. Recommended SOC Actions

1. Verify whether the Administrator account lockout was expected.
2. Review authentication activity involving `203.0.113.88`.
3. Investigate the `temp_intern` successful login.
4. Review Remote Interactive login activity and associated endpoint telemetry.
5. Check whether the successful login was authorised by the account owner.
6. Review subsequent activity for privilege escalation, suspicious processes or lateral movement.
7. Apply account-protection measures and investigate password hygiene where necessary.
8. Escalate to the incident response team if unauthorised access is confirmed.

## 7. Investigation Limitations

- The dataset contains a limited selection of Windows Security events.
- No process execution, network connection or endpoint detection telemetry was provided.
- The account-lockout event does not identify its originating IP.
- The successful login following the second attack sequence involved a different username from those targeted by the failures.
- SPL queries have not yet been validated through actual Splunk execution.
- The source IP addresses belong to reserved documentation ranges and should not be treated as real attacker infrastructure.

## 8. Final Assessment

The dataset contains two distinct suspicious authentication patterns.

The first involves concentrated password failures against the Administrator account, followed by an account-lockout event.

The second involves failed attempts against multiple accounts, followed by successful Remote Interactive authentication from the same source IP against a different account.

Both patterns warrant investigation. Additional endpoint and authentication telemetry would be required to determine whether unauthorised access occurred.

**Investigation outcome:** Suspicious authentication activity identified; compromise not confirmed.
