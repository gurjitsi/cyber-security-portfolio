# Incident Investigation Report
## Windows Brute-Force Detection & Investigation

**Assessment:** Suspicious Windows authentication activity  
**Data source:** Windows Security Event CSV  
**Analysis period:** 15 October 2026 (UTC)  
**Status:** Investigation required; compromise not confirmed

## 1. Executive Summary

The investigation identified repeated failed Windows authentication attempts, an account lockout, and a separate sequence in which a successful login followed multiple failed attempts from the same source IP.

The strongest pattern was 60 failed logons from `203.0.113.88` against four accounts on `NIMBUS-FS01`.

A separate source, `198.51.100.199`, generated seven failed logons against seven distinct accounts before a successful logon for `temp_intern` from the same IP.

These patterns are suspicious and warrant investigation. The available events do not prove that an account was compromised or that the successful login was unauthorised.

## 2. Scope and Data

The supplied CSV contained 74 Windows Security events:

| Event ID | Meaning | Count |
|---|---|---:|
| 4625 | Failed logon | 67 |
| 4624 | Successful logon | 6 |
| 4740 | Account locked out | 1 |
| **Total** | | **74** |

The analysis used timestamps, computer names, event IDs, usernames, source IP addresses, logon types and authentication status codes.

## 3. Investigation Findings

### Finding 1 — Repeated Failed Logons

- **Source IP:** `203.0.113.88`
- **Target host:** `NIMBUS-FS01`
- **Failed attempts:** 60
- **Target accounts:** `Administrator`, `admin`, `administrator1`, `scanner`
- **Observed period:** 03:05:03–03:08:32 UTC
- **Workstation value:** `kali`

This concentrated burst is consistent with automated password-guessing or brute-force activity.

### Finding 2 — Account Lockout

- **Event ID:** 4740
- **Account:** `Administrator`
- **Time:** 03:08:33 UTC

The lockout occurred immediately after the burst of failed logons.

However, the 4740 record does not contain a source IP, so the lockout cannot be directly attributed to `203.0.113.88` from this record alone.

### Finding 3 — Multiple-Account Failures Followed by Successful Login

- **Source IP:** `198.51.100.199`
- **Failed attempts:** 7
- **Distinct accounts targeted:** 7
- **Successful account:** `temp_intern`
- **Successful login time:** 19:37:23 UTC
- **Target host:** `NIMBUS-FS01`
- **Logon type:** 10 — Remote Interactive

The successful login followed seven failed attempts from the same IP within the 30-minute correlation window.

The failed attempts targeted different accounts from the account used in the successful login.

Logon Type 10 is commonly associated with Remote Desktop, but this event alone does not confirm the exact remote access method.

## 4. Technical Interpretation

- Event ID 4625: Failed logon.
- Event ID 4624: Successful logon.
- Event ID 4740: Account lockout.
- SubStatus `0xC000006A`: Incorrect password.
- SubStatus `0xC0000064`: User account does not exist.

The dataset contains:
- 43 events with SubStatus `0xC000006A`.
- 24 events with SubStatus `0xC0000064`.

The behaviour is consistent with brute-force/password-guessing activity and multi-account targeting.

The evidence does not establish password spraying because it does not show whether the same password was attempted against each account.

## 5. MITRE ATT&CK Mapping

| Technique | Evidence | Assessment |
|---|---|---|
| T1110 — Brute Force | Repeated failed authentication attempts | Observed behaviour |
| T1110.001 — Password Guessing | Repeated incorrect-password failures | Strongly consistent |
| T1078 — Valid Accounts | Successful login after suspicious activity | Investigative hypothesis |
| T1021.001 — Remote Desktop Protocol | Logon Type 10 | Possible; requires confirmation |

## 6. Recommended SOC Actions

1. Confirm with the system owner whether the activity and `temp_intern` login were expected.
2. Review the `temp_intern` account's authentication history, owner and privileges.
3. Correlate the successful login with RDP-related logs, VPN records and endpoint telemetry.
4. Review the four accounts targeted by `203.0.113.88`.
5. If activity is unauthorised, follow the organisation's incident-response process to contain the affected account or endpoint and preserve evidence.
6. Review authentication thresholds against normal activity to reduce false positives.

## 7. Limitations

- Both source IPs are reserved documentation addresses (TEST-NET), not actionable public attacker indicators.
- The account lockout event does not contain a source IP.
- Source-IP correlation does not prove that the same person or device generated all events.
- No endpoint process, network-flow, VPN or RDP server telemetry was supplied.
- A successful login after failures does not prove account compromise.
- Python analysis was used to validate the dataset findings. The SPL queries have not yet been executed in a live Splunk environment.

## 8. Conclusion

The dataset shows a concentrated burst of failed logons against multiple accounts, an Administrator account lockout, and a separate successful Remote Interactive login following multi-account failures from the same source IP.

The activity should be treated as suspicious and investigated using additional identity, endpoint and network evidence.

Based on this dataset alone, account compromise and attacker attribution remain unconfirmed.
