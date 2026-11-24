# Windows Brute-Force Detection & Investigation

## Project Overview

This project demonstrates a Security Operations Centre (SOC) investigation of suspicious Windows authentication activity using Windows Security Event Logs, Python and Splunk Search Processing Language (SPL).

The objective was to identify repeated authentication failures, investigate account-targeting behaviour, detect suspicious successful logins and map findings to MITRE ATT&CK.

## Technical Skills Demonstrated

- Windows Security Event Log analysis
- Authentication event investigation
- SPL detection engineering
- Python-based dataset analysis with pandas
- Brute-force and password-guessing detection
- Multi-account authentication correlation
- MITRE ATT&CK mapping
- Incident reporting and documentation

## Dataset

The analysis uses a Windows Security Event CSV containing timestamps, computer names, Event IDs, usernames, source IP addresses, logon types and authentication status codes.

| Event ID | Description | Events |
|---|---|---:|
| 4625 | Failed logon | 67 |
| 4624 | Successful logon | 6 |
| 4740 | Account locked out | 1 |
| **Total** | | **74** |

The analysis script expects the input file at `logs/windows_security.csv` by default. The raw CSV is not included in this repository.

## Detection Use Cases

1. [Repeated failures by source IP and account](queries/01_brute_force_by_source_ip.spl)
2. [Incorrect password attempts](queries/02_wrong_password_attempts.spl)
3. [One source IP targeting multiple accounts](queries/03_multiple_accounts_from_one_ip.spl)
4. [Failed logons followed by a successful login](queries/04_failed_then_successful_login.spl) — at least five failures against the same account and IP within 30 minutes.
5. [Successful login after failures across multiple accounts](queries/05_success_after_multi_account_failures.spl) — at least five failures from the same IP within 30 minutes, regardless of username.

## Key Findings

- 60 failed logons from `203.0.113.88` against four accounts on `NIMBUS-FS01` between 03:05:03 and 03:08:32 UTC.
- An Administrator account lockout occurred at 03:08:33 UTC. The lockout event did not contain a source IP.
- Seven failed attempts against seven distinct accounts came from `198.51.100.199`, followed by a successful login for `temp_intern` at 19:37:23 UTC (Logon Type 10).

These patterns are suspicious and warrant investigation, but they do not independently prove account compromise or identify an attacker.

## Project Documentation

- [Incident Investigation Report](reports/incident_report.md)
- [MITRE ATT&CK Mapping](mitre/attack_mapping.md)
- [Analysis Methodology](analysis/METHODOLOGY.md)
- [Dataset Validation Results](reports/validation_results.md)

## Run the Python Analysis

Install the dependency:

```bash
python3 -m pip install pandas
```

Place the CSV at `logs/windows_security.csv`, then run:

```bash
python3 analysis/analyze_windows_logs.py logs/windows_security.csv
```

To choose a different output directory:

```bash
python3 analysis/analyze_windows_logs.py logs/windows_security.csv --output-dir analysis/results
```

## Validation Status

- Python analysis was validated against the supplied 74-event dataset.
- SPL detection queries have been authored but have not yet been executed in a live Splunk environment.
- SPL queries assume the index is named `windows` and that the required fields are extracted correctly.

## MITRE ATT&CK

Relevant techniques and investigative hypotheses:

- T
