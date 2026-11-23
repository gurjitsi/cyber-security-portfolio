# Analysis Methodology

This evidence pack was generated from the supplied `windows_security.csv`.

## Reproduce

Install the dependency:

```bash
python3 -m pip install pandas
```

Run from the repository root:

```bash
python3 analysis/analyze_windows_logs.py logs/windows_security.csv
```

The script writes CSV reports to `analysis/results/`.

## Correlation logic

The cross-account correlation checks each successful Event ID 4624 and counts Event ID 4625 records from the same source IP during the preceding 30 minutes. It flags a success when at least five prior failures exist, regardless of username.

This is Python validation of the analytical logic, not execution or validation of SPL in Splunk.

## Limitations

- Correlation by source IP alone does not prove the same person or device generated the events.
- NAT, proxies, shared hosts and spoofed/incomplete fields can affect attribution.
- Event ID 4740 has no source IP in this CSV.
- A successful login after failures does not prove compromise.
- The dataset's documentation-range IP addresses are illustrative, not routable attacker indicators.
