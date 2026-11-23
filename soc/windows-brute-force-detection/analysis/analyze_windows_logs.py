#!/usr/bin/env python3
"""
Analyse Windows Security CSV events for authentication attack patterns.

Usage:
    python3 analysis/analyze_windows_logs.py logs/windows_security.csv
    python3 analysis/analyze_windows_logs.py logs/windows_security.csv --output-dir analysis/results

Requires:
    python3 -m pip install pandas
"""
import argparse
from pathlib import Path
import pandas as pd

REQUIRED = {
    "TimeCreated", "Computer", "EventID", "TargetUserName",
    "IpAddress", "LogonType", "Status", "SubStatus", "WorkstationName"
}

def main():
    parser = argparse.ArgumentParser(description="Analyse Windows authentication events.")
    parser.add_argument("csv_file", help="Path to windows_security.csv")
    parser.add_argument("--output-dir", default="analysis/results",
                        help="Directory for generated CSV reports")
    args = parser.parse_args()

    data = pd.read_csv(args.csv_file)
    missing = REQUIRED - set(data.columns)
    if missing:
        raise SystemExit(f"Missing expected CSV columns: {', '.join(sorted(missing))}")

    data["EventID"] = pd.to_numeric(data["EventID"], errors="coerce")
    data["TimeParsed"] = pd.to_datetime(data["TimeCreated"], utc=True, errors="coerce")
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    data.groupby("EventID").size().rename("event_count").reset_index().to_csv(
        output / "event_summary.csv", index=False
    )

    failed = data[data["EventID"] == 4625].copy()
    (failed.groupby(["IpAddress", "TargetUserName", "Computer"])
     .size().rename("failed_attempts").reset_index()
     .sort_values("failed_attempts", ascending=False)
     .to_csv(output / "failed_logins_by_ip_account.csv", index=False))

    (failed.groupby("IpAddress")
     .agg(failed_attempts=("EventID", "size"),
          unique_accounts=("TargetUserName", "nunique"),
          first_seen=("TimeParsed", "min"),
          last_seen=("TimeParsed", "max"))
     .reset_index()
     .to_csv(output / "failed_logins_by_ip.csv", index=False))

    (failed.groupby(["Status", "SubStatus"], dropna=False)
     .size().rename("event_count").reset_index()
     .to_csv(output / "failure_reason_summary.csv", index=False))

    auth = data[data["EventID"].isin([4625, 4624])].dropna(
        subset=["TimeParsed", "IpAddress"]
    ).sort_values("TimeParsed")

    matches = []
    for _, success in auth[auth["EventID"] == 4624].iterrows():
        start = success["TimeParsed"] - pd.Timedelta(minutes=30)
        prior = auth[
            (auth["IpAddress"] == success["IpAddress"]) &
            (auth["EventID"] == 4625) &
            (auth["TimeParsed"] < success["TimeParsed"]) &
            (auth["TimeParsed"] >= start)
        ]
        if len(prior) >= 5:
            matches.append({
                "success_time_utc": success["TimeCreated"],
                "source_ip": success["IpAddress"],
                "successful_account": success["TargetUserName"],
                "computer": success["Computer"],
                "logon_type": success["LogonType"],
                "prior_failed_logins_30m": len(prior),
                "distinct_failed_accounts_30m": prior["TargetUserName"].nunique(),
                "first_prior_failure_utc": prior["TimeCreated"].min(),
                "last_prior_failure_utc": prior["TimeCreated"].max()
            })

    pd.DataFrame(matches).to_csv(
        output / "success_after_prior_failures.csv", index=False
    )

    print(f"Analysed {len(data)} events.")
    print(f"Failed logins: {(data['EventID'] == 4625).sum()}")
    print(f"Successful logins: {(data['EventID'] == 4624).sum()}")
    print(f"Account lockouts: {(data['EventID'] == 4740).sum()}")
    print(f"Success-after-failures correlations: {len(matches)}")
    print(f"Reports written to: {output.resolve()}")

if __name__ == "__main__":
    main()
