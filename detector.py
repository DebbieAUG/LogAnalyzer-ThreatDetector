import re
import pandas as pd


def detect_brute_force(df):
    incidents = []

    failed = df[
        (df["event_type"] == "LOGIN") &
        (df["status"] == "FAILED")
    ]

    grouped = failed.groupby(["ip", "user"])

    for (ip, user), group in grouped:

        if len(group) >= 5:
            incidents.append({
                "type": "Brute Force Attack",
                "severity": "HIGH",
                "ip": ip,
                "user": user,
                "description":
                    f"{len(group)} failed login attempts detected "
                    f"for user '{user}' from {ip}."
            })

    return incidents


def detect_account_compromise(df):
    incidents = []

    for _, row in df.iterrows():

        if row["event_type"] == "LOGIN" and row["status"] == "SUCCESS":

            previous = df[
                (df["ip"] == row["ip"]) &
                (df["user"] == row["user"]) &
                (df["timestamp"] < row["timestamp"]) &
                (df["event_type"] == "LOGIN") &
                (df["status"] == "FAILED")
            ]

            if len(previous) >= 3:

                incidents.append({
                    "type": "Possible Account Compromise",
                    "severity": "CRITICAL",
                    "ip": row["ip"],
                    "user": row["user"],
                    "description":
                        f"Successful login followed "
                        f"{len(previous)} failed attempts."
                })

    return incidents


def detect_sql_injection(df):
    incidents = []

    patterns = [
        r"'\s*OR\s*'1'\s*=\s*'1",
        r"UNION\s+SELECT",
        r"DROP\s+TABLE",
        r"--"
    ]

    for _, row in df.iterrows():

        details = str(row["details"])

        for pattern in patterns:

            if re.search(pattern, details, re.IGNORECASE):

                incidents.append({
                    "type": "SQL Injection Attempt",
                    "severity": "CRITICAL",
                    "ip": row["ip"],
                    "user": row["user"],
                    "description":
                        f"Suspicious SQL pattern detected: {details}"
                })

                break

    return incidents


def detect_privilege_abuse(df):
    incidents = []

    privilege_events = df[
        (df["event_type"] == "PRIVILEGE") &
        (df["details"].str.contains(
            "ADMIN_ROLE_GRANTED",
            case=False,
            na=False
        ))
    ]

    for _, row in privilege_events.iterrows():

        incidents.append({
            "type": "Privilege Escalation",
            "severity": "CRITICAL",
            "ip": row["ip"],
            "user": row["user"],
            "description":
                f"Administrative privileges granted to "
                f"user '{row['user']}'."
        })

    return incidents


def detect_request_flooding(df):
    incidents = []

    requests = df[df["event_type"] == "REQUEST"]

    counts = requests.groupby("ip").size()

    for ip, count in counts.items():

        if count >= 5:

            incidents.append({
                "type": "Request Flooding",
                "severity": "MEDIUM",
                "ip": ip,
                "user": "Unknown",
                "description":
                    f"{count} requests detected from {ip}."
            })

    return incidents


def detect_all(df):

    incidents = []

    incidents.extend(detect_brute_force(df))
    incidents.extend(detect_account_compromise(df))
    incidents.extend(detect_sql_injection(df))
    incidents.extend(detect_privilege_abuse(df))
    incidents.extend(detect_request_flooding(df))

    return pd.DataFrame(incidents)