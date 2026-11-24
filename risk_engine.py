def calculate_risk(incident):

    scores = {
        "Brute Force Attack": 70,
        "Possible Account Compromise": 90,
        "SQL Injection Attempt": 95,
        "Privilege Escalation": 95,
        "Request Flooding": 55
    }

    return scores.get(incident["type"], 30)


def get_severity(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"