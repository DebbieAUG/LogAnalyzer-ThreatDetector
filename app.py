import streamlit as st
import pandas as pd
import plotly.express as px

from parser import load_logs
from detector import detect_all
from risk_engine import calculate_risk, get_severity


st.set_page_config(
    page_title="CyberShield SOC",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ CyberShield")
st.subheader("Automated Threat Detection & Incident Response Platform")


# Load data
df = load_logs("data/security_logs.csv")

# Detect threats
incidents = detect_all(df)


if not incidents.empty:

    incidents["risk_score"] = incidents.apply(
        calculate_risk,
        axis=1
    )

    incidents["severity"] = incidents["risk_score"].apply(
        get_severity
    )


# Metrics
total_events = len(df)
total_incidents = len(incidents)

critical = len(
    incidents[incidents["severity"] == "CRITICAL"]
)

high = len(
    incidents[incidents["severity"] == "HIGH"]
)

medium = len(
    incidents[incidents["severity"] == "MEDIUM"]
)


col1, col2, col3, col4 = st.columns(4)

col1.metric("Security Events", total_events)
col2.metric("Threats Detected", total_incidents)
col3.metric("Critical Threats", critical)
col4.metric("High Threats", high)


st.divider()


# Threat distribution
left, right = st.columns(2)


with left:

    st.subheader("🚨 Threat Distribution")

    threat_counts = incidents["type"].value_counts()

    fig = px.pie(
        values=threat_counts.values,
        names=threat_counts.index,
        hole=0.4
    )

    st.plotly_chart(fig, use_container_width=True)


with right:

    st.subheader("📊 Severity Distribution")

    severity_counts = incidents["severity"].value_counts()

    fig = px.bar(
        x=severity_counts.index,
        y=severity_counts.values,
        labels={
            "x": "Severity",
            "y": "Incidents"
        }
    )

    st.plotly_chart(fig, use_container_width=True)


st.divider()


# Incident table
st.subheader("🔍 Security Incidents")


display_columns = [
    "type",
    "severity",
    "risk_score",
    "ip",
    "user",
    "description"
]

st.dataframe(
    incidents[display_columns],
    use_container_width=True,
    hide_index=True
)


st.divider()


# Investigation
st.subheader("🕵️ Incident Investigation")


selected = st.selectbox(
    "Select an incident",
    range(len(incidents)),
    format_func=lambda x:
        f"{incidents.iloc[x]['type']} — "
        f"{incidents.iloc[x]['ip']}"
)


incident = incidents.iloc[selected]


col1, col2, col3 = st.columns(3)

col1.metric(
    "Risk Score",
    f"{incident['risk_score']}/100"
)

col2.metric(
    "Severity",
    incident["severity"]
)

col3.metric(
    "Source IP",
    incident["ip"]
)


st.write("### Incident Details")

st.write(incident["description"])


# Recommendations
recommendations = {

    "Brute Force Attack": [
        "Temporarily block the source IP",
        "Lock or rate-limit the affected account",
        "Force password reset",
        "Enable multi-factor authentication"
    ],

    "Possible Account Compromise": [
        "Immediately review account activity",
        "Force password reset",
        "Revoke active sessions",
        "Enable MFA",
        "Review privileged actions"
    ],

    "SQL Injection Attempt": [
        "Block or rate-limit the source IP",
        "Review affected application endpoint",
        "Use parameterized database queries",
        "Inspect application logs for successful exploitation"
    ],

    "Privilege Escalation": [
        "Verify whether privilege assignment was authorized",
        "Revoke unauthorized privileges",
        "Review administrator activity",
        "Enable privilege-change monitoring"
    ],

    "Request Flooding": [
        "Rate-limit the source IP",
        "Review request patterns",
        "Enable application-level throttling",
        "Monitor for continued activity"
    ]
}


st.write("### 🛡️ Recommended Response")


for action in recommendations.get(
    incident["type"],
    ["Investigate the incident"]
):

    st.checkbox(action)