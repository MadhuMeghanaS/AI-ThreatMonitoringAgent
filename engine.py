"""
engine.py  –  Core security analysis pipeline
  1. AnomalyDetector  – scores each log event
  2. KillChainBuilder – groups scored events into attack chains
  3. MITRE_PATTERNS   – tactic / technique metadata
"""

import pandas as pd
import numpy as np
from datetime import timedelta

# ── MITRE ATT&CK pattern registry ────────────────────────────────────────────
MITRE_PATTERNS = {
    "brute_force": {
        "tactic":      "Credential Access",
        "technique":   "T1110 – Brute Force",
        "description": "Multiple rapid authentication failures from a single source",
        "severity":    "HIGH",
    },
    "success_after_brute_force": {
        "tactic":      "Initial Access",
        "technique":   "T1078 – Valid Accounts",
        "description": "Successful login immediately following a brute-force burst",
        "severity":    "CRITICAL",
    },
    "off_hours_activity": {
        "tactic":      "Defense Evasion",
        "technique":   "T1078.003 – Cloud Accounts",
        "description": "Authentication outside normal business hours",
        "severity":    "MEDIUM",
    },
    "privilege_escalation": {
        "tactic":      "Privilege Escalation",
        "technique":   "T1078 – Valid Accounts / Admin Access",
        "description": "Access to administrative endpoints by a non-admin user",
        "severity":    "CRITICAL",
    },
    "new_account": {
        "tactic":      "Persistence",
        "technique":   "T1136 – Create Account",
        "description": "New user account created during suspicious session",
        "severity":    "HIGH",
    },
    "lateral_movement": {
        "tactic":      "Lateral Movement",
        "technique":   "T1021 – Remote Services",
        "description": "User activity on a previously unaccessed internal system",
        "severity":    "CRITICAL",
    },
    "data_exfiltration": {
        "tactic":      "Exfiltration",
        "technique":   "T1041 – Exfiltration Over C2 Channel",
        "description": "Anomalously large data transfer to external IP",
        "severity":    "CRITICAL",
    },
    "new_source_ip": {
        "tactic":      "Discovery",
        "technique":   "T1590 – Gather Victim Network Information",
        "description": "Login from an IP address never seen for this user",
        "severity":    "LOW",
    },
}

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class AnomalyDetector:
    """
    Rule-based + statistical anomaly scorer.
    Each event gets a 0-100 risk score and a list of fired flags.
    """

    def __init__(self):
        self.baselines: dict = {}   # user → behavioral profile

    # ── public API ────────────────────────────────────────────────────────────

    def fit(self, df: pd.DataFrame) -> None:
        """Build per-user behavioral baselines from the full log DataFrame."""
        for user, grp in df.groupby("user"):
            success = grp[grp["event_type"] == "auth_success"]
            self.baselines[user] = {
                "normal_hours":    (
                    success["hour"].mode().tolist() if len(success) else list(range(9, 18))
                ),
                "known_ips":       grp["source_ip"].value_counts().head(5).index.tolist(),
                "known_systems":   grp["target_system"].value_counts().head(5).index.tolist(),
            }

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a copy of df with 'anomaly_score' and 'flags' columns added."""
        results = []
        for _, ev in df.iterrows():
            score, flags = self._score_event(ev, df)
            rec = ev.to_dict()
            rec["anomaly_score"] = min(int(score), 100)
            rec["flags"]         = flags
            results.append(rec)
        return pd.DataFrame(results)

    # ── private helpers ───────────────────────────────────────────────────────

    def _score_event(self, ev, df):
        score = 0
        flags = []
        user  = ev["user"]
        bl    = self.baselines.get(user, {})
        ts    = ev["timestamp"]
        hour  = ts.hour if hasattr(ts, "hour") else int(str(ev.get("hour", 12)))

        # ① Off-hours
        normal_hours = bl.get("normal_hours", list(range(9, 18)))
        if hour < 7 or hour > 22:
            score += 30
            flags.append("off_hours_activity")

        # ② New source IP
        known_ips = bl.get("known_ips", [])
        if known_ips and ev["source_ip"] not in known_ips:
            score += 20
            flags.append("new_source_ip")

        # ③ Brute-force burst  (≥3 failures in 10 min)
        if ev["event_type"] == "auth_failure":
            window = df[
                (df["user"] == user) &
                (df["event_type"] == "auth_failure") &
                (df["timestamp"] <= ts) &
                (df["timestamp"] > ts - timedelta(minutes=10))
            ]
            if len(window) >= 3:
                score += 40
                if "brute_force" not in flags:
                    flags.append("brute_force")

        # ④ Success immediately after failures
        if ev["event_type"] == "auth_success":
            prior = df[
                (df["user"] == user) &
                (df["event_type"] == "auth_failure") &
                (df["timestamp"] < ts) &
                (df["timestamp"] > ts - timedelta(minutes=15))
            ]
            if len(prior) >= 2:
                score += 50
                flags.append("success_after_brute_force")

        # ⑤ Admin endpoint
        resource = str(ev.get("resource", ""))
        if "/admin" in resource:
            score += 35
            flags.append("privilege_escalation")

        # ⑥ Account creation
        if ev["event_type"] == "account_created":
            score += 45
            flags.append("new_account")

        # ⑦ Lateral movement  (new system for this user)
        target = str(ev.get("target_system", ""))
        known_sys = bl.get("known_systems", [])
        if target and target not in ("auth_server", "") and known_sys and target not in known_sys:
            score += 40
            flags.append("lateral_movement")

        # ⑧ Large data transfer  (> 50 MB)
        if int(ev.get("bytes_transferred", 0)) > 50_000_000:
            score += 60
            flags.append("data_exfiltration")

        return score, flags


class KillChainBuilder:
    """
    Groups high-scoring events into per-user attack chains,
    maps them to MITRE ATT&CK tactics, and assigns P0-P3 severity.
    """

    def __init__(self, threshold: int = 20):
        self.threshold = threshold

    def build(self, scored_df: pd.DataFrame) -> list[dict]:
        high_risk = scored_df[scored_df["anomaly_score"] >= self.threshold].copy()
        chains    = []

        for user, grp in high_risk.groupby("user"):
            grp = grp.sort_values("timestamp")
            chain_events, tactics_seen = [], []

            for _, ev in grp.iterrows():
                for flag in ev["flags"]:
                    if flag in MITRE_PATTERNS:
                        pattern = MITRE_PATTERNS[flag]
                        tactic  = pattern["tactic"]
                        if tactic not in tactics_seen:
                            tactics_seen.append(tactic)
                        chain_events.append({
                            "timestamp":    ev["timestamp"],
                            "event_type":   ev["event_type"],
                            "resource":     ev.get("resource", ""),
                            "target_system":ev.get("target_system", ""),
                            "source_ip":    ev["source_ip"],
                            "tactic":       tactic,
                            "technique":    pattern["technique"],
                            "severity_tag": pattern["severity"],
                            "anomaly_score":ev["anomaly_score"],
                        })

            if not chain_events:
                continue

            max_score   = max(e["anomaly_score"] for e in chain_events)
            max_sev_tag = max(
                (e["severity_tag"] for e in chain_events),
                key=lambda s: SEVERITY_ORDER.get(s, 0),
            )

            priority = (
                "P0 – CRITICAL" if max_sev_tag == "CRITICAL" and max_score >= 70
                else "P1 – HIGH"   if max_score >= 50
                else "P2 – MEDIUM" if max_score >= 30
                else "P3 – LOW"
            )
            priority_color = {
                "P0 – CRITICAL": "#E24B4A",
                "P1 – HIGH":     "#EF9F27",
                "P2 – MEDIUM":   "#378ADD",
                "P3 – LOW":      "#1D9E75",
            }.get(priority, "#888")

            chains.append({
                "user":           user,
                "source_ip":      grp["source_ip"].mode().iloc[0],
                "events":         chain_events,
                "tactics":        tactics_seen,
                "priority":       priority,
                "priority_color": priority_color,
                "max_score":      max_score,
                "start_time":     chain_events[0]["timestamp"],
                "end_time":       chain_events[-1]["timestamp"],
                "event_count":    len(chain_events),
            })

        return sorted(chains, key=lambda c: c["max_score"], reverse=True)
