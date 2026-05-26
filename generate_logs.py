"""
generate_logs.py
Run once to create sample_logs.json with a realistic attack scenario planted
inside normal background traffic.

Attack story planted:
  23:00-23:05  -> Brute force on 'alice' from 192.168.99.10
  23:06        -> Successful login (after brute force)
  23:08        -> Alice accesses /admin/users (privilege escalation)
  23:10        -> New account 'svc_monitor' created
  23:12        -> svc_monitor accesses DB server (lateral movement)
  23:15        -> 150 MB data export from DB (exfiltration)
"""

import json
import random
from datetime import datetime, timedelta

# random.seed(42)  # Removed to allow for dynamic log generation on each run

BASE_DATE = "2024-01-15"
NORMAL_USERS = ["bob", "carol", "dave", "eve", "frank"]
NORMAL_IPS = {
    "bob":   ["10.0.1.5"],
    "carol": ["10.0.1.8"],
    "dave":  ["10.0.1.12"],
    "eve":   ["10.0.1.20"],
    "frank": ["10.0.1.30"],
    "alice": ["10.0.1.3"],   # alice's real IP
}
RESOURCES = ["/api/dashboard", "/api/reports", "/api/profile", "/api/search", "/api/data"]
SYSTEMS   = ["app_server", "api_gateway", "auth_server"]

logs = []
event_id = 1

def ts(hour, minute, second=0):
    return f"{BASE_DATE}T{hour:02d}:{minute:02d}:{second:02d}Z"

def log(timestamp, user, source_ip, event_type, resource="",
        target_system="app_server", bytes_transferred=0, note=""):
    global event_id
    logs.append({
        "event_id":          f"EVT{event_id:05d}",
        "timestamp":         timestamp,
        "user":              user,
        "source_ip":         source_ip,
        "event_type":        event_type,
        "resource":          resource,
        "target_system":     target_system,
        "bytes_transferred": bytes_transferred,
        "hour":              int(timestamp[11:13]),
        "note":              note,
    })
    event_id += 1

# ── Normal business-hours traffic (09:00–18:00) ──────────────────────────────
for hour in range(9, 18):
    for user in NORMAL_USERS + ["alice"]:
        ip = random.choice(NORMAL_IPS[user])
        # login
        log(ts(hour, random.randint(0, 5)), user, ip, "auth_success",
            target_system="auth_server")
        # 2-5 API calls
        for _ in range(random.randint(2, 5)):
            log(ts(hour, random.randint(6, 58)), user, ip, "api_call",
                resource=random.choice(RESOURCES),
                bytes_transferred=random.randint(1_000, 500_000))
        # occasional logout
        if random.random() > 0.4:
            log(ts(hour, random.randint(55, 59)), user, ip, "logout")

# ── Scattered evening noise (18:00–22:30) ────────────────────────────────────
for user in ["bob", "carol", "dave"]:
    ip = random.choice(NORMAL_IPS[user])
    log(ts(19, random.randint(10, 50)), user, ip, "auth_success",
        target_system="auth_server")
    log(ts(19, random.randint(51, 59)), user, ip, "api_call",
        resource="/api/reports", bytes_transferred=random.randint(5_000, 20_000))

# ── ATTACK SEQUENCE ───────────────────────────────────────────────────────────
ATTACK_IP = "192.168.99.10"

# Phase 1: Brute force (23:00 – 23:05)
for minute in range(0, 5):
    for attempt in range(3):
        log(ts(23, minute, attempt * 18), "alice", ATTACK_IP, "auth_failure",
            target_system="auth_server", note="brute_force")

# Phase 2: Successful compromise (23:06)
log(ts(23, 6), "alice", ATTACK_IP, "auth_success",
    target_system="auth_server", note="post_brute_force_success")

# Phase 3: Privilege escalation (23:08)
log(ts(23, 8), "alice", ATTACK_IP, "api_call",
    resource="/admin/users", target_system="app_server",
    bytes_transferred=12_000, note="priv_escalation")

# Phase 4: Create backdoor account (23:10)
log(ts(23, 10), "alice", ATTACK_IP, "account_created",
    resource="/admin/users/create", target_system="app_server",
    note="persistence")

# Phase 5: Lateral movement to DB server (23:12)
log(ts(23, 12), "svc_monitor", ATTACK_IP, "auth_success",
    target_system="database_server", note="lateral_movement")
log(ts(23, 13), "svc_monitor", ATTACK_IP, "api_call",
    resource="/db/query", target_system="database_server",
    bytes_transferred=2_000_000, note="recon")

# Phase 6: Data exfiltration (23:15)
log(ts(23, 15), "svc_monitor", ATTACK_IP, "api_call",
    resource="/db/export", target_system="database_server",
    bytes_transferred=155_000_000, note="exfiltration")

# -- Save ----------------------------------------------------------------------
logs.sort(key=lambda x: x["timestamp"])
with open("sample_logs.json", "w") as f:
    json.dump(logs, f, indent=2)

print(f"Generated {len(logs)} log events -> sample_logs.json")
print(f"  Normal events : {sum(1 for l in logs if not l['note'])}")
print(f"  Attack events : {sum(1 for l in logs if l['note'])}")
