# rules.py
#
# The four detection rules. Each rule is one SQL query that returns every
# event where the rule's condition is true (a "hit"). Hits that belong to
# the same attack are then grouped into one alert, the same way a SIEM
# groups matches from a scheduled rule into one incident.
#
# Thresholds are written straight into the SQL so the rule reads the same
# here, in the README and on the dashboard.

import ipaddress
from datetime import datetime, timedelta

# A new hit for the same IP (or user) within this many minutes of the last
# one joins the open alert instead of starting a new one.
GROUP_MINUTES = 60

BRUTE_FORCE_SQL = """
-- R1 Brute-force login (MITRE ATT&CK T1110.001)
-- A failed login where the same source IP has 5 or more failed logins
-- in the 5 minutes up to and including it.
SELECT * FROM (
    SELECT f.id, f.ts, f.src_ip, f.user,
           (SELECT COUNT(*) FROM events x
             WHERE x.event = 'login_failure'
               AND x.src_ip = f.src_ip
               AND x.ts BETWEEN datetime(f.ts, '-5 minutes') AND f.ts) AS window_count
    FROM events f
    WHERE f.event = 'login_failure'
)
WHERE window_count >= 5
ORDER BY ts, id
"""

PASSWORD_SPRAY_SQL = """
-- R2 Password spraying (MITRE ATT&CK T1110.003)
-- A failed login where the same source IP has failed logins for 8 or more
-- different user names in the 30 minutes up to and including it.
SELECT * FROM (
    SELECT f.id, f.ts, f.src_ip, f.user,
           (SELECT COUNT(DISTINCT x.user) FROM events x
             WHERE x.event = 'login_failure'
               AND x.src_ip = f.src_ip
               AND x.ts BETWEEN datetime(f.ts, '-30 minutes') AND f.ts) AS window_count
    FROM events f
    WHERE f.event = 'login_failure'
)
WHERE window_count >= 8
ORDER BY ts, id
"""

OFF_HOURS_ADMIN_SQL = """
-- R3 Off-hours admin login (MITRE ATT&CK T1078 Valid Accounts)
-- A successful login by an admin account before 07:00 or from 19:00 on.
SELECT e.id, e.ts, e.src_ip, e.user, 1 AS window_count
FROM events e
WHERE e.event = 'login_success'
  AND e.user IN (SELECT user FROM admin_accounts)
  AND (time(e.ts) < '07:00:00' OR time(e.ts) >= '19:00:00')
ORDER BY ts, id
"""

SCANNING_SQL = """
-- R4 Scanning (MITRE ATT&CK T1595 Active Scanning)
-- A refused probe (web 404 or firewall block) where the same source IP
-- has probed 15 or more different URLs or ports in the 2 minutes up to
-- and including it.
SELECT * FROM (
    SELECT p.id, p.ts, p.src_ip, p.user,
           (SELECT COUNT(DISTINCT x.event || ' ' || x.detail) FROM events x
             WHERE x.event IN ('http_404', 'fw_block')
               AND x.src_ip = p.src_ip
               AND x.ts BETWEEN datetime(p.ts, '-2 minutes') AND p.ts) AS window_count
    FROM events p
    WHERE p.event IN ('http_404', 'fw_block')
)
WHERE window_count >= 15
ORDER BY ts, id
"""

# group_by:   which column decides "same attack" when grouping hits
# evidence:   which events to show an analyst, and how far back to look
#             from the first hit (the rule's window)
RULES = [
    {
        "id": "R1", "name": "Brute-force login",
        "mitre": "T1110.001", "mitre_name": "Brute Force: Password Guessing",
        "sql": BRUTE_FORCE_SQL, "group_by": "src_ip",
        "evidence": ["login_failure"], "lookback": "-5 minutes",
        "severity": "Medium",
        "triage": "Check whether a login from this IP succeeded afterwards. "
                  "If the IP is external, block it at the firewall.",
    },
    {
        "id": "R2", "name": "Password spraying",
        "mitre": "T1110.003", "mitre_name": "Brute Force: Password Spraying",
        "sql": PASSWORD_SPRAY_SQL, "group_by": "src_ip",
        "evidence": ["login_failure"], "lookback": "-30 minutes",
        "severity": "Medium",
        "triage": "List which of the targeted user names are real accounts, check "
                  "them for successful logins, and block the source IP.",
    },
    {
        "id": "R3", "name": "Off-hours admin login",
        "mitre": "T1078", "mitre_name": "Valid Accounts",
        "sql": OFF_HOURS_ADMIN_SQL, "group_by": "user",
        "evidence": ["login_success"], "lookback": "-0 minutes",
        "severity": "Medium",
        "triage": "Ask the account owner whether this was planned work. If not, "
                  "disable the account and reset its password.",
    },
    {
        "id": "R4", "name": "Scanning",
        "mitre": "T1595", "mitre_name": "Active Scanning",
        "sql": SCANNING_SQL, "group_by": "src_ip",
        "evidence": ["http_404", "fw_block"], "lookback": "-2 minutes",
        "severity": "Low",
        "triage": "Usually internet noise. Check that nothing it probed returned "
                  "200, then block the IP if it keeps coming back.",
    },
]

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def load_admin_accounts(db, path):
    """Admin account names, one per line. Kept in a temporary table so the
    off-hours rule can use it in SQL."""
    db.execute("DROP TABLE IF EXISTS temp.admin_accounts")
    db.execute("CREATE TEMP TABLE admin_accounts (user TEXT)")
    with open(path) as f:
        for line in f:
            name = line.strip()
            if name and not name.startswith("#"):
                db.execute("INSERT INTO admin_accounts VALUES (?)", (name,))


def to_time(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def is_internal(ip):
    """True for this machine and the private ranges (10.x, 172.16-31.x, 192.168.x)."""
    if ip == "local":
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    for network in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
        if address.version == 4 and address in ipaddress.ip_network(network):
            return True
    return False


def group_hits(rule, hits):
    """Turn a list of hits (sorted by time) into alerts. A hit joins the
    open alert for the same IP/user if it is within GROUP_MINUTES of
    that alert's last hit."""
    alerts = []
    open_alerts = {}
    for hit in hits:
        key = hit[rule["group_by"]]
        alert = open_alerts.get(key)
        if alert is not None and to_time(hit["ts"]) - to_time(alert["last_hit"]) <= timedelta(minutes=GROUP_MINUTES):
            alert["last_hit"] = hit["ts"]
            alert["peak"] = max(alert["peak"], hit["window_count"])
        else:
            alert = {"key": key, "first_hit": hit["ts"], "last_hit": hit["ts"],
                     "peak": hit["window_count"]}
            alerts.append(alert)
            open_alerts[key] = alert
    return alerts


def add_evidence(db, rule, alert):
    """Pull the log lines behind the alert, and fill in first/last seen."""
    placeholders = ", ".join(["?"] * len(rule["evidence"]))
    sql = ("SELECT id, ts, src_ip, user, event, detail, raw FROM events "
           "WHERE " + rule["group_by"] + " = ? AND event IN (" + placeholders + ") "
           "AND ts BETWEEN datetime(?, ?) AND ? ORDER BY ts, id")
    params = [alert["key"]] + rule["evidence"] + [alert["first_hit"], rule["lookback"], alert["last_hit"]]
    rows = [dict(r) for r in db.execute(sql, params)]

    alert["evidence"] = [r["ts"] + "  " + r["raw"] for r in rows]
    alert["events"] = len(rows)
    alert["first_seen"] = rows[0]["ts"]
    alert["last_seen"] = rows[-1]["ts"]

    ips = sorted(set(r["src_ip"] for r in rows))
    users = sorted(set(r["user"] for r in rows if r["user"]))
    alert["ip_list"] = ips
    alert["src_ip"] = ", ".join(ips)
    alert["users"] = ", ".join(users)
    alert["user_count"] = len(users)
    alert["targets"] = len(set(r["event"] + r["detail"] for r in rows))


def login_succeeded_after(db, alert):
    """Did the same IP log in successfully during the attack or within
    30 minutes after it? Returns the time of that login, or None."""
    row = db.execute("SELECT ts, user FROM events WHERE event = 'login_success' AND src_ip = ? "
                     "AND ts BETWEEN ? AND datetime(?, '+30 minutes') ORDER BY ts LIMIT 1",
                     (alert["src_ip"], alert["first_seen"], alert["last_seen"])).fetchone()
    return row


def how_long(first, last):
    """'45 s' or '18 min' between two timestamps."""
    seconds = int((to_time(last) - to_time(first)).total_seconds())
    if seconds < 120:
        return str(seconds) + " s"
    return str(seconds // 60) + " min"


def describe(db, rule, alert):
    """Set severity, a one-line summary and any extra note for an analyst."""
    alert["severity"] = rule["severity"]
    alert["note"] = ""
    took = how_long(alert["first_seen"], alert["last_seen"])

    if rule["id"] == "R1":
        alert["summary"] = (str(alert["events"]) + " failed logins in " + took + " from "
                            + alert["src_ip"] + " against " + alert["users"])
    elif rule["id"] == "R2":
        alert["summary"] = ("Failed logins for " + str(alert["user_count"]) + " different users in "
                            + took + " from " + alert["src_ip"])
    elif rule["id"] == "R3":
        if alert["events"] == 1:
            when = "at " + alert["first_seen"][11:16]
        else:
            when = str(alert["events"]) + " times between " + alert["first_seen"][11:16] + " and " + alert["last_seen"][11:16]
        alert["summary"] = "Admin account " + alert["users"] + " logged in " + when + " from " + alert["src_ip"]
        for ip in alert["ip_list"]:
            if not is_internal(ip):
                alert["severity"] = "High"
                alert["note"] = "The login came from outside the internal network."
    else:
        alert["summary"] = (str(alert["targets"]) + " different URLs or ports probed and refused in "
                            + took + " from " + alert["src_ip"])

    # a brute force or spray that ends in a successful login is the worst case
    if rule["id"] in ("R1", "R2"):
        success = login_succeeded_after(db, alert)
        if success is not None:
            alert["severity"] = "High"
            alert["note"] = ("A login as " + success["user"] + " from this IP succeeded at "
                             + success["ts"][11:19] + ". Treat that account as compromised.")


def run_rules(db, admin_file):
    """Run every rule and return the alerts, oldest first, with IDs AL-001, ..."""
    load_admin_accounts(db, admin_file)
    alerts = []
    for rule in RULES:
        hits = [dict(r) for r in db.execute(rule["sql"])]
        for alert in group_hits(rule, hits):
            add_evidence(db, rule, alert)
            describe(db, rule, alert)
            alert["rule_id"] = rule["id"]
            alert["rule"] = rule["name"]
            alert["mitre"] = rule["mitre"]
            alert["mitre_name"] = rule["mitre_name"]
            alert["triage"] = rule["triage"]
            alerts.append(alert)

    alerts.sort(key=lambda a: (a["first_seen"], a["rule_id"]))
    for number, alert in enumerate(alerts, start=1):
        alert["alert_id"] = "AL-" + str(number).zfill(3)
    return alerts


def count_by_rule(alerts):
    counts = {}
    for rule in RULES:
        counts[rule["id"]] = 0
    for alert in alerts:
        counts[alert["rule_id"]] += 1
    return counts
