# dashboard_data.py
#
# Builds the one object the dashboard page reads (data.json). The local
# FastAPI server builds it live from soc.db; `python3 soc.py export`
# writes it to docs/data.json for GitHub Pages. Same page, same data.

from datetime import timedelta

import rules
import store

# events that are worth a second look on the timeline
SUSPICIOUS = ("login_failure", "http_404", "fw_block")
BUCKET_MINUTES = 30

# the alert fields the page shows (internal working fields are left out)
ALERT_FIELDS = ["alert_id", "rule_id", "rule", "mitre", "mitre_name", "severity", "src_ip",
                "users", "first_seen", "last_seen", "events", "summary", "note", "triage",
                "evidence"]


def build_timeline(db, alerts):
    """Count events per 30-minute bucket, split into suspicious and other,
    and list which alerts started in each bucket (shown on hover)."""
    rows = db.execute("SELECT ts, event FROM events ORDER BY ts").fetchall()
    if not rows:
        return {"labels": [], "suspicious": [], "other": [], "alerts": []}

    first = rules.to_time(rows[0]["ts"])
    first = first.replace(minute=first.minute - first.minute % BUCKET_MINUTES, second=0)
    last = rules.to_time(rows[-1]["ts"])
    size = timedelta(minutes=BUCKET_MINUTES)
    count = int((last - first) / size) + 1
    one_day = first.date() == last.date()

    labels = []
    for i in range(count):
        start = first + size * i
        if one_day:
            labels.append(start.strftime("%H:%M"))
        else:
            labels.append(start.strftime("%m-%d %H:%M"))

    suspicious = [0] * count
    other = [0] * count
    for row in rows:
        i = int((rules.to_time(row["ts"]) - first) / size)
        if row["event"] in SUSPICIOUS:
            suspicious[i] += 1
        else:
            other[i] += 1

    alerts_in_bucket = []
    for i in range(count):
        alerts_in_bucket.append([])
    for alert in alerts:
        i = int((rules.to_time(alert["first_seen"]) - first) / size)
        alerts_in_bucket[i].append(alert["alert_id"] + " " + alert["rule"] + " (" + alert["src_ip"] + ")")

    return {"labels": labels, "suspicious": suspicious, "other": other, "alerts": alerts_in_bucket}


def build(db, alerts):
    counts = rules.count_by_rule(alerts)
    rule_list = []
    for rule in rules.RULES:
        rule_list.append({"id": rule["id"], "name": rule["name"], "mitre": rule["mitre"],
                          "mitre_name": rule["mitre_name"], "alerts": counts[rule["id"]],
                          "sql": rule["sql"].strip()})

    alert_list = []
    for alert in alerts:
        row = {}
        for field in ALERT_FIELDS:
            row[field] = alert[field]
        alert_list.append(row)

    span = db.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
    by_source = {}
    for row in db.execute("SELECT source, COUNT(*) AS n FROM events GROUP BY source"):
        by_source[row["source"]] = row["n"]

    flagged_ips = set()
    for alert in alerts:
        for ip in alert["ip_list"]:
            flagged_ips.add(ip)

    return {
        "synthetic": store.is_synthetic(db),
        "log_start": span[0],
        "log_end": span[1],
        "totals": {
            "events": store.count_events(db),
            "alerts": len(alerts),
            "high": len([a for a in alerts if a["severity"] == "High"]),
            "ips": len(flagged_ips),
        },
        "events_by_source": by_source,
        "rules": rule_list,
        "alerts": alert_list,
        "timeline": build_timeline(db, alerts),
    }
