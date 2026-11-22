# soc.py
#
# Command line for Home SOC Lite.
#
#   python3 soc.py demo                load the SYNTHETIC sample logs and show the alerts
#   python3 soc.py ingest FILE ...     add log lines from files ("-" reads pasted text)
#       --macos                        lines come from macOS `log show`
#       --reset                        empty the database first
#   python3 soc.py alerts              run the rules on whatever is loaded
#   python3 soc.py export              write the static dashboard to docs/ for GitHub Pages
#
# The local dashboard is separate:  python3 app.py

import argparse
import csv
import json
import os
import shutil

import dashboard_data
import rules
import store

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "soc.db")
ADMIN_FILE = os.path.join(HERE, "config", "admin_accounts.txt")
WEB_DIR = os.path.join(HERE, "web")
SAMPLE_FILES = ["sample_logs/auth.log", "sample_logs/web_access.log", "sample_logs/firewall.log"]

CSV_COLUMNS = ["alert_id", "severity", "rule_id", "rule", "mitre", "src_ip", "users",
               "first_seen", "last_seen", "events", "summary", "note", "triage"]


def load_demo(db):
    store.reset(db)
    total_added = 0
    total_skipped = 0
    for name in SAMPLE_FILES:
        added, skipped = store.ingest_file(db, os.path.join(HERE, name))
        total_added += added
        total_skipped += skipped
    return total_added, total_skipped


def print_alerts(db, alerts):
    print()
    if store.is_synthetic(db):
        print("*** SYNTHETIC / MOCK DATA ***")
    print("Events in database:", store.count_events(db))
    print()
    print("Rule".ljust(28) + "MITRE".ljust(12) + "Alerts".rjust(6))
    counts = rules.count_by_rule(alerts)
    for rule in rules.RULES:
        print((rule["id"] + " " + rule["name"]).ljust(28) + rule["mitre"].ljust(12)
              + str(counts[rule["id"]]).rjust(6))
    print("Total".ljust(40) + str(len(alerts)).rjust(6))
    print()
    for a in alerts:
        print(a["alert_id"].ljust(8) + a["severity"].ljust(8) + a["first_seen"][11:].ljust(10)
              + a["rule"].ljust(23) + a["summary"])
        if a["note"]:
            print(" " * 26 + "! " + a["note"])


def write_alerts_csv(path, alerts, synthetic):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        if synthetic:
            f.write("# SYNTHETIC / MOCK DATA - alerts from made-up logs\n")
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)


def export_static(db, alerts, out_dir):
    """Copy the dashboard page and write data.json next to it."""
    os.makedirs(out_dir, exist_ok=True)
    for name in ["index.html", "style.css", "app.js"]:
        shutil.copy(os.path.join(WEB_DIR, name), os.path.join(out_dir, name))
    data = dashboard_data.build(db, alerts)
    with open(os.path.join(out_dir, "data.json"), "w") as f:
        json.dump(data, f, indent=1)
    # tells GitHub Pages to serve the files as they are
    open(os.path.join(out_dir, ".nojekyll"), "w").close()


def main():
    parser = argparse.ArgumentParser(description="Home SOC Lite: logs in, alerts out.")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("demo", help="load the SYNTHETIC sample logs and show the alerts")

    ingest = commands.add_parser("ingest", help="add log lines from files")
    ingest.add_argument("files", nargs="+", help='log files, or "-" to paste lines')
    ingest.add_argument("--macos", action="store_true", help="lines come from macOS `log show`")
    ingest.add_argument("--reset", action="store_true", help="empty the database first")

    commands.add_parser("alerts", help="run the rules on what is loaded")

    export = commands.add_parser("export", help="write the static dashboard for GitHub Pages")
    export.add_argument("--out", default=os.path.join(HERE, "docs"))

    args = parser.parse_args()
    db = store.open_db(DB_PATH)

    if args.command == "demo":
        added, skipped = load_demo(db)
        print("Loaded", added, "events from the sample logs (" + str(skipped)
              + " lines were not login, web or firewall events).")

    if args.command == "ingest":
        if args.reset:
            store.reset(db)
        for path in args.files:
            if path == "-":
                print("Paste log lines, then press Ctrl-D:")
            added, skipped = store.ingest_file(db, path, args.macos)
            print(path + ":", added, "events added,", skipped, "lines not recognised")

    alerts = rules.run_rules(db, ADMIN_FILE)

    if args.command == "export":
        export_static(db, alerts, args.out)
        print("Wrote the static dashboard to", os.path.relpath(args.out, HERE) + "/")
    else:
        print_alerts(db, alerts)
        csv_path = os.path.join(HERE, "output", "alerts.csv")
        write_alerts_csv(csv_path, alerts, store.is_synthetic(db))
        print()
        print("Wrote", os.path.relpath(csv_path, HERE))

    db.close()


if __name__ == "__main__":
    main()
