# Tests for the detection rules.
#
# tests/fixture/ holds small logs where every alert is known in advance.
# Each case is commented in the fixture file itself. The boundary cases:
#   4 failures in 5 min = no alert, 5 = alert, 5 spread over 5:01 = no alert
#   8 users sprayed = alert, 7 = no alert, 8 spread over 35 min = no alert
#   admin login at 06:59:59 = alert, 07:00:00 = no, 18:59:59 = no, 19:00:00 = alert
#   15 different 404s or blocked ports in 2 min = alert, 14 = no alert
#
# Run from the project folder:  python3 -m unittest discover -s tests -v

import json
import os
import tempfile
import unittest

import dashboard_data
import rules
import soc
import store

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixture")


def load_fixture():
    db = store.open_db(":memory:")
    for name in ["auth.log", "web.log", "firewall.log"]:
        store.ingest_file(db, os.path.join(FIXTURE, name))
    return db


def alerts_for(alerts, rule_id):
    return [a for a in alerts if a["rule_id"] == rule_id]


class TestRules(unittest.TestCase):

    def setUp(self):
        self.db = load_fixture()
        self.alerts = rules.run_rules(self.db, soc.ADMIN_FILE)

    def tearDown(self):
        self.db.close()

    def test_brute_force(self):
        found = sorted(a["src_ip"] for a in alerts_for(self.alerts, "R1"))
        # .1 (4 failures) and .3 (5 failures over 5:01) do not alert,
        # .5 alerts twice (bursts 2 h apart), .6 once (bursts 30 min apart)
        self.assertEqual(found, ["192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.5", "192.0.2.6"])

    def test_brute_force_then_success_is_high(self):
        by_ip = {a["src_ip"]: a for a in alerts_for(self.alerts, "R1")}
        self.assertEqual(by_ip["192.0.2.4"]["severity"], "High")
        self.assertIn("dbadmin", by_ip["192.0.2.4"]["note"])
        self.assertEqual(by_ip["192.0.2.2"]["severity"], "Medium")

    def test_brute_force_evidence(self):
        by_ip = {a["src_ip"]: a for a in alerts_for(self.alerts, "R1")}
        self.assertEqual(by_ip["192.0.2.2"]["events"], 5)
        self.assertEqual(by_ip["192.0.2.2"]["first_seen"], "2026-11-20 10:00:00")
        self.assertEqual(by_ip["192.0.2.2"]["last_seen"], "2026-11-20 10:05:00")

    def test_password_spray(self):
        found = [a["src_ip"] for a in alerts_for(self.alerts, "R2")]
        self.assertEqual(found, ["198.51.100.1"])
        self.assertEqual(alerts_for(self.alerts, "R2")[0]["events"], 8)

    def test_off_hours_admin(self):
        found = [(a["users"], a["first_seen"][11:]) for a in alerts_for(self.alerts, "R3")]
        self.assertEqual(found, [("admin", "06:59:59"), ("root", "19:00:00")])

    def test_off_hours_outside_ip_is_high(self):
        severity = {a["users"]: a["severity"] for a in alerts_for(self.alerts, "R3")}
        self.assertEqual(severity["admin"], "Medium")   # from 10.0.0.5
        self.assertEqual(severity["root"], "High")      # from 203.0.113.9

    def test_scanning(self):
        found = sorted(a["src_ip"] for a in alerts_for(self.alerts, "R4"))
        # .2 has 14 URLs, .3 hits one URL 20 times, .5 is too slow
        self.assertEqual(found, ["203.0.113.1", "203.0.113.4"])

    def test_alert_ids_in_time_order(self):
        ids = [a["alert_id"] for a in self.alerts]
        self.assertEqual(ids[0], "AL-001")
        times = [a["first_seen"] for a in self.alerts]
        self.assertEqual(times, sorted(times))

    def test_sudo_failure_stored(self):
        row = self.db.execute("SELECT user, src_ip FROM events WHERE detail = 'sudo'").fetchone()
        self.assertEqual((row["user"], row["src_ip"]), ("alice", "local"))


class TestIngest(unittest.TestCase):

    def test_invalid_user_lines_not_double_counted(self):
        db = load_fixture()
        n = db.execute("SELECT COUNT(*) FROM events WHERE src_ip = '198.51.100.1'").fetchone()[0]
        self.assertEqual(n, 8)
        db.close()

    def test_macos_file(self):
        db = store.open_db(":memory:")
        added, skipped = store.ingest_file(db, os.path.join(FIXTURE, "macos.txt"), macos_only=True)
        self.assertEqual(added, 4)
        self.assertEqual(skipped, 3)   # the "Filtering..." line, the header and the kernel line
        db.close()

    def test_synthetic_label(self):
        db = store.open_db(":memory:")
        store.ingest_lines(db, ["2026-11-20T10:00:00-04:00 srv sshd[1]: Failed password for a from 192.0.2.9 port 1 ssh2\n"])
        self.assertFalse(store.is_synthetic(db))
        store.ingest_lines(db, ["# SYNTHETIC / MOCK DATA\n"])
        self.assertTrue(store.is_synthetic(db))
        db.close()


class TestDashboard(unittest.TestCase):

    def test_data_and_export(self):
        db = load_fixture()
        alerts = rules.run_rules(db, soc.ADMIN_FILE)
        data = dashboard_data.build(db, alerts)
        self.assertEqual(data["totals"]["alerts"], len(alerts))
        self.assertEqual(sum(r["alerts"] for r in data["rules"]), len(alerts))
        # every event lands in exactly one timeline bucket
        t = data["timeline"]
        self.assertEqual(sum(t["suspicious"]) + sum(t["other"]), data["totals"]["events"])

        with tempfile.TemporaryDirectory() as folder:
            soc.export_static(db, alerts, folder)
            for name in ["index.html", "style.css", "app.js", "data.json", ".nojekyll"]:
                self.assertTrue(os.path.exists(os.path.join(folder, name)), name)
            with open(os.path.join(folder, "data.json")) as f:
                self.assertEqual(json.load(f)["totals"]["alerts"], len(alerts))
        db.close()


class TestSampleLogs(unittest.TestCase):
    """The README quotes these numbers, so check they stay true."""

    def test_planted_attacks(self):
        db = store.open_db(":memory:")
        added, skipped = soc.load_demo(db)
        self.assertTrue(store.is_synthetic(db))
        self.assertEqual(added, 505)
        alerts = rules.run_rules(db, soc.ADMIN_FILE)
        self.assertEqual(rules.count_by_rule(alerts), {"R1": 3, "R2": 2, "R3": 4, "R4": 3})
        self.assertEqual(len([a for a in alerts if a["severity"] == "High"]), 2)
        db.close()


if __name__ == "__main__":
    unittest.main()
