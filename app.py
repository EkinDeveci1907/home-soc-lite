# app.py
#
# The local dashboard, served by FastAPI.
#
#   python3 app.py        then open http://127.0.0.1:8000
#
# If nothing has been loaded yet it loads the SYNTHETIC sample logs first.
# It only listens on 127.0.0.1, so nothing outside this computer can reach it.
#
# Routes:
#   /                the dashboard page (web/index.html)
#   /data.json       everything the page shows, built live from soc.db
#   /api/alerts      the alerts as JSON, optional ?severity=High&rule=R1
#   /api/health      a quick "is it up" check with the event count

import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import dashboard_data
import rules
import soc
import store

app = FastAPI(title="Home SOC Lite")


def current_data():
    # a fresh connection per request, so requests never share one
    db = store.open_db(soc.DB_PATH)
    try:
        alerts = rules.run_rules(db, soc.ADMIN_FILE)
        return dashboard_data.build(db, alerts)
    finally:
        db.close()


@app.get("/api/health")
def health():
    db = store.open_db(soc.DB_PATH)
    try:
        return {"status": "ok", "events": store.count_events(db)}
    finally:
        db.close()


@app.get("/data.json")
def data():
    return current_data()


@app.get("/api/alerts")
def alerts(severity: str = "", rule: str = ""):
    result = []
    for alert in current_data()["alerts"]:
        if severity and alert["severity"] != severity:
            continue
        if rule and alert["rule_id"] != rule:
            continue
        result.append(alert)
    return result


# everything else is the page itself: index.html, style.css, app.js
app.mount("/", StaticFiles(directory=soc.WEB_DIR, html=True), name="web")


if __name__ == "__main__":
    import uvicorn

    db = store.open_db(soc.DB_PATH)
    if store.count_events(db) == 0:
        print("No logs loaded yet, so loading the SYNTHETIC sample logs.")
        soc.load_demo(db)
    db.close()

    port = int(os.environ.get("PORT", "8000"))
    print("Dashboard: http://127.0.0.1:" + str(port) + "   (Ctrl-C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
