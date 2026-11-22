// Front-end for Home SOC Lite. Loads data.json (built live by app.py, or
// exported to docs/ for GitHub Pages), fills the number cards, draws two
// charts with Chart.js, and fills the alert table. No build step, just plain
// JS loaded with defer.
//
// Log lines come from outside, so an attacker controls some of their text
// (URLs, user names). Everything from the logs is put on the page with
// textContent, never innerHTML, so it can't run as code in the browser.

const INDIGO = "#4f46e5";
const SLATE = "#94a3b8";

let allAlerts = [];

async function start() {
  let response = await fetch("data.json", {cache: "no-store"});
  let data = await response.json();
  allAlerts = data.alerts;

  showHeader(data);
  if (typeof Chart === "undefined") {
    document.getElementById("no-charts").hidden = false;
  } else {
    drawRuleChart(data);
    drawTimeline(data);
  }
  setupFilters(data);
  drawTable();
  drawRules(data);
}

function showHeader(data) {
  document.getElementById("synthetic").hidden = !data.synthetic;
  document.getElementById("span").textContent = data.log_start + " to " + data.log_end.slice(11);
  document.getElementById("s-events").textContent = data.totals.events;
  document.getElementById("s-alerts").textContent = data.totals.alerts;
  document.getElementById("s-high").textContent = data.totals.high;
  document.getElementById("s-ips").textContent = data.totals.ips;

  let text = data.totals.alerts + " alerts from " + data.totals.events + " events.";
  let high = data.alerts.filter(function (a) { return a.severity === "High"; });
  if (high.length > 0) {
    text += " Start with " + high[0].alert_id + ": " + high[0].summary + ".";
  }
  document.getElementById("headline").textContent = text;
}

// one bar per rule, labelled with its MITRE ATT&CK technique
function drawRuleChart(data) {
  let labels = data.rules.map(function (r) { return [r.name, r.mitre]; });
  let counts = data.rules.map(function (r) { return r.alerts; });
  new Chart(document.getElementById("ruleChart"), {
    type: "bar",
    data: {labels: labels, datasets: [{label: "Alerts", data: counts, backgroundColor: INDIGO,
                                        borderRadius: 4, maxBarThickness: 28}]},
    options: {
      indexAxis: "y",
      plugins: {legend: {display: false}},
      scales: {x: {beginAtZero: true, ticks: {precision: 0}, grid: {color: "#f1f5f9"}},
               y: {grid: {display: false}}}
    }
  });
}

// events per 30 minutes, suspicious ones (failed logins, 404s, firewall blocks)
// stacked on top of everything else; the tooltip lists alerts that started there
function drawTimeline(data) {
  let t = data.timeline;
  new Chart(document.getElementById("timeChart"), {
    type: "bar",
    data: {
      labels: t.labels,
      datasets: [
        {label: "Failed logins, 404s, firewall blocks", data: t.suspicious, backgroundColor: INDIGO, stack: "s"},
        {label: "Everything else", data: t.other, backgroundColor: SLATE, stack: "s"}
      ]
    },
    options: {
      plugins: {
        legend: {position: "bottom", labels: {boxWidth: 12, font: {size: 11}}},
        tooltip: {
          callbacks: {
            footer: function (items) {
              let started = t.alerts[items[0].dataIndex];
              if (started.length === 0) { return ""; }
              return "Alerts starting here:\n" + started.join("\n");
            }
          }
        }
      },
      scales: {
        x: {stacked: true, grid: {display: false}, ticks: {maxTicksLimit: 12, font: {size: 10}}},
        y: {stacked: true, beginAtZero: true, ticks: {precision: 0}, grid: {color: "#f1f5f9"}}
      }
    }
  });
}

function fillSelect(id, values, allLabel) {
  let select = document.getElementById(id);
  let option = document.createElement("option");
  option.value = "";
  option.textContent = allLabel;
  select.appendChild(option);
  for (let i = 0; i < values.length; i++) {
    option = document.createElement("option");
    option.value = values[i][0];
    option.textContent = values[i][1];
    select.appendChild(option);
  }
  select.onchange = drawTable;
}

function setupFilters(data) {
  let ruleOptions = data.rules.map(function (r) { return [r.id, r.name + " (" + r.mitre + ")"]; });
  fillSelect("ruleFilter", ruleOptions, "All rules");
  fillSelect("severityFilter", [["High", "High"], ["Medium", "Medium"], ["Low", "Low"]], "All");
}

function addCell(row, text, className) {
  let cell = document.createElement("td");
  cell.textContent = text;
  if (className) { cell.className = className; }
  row.appendChild(cell);
  return cell;
}

function drawTable() {
  let rule = document.getElementById("ruleFilter").value;
  let severity = document.getElementById("severityFilter").value;
  let body = document.getElementById("alertRows");
  body.textContent = "";
  document.getElementById("detail").hidden = true;

  for (let i = 0; i < allAlerts.length; i++) {
    let a = allAlerts[i];
    if (rule && a.rule_id !== rule) { continue; }
    if (severity && a.severity !== severity) { continue; }

    let row = document.createElement("tr");
    addCell(row, a.alert_id, "mono");
    let sevCell = addCell(row, "");
    let badge = document.createElement("span");
    badge.className = "sev sev-" + a.severity;
    badge.textContent = a.severity;
    sevCell.appendChild(badge);
    addCell(row, a.rule + " · " + a.mitre);
    addCell(row, a.src_ip, "mono");
    addCell(row, a.users);
    addCell(row, a.first_seen.slice(5), "mono");   // drop the year to keep the column narrow
    addCell(row, a.summary);
    row.onclick = function () { showDetail(a, row); };
    body.appendChild(row);
  }
}

// the panel under the table: what fired, what to do, and the raw log lines
function showDetail(a, row) {
  let rows = document.querySelectorAll("#alertRows tr");
  for (let i = 0; i < rows.length; i++) { rows[i].classList.remove("selected"); }
  row.classList.add("selected");

  let panel = document.getElementById("detail");
  panel.textContent = "";
  let title = document.createElement("h3");
  title.textContent = a.alert_id + " · " + a.rule + " (" + a.mitre + " " + a.mitre_name + ") · " + a.severity;
  panel.appendChild(title);

  let lines = [
    ["", a.summary + ". Seen from " + a.first_seen + " to " + a.last_seen.slice(11) + ", " + a.events + " log lines."],
    ["note", a.note],
    ["", "Next step: " + a.triage]
  ];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i][1]) { continue; }
    let p = document.createElement("p");
    p.className = lines[i][0];
    p.textContent = lines[i][1];
    panel.appendChild(p);
  }

  let pre = document.createElement("pre");
  pre.className = "evidence";
  pre.textContent = a.evidence.join("\n");
  panel.appendChild(pre);
  panel.hidden = false;
}

function mitreLink(id) {
  return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
}

function drawRules(data) {
  let list = document.getElementById("ruleList");
  for (let i = 0; i < data.rules.length; i++) {
    let r = data.rules[i];
    let box = document.createElement("div");
    box.className = "rule";

    let name = document.createElement("strong");
    name.textContent = r.id + " " + r.name;
    box.appendChild(name);
    let link = document.createElement("a");
    link.className = "tag";
    link.href = mitreLink(r.mitre);
    link.target = "_blank";
    link.textContent = r.mitre + " " + r.mitre_name;
    box.appendChild(link);
    box.appendChild(document.createTextNode("  " + r.alerts + " alert" + (r.alerts === 1 ? "" : "s")));

    let details = document.createElement("details");
    let summary = document.createElement("summary");
    summary.textContent = "Show the SQL";
    let pre = document.createElement("pre");
    pre.textContent = r.sql;
    details.appendChild(summary);
    details.appendChild(pre);
    box.appendChild(details);
    list.appendChild(box);
  }
}

start();
