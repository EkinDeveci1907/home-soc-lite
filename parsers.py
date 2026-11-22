# parsers.py
#
# Turns one log line into an event (a dict), or None if the line is not
# something we track. Every event has the same fields:
#
#   ts      local time as written in the log, "YYYY-MM-DD HH:MM:SS"
#   source  which kind of log it came from: auth, web, firewall or macos
#   src_ip  where the traffic came from ("local" for sudo on this machine)
#   user    the account name, if the line has one
#   event   login_success, login_failure, sudo_command, http_<status>,
#           fw_block or fw_allow
#   detail  extra info: login method, URL path, or protocol/port
#   raw     the original line, kept so an analyst can see the evidence
#
# Formats understood:
#   auth      sshd lines from a Linux syslog with ISO timestamps (rsyslog)
#   web       web server access log, Apache / nginx "combined" format
#   firewall  UFW lines (the Ubuntu firewall) from the same syslog
#   macos     lines from macOS `log show` (default or --style syslog),
#             sshd and sudo messages

import re

MONTHS = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
          "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}

# 2026-11-20T02:10:05-04:00 web01 sshd[2211]: ...
ISO_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S*\s+(.*)$")

# 2026-11-20 02:10:05.123456-0400 0x2f1c3  Default ... sshd-session: ...
MACOS_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{4})?\s+(.*)$")

# 203.0.113.7 - - [20/Nov/2026:04:10:02 -0400] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.4"
WEB_LINE = re.compile(r'^(\S+) \S+ (\S+) \[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2}) [^\]]*\] '
                      r'"(\S+) (\S+)[^"]*" (\d{3}) ')

# ... kernel: [12345.678] [UFW BLOCK] IN=eth0 ... SRC=1.2.3.4 ... PROTO=TCP SPT=5555 DPT=22 ...
UFW = re.compile(r"\[UFW (BLOCK|ALLOW)\].*?SRC=(\S+).*?PROTO=(\w+)(?:.*?DPT=(\d+))?")

# sshd and sudo messages. These look the same on Linux and macOS.
SSH_FAILED = re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port")
SSH_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
SUDO_FAILED = re.compile(r"(\S+) : \d+ incorrect password attempts? ;")
SUDO_OK = re.compile(r"(\S+) : TTY=\S+ ; PWD=.* ; USER=(\S+) ; COMMAND=")


def make_event(ts, source, src_ip, user, event, detail, raw):
    return {"ts": ts, "source": source, "src_ip": src_ip, "user": user,
            "event": event, "detail": detail, "raw": raw}


def read_auth_message(message):
    """Look for a login message. Returns (event, user, src_ip, detail) or None.

    Note: sshd also writes "Invalid user bob from ..." just before
    "Failed password for invalid user bob ...". We only count the
    "Failed" line, so one attempt is one event.
    """
    m = SSH_FAILED.search(message)
    if m:
        return "login_failure", m.group(2), m.group(3), "ssh " + m.group(1)

    m = SSH_ACCEPTED.search(message)
    if m:
        return "login_success", m.group(2), m.group(3), "ssh " + m.group(1)

    m = SUDO_FAILED.search(message)
    if m:
        return "login_failure", m.group(1), "local", "sudo"

    m = SUDO_OK.search(message)
    if m:
        return "sudo_command", m.group(1), "local", "sudo as " + m.group(2)

    return None


def parse_auth(line):
    m = ISO_LINE.match(line)
    if not m:
        return None
    found = read_auth_message(m.group(3))
    if not found:
        return None
    event, user, src_ip, detail = found
    ts = m.group(1) + " " + m.group(2)
    return make_event(ts, "auth", src_ip, user, event, detail, line)


def parse_firewall(line):
    m = ISO_LINE.match(line)
    if not m:
        return None
    fw = UFW.search(m.group(3))
    if not fw:
        return None
    action, src_ip, proto, port = fw.groups()
    detail = proto.lower()
    if port:
        detail = detail + "/" + port
    ts = m.group(1) + " " + m.group(2)
    return make_event(ts, "firewall", src_ip, "", "fw_" + action.lower(), detail, line)


def parse_web(line):
    m = WEB_LINE.match(line)
    if not m:
        return None
    src_ip, user, day, month, year, clock, method, path, status = m.groups()
    if month not in MONTHS:
        return None
    if user == "-":
        user = ""
    ts = year + "-" + MONTHS[month] + "-" + day + " " + clock
    return make_event(ts, "web", src_ip, user, "http_" + status, path, line)


def parse_macos(line):
    """A line from `log show`. The time zone offset is dropped and the
    local time is kept, same as the other formats."""
    m = MACOS_LINE.match(line)
    if not m:
        return None
    found = read_auth_message(m.group(5))
    if not found:
        return None
    event, user, src_ip, detail = found
    ts = m.group(1) + " " + m.group(2)
    return make_event(ts, "macos", src_ip, user, event, detail, line)


def parse_line(line):
    """Try each format in turn. Blank lines and # notes return None."""
    line = line.rstrip("\r\n")
    if line.strip() == "" or line.startswith("#"):
        return None
    for parser in [parse_web, parse_firewall, parse_auth, parse_macos]:
        event = parser(line)
        if event is not None:
            return event
    return None
