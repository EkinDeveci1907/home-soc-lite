# Tests for parsers.py: one line in, one event (or None) out.
#
# Run from the project folder:  python3 -m unittest discover -s tests -v

import unittest

from parsers import parse_line, parse_macos


class TestParsers(unittest.TestCase):

    def test_ssh_failure(self):
        e = parse_line("2026-11-20T02:10:05-04:00 web01 sshd[2211]: Failed password for root "
                       "from 203.0.113.45 port 51122 ssh2")
        self.assertEqual(e["ts"], "2026-11-20 02:10:05")
        self.assertEqual(e["event"], "login_failure")
        self.assertEqual(e["user"], "root")
        self.assertEqual(e["src_ip"], "203.0.113.45")
        self.assertEqual(e["source"], "auth")

    def test_ssh_failure_invalid_user(self):
        e = parse_line("2026-11-20T03:00:00-04:00 web01 sshd[1]: Failed password for invalid user "
                       "oracle from 203.0.113.99 port 4000 ssh2")
        self.assertEqual(e["user"], "oracle")

    def test_invalid_user_line_is_not_counted(self):
        # sshd writes this AND a "Failed password" line for the same attempt
        e = parse_line("2026-11-20T03:00:00-04:00 web01 sshd[1]: Invalid user oracle "
                       "from 203.0.113.99 port 4000")
        self.assertIsNone(e)

    def test_ssh_success(self):
        e = parse_line("2026-11-20T09:15:12-04:00 web01 sshd[1]: Accepted publickey for admin "
                       "from 10.0.0.15 port 5555 ssh2")
        self.assertEqual(e["event"], "login_success")
        self.assertEqual(e["detail"], "ssh publickey")

    def test_web_404(self):
        e = parse_line('192.0.2.200 - - [20/Nov/2026:04:10:02 -0400] "GET /.env HTTP/1.1" '
                       '404 153 "-" "zgrab"')
        self.assertEqual(e["ts"], "2026-11-20 04:10:02")
        self.assertEqual(e["event"], "http_404")
        self.assertEqual(e["detail"], "/.env")
        self.assertEqual(e["user"], "")
        self.assertEqual(e["source"], "web")

    def test_firewall_block(self):
        e = parse_line("2026-11-20T22:05:00-04:00 fw01 kernel: [86400.1] [UFW BLOCK] IN=eth0 OUT= "
                       "SRC=203.0.113.250 DST=10.0.0.5 LEN=44 PROTO=TCP SPT=40000 DPT=3389 SYN")
        self.assertEqual(e["event"], "fw_block")
        self.assertEqual(e["detail"], "tcp/3389")
        self.assertEqual(e["src_ip"], "203.0.113.250")

    def test_macos_default_style(self):
        e = parse_macos("2026-11-20 08:15:02.123456-0400 0x2f1c3    Default     0x0     8812   0    "
                        "sshd-session: Failed password for invalid user test from 192.168.1.50 port 52314 ssh2")
        self.assertEqual(e["ts"], "2026-11-20 08:15:02")   # fraction and offset dropped
        self.assertEqual(e["event"], "login_failure")
        self.assertEqual(e["user"], "test")
        self.assertEqual(e["source"], "macos")

    def test_macos_syslog_style(self):
        e = parse_line("2026-11-20 08:15:09.004112-0400  localhost sshd-session[8813]: Accepted "
                       "publickey for ekim from 192.168.1.20 port 50022 ssh2")
        self.assertEqual(e["event"], "login_success")
        self.assertEqual(e["source"], "macos")

    def test_sudo_failure(self):
        e = parse_macos("2026-11-20 08:20:00.000001-0400 0x1a2b Default 0x0 900 0 sudo:     ekim : "
                        "1 incorrect password attempt ; TTY=ttys001 ; PWD=/Users/ekim ; USER=root ; COMMAND=/usr/bin/true")
        self.assertEqual(e["event"], "login_failure")
        self.assertEqual(e["src_ip"], "local")
        self.assertEqual(e["user"], "ekim")

    def test_lines_we_skip(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("# a note"))
        self.assertIsNone(parse_line("Timestamp                       Thread     Type"))
        self.assertIsNone(parse_line("2026-11-20 08:21:00.000001-0400 0x77 Default 0x0 0 0 "
                                     "kernel: (AppleACPIPlatform) an unrelated message"))


if __name__ == "__main__":
    unittest.main()
