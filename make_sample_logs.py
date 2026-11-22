# make_sample_logs.py
#
# Makes the SYNTHETIC / MOCK logs in sample_logs/ for one day
# (2026-11-20) on a fictional small company server:
#   auth.log         sshd and sudo lines
#   web_access.log   web server access log
#   firewall.log     UFW firewall lines
#
# None of it is real traffic. Outside IPs come from the documentation
# ranges 192.0.2.x, 198.51.100.x and 203.0.113.x (RFC 5737), which are
# never used on the real internet. Inside IPs are private 10.x addresses.
#
# Normal background activity is random (with a fixed seed, so the files
# are the same every time). The attacks are planted by hand below, along
# with some "near misses" that must NOT raise an alert.
#
# Run:  python3 make_sample_logs.py

import random
from datetime import datetime, timedelta

random.seed(20261120)

DAY = "2026-11-20"
NOTE = ("# SYNTHETIC / MOCK DATA - made by make_sample_logs.py. Not real systems, "
        "people or traffic. IPs are from documentation and private ranges.\n")

auth = []      # (time, line) pairs, sorted before writing
web = []
firewall = []


def at(clock):
    return datetime.strptime(DAY + " " + clock, "%Y-%m-%d %H:%M:%S")


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S") + "-04:00"


def random_time(start, end):
    a = at(start)
    b = at(end)
    return a + timedelta(seconds=random.randint(0, int((b - a).total_seconds())))


# ---------- line writers ----------

def ssh_fail(t, user, ip, invalid=False):
    pid = random.randint(2000, 9000)
    port = random.randint(30000, 65000)
    if invalid:
        # real sshd writes this line first for unknown users
        auth.append((t, iso(t) + " web01 sshd[" + str(pid) + "]: Invalid user " + user
                     + " from " + ip + " port " + str(port)))
        user_text = "invalid user " + user
    else:
        user_text = user
    auth.append((t, iso(t) + " web01 sshd[" + str(pid) + "]: Failed password for " + user_text
                 + " from " + ip + " port " + str(port) + " ssh2"))


def ssh_ok(t, user, ip, method="publickey"):
    pid = random.randint(2000, 9000)
    port = random.randint(30000, 65000)
    auth.append((t, iso(t) + " web01 sshd[" + str(pid) + "]: Accepted " + method + " for " + user
                 + " from " + ip + " port " + str(port) + " ssh2"))


def sudo(t, user, command):
    auth.append((t, iso(t) + " web01 sudo:    " + user + " : TTY=pts/0 ; PWD=/home/" + user
                 + " ; USER=root ; COMMAND=" + command))


def http(t, ip, path, status, agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)"):
    stamp = t.strftime("%d/%b/%Y:%H:%M:%S") + " -0400"
    size = random.randint(300, 9000) if status == 200 else random.randint(120, 400)
    web.append((t, ip + ' - - [' + stamp + '] "GET ' + path + ' HTTP/1.1" ' + str(status) + " "
                + str(size) + ' "-" "' + agent + '"'))


def fw(t, action, ip, port, proto="TCP"):
    uptime = 86400 + (t - at("00:00:00")).total_seconds() + random.random()
    firewall.append((t, iso(t) + " fw01 kernel: [" + format(uptime, ".6f") + "] [UFW " + action
                     + "] IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC=" + ip
                     + " DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=" + str(random.randint(40, 250))
                     + " ID=" + str(random.randint(1000, 65000)) + " PROTO=" + proto + " SPT="
                     + str(random.randint(1024, 65000)) + " DPT=" + str(port)
                     + " WINDOW=1024 RES=0x00 SYN URGP=0"))


# ---------- normal background activity ----------

STAFF = ["jsmith", "apatel", "mchen", "lnguyen", "rroy", "kmurphy", "sali", "tclarke",
         "dsingh", "eokafor", "gfraser", "hsilva", "ikaya", "jreid", "ogrant"]
staff_ip = {}
for i, name in enumerate(STAFF):
    staff_ip[name] = "10.0.1." + str(11 + i)

# staff log in 2-3 times during the working day, sometimes after a typo
for name in STAFF:
    for i in range(random.randint(2, 3)):
        t = random_time("08:00:00", "17:30:00")
        if random.random() < 0.25:
            ssh_fail(t - timedelta(seconds=random.randint(20, 90)), name, staff_ip[name])
        ssh_ok(t, name, staff_ip[name], random.choice(["publickey", "password"]))

# admins working normal hours (no alert expected)
ssh_ok(at("09:15:12"), "admin", "10.0.0.15", "password")
sudo(at("09:16:40"), "admin", "/usr/bin/apt update")
ssh_ok(at("10:45:03"), "root", "10.0.0.8")
ssh_ok(at("12:00:05"), "svc_backup", "10.0.0.20")
ssh_ok(at("13:30:40"), "admin", "10.0.0.15", "password")
sudo(at("13:31:02"), "admin", "/usr/bin/systemctl restart nginx")

SITE = ["/", "/index.html", "/about", "/products", "/products/widgets", "/contact",
        "/css/site.css", "/js/app.js", "/img/logo.png", "/blog", "/blog/winter-sale",
        "/login", "/support", "/careers"]
VISITORS = []
for i in range(8):
    VISITORS.append("10.0.1." + str(11 + i))
for i in range(12):
    VISITORS.append(random.choice(["192.0.2.", "198.51.100.", "203.0.113."]) + str(random.randint(60, 76)))

for i in range(190):
    t = random_time("07:00:00", "23:00:00")
    status = random.choice([200] * 12 + [304, 304, 301])
    http(t, random.choice(VISITORS), random.choice(SITE), status)
for i in range(6):   # the odd broken link
    http(random_time("08:00:00", "22:00:00"), random.choice(VISITORS), "/old-page", 404)

for i in range(25):  # firewall: normal allowed traffic
    fw(random_time("07:00:00", "23:00:00"), "ALLOW", random.choice(VISITORS), 443)

for i in range(26):  # firewall: everyday internet noise, 1-2 blocked ports per IP
    ip = random.choice(["192.0.2.", "198.51.100.", "203.0.113."]) + str(random.randint(100, 140))
    t = random_time("00:00:00", "23:59:00")
    for port in random.sample([23, 445, 3389, 8080, 5900, 1433, 6379], random.randint(1, 2)):
        fw(t, "BLOCK", ip, port)
        t = t + timedelta(seconds=random.randint(1, 20))


# ---------- planted attacks: these MUST raise alerts ----------

# R1 brute force x3
for i in range(12):   # BF-1: root, 12 tries, one every 15 s
    ssh_fail(at("02:10:05") + timedelta(seconds=15 * i), "root", "203.0.113.45")
for i in range(9):    # BF-2: svc_backup, 9 tries, then the password works
    ssh_fail(at("01:50:00") + timedelta(seconds=25 * i), "svc_backup", "198.51.100.77")
ssh_ok(at("01:55:40"), "svc_backup", "198.51.100.77", "password")   # also R3, off-hours
for i in range(6):    # BF-3: a user name that does not exist on this server
    ssh_fail(at("11:05:00") + timedelta(seconds=20 * i), "ubuntu", "192.0.2.10", invalid=True)

# R2 password spraying x2 (slow on purpose, so they are not brute force)
SPRAY_1 = ["admin", "test", "guest", "oracle", "postgres", "ubuntu", "user", "support",
           "backup", "ftp", "mysql", "deploy"]
for i, name in enumerate(SPRAY_1):   # SP-1: 12 users, one try every 100 s
    ssh_fail(at("03:00:00") + timedelta(seconds=100 * i), name, "203.0.113.99",
             invalid=name not in ("admin",))
for i, name in enumerate(STAFF[:9]):  # SP-2: 9 real staff names, one try every 150 s
    ssh_fail(at("15:40:00") + timedelta(seconds=150 * i), name, "198.51.100.23")

# R3 off-hours admin login x4 (BF-2's svc_backup login above is one of them)
ssh_ok(at("23:12:09"), "root", "10.0.0.8")
ssh_ok(at("05:40:22"), "admin", "10.0.0.15", "password")
ssh_ok(at("19:00:00"), "admin", "10.0.0.15", "password")   # exactly 19:00 counts

# R4 scanning x3
WORDLIST = ["/admin", "/admin.php", "/wp-login.php", "/wp-admin/", "/.env", "/.git/config",
            "/phpmyadmin/", "/backup.zip", "/config.php", "/server-status", "/login.php",
            "/administrator/", "/db.sql", "/.aws/credentials", "/api/v1/users",
            "/cgi-bin/test.cgi", "/xmlrpc.php", "/shell.php", "/test.php", "/console",
            "/actuator/env", "/.DS_Store", "/old/", "/backup/", "/web.config", "/install.php",
            "/setup.php", "/debug", "/info.php", "/phpinfo.php", "/.htaccess", "/.svn/entries",
            "/admin/login", "/manager/html", "/solr/", "/jenkins/", "/owa/", "/remote/login",
            "/HNAP1/", "/boaform/admin/formLogin"]
SCANNER = "Mozilla/5.0 zgrab/0.x"
http(at("04:09:58"), "192.0.2.200", "/robots.txt", 200, SCANNER)
for i, path in enumerate(WORDLIST):          # SC-1: 40 paths, one every 2 s
    http(at("04:10:00") + timedelta(seconds=2 * i), "192.0.2.200", path, 404, SCANNER)
for i, path in enumerate(WORDLIST[:18]):     # SC-3: same IP as BF-1, scouting first
    http(at("01:58:04") + timedelta(seconds=3 * i), "203.0.113.45", path, 404, SCANNER)
PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433,
         1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 9200, 27017]
for i, port in enumerate(PORTS):             # SC-2: port scan, 30 ports, one every 1.3 s
    fw(at("22:05:00") + timedelta(seconds=1.3 * i), "BLOCK", "203.0.113.250", port)


# ---------- near misses: these must NOT raise alerts ----------

for i in range(4):    # 4 failures in 3 min: one short of brute force
    ssh_fail(at("14:00:00") + timedelta(seconds=45 * i), "root", "203.0.113.200")
for s in [0, 90, 180, 270, 361]:   # 5 failures, but spread over just over 6 min
    ssh_fail(at("15:10:00") + timedelta(seconds=s), "admin", "198.51.100.150")
for i, name in enumerate(["admin", "test", "guest", "oracle", "ftp", "pi", "web"]):
    ssh_fail(at("20:10:00") + timedelta(seconds=120 * i), name, "192.0.2.55", invalid=name != "admin")
ssh_ok(at("07:00:00"), "admin", "10.0.0.15", "password")    # 07:00 is office hours
ssh_ok(at("18:59:59"), "admin", "10.0.0.15", "password")    # still office hours
ssh_ok(at("02:00:31"), "jsmith", staff_ip["jsmith"])        # night login, but not an admin
for i in range(20):   # the same missing favicon 20 times: many 404s, one URL
    http(at("09:30:00") + timedelta(seconds=8 * i), "10.0.1.23", "/favicon.ico", 404)
for i, path in enumerate(["/blog/2019", "/blog/2020", "/team/old", "/pdf/catalog-2021.pdf",
                          "/promo", "/promo/summer", "/legacy", "/store", "/store/cart",
                          "/docs/v1", "/press", "/events"]):
    http(at("16:20:00") + timedelta(seconds=8 * i), "198.51.100.9", path, 404, "LinkChecker/10.0")


# ---------- write the files ----------

def write_log(path, rows):
    rows.sort(key=lambda row: row[0])
    with open(path, "w") as f:
        f.write(NOTE)
        for t, line in rows:
            f.write(line + "\n")
    return len(rows)


total = 0
total += write_log("sample_logs/auth.log", auth)
total += write_log("sample_logs/web_access.log", web)
total += write_log("sample_logs/firewall.log", firewall)
print("Wrote", total, "log lines to sample_logs/")
