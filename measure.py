# measure.py
#
# Measures what Home SOC Lite costs to run, so the numbers in the README
# can be checked on any machine:
#   - peak memory of the biggest process: the demo, the export, and the
#     dashboard server answering 50 page loads
#   - disk used by the project folder and by its .venv
#
# Run it inside the venv:  python3 measure.py
# (It runs the demo, so it reloads the SYNTHETIC sample logs into soc.db.)

import os
import platform
import resource
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = "8799"


def megabytes_from_maxrss(value):
    # ru_maxrss is in bytes on macOS but in kilobytes on Linux
    if sys.platform == "darwin":
        return value / 1024 / 1024
    return value / 1024


def folder_size_mb(path, skip=None):
    total = 0
    for root, dirs, files in os.walk(path):
        if skip in dirs:
            dirs.remove(skip)
        for name in files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                total += os.path.getsize(full)
    return total / 1024 / 1024


def run(args):
    subprocess.run([sys.executable] + args, cwd=HERE, check=True, stdout=subprocess.DEVNULL)


def fetch(path):
    with urllib.request.urlopen("http://127.0.0.1:" + PORT + path, timeout=5) as response:
        return response.read()


def measure_server():
    env = dict(os.environ)
    env["PORT"] = PORT
    server = subprocess.Popen([sys.executable, "app.py"], cwd=HERE, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for i in range(60):            # wait up to 15 s for it to start
            try:
                fetch("/api/health")
                break
            except OSError:
                time.sleep(0.25)
        for i in range(50):            # 50 full page loads
            fetch("/")
            fetch("/app.js")
            fetch("/data.json")
    finally:
        server.terminate()
        server.wait()


run(["soc.py", "demo"])
run(["soc.py", "export", "--out", os.path.join(HERE, "output", "measure_export")])
measure_server()

peak = megabytes_from_maxrss(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
project = folder_size_mb(HERE, skip=".venv")
venv = folder_size_mb(os.path.join(HERE, ".venv")) if os.path.isdir(os.path.join(HERE, ".venv")) else 0

print("Machine:          ", platform.system(), platform.machine(), "| Python", platform.python_version())
print("Peak memory:      ", round(peak, 1), "MB (largest single process)")
print("Project folder:   ", round(project, 1), "MB (without .venv)")
print(".venv:            ", round(venv, 1), "MB")
print("Total disk:       ", round(project + venv, 1), "MB")
