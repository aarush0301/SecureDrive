"""Real transfer speed and multi-user test, run against a live SecureDrive server.

Start the server first (python app.py), then in a second terminal:
  python load_test.py
  python load_test.py --clients 10 --size-mb 5
"""
import argparse
import csv
import io
import os
import re
import statistics
import threading
import time

import requests
import urllib3

urllib3.disable_warnings()          # we use a self-signed certificate

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="https://127.0.0.1:5443", help="server address")
ap.add_argument("--clients", type=int, default=10, help="users acting at the same time")
ap.add_argument("--size-mb", type=float, default=5, help="file size each of those users sends")
a = ap.parse_args()
URL = a.url.rstrip("/")


# ---------- helpers ----------
def token(s, path):
    """Read the hidden CSRF token from a page."""
    page = s.get(URL + path, verify=False).text
    return re.search(r'name="csrf" value="(\w+)"', page).group(1)


def new_user(tag):
    """Register and log in a brand-new user. Returns a logged-in session."""
    s = requests.Session()
    name = f"l{os.urandom(3).hex()}{tag}"       # usernames may be at most 20 characters
    assert len(name) <= 20, name
    pw = "loadtest123"
    s.post(URL + "/register", data={"username": name, "password": pw,
                                    "csrf": token(s, "/register")}, verify=False)
    s.post(URL + "/login", data={"username": name, "password": pw,
                                 "csrf": token(s, "/login")}, verify=False)
    return s


def upload(s, data, filename="load.mp4"):
    """Upload a file. Returns (seconds taken, response)."""
    t = token(s, "/")
    start = time.perf_counter()
    r = s.post(URL + "/upload", data={"csrf": t},
               files={"file": (filename, io.BytesIO(data))}, verify=False)
    return time.perf_counter() - start, r


def only_file_id(s):
    """A fresh user has one file, so the first download link is the one we want."""
    return re.findall(r"/download/(\w{32})", s.get(URL + "/", verify=False).text)[0]


def download(s, file_id):
    start = time.perf_counter()
    r = s.get(f"{URL}/download/{file_id}", verify=False)
    return time.perf_counter() - start, r


# ---------- PART 1: one user, real transfers ----------
print("PART 1 - one user, real uploads and downloads through the app")
REPEATS = 3
upload(new_user("warm"), os.urandom(1024 * 1024))          # warm-up, not counted
print(f"{'Size':>6} | {'Upload s':>8} | {'Download s':>10} | {'Up MB/s':>8} | {'Down MB/s':>9} | Correct")
print("-" * 66)
rows = []
for mb in [1, 10, 50, 100]:
    data = os.urandom(mb * 1024 * 1024)
    ups, downs, all_ok = [], [], True
    for i in range(REPEATS):
        s = new_user(f"solo{mb}_{i}")
        up, r = upload(s, data)
        dn, d = download(s, only_file_id(s))
        all_ok = all_ok and r.ok and d.status_code == 200 and d.content == data
        ups.append(up)
        downs.append(dn)
    up, dn = statistics.mean(ups), statistics.mean(downs)
    rows.append([mb, round(up, 2), round(dn, 2), round(mb / up, 1), round(mb / dn, 1)])
    print(f"{mb:>4}MB | {up:>8.2f} | {dn:>10.2f} | {mb/up:>8.1f} | {mb/dn:>9.1f} | {'yes' if all_ok else 'NO'}")
with open("transfer_results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["size_mb", "upload_s", "download_s", "upload_MB_per_s", "download_MB_per_s"])
    w.writerows(rows)
print(f"(average of {REPEATS} runs each; saved to transfer_results.csv)")

# ---------- PART 2: many users at the same moment ----------
print(f"\nPART 2 - {a.clients} users at the same time, {a.size_mb} MB each")
payload = os.urandom(int(a.size_mb * 1024 * 1024))
sessions = [new_user(f"c{i}") for i in range(a.clients)]   # set-up, not timed
barrier = threading.Barrier(a.clients)                      # everyone starts together
results, lock = [], threading.Lock()


def worker(s):
    try:
        barrier.wait()
        up, r = upload(s, payload)
        dn, d = download(s, only_file_id(s))
        ok = r.ok and d.status_code == 200 and d.content == payload
    except Exception:
        up = dn = 0
        ok = False
    with lock:
        results.append((ok, up, dn))


t0 = time.perf_counter()
threads = [threading.Thread(target=worker, args=(s,)) for s in sessions]
for t in threads:
    t.start()
for t in threads:
    t.join()
wall = time.perf_counter() - t0

good = [r for r in results if r[0]]
print(f"Users who finished correctly: {len(good)} of {a.clients}")
if good:
    ups, downs = [r[1] for r in good], [r[2] for r in good]
    print(f"Upload   average {statistics.mean(ups):.2f} s, slowest {max(ups):.2f} s")
    print(f"Download average {statistics.mean(downs):.2f} s, slowest {max(downs):.2f} s")
    print(f"Total time for everyone: {wall:.1f} s")
    print(f"Combined throughput: {len(good) * a.size_mb * 2 / wall:.1f} MB/s (uploads + downloads)")

# ---------- PART 3: protection checks (availability) ----------
print("\nPART 3 - protection checks")


def check(name, passed):
    print(("PASS  " if passed else "FAIL  ") + name)


s = new_user("chk")
_, r = upload(s, b"MZ", "evil.exe")
check("a .exe file is rejected", "not allowed" in r.text)

r = requests.get(URL + "/", verify=False, allow_redirects=False)
check("the home page needs a login (redirects)", r.status_code == 302)

r = s.post(URL + "/delete/abc", data={}, verify=False)
check("a request without a CSRF token is refused (400)", r.status_code == 400)

try:
    _, r = upload(s, os.urandom(106 * 1024 * 1024), "huge.mp4")
    check("a file over the size limit is refused (413)", r.status_code == 413)
except requests.exceptions.ConnectionError:
    check("a file over the size limit is refused (connection closed)", True)