"""Final automated security test: 15 checks against a running SecureDrive server.

Run it against a FRESH data folder (see the instructions), with the server running:
  python test_security.py
"""
import argparse
import io
import os
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()          # we use a self-signed certificate

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="https://127.0.0.1:5443", help="server address")
a = ap.parse_args()
URL = a.url.rstrip("/")
HERE = os.path.dirname(os.path.abspath(__file__))
results = []


def check(name, passed):
    results.append(bool(passed))
    print(("PASS  " if passed else "FAIL  ") + name)


def token(s, path):
    page = s.get(URL + path, verify=False).text
    return re.search(r'name="csrf" value="(\w+)"', page).group(1)


def session(user, pw, register=True):
    """Return (session, response of the login attempt)."""
    s = requests.Session()
    if register:
        s.post(URL + "/register", data={"username": user, "password": pw,
                                        "csrf": token(s, "/register")}, verify=False)
    r = s.post(URL + "/login", data={"username": user, "password": pw,
                                     "csrf": token(s, "/login")}, verify=False)
    return s, r


def upload(s, name, data):
    return s.post(URL + "/upload", data={"csrf": token(s, "/")},
                  files={"file": (name, io.BytesIO(data))}, verify=False)


def first_file_id(s):
    m = re.search(r"/download/(\w{32})", s.get(URL + "/", verify=False).text)
    return m.group(1) if m else None


suffix = os.urandom(3).hex()
alice, bob = f"alice_{suffix}", f"bob_{suffix}"
secret = b"TOP SECRET CONTENT " * 1000

# ----- authentication -----
sa, r = session(alice, "alicepass123")
check("Authentication: a valid login succeeds", "My files" in r.text)
sb, _ = session(bob, "bobpass12345")
_, r = session(alice, "wrong-password", register=False)
check("Authentication: a wrong password is rejected", "Invalid" in r.text)

# ----- confidentiality -----
upload(sa, "plan.txt", secret)
fid = first_file_id(sa)
check("Upload: the file is stored and listed", fid is not None)
stored = os.path.join(HERE, "data", "storage", f"{fid}.enc")
blob = open(stored, "rb").read() if fid and os.path.exists(stored) else b"TOP SECRET"
check("Confidentiality: the plain text is NOT in the stored file", b"TOP SECRET" not in blob)
r = sa.get(f"{URL}/download/{fid}", verify=False)
check("Download: the file comes back identical", r.content == secret)

# ----- access control -----
check("Access control: another user cannot download it",
      sb.get(f"{URL}/download/{fid}", verify=False).status_code == 404)
sa.post(f"{URL}/share/{fid}", data={"csrf": token(sa, "/"), "target": bob}, verify=False)
check("Sharing: the shared user can now download it",
      sb.get(f"{URL}/download/{fid}", verify=False).content == secret)
sb.post(f"{URL}/delete/{fid}", data={"csrf": token(sb, "/")}, verify=False)
check("Access control: a shared (non-owner) user cannot delete it",
      sa.get(f"{URL}/download/{fid}", verify=False).status_code == 200)

# ----- integrity -----
data = bytearray(open(stored, "rb").read())
data[60] ^= 1                                   # flip one bit of the stored file
open(stored, "wb").write(bytes(data))
r = sa.get(f"{URL}/download/{fid}", verify=False)
check("Integrity: a changed file is detected and not released (422)",
      r.status_code == 422 and "integrity" in r.text.lower())

# ----- availability / input checks -----
r = upload(sa, "evil.exe", b"MZ")
check("Validation: a disallowed file type is rejected", "not allowed" in r.text)
try:
    r = upload(sa, "huge.mp4", os.urandom(106 * 1024 * 1024))
    check("Availability: an oversize upload is refused (413)", r.status_code == 413)
except requests.exceptions.ConnectionError:
    check("Availability: an oversize upload is refused (connection closed)", True)
r = sa.post(URL + "/delete/xyz", data={}, verify=False)
check("CSRF: a request without a token is refused (400)", r.status_code == 400)
for _ in range(5):
    session(bob, "nope-nope-nope", register=False)
_, r = session(bob, "bobpass12345", register=False)
check("Availability: the account is locked after 5 failed logins", "Too many" in r.text)

# ----- accountability -----
page = sa.get(URL + "/audit", verify=False).text
check("Accountability: the audit log lists the events",
      "INTEGRITY_FAIL" in page and "FILE_UPLOAD" in page and "FILE_SHARE" in page)
check("Accountability: the audit chain verifies", "verified" in page)

print(f"\n{sum(results)} of {len(results)} checks passed")
sys.exit(0 if all(results) else 1)