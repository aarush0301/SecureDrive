"""
analyze_file.py - run the ISL experiments on a REAL file stored by SecureDrive.

  python analyze_file.py --list            show files stored in the app
  python analyze_file.py <file_id>         analyse that file
  python analyze_file.py <file_id> --trials 300

It reads the app's own database, storage folder and master key (read-only),
so every number comes from the files you uploaded through the web app.
"""
import argparse, hashlib, os, random, sqlite3, time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from crypto_utils import (decrypt_bytes, load_master_key, load_signing_key,
                          verify_file_record, sign_file_record, sha256_hex)

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
STORAGE = os.path.join(DATA, "storage")
DB = os.path.join(DATA, "securedrive.db")


def title(t):
    print("\n" + "=" * 66 + f"\n{t}\n" + "=" * 66)


def bit_pct(a, b):
    n = min(len(a), len(b))
    return 100.0 * sum(bin(x ^ y).count("1") for x, y in zip(a[:n], b[:n])) / (n * 8)


def byte_pct(a, b):
    n = min(len(a), len(b))
    return 100.0 * sum(1 for x, y in zip(a[:n], b[:n]) if x != y) / n


def flip(data, i):
    b = bytearray(data); b[i // 8] ^= 1 << (i % 8); return bytes(b)


def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def list_files():
    con = connect()
    rows = con.execute("SELECT f.id, f.orig_name, f.size, u.username, f.uploaded_at "
                       "FROM files f JOIN users u ON u.id = f.owner_id "
                       "ORDER BY f.uploaded_at").fetchall()
    title("FILES STORED IN SECUREDRIVE")
    if not rows:
        print("No files yet. Upload one in the web app first.")
    for r in rows:
        print(f"{r['id']}  {r['orig_name']:<28}{r['size']:>10} B  owner={r['username']}")


def analyse(file_id, trials):
    con = connect()
    row = con.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        print("No such file id. Run:  python analyze_file.py --list")
        return
    master = load_master_key(os.path.join(DATA, "master.key"))
    sign_key = load_signing_key(os.path.join(DATA, "signing.key"))
    with open(os.path.join(STORAGE, file_id + ".enc"), "rb") as f:
        blob = f.read()

    # ---- 1. plaintext vs ciphertext (decrypting with the app's real keys) ----
    title(f"1. STORED FILE: {row['orig_name']}  ({row['size']} bytes)")
    data_key = decrypt_bytes(master, row["wrapped_key"], aad=b"dek:" + file_id.encode())
    t0 = time.perf_counter()
    plain = decrypt_bytes(data_key, blob, aad=file_id.encode())
    dec_ms = (time.perf_counter() - t0) * 1000
    print("On disk (encrypted) :", f"data/storage/{file_id}.enc  ({len(blob)} bytes)")
    print("  nonce  (12 B)    :", blob[:12].hex())
    print("  tag    (16 B)    :", blob[12:28].hex())
    print("  ciphertext first 32 bytes (hex):", blob[28:60].hex())
    print("Decrypted (original):")
    print("  plaintext first 32 bytes (hex):", plain[:32].hex())
    try:
        print("  as text:", plain[:200].decode("utf-8").replace("\n", " "))
    except UnicodeDecodeError:
        print("  (binary file, e.g. image/audio/video, so no readable text)")
    print(f"Decrypt time (real file): {dec_ms:.3f} ms  =  "
          f"{(len(plain)/1048576)/(dec_ms/1000):.1f} MB/s")
    print("Per-file data key is stored only wrapped (encrypted) by the master key.")

    # ---- 2. avalanche on this file's real content and real key ----
    title("2. AVALANCHE / CONFUSION / DIFFUSION (on this file's data and key)")
    sample = plain[:64] if len(plain) >= 64 else plain.ljust(64, b"\0")
    nonce, iv = blob[:12], os.urandom(16)

    def gcm(k, p):
        c = AES.new(k, AES.MODE_GCM, nonce=nonce); return c.encrypt(p)

    def cbc(p):
        return AES.new(data_key, AES.MODE_CBC, iv=iv).encrypt(pad(p, 16))

    def ecb(p):
        return AES.new(data_key, AES.MODE_ECB).encrypt(p)

    results = {k: ([], []) for k in "ABCD"}
    base_g, base_c, blk = gcm(data_key, sample), cbc(sample), sample[:16]
    base_e = ecb(blk)
    for _ in range(trials):
        c = gcm(flip(data_key, random.randrange(256)), sample)
        results["A"][0].append(bit_pct(base_g, c)); results["A"][1].append(byte_pct(base_g, c))
        c = cbc(flip(sample, random.randrange(128)))
        results["B"][0].append(bit_pct(base_c, c)); results["B"][1].append(byte_pct(base_c, c))
        c = ecb(flip(blk, random.randrange(128)))
        results["C"][0].append(bit_pct(base_e, c)); results["C"][1].append(byte_pct(base_e, c))
        c = gcm(data_key, flip(sample, random.randrange(len(sample) * 8)))
        results["D"][0].append(bit_pct(base_g, c)); results["D"][1].append(byte_pct(base_g, c))
    names = {"A": "1 KEY bit flipped, AES-256-GCM (confusion)",
             "B": "1 plaintext bit (block 1), AES-256-CBC",
             "C": "1 plaintext bit, single AES block",
             "D": "1 plaintext bit, AES-256-GCM (stream-like)"}
    print(f"{'Test':<46}{'bit-level %':>12}{'char-level %':>14}")
    for k in "ABCD":
        print(f"{k}. {names[k]:<43}{sum(results[k][0])/trials:>12.2f}{sum(results[k][1])/trials:>14.2f}")
    print("(D is low by design: GCM is counter mode, one plaintext bit flips one ciphertext bit.)")

    # ---- 3. hash of the real file ----
    title("3. HASH OF THIS FILE (SHA-256)")
    t0 = time.perf_counter(); digest = hashlib.sha256(plain).hexdigest()
    hash_ms = (time.perf_counter() - t0) * 1000
    print("Computed now        :", digest)
    print("Stored at upload    :", row["sha256"])
    print("Match               :", digest == row["sha256"], f"(hash time {hash_ms:.3f} ms)")
    m = bytearray(plain); m[0] ^= 1
    d2 = hashlib.sha256(bytes(m)).hexdigest()
    print("\nSecond pre-image test: flip 1 bit of the file")
    print("  new digest        :", d2)
    print(f"  digest bits changed: {bit_pct(bytes.fromhex(digest), bytes.fromhex(d2)):.1f}% (ideal ~50%)")
    print("Pre-image / collision resistance demo: python crypto_lab.py hash")

    # ---- 4. signature on this file ----
    title("4. DIGITAL SIGNATURE OF THIS FILE (Ed25519, made by the app at upload)")
    pub = sign_key.public_key()
    if row["signature"]:
        print("Stored signature    :", row["signature"][:64] + "...")
        print(f"Signing time at upload: {row['sign_ms']:.3f} ms" if row["sign_ms"] is not None else "")
        t0 = time.perf_counter()
        ok = verify_file_record(pub, file_id, row["sha256"], row["signature"])
        v_ms = (time.perf_counter() - t0) * 1000
        print(f"Verification now    : {'VALID' if ok else 'INVALID'}  ({v_ms:.3f} ms)")
        bad = verify_file_record(pub, file_id, row["sha256"][:-1] + ("0" if row["sha256"][-1] != "0" else "1"),
                                 row["signature"])
        print("If the hash is altered:", "VALID (bad!)" if bad else "INVALID (tamper detected)")
    else:
        print("This file was uploaded before signing was added. Re-upload it to get a signature.")

    # ---- 5. upload-time numbers recorded by the app ----
    title("5. PERFORMANCE RECORDED BY THE APP FOR THIS FILE")
    mb = row["size"] / 1048576
    if row["enc_ms"] is not None:
        print(f"Encrypt at upload   : {row['enc_ms']:.3f} ms  =  {mb/(row['enc_ms']/1000):.1f} MB/s")
    print(f"Decrypt (just now)  : {dec_ms:.3f} ms  =  {mb/(dec_ms/1000):.1f} MB/s")
    print("Full tables with graphs: python crypto_lab.py perf, and the audit page in the app")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file_id", nargs="?")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--trials", type=int, default=300)
    a = ap.parse_args()
    if a.list or not a.file_id:
        list_files()
    else:
        analyse(a.file_id, a.trials)