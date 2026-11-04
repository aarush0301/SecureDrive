"""
crypto_lab.py - ISL project: measurable crypto experiments for SecureDrive.

Usage:
  python crypto_lab.py show --text "Hello professor"
  python crypto_lab.py show --file photo.png
  python crypto_lab.py avalanche
  python crypto_lab.py hash
  python crypto_lab.py sign
  python crypto_lab.py perf
  python crypto_lab.py all
"""
import argparse, csv, hashlib, os, random, time, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# ---------- small helpers ----------
def bit_diff_percent(a: bytes, b: bytes) -> float:
    n = min(len(a), len(b))
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a[:n], b[:n]))
    return 100.0 * diff / (n * 8)

def byte_diff_percent(a: bytes, b: bytes) -> float:
    n = min(len(a), len(b))
    return 100.0 * sum(1 for x, y in zip(a[:n], b[:n]) if x != y) / n

def flip_bit(data: bytes, bit_index: int) -> bytes:
    b = bytearray(data)
    b[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(b)

def gcm_encrypt(key, nonce, data):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(data)
    return ct, tag

def gcm_decrypt(key, nonce, ct, tag):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)

def title(t):
    print("\n" + "=" * 64 + f"\n{t}\n" + "=" * 64)

# ---------- 1. show plaintext / ciphertext ----------
def cmd_show(args):
    title("TEXT / IMAGE ENCRYPT-DECRYPT (AES-256-GCM)")
    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
        label = f"file {os.path.basename(args.file)} ({len(data)} bytes)"
    else:
        data = (args.text or "Hello professor, this is SecureDrive").encode()
        label = f"text ({len(data)} bytes)"
    key, nonce = get_random_bytes(32), get_random_bytes(12)
    gcm_encrypt(key, nonce, b"warm-up")  # first call is slow (loading); do it before timing

    t0 = time.perf_counter(); ct, tag = gcm_encrypt(key, nonce, data); t_enc = time.perf_counter() - t0
    t0 = time.perf_counter(); back = gcm_decrypt(key, nonce, ct, tag); t_dec = time.perf_counter() - t0

    print("Input     :", label)
    print("Key (hex) :", key.hex())
    print("Nonce     :", nonce.hex())
    if args.file:
        print("Plaintext first 32 bytes (hex):", data[:32].hex())
        print("Cipher    first 32 bytes (hex):", ct[:32].hex())
        out = args.file + ".enc"
        with open(out, "wb") as f:
            f.write(nonce + tag + ct)
        print("Encrypted file saved as:", out, "(cannot be opened as an image)")
    else:
        print("Plaintext :", data.decode())
        print("Ciphertext (hex):", ct.hex())
        print("Ciphertext (b64):", base64.b64encode(ct).decode())
    print("Auth tag  :", tag.hex())
    print("Decrypted OK and identical to original:", back == data)
    print(f"Encrypt time {t_enc*1000:.3f} ms | Decrypt time {t_dec*1000:.3f} ms")

# ---------- 2. avalanche / confusion / diffusion ----------
def cmd_avalanche(args):
    title("AVALANCHE, CONFUSION AND DIFFUSION")
    trials = args.trials
    plain = os.urandom(64)
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    iv = get_random_bytes(16)

    # A. key-bit flip (confusion), AES-GCM with fixed nonce
    base_ct, _ = gcm_encrypt(key, nonce, plain)
    bits, chars = [], []
    for _ in range(trials):
        k2 = flip_bit(key, random.randrange(256))
        ct2, _ = gcm_encrypt(k2, nonce, plain)
        bits.append(bit_diff_percent(base_ct, ct2)); chars.append(byte_diff_percent(base_ct, ct2))
    a_bit, a_chr = sum(bits) / trials, sum(chars) / trials

    # B. plaintext-bit flip, AES-CBC (diffusion)
    def cbc(k, p):
        return AES.new(k, AES.MODE_CBC, iv=iv).encrypt(pad(p, 16))
    base_cbc = cbc(key, plain)
    bits, chars = [], []
    for _ in range(trials):
        p2 = flip_bit(plain, random.randrange(128))  # a bit inside the FIRST 16-byte block
        c2 = cbc(key, p2)
        bits.append(bit_diff_percent(base_cbc, c2)); chars.append(byte_diff_percent(base_cbc, c2))
    b_bit, b_chr = sum(bits) / trials, sum(chars) / trials

    # C. single AES block (ECB, 16 bytes): pure block-cipher diffusion
    block = os.urandom(16)
    ecb = lambda p: AES.new(key, AES.MODE_ECB).encrypt(p)
    base_ecb = ecb(block)
    bits, chars = [], []
    for _ in range(trials):
        c2 = ecb(flip_bit(block, random.randrange(128)))
        bits.append(bit_diff_percent(base_ecb, c2)); chars.append(byte_diff_percent(base_ecb, c2))
    c_bit, c_chr = sum(bits) / trials, sum(chars) / trials

    # D. plaintext-bit flip, AES-GCM (why it is NOT 50%)
    bits, chars = [], []
    for _ in range(trials):
        p2 = flip_bit(plain, random.randrange(len(plain) * 8))
        c2, _ = gcm_encrypt(key, nonce, p2)
        bits.append(bit_diff_percent(base_ct, c2)); chars.append(byte_diff_percent(base_ct, c2))
    d_bit, d_chr = sum(bits) / trials, sum(chars) / trials

    print(f"Trials per test: {trials}   (ideal: ~50% bit-level, ~100% char-level)\n")
    print(f"{'Test':<52}{'bit-level %':>12}{'char-level %':>14}")
    rows = [
        ("A. 1 KEY bit flipped, AES-256-GCM  (confusion)", a_bit, a_chr),
        ("B. 1 plaintext bit (block 1), AES-256-CBC", b_bit, b_chr),
        ("C. 1 plaintext bit, single AES block (ECB)", c_bit, c_chr),
        ("D. 1 plaintext bit, AES-256-GCM (stream-like)", d_bit, d_chr),
    ]
    for r in rows:
        print(f"{r[0]:<52}{r[1]:>12.2f}{r[2]:>14.2f}")
    print("\nReading the table:")
    print(" - A shows CONFUSION: changing one key bit changes about half the ciphertext bits.")
    print(" - B and C show DIFFUSION: one plaintext bit changes that whole block and, in CBC, every block after it.")
    print(" - D is low on purpose: GCM uses counter mode, so one plaintext bit flips exactly one")
    print("   ciphertext bit. That is a property of the MODE, not a weakness of AES.")
    print(" - Char-level is about 99.6% (not exactly 100%) because a random byte equals the old byte")
    print("   by chance 1 time in 256.")
    return rows

# ---------- 3. hash lab ----------
def trunc_int(data: bytes, bits: int) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big") >> (256 - bits)

def cmd_hash(args):
    title("HASH LAB (SHA-256)")
    msg = (args.text or "SecureDrive report").encode()
    d = hashlib.sha256(msg).hexdigest()
    print("Message :", msg.decode())
    print("SHA-256 :", d, f"({len(d)*4} bits)")

    print("\n[1] PRE-IMAGE resistance: given a digest, finding ANY input is infeasible")
    print("    Brute-force on a TRUNCATED hash (first n bits only) to show how cost grows:")
    print(f"    {'bits':>5}{'avg tries':>12}{'avg time (s)':>14}   expected ~2^n")
    for n, runs in ((8, 30), (12, 30), (16, 20), (20, 5)):
        total_tries, t0 = 0, time.perf_counter()
        for _ in range(runs):
            target = trunc_int(os.urandom(8), n)
            i = 0
            while trunc_int(b"guess-%d" % i, n) != target:
                i += 1
            total_tries += i + 1
        print(f"    {n:>5}{total_tries/runs:>12.0f}{(time.perf_counter()-t0)/runs:>14.4f}   2^{n} = {2**n}")
    print("    Every +1 bit doubles the work. Full SHA-256 needs about 2^256 tries: impossible.")

    print("\n[2] SECOND PRE-IMAGE resistance: given one input, finding a different input with")
    print("    the same digest is infeasible. Evidence: a 1-bit change gives an unrelated digest.")
    m2 = bytearray(msg); m2[0] ^= 1
    d2 = hashlib.sha256(bytes(m2)).hexdigest()
    diff = bit_diff_percent(bytes.fromhex(d), bytes.fromhex(d2))
    print("    original :", d)
    print("    1 bit off:", d2)
    print(f"    digest bits changed: {diff:.1f}% (ideal ~50%)")

    print("\n[3] COLLISION resistance: finding ANY two inputs with the same digest")
    print("    Birthday attack on truncated hash (expected ~2^(n/2) tries):")
    print(f"    {'bits':>5}{'tries':>12}{'time (s)':>12}   2^(n/2)")
    for n in (16, 24, 32, 40):
        seen, i, t0 = {}, 0, time.perf_counter()
        while True:
            h = trunc_int(b"msg-%d" % i, n)
            if h in seen:
                break
            seen[h] = i; i += 1
        print(f"    {n:>5}{i+1:>12}{time.perf_counter()-t0:>12.3f}   2^{n//2} = {2**(n//2)}")
    print("    Full SHA-256 collision needs about 2^128 tries: impossible.")

# ---------- 4. digital signature ----------
def cmd_sign(args):
    title("DIGITAL SIGNATURE LAB")
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
    msg = (args.text or "Report v1 - approved").encode()
    N = 50
    os.makedirs("signatures", exist_ok=True)

    def avg(fn, n):
        t0 = time.perf_counter()
        for _ in range(n): r = fn()
        return (time.perf_counter() - t0) / n * 1000, r

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    results = []
    # Ed25519
    kg, priv = avg(lambda: ed25519.Ed25519PrivateKey.generate(), N)
    pub = priv.public_key()
    sg, sig = avg(lambda: priv.sign(msg), N)
    def v_ed():
        pub.verify(sig, msg)
    vf, _ = avg(v_ed, N)
    results.append(("Ed25519", kg, sg, vf, len(sig), sig, pub))
    # RSA-2048 PSS
    kg, priv_r = avg(lambda: rsa.generate_private_key(65537, 2048), 5)
    pub_r = priv_r.public_key()
    sg, sig_r = avg(lambda: priv_r.sign(msg, pss, hashes.SHA256()), N)
    vf, _ = avg(lambda: pub_r.verify(sig_r, msg, pss, hashes.SHA256()), N)
    results.append(("RSA-2048-PSS", kg, sg, vf, len(sig_r), sig_r, pub_r))

    print("Message:", msg.decode(), "\n")
    print(f"{'Algorithm':<15}{'keygen ms':>11}{'sign ms':>10}{'verify ms':>11}{'sig bytes':>11}")
    for name, kg, sg, vf, ln, sig_b, pub_k in results:
        print(f"{name:<15}{kg:>11.3f}{sg:>10.3f}{vf:>11.3f}{ln:>11}")
        base = os.path.join("signatures", name)
        with open(base + ".sig.hex", "w") as f: f.write(sig_b.hex())
        with open(base + ".pub.pem", "wb") as f:
            f.write(pub_k.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    print("\nStored in the 'signatures' folder (signature in hex + public key in PEM).")
    print("Ed25519 signature (hex):", results[0][5].hex()[:64] + "...")

    print("\nVerification checks (Ed25519):")
    try:
        pub.verify(sig, msg); print("  original message      -> VALID")
    except InvalidSignature:
        print("  original message      -> INVALID")
    try:
        pub.verify(sig, msg + b"!"); print("  tampered message      -> VALID (bad!)")
    except InvalidSignature:
        print("  tampered message      -> INVALID (tamper detected)")
    other = ed25519.Ed25519PrivateKey.generate().public_key()
    try:
        other.verify(sig, msg); print("  wrong public key      -> VALID (bad!)")
    except InvalidSignature:
        print("  wrong public key      -> INVALID (not signed by this person)")

# ---------- 5. performance + graph ----------
def cmd_perf(args):
    title("PERFORMANCE: encryption/decryption time and speed")
    sizes_mb = [0.1, 1, 5, 10, 25, 50]
    REPEATS = 5
    key, nonce = get_random_bytes(32), get_random_bytes(12)
    gcm_encrypt(key, nonce, os.urandom(1024 * 1024))  # warm-up
    rows = []
    print(f"{'size MB':>8}{'enc ms':>10}{'dec ms':>10}{'enc MB/s':>11}{'dec MB/s':>11}{'sha256 ms':>11}")
    for s in sizes_mb:
        data = os.urandom(int(s * 1024 * 1024))
        e, d, h = [], [], []
        for _ in range(REPEATS):
            t0 = time.perf_counter(); ct, tag = gcm_encrypt(key, nonce, data); e.append(time.perf_counter() - t0)
            t0 = time.perf_counter(); gcm_decrypt(key, nonce, ct, tag); d.append(time.perf_counter() - t0)
            t0 = time.perf_counter(); hashlib.sha256(data).digest(); h.append(time.perf_counter() - t0)
        e_ms, d_ms, h_ms = [sorted(x)[len(x)//2] * 1000 for x in (e, d, h)]
        rows.append((s, e_ms, d_ms, s / (e_ms / 1000), s / (d_ms / 1000), h_ms))
        print(f"{s:>8}{e_ms:>10.2f}{d_ms:>10.2f}{rows[-1][3]:>11.1f}{rows[-1][4]:>11.1f}{h_ms:>11.2f}")
    with open("performance_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["size_mb", "enc_ms", "dec_ms", "enc_MBps", "dec_MBps", "sha256_ms"])
        w.writerows(rows)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs = [r[0] for r in rows]
        fig, ax = plt.subplots(1, 2, figsize=(11, 4))
        ax[0].plot(xs, [r[1] for r in rows], "o-", label="Encrypt")
        ax[0].plot(xs, [r[2] for r in rows], "s-", label="Decrypt")
        ax[0].plot(xs, [r[5] for r in rows], "^--", label="SHA-256")
        ax[0].set_xlabel("Data size (MB)"); ax[0].set_ylabel("Time (ms)")
        ax[0].set_title("Time vs size"); ax[0].legend(); ax[0].grid(alpha=.3)
        ax[1].plot(xs, [r[3] for r in rows], "o-", label="Encrypt")
        ax[1].plot(xs, [r[4] for r in rows], "s-", label="Decrypt")
        ax[1].set_xlabel("Data size (MB)"); ax[1].set_ylabel("Speed (MB/s)")
        ax[1].set_title("Throughput vs size"); ax[1].legend(); ax[1].grid(alpha=.3)
        fig.suptitle("AES-256-GCM performance (median of %d runs)" % REPEATS)
        fig.tight_layout(); fig.savefig("performance_graph.png", dpi=150)
        print("\nSaved performance_results.csv and performance_graph.png")
    except ImportError:
        print("\nmatplotlib not installed: run  pip install matplotlib  then run again for the graph.")

# ---------- main ----------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["show", "avalanche", "hash", "sign", "perf", "all"])
    ap.add_argument("--text"); ap.add_argument("--file")
    ap.add_argument("--trials", type=int, default=500)
    a = ap.parse_args()
    if a.cmd in ("show", "all"): cmd_show(a)
    if a.cmd in ("avalanche", "all"): cmd_avalanche(a)
    if a.cmd in ("hash", "all"): cmd_hash(a)
    if a.cmd in ("sign", "all"): cmd_sign(a)
    if a.cmd in ("perf", "all"): cmd_perf(a)