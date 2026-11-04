"""
lab_core.py - the experiment code used by the SecureDrive web pages
(/inspect/<file>, /lab, /perf). Pure functions, no Flask inside.
"""
import hashlib
import os
import random
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# ---------- small helpers ----------
def bit_pct(a, b):
    n = min(len(a), len(b))
    return 100.0 * sum(bin(x ^ y).count("1") for x, y in zip(a[:n], b[:n])) / (n * 8)


def byte_pct(a, b):
    n = min(len(a), len(b))
    return 100.0 * sum(1 for x, y in zip(a[:n], b[:n]) if x != y) / n


def flip(data, i):
    b = bytearray(data)
    b[i // 8] ^= 1 << (i % 8)
    return bytes(b)


def hexdump(data, n=64):
    """First n bytes as hex, 16 bytes per line."""
    data = data[:n]
    return "\n".join(data[i:i + 16].hex(" ") for i in range(0, len(data), 16))


# ---------- avalanche / confusion / diffusion ----------
def avalanche(key, data, trials=100):
    """Return rows [(name, bit-level %, char-level %)] measured on THIS data and key."""
    sample = data[:64] if len(data) >= 64 else data.ljust(64, b"\0")
    nonce, iv = os.urandom(12), os.urandom(16)

    def gcm(k, p):
        return AES.new(k, AES.MODE_GCM, nonce=nonce).encrypt(p)

    def cbc(p):
        return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(p, 16))

    def ecb(p):
        return AES.new(key, AES.MODE_ECB).encrypt(p)

    block = sample[:16]
    base_g, base_c, base_e = gcm(key, sample), cbc(sample), ecb(block)
    acc = {k: [[], []] for k in "ABCD"}
    for _ in range(trials):
        pairs = {
            "A": (base_g, gcm(flip(key, random.randrange(256)), sample)),
            "B": (base_c, cbc(flip(sample, random.randrange(128)))),
            "C": (base_e, ecb(flip(block, random.randrange(128)))),
            "D": (base_g, gcm(key, flip(sample, random.randrange(512)))),
        }
        for k, (x, y) in pairs.items():
            acc[k][0].append(bit_pct(x, y))
            acc[k][1].append(byte_pct(x, y))
    names = {
        "A": "1 KEY bit flipped, AES-256-GCM (confusion)",
        "B": "1 plaintext bit (block 1), AES-256-CBC (diffusion)",
        "C": "1 plaintext bit, single AES block (diffusion)",
        "D": "1 plaintext bit, AES-256-GCM (stream-like, low by design)",
    }
    return [(k + ". " + names[k], sum(acc[k][0]) / trials, sum(acc[k][1]) / trials)
            for k in "ABCD"]


# ---------- hash ----------
def hash_report(data, stored_hex=None):
    t0 = time.perf_counter()
    digest = hashlib.sha256(data).hexdigest()
    hash_ms = (time.perf_counter() - t0) * 1000
    flipped = bytearray(data or b"\0")
    flipped[0] ^= 1
    d2 = hashlib.sha256(bytes(flipped)).hexdigest()
    return {
        "digest": digest, "hash_ms": hash_ms,
        "stored": stored_hex, "match": (digest == stored_hex) if stored_hex else None,
        "flipped_digest": d2,
        "changed_pct": bit_pct(bytes.fromhex(digest), bytes.fromhex(d2)),
    }


# ---------- performance table + SVG chart ----------
def perf_series(sizes_mb=(0.1, 1, 5, 10, 25), repeats=3):
    key, nonce = os.urandom(32), os.urandom(12)
    AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(os.urandom(1 << 20))  # warm-up
    rows = []
    for s in sizes_mb:
        data = os.urandom(int(s * 1024 * 1024))
        e, d = [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(data)
            e.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
            d.append(time.perf_counter() - t0)
        e_ms, d_ms = sorted(e)[len(e) // 2] * 1000, sorted(d)[len(d) // 2] * 1000
        rows.append({"mb": s, "enc_ms": e_ms, "dec_ms": d_ms,
                     "enc_mbps": s / (e_ms / 1000), "dec_mbps": s / (d_ms / 1000)})
    return rows


def svg_chart(rows, k1, k2, title, ylabel, w=470, h=270):
    """Tiny dependency-free SVG line chart with two series (k1, k2)."""
    L, R, T, B = 55, 15, 30, 40
    xs = [r["mb"] for r in rows]
    ymax = max(max(r[k1], r[k2]) for r in rows) * 1.1 or 1
    xmax = max(xs)
    px = lambda x: L + (w - L - R) * x / xmax
    py = lambda y: h - B - (h - T - B) * y / ymax
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
           f'style="background:#fff;border:1px solid #ccc">',
           f'<text x="{w/2}" y="18" text-anchor="middle" font-size="14" font-family="sans-serif">{title}</text>',
           f'<line x1="{L}" y1="{h-B}" x2="{w-R}" y2="{h-B}" stroke="#000"/>',
           f'<line x1="{L}" y1="{T}" x2="{L}" y2="{h-B}" stroke="#000"/>']
    for i in range(5):
        yv = ymax * i / 4
        out.append(f'<line x1="{L}" y1="{py(yv):.1f}" x2="{w-R}" y2="{py(yv):.1f}" stroke="#eee"/>')
        out.append(f'<text x="{L-5}" y="{py(yv)+4:.1f}" text-anchor="end" font-size="10" '
                   f'font-family="sans-serif">{yv:.0f}</text>')
    for x in xs:
        out.append(f'<text x="{px(x):.1f}" y="{h-B+14}" text-anchor="middle" font-size="10" '
                   f'font-family="sans-serif">{x:g}</text>')
    out.append(f'<text x="{w/2}" y="{h-6}" text-anchor="middle" font-size="11" '
               f'font-family="sans-serif">Data size (MB)</text>')
    out.append(f'<text x="12" y="{h/2}" font-size="11" font-family="sans-serif" '
               f'transform="rotate(-90 12 {h/2})" text-anchor="middle">{ylabel}</text>')
    for key, color, label, ly in ((k1, "#d62728", "Encrypt", 36), (k2, "#1f77b4", "Decrypt", 50)):
        pts = " ".join(f"{px(r['mb']):.1f},{py(r[key]):.1f}" for r in rows)
        out.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2"/>')
        for r in rows:
            out.append(f'<circle cx="{px(r["mb"]):.1f}" cy="{py(r[key]):.1f}" r="3" fill="{color}"/>')
        out.append(f'<text x="{w-R-60}" y="{ly}" font-size="11" fill="{color}" '
                   f'font-family="sans-serif">&#9632; {label}</text>')
    out.append("</svg>")
    return "".join(out)