"""Efficiency test: how long do AES-256-GCM encryption, decryption and SHA-256 take?"""
import csv
import os
import statistics
import time

from crypto_utils import decrypt_bytes, encrypt_bytes, new_data_key, sha256_hex

SIZES_MB = [1, 10, 50, 100]    # file sizes to test
REPEATS = 5                  # run each test this many times and take the average

key = new_data_key()
rows = []

# warm-up: the very first call is slow (one-time start-up cost), so do one untimed run
encrypt_bytes(key, os.urandom(1024 * 1024))

print(f"{'Size':>6} | {'Encrypt ms':>10} | {'Decrypt ms':>10} | {'SHA-256 ms':>10} | {'Speed MB/s':>10} | {'Extra bytes':>11}")
print("-" * 72)

for mb in SIZES_MB:
    data = os.urandom(mb * 1024 * 1024)           # a file full of random bytes
    enc_times, dec_times, sha_times = [], [], []

    for _ in range(REPEATS):
        t = time.perf_counter()
        blob = encrypt_bytes(key, data)
        enc_times.append(time.perf_counter() - t)

        t = time.perf_counter()
        back = decrypt_bytes(key, blob)
        dec_times.append(time.perf_counter() - t)

        t = time.perf_counter()
        sha256_hex(data)
        sha_times.append(time.perf_counter() - t)

        assert back == data                        # decryption must return the original

    enc = statistics.mean(enc_times) * 1000        # seconds -> milliseconds
    dec = statistics.mean(dec_times) * 1000
    sha = statistics.mean(sha_times) * 1000
    speed = mb / (enc / 1000)                      # MB per second
    extra = len(blob) - len(data)                  # bytes added by encryption

    rows.append([mb, round(enc, 1), round(dec, 1), round(sha, 1), round(speed, 1), extra])
    print(f"{mb:>4}MB | {enc:>10.1f} | {dec:>10.1f} | {sha:>10.1f} | {speed:>10.1f} | {extra:>11}")

with open("benchmark_results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["size_mb", "encrypt_ms", "decrypt_ms", "sha256_ms", "encrypt_MB_per_s", "extra_bytes"])
    w.writerows(rows)

print(f"\nAverage of {REPEATS} runs each. Saved to benchmark_results.csv")