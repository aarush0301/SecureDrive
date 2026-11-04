"""Traffic analysis of a Wireshark capture, using PyShark.

Run it once per capture file:
  python pyshark_analyze.py capture_http.pcapng  --port 5000 --marker hunter2pass --marker SECRET_REPORT
  python pyshark_analyze.py capture_https.pcapng --port 5443 --marker hunter2pass --marker SECRET_REPORT
"""
import argparse
import asyncio
import collections
import math

import pyshark

# ---------- 1. read the command-line options ----------
ap = argparse.ArgumentParser()
ap.add_argument("pcap", help="the .pcapng file saved from Wireshark")
ap.add_argument("--port", type=int, required=True, help="5000 (HTTP) or 5443 (HTTPS)")
ap.add_argument("--marker", action="append", default=[],
                help="text to look for inside the packets, e.g. a password")
ap.add_argument("--tshark", default=None,
                help=r"path to tshark.exe if PyShark cannot find it")
a = ap.parse_args()

# PyShark needs an asyncio event loop to exist
try:
    asyncio.get_running_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())


def entropy(data):
    """Randomness of the bytes, 0 to 8. Readable text is about 4-6, encrypted about 7.7-8."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    return -sum(n / len(data) * math.log2(n / len(data)) for n in counts.values())


# ---------- 2. go through every packet on our port ----------
cap = pyshark.FileCapture(a.pcap, display_filter=f"tcp.port=={a.port}",
                          keep_packets=False, tshark_path=a.tshark)
packets = wire_bytes = 0
layers = collections.Counter()      # how many packets of each protocol
hits = collections.Counter()        # how many packets contain each marker
http_requests = []                  # readable web requests
payload = bytearray()               # all the data carried by the packets

for pkt in cap:
    packets += 1
    wire_bytes += int(pkt.length)
    layers[pkt.highest_layer] += 1

    if hasattr(pkt, "http") and hasattr(pkt.http, "request_method"):
        uri = getattr(pkt.http, "request_uri", "")
        http_requests.append(f"{pkt.http.request_method} {uri}")

    if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
        raw = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
        payload += raw
        for m in a.marker:
            if m.encode() in raw:
                hits[m] += 1
cap.close()

# ---------- 3. TLS details (only exist in the HTTPS capture) ----------
CIPHERS = {0x1301: "TLS_AES_128_GCM_SHA256",
           0x1302: "TLS_AES_256_GCM_SHA384",
           0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
VERSIONS = {0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def decode(value, table):
    try:
        number = int(str(value), 16)
        return f"{table.get(number, 'unknown')} ({hex(number)})"
    except ValueError:
        return str(value)


tls_lines = []
cap2 = pyshark.FileCapture(a.pcap, display_filter=f"tcp.port=={a.port} && tls.handshake.type == 2",
                           keep_packets=False, tshark_path=a.tshark)
for pkt in cap2:
    tls = getattr(pkt, "tls", None)
    if tls is None:
        continue
    cs = getattr(tls, "handshake_ciphersuite", None)
    ver = getattr(tls, "handshake_extensions_supported_version", None)
    if cs is not None:
        tls_lines.append("Cipher suite chosen: " + decode(cs, CIPHERS))
    if ver is not None:
        tls_lines.append("TLS version chosen:  " + decode(ver, VERSIONS))
cap2.close()

# ---------- 4. print the report ----------
print(f"\n=== Traffic analysis: {a.pcap}  (tcp port {a.port}) ===")
print(f"Packets: {packets}     Bytes on the wire: {wire_bytes}")
print("Protocol breakdown:", dict(layers))

if http_requests:
    print("\nWeb requests an eavesdropper can read:")
    for r in http_requests[:20]:
        print("   ", r)

if tls_lines:
    print("\nTLS handshake (visible, but the data after it is encrypted):")
    for line in dict.fromkeys(tls_lines):
        print("   ", line)

print(f"\nPayload entropy: {entropy(bytes(payload)):.2f} bits per byte")
print("   (readable text is about 4-6, encrypted data is about 7.7-8)")

print("\nSearching the packets for your secret text:")
exposed = False
for m in a.marker:
    if hits[m]:
        exposed = True
        print(f"   '{m}': FOUND in {hits[m]} packet(s)  -> exposed")
    else:
      print(f"   '{m}': not found in these packets")

print("\nVERDICT:", "an eavesdropper can read the secrets." if exposed
      else "no secret text could be read from the network traffic.")