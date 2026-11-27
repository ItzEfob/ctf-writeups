#!/usr/bin/env python3
"""Robben's (Red Reaper CTF 2026, DFIR) - evidence parser.

Reads only; never executes anything from the evidence.
  1. Clock offset: compare Cowrie's "Z" timestamps with the pcap (true UTC).
  2. Bytes received: reassemble the HTTP keep-alive streams and sum every
     payload-build transfer (phantom.x86/.mips/.mpsl), duplicates included.
  3. XOR key + bot name: decode the string tables in robben.rodata.bin.

Usage: pip install dpkt ; python3 solve.py capture.pcap cowrie.json robben.rodata.bin
"""
import datetime
import json
import re
import socket
import sys

import dpkt

pcap_path, log_path, ro_path = (sys.argv[1:4] if len(sys.argv) >= 4
                                else ("capture.pcap", "cowrie.json", "robben.rodata.bin"))

# --- 1. clock offset -------------------------------------------------------------
log = [json.loads(l) for l in open(log_path)]
connect = next(e for e in log if e["eventid"] == "cowrie.session.connect")
sensor = datetime.datetime.fromisoformat(connect["timestamp"].replace("Z", "+00:00"))
port = int(re.search(r":(\d+) \(", connect["message"]).group(1))

segs, first_ts = {}, {}
for ts, buf in dpkt.pcap.Reader(open(pcap_path, "rb")):
    ip = dpkt.ethernet.Ethernet(buf).data
    if not isinstance(ip, dpkt.ip.IP) or ip.p != 6:
        continue
    t = ip.data
    key = (socket.inet_ntoa(ip.src), t.sport, socket.inet_ntoa(ip.dst), t.dport)
    first_ts.setdefault(key, ts)
    if t.data:
        segs.setdefault(key, {}).setdefault(t.seq, bytes(t.data))   # dedupe retransmits

wire = datetime.datetime.fromtimestamp(
    min(v for k, v in first_ts.items() if port in (k[1], k[3])), datetime.timezone.utc)
offset_h = round((sensor - wire).total_seconds() / 3600)
print(f"sensor {sensor:%H:%M:%S}Z vs wire {wire:%H:%M:%S} UTC -> sensor clock is UTC{offset_h:+d}")

# --- 2. bytes of payload builds actually received ---------------------------------
total = 0
for key, chunks in segs.items():
    if key[1] != 80:                    # server -> client HTTP streams only
        continue
    data = b"".join(chunks[s] for s in sorted(chunks))
    req_key = (key[2], key[3], key[0], key[1])
    req = b"".join(segs[req_key][s] for s in sorted(segs[req_key]))
    paths = re.findall(rb"GET (\S+) HTTP", req)
    i = 0
    for path in paths:                  # responses come back in request order
        he = data.find(b"\r\n\r\n", i)
        cl = int(re.search(rb"Content-Length: *(\d+)", data[i:he], re.I).group(1))
        body = data[he + 4: he + 4 + cl]
        tag = "build" if b"/bins/" in path else "script"
        print(f"  {path.decode():22} {len(body):6} bytes ({tag})")
        if tag == "build":
            total += len(body)
        i = he + 4 + cl
print("payload-build bytes received:", total)

# --- 3. XOR key and bot name -------------------------------------------------------
ro = open(ro_path, "rb").read()
key = 0x54   # every encrypted string ends in 'T' == NUL ^ key
dec = bytes(b ^ key if b else 0 for b in ro)
strings = [s.decode() for s in re.findall(rb"[\x20-\x7e]{4,}", dec)]
name = next(s.split()[-1] for s in strings if s.startswith("/bin/busybox ") and s.split()[-1].isupper())
print(f"xor key 0x{key:02x}; bot name: {name}")
print(f"\nRxR{{UTC+{offset_h}_{total}_0x{key:02x}_{name}}}")
