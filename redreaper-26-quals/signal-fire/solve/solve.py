#!/usr/bin/env python3
"""Signal Fire (Red Reaper CTF 2026, RE) - static solver.

main() raises SIGUSR1 for every even index and SIGUSR2 for every odd one; the
handlers do the per-character check. Both handlers reduce to:
    in[i] ^ k8[i&7] ^ byte(C >> 8*(i&7)) == (tbl[i] + 5*i) mod 256
so each character inverts directly.

Usage: python3 solve.py signal_fire
"""
import sys

d = open(sys.argv[1] if len(sys.argv) > 1 else "signal_fire", "rb").read()
D = d[0x7020:0x70A0]            # .data block at VA 0x408020 (file offset 0x7020)
k8 = D[8:16]                    # 8-byte key
n = D[0x10]                     # expected length
tbl = D[0x11:]                  # per-character targets
C = 0xB1B7509A1E72F546          # constant from both handlers

flag = bytes(((tbl[i] + 5 * i) & 0xFF) ^ k8[i & 7] ^ ((C >> (8 * (i & 7))) & 0xFF) for i in range(n))
print(flag.decode())
