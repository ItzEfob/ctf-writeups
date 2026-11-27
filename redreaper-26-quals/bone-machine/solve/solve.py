#!/usr/bin/env python3
"""Bone Machine (Red Reaper CTF 2026, RE) - static solver.

The binary runs a small stack VM over encrypted bytecode. Instead of debugging it
(ptrace anti-debug changes the decryption key), we decode the bytecode statically
and invert the checks.

Usage: python3 solve.py bone_machine
"""
import struct
import sys

DATA = open(sys.argv[1] if len(sys.argv) > 1 else "bone_machine", "rb").read()


def va(addr, n):
    """Map a virtual address to file bytes (.rodata @0x405000, .data @0x407000)."""
    if 0x405000 <= addr < 0x406000:
        off = addr - 0x405000 + 0x5000
    elif 0x407000 <= addr < 0x4072B0:
        off = addr - 0x407000 + 0x6000
    else:
        raise ValueError(hex(addr))
    return DATA[off:off + n]


def fetch(code, key, i):
    """Opcode fetch from 0x401560: per-index hash of the key, XOR the stored byte."""
    x = (i * 0x9E3779B1) & 0xFFFFFFFF
    x ^= key
    x ^= x >> 15
    x = (x * 0x2C1B3C6D) & 0xFFFFFFFF
    x ^= x >> 12
    return (x ^ code[i]) & 0xFF


KEY = struct.unpack("<I", va(0x407024, 4))[0]          # 0x5eed0b0e when not traced
BLK = va(0x407040, 0x70)                               # VM data block

# --- 1. Visible program (runs by default) -------------------------------------
# Checks: (in[i] ^ k8[i&7]) + 25*i == tbl[i]  (mod 256), for i < BLK[0x10]
length = BLK[0x10]
k8 = bytes(BLK[8 + j] ^ ((0x2369302C2EA705A2 >> (8 * j)) & 0xFF) for j in range(8))
tbl = BLK[0x11:]
visible = bytes(((tbl[i] - 25 * i) & 0xFF) ^ k8[i & 7] for i in range(length))
print("visible program accepts:", visible.decode())

# --- 2. Hidden program (FNV-gated, never runs as shipped) ---------------------
# Decoded bytecode: len == 32, then repeated blocks  91 3a A 6f 3a B b9 45 d2
# i.e.  in[i] ^ A != B  ->  fail.  So in[i] = A ^ B.
hidden_code = va(0x4050C0, 0x126)
dec = bytes(fetch(hidden_code, KEY, i) for i in range(len(hidden_code)))
out, p = [], 5
while dec[p] == 0x91:
    out.append(dec[p + 2] ^ dec[p + 5])
    p += 9
print("hidden program decodes to:", bytes(out).decode(), "(decoy)")
