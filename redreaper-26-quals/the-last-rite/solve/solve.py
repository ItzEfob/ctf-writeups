#!/usr/bin/env python3
"""The Last Rite (Red Reaper CTF 2026, RE) - static solver.

The check runs in an 8-register VM whose 3684 eight-byte instructions live in the
`rxprog` section, decrypted per instruction with a key = FNV-1a(rxguard code).
The program is branch-free: it runs 224 invertible updates over 12 state words
(the input) and ORs (state ^ expected) into r0. We:
  1. decrypt + emulate the VM to get the straight-line instruction order,
  2. symbolically record every state-word update (z3),
  3. walk the updates backwards from the expected words, solving each
     one-unknown equation (inverse S-box table for the substitution steps).

Usage: pip install z3-solver ; python3 solve.py last_rite
"""
import struct
import sys

from z3 import (BitVec, BitVecVal, BitVecSort, Concat, Extract, K, LShR,
                RotateLeft, Select, Solver, Store, ZeroExt, is_bv_value,
                is_const, simplify, substitute, sat, Z3_OP_UNINTERPRETED)

B = open(sys.argv[1] if len(sys.argv) > 1 else "last_rite", "rb").read()
M32 = 0xFFFFFFFF


def va(a, n):
    """VA -> file bytes. Text/rodata map 1:1 from 0x400000; data is shifted by 0x1000."""
    o = a - 0x400000 if a < 0x411000 else a - 0x401000
    return B[o:o + n]


# ---- VM decoding -------------------------------------------------------------
KEY = 0x811C9DC5                                     # FNV-1a over rxguard (anti-patch)
for c in va(0x4070B0, 0x40732C - 0x4070B0):
    KEY = ((KEY ^ c) * 0x1000193) & M32              # (XORed with 0x5ea1ed00 if traced)
PROG = va(0x409220, 0x7320)
N = len(PROG) // 8


def dec(i):
    r13 = ((i * 0x9E3779B1) & M32) ^ KEY
    ecx, out = 0, bytearray()
    for j in range(8):
        x = r13 ^ ecx
        ecx = (ecx - 0x7A143595) & M32
        x ^= x >> 15; x = (x * 0x2C1B3C6D) & M32; x ^= x >> 12
        x = (x * 0x297A2D39) & M32; x ^= x >> 15
        out.append((x & 0xFF) ^ PROG[i * 8 + j])
    return bytes(out)


JT = [0x408000 + struct.unpack("<i", va(0x408000 + 4 * k, 4))[0] for k in range(0xE8)]
HANDLERS = {
    0x4071E7: "rol", 0x4071EB: "roli", 0x407238: "addi", 0x40723B: "movi",
    0x407240: "st32", 0x407252: "add", 0x40725E: "ld32", 0x407270: "sub",
    0x40727F: "and", 0x40728E: "xor", 0x40729D: "or", 0x4072AC: "st8",
    0x4072C1: "shri", 0x4072CE: "jnz", 0x4072D9: "jmp", 0x4072E1: "mov",
    0x4072EC: "mul", 0x4072FC: "ld8", 0x407312: "shli", 0x40731F: "halt",
}


def decode(i):
    b = dec(i)
    op = (b[0] - 9) & 0xFF
    name = HANDLERS.get(JT[op], "BAD") if op <= 0xE7 else "BAD"
    return name, b[1] & 7, b[2] & 7, b[3] & 7, struct.unpack("<I", b[4:])[0]


INS = [decode(i) for i in range(N)]


def memimg(inp):
    """VM memory: input @0x00, key16 @0x30, expected @0x40, len @0x70, byte @0x74."""
    m = bytearray(0x400)
    m[0:min(len(inp), 0x30)] = inp[:0x30]
    m[0x30:0x40] = va(0x412028, 16)
    m[0x40:0x70] = va(0x412039, 48)
    m[0x70:0x74] = struct.pack("<I", len(inp))
    m[0x74:0x78] = struct.pack("<I", va(0x412038, 1)[0])
    return m


def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32 if n else x


def run(inp, trace=None):
    """Concrete emulator. Returns r0 (0 == accepted)."""
    m, r, pc = memimg(inp), [0] * 8, 0
    for _ in range(0x61A80):
        if pc >= N:
            return -1
        n, d, s, t, imm = INS[pc]
        if trace is not None:
            trace.append((pc, n, d, s, t, imm, list(r)))
        nxt = pc + 1
        if n == "movi": r[d] = imm
        elif n == "addi": r[d] = (imm + r[s]) & M32
        elif n == "add": r[d] = (r[s] + r[t]) & M32
        elif n == "sub": r[d] = (r[s] - r[t]) & M32
        elif n == "mul": r[d] = (r[s] * r[t]) & M32
        elif n == "and": r[d] = r[s] & r[t]
        elif n == "or": r[d] = r[s] | r[t]
        elif n == "xor": r[d] = r[s] ^ r[t]
        elif n == "mov": r[d] = r[s]
        elif n == "shri": r[d] = r[s] >> (imm & 31)
        elif n == "shli": r[d] = (r[s] << (imm & 31)) & M32
        elif n == "roli": r[d] = rol(r[s], imm)
        elif n == "rol": r[d] = rol(r[s], r[t])
        elif n == "ld32": a = (imm + r[s]) & 0x3FC; r[d] = struct.unpack("<I", m[a:a + 4])[0]
        elif n == "st32": a = (imm + r[s]) & 0x3FC; m[a:a + 4] = struct.pack("<I", r[d])
        elif n == "ld8": r[d] = m[(imm + r[s]) & 0x3FF]
        elif n == "st8": m[(imm + r[s]) & 0x3FF] = r[d] & 0xFF
        elif n == "jnz": nxt = imm if r[d] else nxt
        elif n == "jmp": nxt = imm
        elif n == "halt": return r[0]
        else: return -1
        pc = nxt
    return -1


# ---- symbolic pass: record every state-word update -----------------------------
L = 31                                   # any length works; the trace is input-independent
tr = []
run(b"A" * L, tr)
V = lambda w, v: BitVec(f"s{w}_{v}", 32)
ver = {w: 0 for w in range(12)}
words = {a: BitVecVal(struct.unpack("<I", memimg(b"\0" * L)[a:a + 4])[0], 32) for a in range(0, 0x400, 4)}
for w in range(12):
    words[4 * w] = V(w, 0)
R = [BitVecVal(0, 32) for _ in range(8)]
SB = None; sbox = None
steps, finals = [], []


def conc(x):
    x = simplify(x)
    assert is_bv_value(x), x
    return x.as_long()


def byte_of(a):
    return Extract(8 * (a % 4) + 7, 8 * (a % 4), words[a & ~3])


for pc, n, d, s, t, imm, _ in tr:
    I = BitVecVal(imm, 32)
    if n == "movi": R[d] = I
    elif n == "addi": R[d] = I + R[s]
    elif n == "add": R[d] = R[s] + R[t]
    elif n == "sub": R[d] = R[s] - R[t]
    elif n == "mul": R[d] = R[s] * R[t]
    elif n == "and": R[d] = R[s] & R[t]
    elif n == "or":
        if d == 0 and s == 0:
            finals.append(simplify(R[t]))          # r0 |= (state ^ expected)
        R[d] = R[s] | R[t]
    elif n == "xor": R[d] = R[s] ^ R[t]
    elif n == "mov": R[d] = R[s]
    elif n == "shri": R[d] = LShR(R[s], imm & 31)
    elif n == "shli": R[d] = R[s] << (imm & 31)
    elif n == "roli": R[d] = RotateLeft(R[s], imm & 31)
    elif n == "rol": R[d] = RotateLeft(R[s], R[t] & 31)
    elif n == "ld32": R[d] = words[conc(I + R[s]) & 0x3FC]
    elif n == "st32":
        a, e = conc(I + R[s]) & 0x3FC, simplify(R[d])
        if a < 0x30:                                   # a state word -> new version
            w = a // 4; ver[w] += 1; nv = V(w, ver[w])
            steps.append((w, nv, e)); words[a] = nv
        else:
            words[a] = e
    elif n == "st8":
        a = conc(I + R[s]) & 0x3FF; sh = 8 * (a % 4)
        old = words[a & ~3]
        words[a & ~3] = simplify((old & ~BitVecVal(0xFF << sh, 32)) | (ZeroExt(24, Extract(7, 0, R[d])) << sh))
    elif n == "ld8":
        a = simplify((I + R[s]) & 0x3FF)
        if is_bv_value(a):
            R[d] = ZeroExt(24, byte_of(a.as_long()))
        else:                                          # S-box lookup at 0x80
            if SB is None:
                sbox = [conc(byte_of(0x80 + k)) for k in range(256)]
                SB = K(BitVecSort(8), BitVecVal(0, 8))
                for k, v in enumerate(sbox):
                    SB = Store(SB, k, v)
            R[d] = ZeroExt(24, Select(SB, Extract(7, 0, R[s])))
    elif n == "halt":
        break
    R = [simplify(x) for x in R]

# ---- backward pass -------------------------------------------------------------
known = {}
for f in finals:                                       # each term: s_w_last ^ const == 0
    vs = set()
    stack = [f]
    while stack:
        e = stack.pop()
        if is_const(e) and e.decl().kind() == Z3_OP_UNINTERPRETED:
            vs.add(e)
        stack.extend(e.children())
    v = vs.pop(); S = Solver(); S.add(f == 0); S.check()
    known[str(v)] = S.model()[v].as_long()

inv_sbox = [0] * 256
for k, v in enumerate(sbox):
    inv_sbox[v] = k

for w, nv, e in reversed(steps):
    newval = known[str(nv)]
    old = V(w, int(str(nv).split("_")[1]) - 1)
    e2 = simplify(substitute(e, *[(BitVec(k, 32), BitVecVal(v, 32)) for k, v in known.items()]))
    if "Store(" in str(e2)[:40]:                       # byte-wise S-box step
        val = sum(inv_sbox[(newval >> (8 * i)) & 0xFF] << (8 * i) for i in range(4))
    else:
        S = Solver(); S.add(e2 == newval); assert S.check() == sat
        val = S.model().eval(old, model_completion=True).as_long()
    known[str(old)] = val

flag = b"".join(struct.pack("<I", known[f"s{w}_0"]) for w in range(12)).rstrip(b"\0")
print(flag.decode())
print("emulator check r0 =", hex(run(flag)), "(0 = accepted)")
