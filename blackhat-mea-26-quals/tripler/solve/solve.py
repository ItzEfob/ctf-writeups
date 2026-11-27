#!/usr/bin/env python3
"""
TripleR (Black Hat MEA 2026 quals, crypto) -- solver.

    python3 solve.py HOST PORT

The service encrypts f"{ch}|encrypted by {key.hex()}" with AES-GCM under a
FIXED key and a FIXED nonce, once for each of up to 6 characters you send, and
prints half of each tag: round 0 shows the high nibble of every tag byte,
round 1 the low nibble.  Give the key after round 0 and the nonce after
round 1, and it prints the flag.  It all has to happen inside alarm(300).

Stages:
  1. H        Two messages of equal length that differ only in their first
              character: their tags differ by Delta * H^4, which is linear in
              H^4.  Two such pairs pin H^4, and H = (H^4)^(2^126).
  2. key      Python iterates CHARACTERS, so a multi-byte UTF-8 character
              shifts the key hex one byte to the right while the keystream
              stays put.  A 47-byte and a 48-byte message share their block
              count, so their tag difference cancels the keystream and is
              linear in the key hex.  Two such pairs (47/48 and 49/50) plus the
              fixed bits of lowercase hex leave 48 free bits; guessing which
              hex digits are 8 or 9 makes the rest linear.  AES_K(0) == H
              confirms the key.
  3. nonce    Replay the same 6 characters to get the low nibbles, so the full
              tags.  With the key known, E49 ^ H*E48 cancels every keystream
              block except one byte; 256 guesses give S = E_K(J0), which
              decrypts to J0, and the nonce falls out of GHASH.
"""
import socket
import sys
import time
from itertools import combinations

import numpy as np
from Crypto.Cipher import AES

KNOWN = b"|encrypted by "
# UTF-8 lengths 1,1,2,2,3,4  ->  message lengths 47,47,48,48,49,50
CHARS = ["A", "B", "é", "ü", "€", "\U0001D11E"]
SAME_PAIRS = ((0, 1), (2, 3))            # equal length         -> H
SHIFT_PAIRS = ((0, 2, 0), (4, 5, 1))     # length L and L+1     -> key hex
NB = 256 + 16                            # key-hex bits + 2 unknown keystream bytes
HI = [8 * j + t for j in range(16) for t in range(4)]   # high-nibble bit positions
MAX_SPECIAL = 6                          # max number of 8/9 hex digits searched


# --------------------------------------------------------------------------
# GF(2^128) as GCM defines it (bit 0 = MSB = coefficient of x^0)
# --------------------------------------------------------------------------
R = 0xE1 << 120
ONE = 1 << 127


def gf_mul(x, y):
    z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= y
        y = (y >> 1) ^ R if y & 1 else y >> 1
    return z


def gf_pow(x, e):
    r = ONE
    while e:
        if e & 1:
            r = gf_mul(r, x)
        x = gf_mul(x, x)
        e >>= 1
    return r


def gf_inv(x):
    return gf_pow(x, (1 << 128) - 2)


def b2i(b):
    return int.from_bytes(b, "big")


def i2b(x):
    return x.to_bytes(16, "big")


def blocks(data):
    return [data[i:i + 16].ljust(16, b"\x00") for i in range(0, len(data), 16)]


def ghash(H, data):
    """GHASH with empty AAD, as GCM uses it for both the tag and a 16-byte nonce."""
    y = 0
    for blk in blocks(data):
        y = gf_mul(y ^ b2i(blk), H)
    return gf_mul(y ^ (len(data) * 8), H)


def gcm_tag(key, nonce, pt):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.encrypt(pt)
    return c.digest()


def message(ch, keyhex):
    return ch.encode() + KNOWN + keyhex


# --------------------------------------------------------------------------
# Linear algebra over GF(2); an equation is (bitmask over unknowns, rhs bit)
# --------------------------------------------------------------------------
def solve_gf2(rows, n):
    """Returns (one solution, kernel basis) as bitmasks, or None if inconsistent."""
    piv = {}
    for m, r in rows:
        while m:
            b = m.bit_length() - 1
            if b not in piv:
                piv[b] = (m, r)
                break
            pm, pr = piv[b]
            m ^= pm
            r ^= pr
        else:
            if r:
                return None
    for b in sorted(piv):                       # back-substitute to reduced form
        m, r = piv[b]
        for c in sorted(piv):
            if c < b and (m >> c) & 1:
                cm, cr = piv[c]
                m ^= cm
                r ^= cr
        piv[b] = (m, r)
    part = sum(1 << b for b, (m, r) in piv.items() if r)
    basis = []
    for f in (i for i in range(n) if i not in piv):
        v = 1 << f
        for b, (m, r) in piv.items():
            if (m >> f) & 1:
                v |= 1 << b
        basis.append(v)
    return part, basis


def gbit(v, p):
    return (v >> (127 - p)) & 1


def rows_from_columns(cols, positions, rhs):
    """cols[k] = GF(2^128) image of unknown k; one equation per observed bit."""
    out = []
    for p in positions:
        mask = 0
        for k, col in enumerate(cols):
            if gbit(col, p):
                mask |= 1 << k
        out.append((mask, rhs(p)))
    return out


def nibble_bits(nibs):
    """16 observed high nibbles -> {bit position in the tag: bit}."""
    return {HI[4 * j + t]: (v >> (3 - t)) & 1 for j, v in enumerate(nibs) for t in range(4)}


# --------------------------------------------------------------------------
# Stage 1: H from the equal-length pairs
# --------------------------------------------------------------------------
def recover_H(hi):
    rows = []
    for i, j in SAME_PAIRS:
        delta = bytes(x ^ y for x, y in zip(CHARS[i].encode(), CHARS[j].encode()))
        d = b2i(delta.ljust(16, b"\x00"))
        cols = [gf_mul(d, 1 << (127 - k)) for k in range(128)]   # Delta * X, X = H^4
        bi, bj = nibble_bits(hi[i]), nibble_bits(hi[j])
        rows += rows_from_columns(cols, HI, lambda p: bi[p] ^ bj[p])
    sol = solve_gf2(rows, 128)
    if sol is None or sol[1]:
        return None
    X = sum(((sol[0] >> k) & 1) << (127 - k) for k in range(128))
    for _ in range(126):                        # fourth root: X^(2^126)
        X = gf_mul(X, X)
    return X


# --------------------------------------------------------------------------
# Stage 2: the key from the length-shifted pairs
# --------------------------------------------------------------------------
def shift_difference(H, cs, cl, keyhex, ks_byte):
    """
    Tag(cs + R) ^ Tag(cl + R) for R = KNOWN + keyhex, where cl is one byte longer
    and both messages have the same block count.  The keystream cancels on every
    position the two share; only the final byte of the longer one keeps ks_byte.
    """
    rest = KNOWN + keyhex
    short, long_ = cs + rest, cl + rest
    n = len(long_)
    D = bytearray(n)
    for i in range(len(short)):
        D[i] = short[i] ^ long_[i]
    D[n - 1] = rest[-1] ^ ks_byte
    nb = (n + 15) // 16
    acc = gf_mul((len(short) * 8) ^ (n * 8), H)  # the length blocks differ too
    for j, blk in enumerate(blocks(bytes(D))):
        acc ^= gf_mul(b2i(blk), gf_pow(H, nb + 1 - j))
    return acc


def key_system(H, hi):
    pairs = [(CHARS[a].encode(), CHARS[b].encode(), s) for a, b, s in SHIFT_PAIRS]

    def evaluate(kh, ks):
        return [shift_difference(H, s, l, kh, ks[i]) for s, l, i in pairs]

    const = evaluate(b"\x00" * 32, [0, 0])      # the map is affine: split it
    cols = []
    for i in range(NB):
        kh, ks = bytearray(32), [0, 0]
        if i < 256:
            kh[i // 8] = 1 << (7 - i % 8)
        else:
            ks[(i - 256) // 8] = 1 << (7 - (i - 256) % 8)
        cols.append([a ^ b for a, b in zip(evaluate(bytes(kh), ks), const)])

    rows = []
    for r, (a, b, _) in enumerate(SHIFT_PAIRS):
        ba, bb = nibble_bits(hi[a]), nibble_bits(hi[b])
        rows += rows_from_columns([c[r] for c in cols], HI,
                                  lambda p, ba=ba, bb=bb, r=r:
                                  ba[p] ^ bb[p] ^ gbit(const[r], p))
    for j in range(32):                         # every lowercase hex byte:
        o = 8 * j                               # bit7 = 0, bit5 = 1, bit6 ^ bit4 = 1
        rows.append((1 << o, 0))
        rows.append((1 << (o + 2), 1))
        rows.append(((1 << (o + 1)) | (1 << (o + 3)), 1))
    return rows


VALID_HEX = np.zeros(256, bool)
for _v in b"0123456789abcdef":
    VALID_HEX[_v] = True


def _hex_bytes(x):
    out = bytearray(32)
    for j in range(32):
        out[j] = sum(((x >> (8 * j + t)) & 1) << (7 - t) for t in range(8))
    return np.frombuffer(bytes(out), dtype=np.uint8)


def recover_key(H, hi, max_special=MAX_SPECIAL):
    """
    Bit 3 of a lowercase hex byte is 1 only for '8' (0x38) and '9' (0x39), and
    those two also force bits 6, 2 and 1 to 0.  Guessing the set S of 8/9 digits
    therefore turns everything into linear equations.  Searched by |S| upwards.
    """
    sol = solve_gf2(key_system(H, hi), NB)
    if sol is None:
        return None
    part, basis = sol
    d = len(basis)

    def functional(idx):                        # unknown bit idx as an affine
        m = sum(1 << c for c, v in enumerate(basis) if (v >> idx) & 1)
        return m, (part >> idx) & 1             # function of the free coords

    F = {(j, name): functional(8 * j + off)
         for j in range(32)
         for name, off in (("b6", 1), ("b3", 4), ("b2", 5), ("b1", 6))}

    # Solutions of the bit-3 equations form a0 + span(W[i] for i in S) + span(K)
    b3 = [F[(j, "b3")] for j in range(32)]
    z = solve_gf2(b3, d)
    if z is None:
        return None
    a0, K = z
    W = []
    for i in range(32):
        w = solve_gf2([(m, int(j == i)) for j, (m, _) in enumerate(b3)], d)
        if w is None:
            return None
        W.append(w[0])

    def dot(m, v):
        return bin(m & v).count("1") & 1

    forced = ("b6", "b2", "b1")
    kmask = {k: sum(1 << t for t, kv in enumerate(K) if dot(F[k][0], kv)) for k in F}
    a0rhs = {k: dot(F[k][0], a0) ^ F[k][1] for k in F}
    wdot = {k: [dot(F[k][0], w) for w in W] for k in F}

    def as_hex(coords):
        acc = np.zeros(32, np.uint8)
        for c in range(d):
            if (coords >> c) & 1:
                acc ^= B[c]
        return acc

    B = [_hex_bytes(v) for v in basis]
    A0 = _hex_bytes(part) ^ as_hex(a0)
    WA = [as_hex(w) for w in W]
    KA = [as_hex(k) for k in K]

    for size in range(max_special + 1):
        for S in combinations(range(32), size):
            rows = []
            for j in S:
                for name in forced:
                    k = (j, name)
                    rhs = a0rhs[k]
                    for i in S:
                        rhs ^= wdot[k][i]
                    rows.append((kmask[k], rhs))
            r = solve_gf2(rows, len(K))
            if r is None:
                continue
            tpart, tker = r
            base = A0.copy()
            for i in S:
                base ^= WA[i]
            for t in range(len(K)):
                if (tpart >> t) & 1:
                    base ^= KA[t]
            cands = base[None, :]
            for v in tker:
                delta = np.zeros(32, np.uint8)
                for t in range(len(K)):
                    if (v >> t) & 1:
                        delta ^= KA[t]
                cands = np.concatenate([cands, cands ^ delta])
            for cand in cands[VALID_HEX[cands].all(axis=1)]:
                key = bytes.fromhex(bytes(cand).decode())
                if b2i(AES.new(key, AES.MODE_ECB).encrypt(b"\x00" * 16)) == H:
                    return key
    return None


# --------------------------------------------------------------------------
# Stage 3: the nonce from the full tags
# --------------------------------------------------------------------------
def recover_nonce(key, H, tags):
    """
    E = Tag ^ GHASH(plaintext) leaves the masked keystream plus S.  For the 48-
    and 49-byte messages,  E49 ^ H*E48 = KS4[0]*H^2 ^ S*(1 ^ H):  one unknown
    keystream byte.  J0 = E_K^-1(S) and J0 = ((nonce*H) ^ 128) * H.
    """
    ecb = AES.new(key, AES.MODE_ECB)
    kh = key.hex().encode()

    def E(i):
        return b2i(tags[i]) ^ ghash(H, message(CHARS[i], kh))

    lhs = E(4) ^ gf_mul(H, E(2))
    inv_1h = gf_inv(ONE ^ H)
    H2, Hinv = gf_mul(H, H), gf_inv(H)
    check_pt = message(CHARS[2], kh)
    for g in range(256):
        S = gf_mul(lhs ^ gf_mul(g << 120, H2), inv_1h)
        J0 = b2i(ecb.decrypt(i2b(S)))
        nonce = i2b(gf_mul(gf_mul(J0, Hinv) ^ 128, Hinv))
        if gcm_tag(key, nonce, check_pt) == tags[2]:
            return nonce
    return None


# --------------------------------------------------------------------------
# Networking
# --------------------------------------------------------------------------
class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)), timeout=60)
        self.buf = b""

    def until(self, token):
        while token not in self.buf:
            d = self.s.recv(65536)
            if not d:
                raise EOFError(f"closed while waiting for {token!r}: {self.buf[-200:]!r}")
            self.buf += d
        head, self.buf = self.buf.split(token, 1)
        return head

    def send(self, text):
        self.s.sendall(text.encode() + b"\n")

    def tag_round(self, prompt):
        self.until(b"> ")
        self.send("".join(CHARS))
        lines = [l.strip() for l in self.until(prompt).split(b"\n") if l.strip()]
        return [[int(c, 16) for c in l.decode()] for l in lines]


def attempt(host, port):
    c = Conn(host, port)
    hi = c.tag_round(b"keys[0]> ")
    if len(hi) != 6 or any(len(x) != 16 for x in hi):
        raise ValueError(f"unexpected round-0 output: {hi}")

    H = recover_H(hi)
    if H is None:
        raise ValueError("H is not determined")
    t0 = time.time()
    key = recover_key(H, hi)
    if key is None:
        print(f"[-] key has more than {MAX_SPECIAL} digits in {{8,9}} ({time.time()-t0:.0f}s), retrying")
        return None
    print(f"[+] key   {key.hex()}  ({time.time()-t0:.0f}s)")

    c.send(key.hex())
    lo = c.tag_round(b"keys[1]> ")
    tags = {i: bytes((hi[i][j] << 4) | lo[i][j] for j in range(16)) for i in range(6)}
    nonce = recover_nonce(key, H, tags)
    if nonce is None:
        raise ValueError("nonce not found")
    print(f"[+] nonce {nonce.hex()}")

    c.send(nonce.hex())
    c.s.settimeout(10)
    try:
        while (d := c.s.recv(65536)):
            c.buf += d
    except socket.timeout:
        pass
    return c.buf.decode("latin1", "replace").strip()


def main(host, port):
    for n in range(1, 21):                      # fresh key and nonce per connection
        print(f"[*] attempt {n}")
        try:
            out = attempt(host, port)
        except (OSError, EOFError, ValueError) as e:
            print(f"[-] {type(e).__name__}: {e}")
            continue
        if out and "{" in out:
            print("[+]", out)
            return 0
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
