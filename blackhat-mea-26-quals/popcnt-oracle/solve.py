#!/usr/bin/env python3
"""
Popcnt Oracle (Black Hat MEA 2026 quals, crypto) -- solver.

    python3 solve.py HOST PORT

The service is textbook RSA-2048 with a decryption oracle that only leaks the
popcount:  send x, receive popcount(x^d mod n).  Send x == m to get the flag.

Idea in one paragraph:
  Querying x = c * (r * 2^i)^e  makes the oracle return popcount(r*m*2^i mod n).
  Doubling mod n is a plain left shift unless it wraps past n, and a left shift
  never changes the popcount.  So "popcount unchanged between step i and i+1"
  means "no wrap", and the sequence of wraps is the binary expansion of
  frac(r*m / n).  The catch: when a wrap DOES happen, the two popcounts are of
  unrelated ~1024-weight numbers and collide about 1 time in 80, hiding the
  wrap.  The noise is one-sided -- an observed wrap is certain, an observed
  "no wrap" is only probable -- so a DFS over m's bits that treats every
  observed wrap as a hard constraint (checked against extra chains r = 3, 5, 7)
  repairs the corrupted bits.
"""
import re
import socket
import sys
import threading
import time

MULTS = [1, 3, 5, 7]      # extra chains are only fetched if needed
EXTRA_BITS = 4
NODE_BUDGET = 150_000


# --------------------------------------------------------------------------
# Reconstruction (pure math, no networking)
# --------------------------------------------------------------------------
def bits_from_popcounts(pcs):
    """pcs[i] = popcount(r*m*2^i mod n)  ->  wrap bits, MSB first."""
    return [1 if pcs[i + 1] != pcs[i] else 0 for i in range(len(pcs) - 1)]


def _pack(bits, N):
    v = 0
    for b in bits[:N]:
        v = (v << 1) | b
    return v << (N - min(len(bits), N))


def recover(n, chains, e=None, c=None, max_nodes=NODE_BUDGET):
    """
    chains: {r: wrap bits of r*m mod n}, must contain r == 1.
    Returns m, or None if the node budget runs out.

    A prefix B of length t of the main chain pins m to the interval
    [ceil(n*B/2^t), ceil(n*(B+1)/2^t)).  For every other chain r, that interval
    predicts a prefix of frac(r*m/n); if the observed chain has a 1 (a certain
    wrap) where the prediction has a 0, the branch is impossible.
    """
    N = min(len(b) for b in chains.values())
    obs = {r: _pack(b, N) for r, b in chains.items()}
    main = chains[1]
    others = [r for r in chains if r != 1]
    depth_needed = n.bit_length() + 2

    stack = [(0, 0)]            # (depth t, prefix B)
    nodes = 0
    while stack:
        t, B = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return None

        if t:
            den = 1 << t
            lo = -((-n * B) // den)
            hi = -((-n * (B + 1)) // den)
            if lo >= hi:
                continue
            if hi - lo == 1:                       # pinned to one integer
                if e is None or pow(lo, e, n) == c:
                    return lo
                continue

            ok = True
            for r in others:
                a, z = r * lo, r * (hi - 1)
                qa = a // n
                if z // n != qa:                   # interval straddles a wrap
                    continue
                vlo, vhi = a - qa * n, z - qa * n
                plo = (vlo << N) // n
                phi = (vhi << N) // n
                x = plo ^ phi
                L = N if x == 0 else N - x.bit_length()   # agreed prefix length
                if L == 0:
                    continue
                sh = N - L
                if (obs[r] >> sh) & ~(plo >> sh):  # observed 1 where 0 predicted
                    ok = False
                    break
            if not ok:
                continue

        if t >= depth_needed:
            continue
        stack.append((t + 1, (B << 1) | 1))
        if main[t] == 0:                           # a 0 may be a hidden 1
            stack.append((t + 1, B << 1))          # LIFO: tried first
    return None


# --------------------------------------------------------------------------
# Networking
# --------------------------------------------------------------------------
class Oracle:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)), timeout=60)
        self.s.settimeout(300)
        self.buf = b""
        while self.buf.count(b"\n") < 3:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("server closed during the header")
            self.buf += d
        head = self.buf.decode("latin1")
        self.e = int(re.search(r"e = (\d+)", head).group(1))
        self.n = int(re.search(r"n = (\d+)", head).group(1))
        self.c = int(re.search(r"c = (\d+)", head).group(1))
        self.buf = self.buf.split(b"\n", 3)[3]

    def _send(self, blob):
        try:
            self.s.sendall(blob)
        except OSError:
            pass

    def ask_many(self, xs):
        """All queries are non-adaptive: stream them out, read answers back."""
        blob = b"\n".join(b"%d" % x for x in xs) + b"\n"
        threading.Thread(target=self._send, args=(blob,), daemon=True).start()
        out, t0, mark = [], time.time(), 0
        while len(out) < len(xs):
            d = self.s.recv(262144)
            if not d:
                raise EOFError(f"server closed after {len(out)}/{len(xs)}")
            self.buf += d
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                line = line.replace(b"x> ", b"").strip()
                if line.isdigit():
                    out.append(int(line))
            if len(out) - mark >= 500:
                mark = len(out)
                print(f"\r    {len(out)}/{len(xs)}  {time.time()-t0:.0f}s",
                      end="", flush=True)
        print(f"\r    {len(out)}/{len(xs)}  {time.time()-t0:.0f}s")
        return out

    def answer(self, m):
        self.s.sendall(b"%d\n" % m)
        self.s.settimeout(30)
        out = self.buf
        try:
            while b"}" not in out:
                d = self.s.recv(65536)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        return out.decode("latin1")


def main(host, port):
    o = Oracle(host, port)
    n, e, c = o.n, o.e, o.c
    print(f"[*] n is {n.bit_length()} bits, e = {e}")

    N = n.bit_length() + EXTRA_BITS
    two_e = pow(2, e, n)
    chains, m = {}, None

    for r in MULTS:
        print(f"[*] chain r={r}: {N + 1} queries")
        xs, cur = [], c * pow(r, e, n) % n        # decrypts to r*m
        for _ in range(N + 1):
            xs.append(cur)
            cur = cur * two_e % n                 # ... then r*m*2, r*m*4, ...
        chains[r] = bits_from_popcounts(o.ask_many(xs))
        if len(chains) < 2:
            continue
        m = recover(n, chains, e, c)
        if m is not None:
            break
        print("[*] not enough redundancy yet, adding another chain")

    if m is None:
        print("[-] failed with every chain; reconnect and rerun")
        return 1
    print("[+] m recovered and verified against c")
    txt = o.answer(m)
    hit = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", txt)
    print("[+]", hit.group(0) if hit else txt.strip()[-300:])
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
