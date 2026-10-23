# Popcnt Oracle

**Black Hat MEA CTF 2026 Qualifiers · Crypto**

> TL;DR: an RSA decryption oracle that only tells you the *popcount* of the
> plaintext. Multiplying the ciphertext by `2^e` doubles the hidden plaintext,
> and doubling only changes the popcount when it wraps around `n`, so the
> oracle leaks the binary expansion of `m/n`. The leak is noisy, but the noise
> is one-sided, and that is what makes it repairable.

## The challenge

```python
e = 65537
while True:
    p = getPrime(1024)
    q = getPrime(1024)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q
d = pow(e, -1, (p-1)*(q-1))
m = secrets.randbelow(n)
c = pow(m, e, n)

print(f"{e = }")
print(f"{n = }")
print(f"{c = }")
while True:
    x = int(input("x> "))
    if x == m:
        print(flag)
        break
    print(pow(x, d, n).bit_count())
```

Textbook RSA-2048 with a random secret `m`. We get `n`, `e`, `c`, and unlimited
queries to an oracle that decrypts anything we send and returns the number of
1-bits in the result. Send `m` itself and we get the flag. The flag is
per-instance, so the goal is a solver that recovers `m` on any instance.

## Step 1: steering the plaintext

Textbook RSA is multiplicatively homomorphic. If we send `x = c · t^e mod n`,
the oracle computes

```
x^d = (m^e · t^e)^d = m · t   (mod n)
```

so we learn `popcount(t·m mod n)` for any `t` we like, without knowing `m`.

## Step 2: doubling is a shift, until it wraps

Pick `t = 2^i`. Write `w_i = 2^i·m mod n`. Going from `w_i` to `w_{i+1}` there
are only two cases:

- `2·w_i < n`: then `w_{i+1} = 2·w_i`, a plain left shift. **A left shift never
  changes the popcount.**
- `2·w_i ≥ n`: then `w_{i+1} = 2·w_i − n`, a subtraction that scrambles the
  bits, so the popcount almost always changes.

So comparing consecutive answers tells us whether each doubling wrapped:

```
b_i = 1  if popcount(w_{i+1}) != popcount(w_i)   (wrapped)
b_i = 0  otherwise                                (did not wrap)
```

Those wrap bits are not random. Since `w_i / n` is the fractional part of
`2^i · m/n`, the bit `b_i` is exactly the `(i+1)`-th binary digit of `m/n`.
About 2048 of them pin `m/n` precisely enough to recover `m`, at one query per
bit.

## Step 3: the trap, an almost-correct answer

The straightforward solve is "query 2049 doublings, read off the bits, rebuild
`m`". It does not work, and the way it fails is instructive: the rebuilt value
matches the real `m` in its leading digits and then diverges into garbage.
It looks like an off-by-one, and it is very tempting to search a few integers
around it. That never works, because the error is enormous.

The cause is the "almost always" in step 2. When a wrap happens, the two
popcounts belong to two unrelated ~2048-bit numbers, each with popcount around
1024, and occasionally they are equal by coincidence. The wrap then goes
unnoticed and we record a 0 where the truth is 1.

We measured it on 40 simulated instances:

| | |
|---|---|
| hidden wraps | about **1 in 81** wraps |
| wrong bits per 2048-bit chain | **12.7** on average (min 3, max 19) |
| direction of every error | a true **1 read as 0**, never the reverse |

A dozen bad bits is enough to destroy a naive reconstruction, since everything
after the first one is wrong. But the last row is the important one.

## Step 4: one-sided noise is repairable

The errors only go one way:

- an **observed 1** (popcount changed) is **certain**: equal-length shifts can
  never change the popcount, so a change proves a wrap happened.
- an **observed 0** is only **probable**: usually right, occasionally a hidden 1.

So every observed 1 is a hard constraint. To get enough of them we query more
than one chain. With `t = r·2^i` the oracle leaks the binary expansion of
`frac(r·m/n)`, a different view of the same `m`. We take `r = 1` as the main
chain and `r = 3` (then `5`, then `7` if needed) as checks.

Then we rebuild `m` bit by bit with a depth-first search over the main chain:

- A prefix `B` of length `t` of the wrap bits pins `m` to an interval:
  `ceil(n·B/2^t) ≤ m < ceil(n·(B+1)/2^t)`.
- That interval predicts a prefix of `frac(r·m/n)` for every check chain `r`.
  If a check chain **observed a 1 where the interval predicts a 0**, the branch
  is impossible and gets pruned.
- Where the main chain observed a 1, there is only one child (it is certain).
  Where it observed a 0, try 0 first (usually right), then 1 (a hidden wrap).
- When the interval shrinks to a single integer, check `pow(m, e, n) == c`.

Wrong branches usually contradict an observed 1 within a few bits, so the
search barely branches: typically a fraction of a second for all 2048 bits.

Results over the same 40 simulated instances:

| | |
|---|---|
| solved | **40 / 40** |
| chains needed | 2 chains in 33 runs, 3 chains in 7 |
| worst reconstruction time | 13 s |

## Step 5: making it fast enough over the network

Each chain is 2053 queries, and none of them depends on an earlier answer. The
whole chain can be computed up front (`x_{i+1} = x_i · 2^e mod n`) and streamed
to the server in one write, then the answers read back in order. That turns
thousands of round trips into one, which is the difference between a couple of
minutes and much longer. The solver fetches two chains, tries to reconstruct,
and only fetches another chain if it has to.

## Solver

[`solve.py`](solve.py) is self-contained (Python 3 + pycryptodome).

```
python3 solve.py HOST PORT
```

To try it without the remote, serve the challenge locally:

```bash
DYN_FLAG='BHFlagY{local_test}' \
  socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 -u prob.py"
python3 solve.py 127.0.0.1 1337
```

A local run (the progress counters are omitted):

```
[*] n is 2048 bits, e = 65537
[*] chain r=1: 2053 queries
[*] chain r=3: 2053 queries
[*] not enough redundancy yet, adding another chain
[*] chain r=5: 2053 queries
[+] m recovered and verified against c
[+] BHFlagY{l0cal_popcnt_test}
```

## Takeaways

- A popcount looks like it leaks almost nothing. Combined with a homomorphic
  scheme it leaks everything, because the attacker controls *which* plaintext
  gets measured.
- When an attack returns something almost right, do not search near it. Measure
  the error against a synthetic instance where you know the answer. Here that
  measurement is what revealed the one-sided noise and the fix.
- Asymmetric noise is a gift: the side that cannot be wrong becomes a hard
  constraint.
- Non-adaptive queries can be pipelined. Always check whether the next query
  actually depends on the last answer.
