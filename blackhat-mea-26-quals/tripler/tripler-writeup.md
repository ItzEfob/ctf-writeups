# TripleR

**Black Hat MEA CTF 2026 Qualifiers · Crypto (hard)**

> TL;DR: AES-GCM with a fixed key and a fixed nonce, encrypting a message that
> contains the key itself, and showing only half of each tag. Equal-length
> messages give `H`. The real leak is that Python iterates *characters*:
> multi-byte UTF-8 characters slide the key hex across a fixed keystream, so
> tag differences become linear in the key. A small guess about which hex
> digits are `8` or `9` closes the gap, and the nonce falls out afterwards.

## The challenge

```python
signal.alarm(300)
keys = [os.urandom(16), os.urandom(16)]
for r in [0, 1]:
    for ch in input("> ")[:6]:
        cipher = AES.new(keys[0], AES.MODE_GCM, nonce=keys[1])
        cipher.encrypt(f"{ch}|encrypted by {keys[0].hex()}".encode())
        print(cipher.hexdigest()[r::2])
    assert input(f"keys[{r}]> ") == keys[r].hex()
print(os.environ.get("DYN_FLAG", "BHFlagY{0000000000000000}"))
```

- One AES key and one 16-byte nonce, reused for every encryption.
- Each round we send up to **6 characters**; each one is encrypted inside the
  plaintext `"<ch>|encrypted by <key hex>"`, and only the tag is printed.
- Round 0 prints `hexdigest()[0::2]`: the **high nibble** of each tag byte, 64
  of the 128 bits. Round 1 prints the low nibbles.
- We must type the **key** right after round 0, so it has to come from half-tags
  alone. The **nonce** is due after round 1.
- Five minutes per connection, with a fresh key and nonce every time.

## GCM in one formula

With no associated data, a GCM tag over `nb` ciphertext blocks `C_1 … C_nb` is

```
T = C_1·H^(nb+1) ⊕ C_2·H^nb ⊕ … ⊕ C_nb·H^2 ⊕ L·H ⊕ S
```

where every product is in GF(2^128), `H = AES_K(0^128)`, `L` encodes the
message length in bits, `S = AES_K(J0)`, and the last block is zero-padded.
The ciphertext is `C = P ⊕ KS` for a keystream `KS` that depends only on the key
and nonce. Because both are reused, **`KS`, `H` and `S` are the same for every
message**. That is what we exploit.

## Choosing the six characters

`input()` returns a `str`, so `for ch in ...` iterates **characters**, while
`.encode()` produces **bytes**. A character can be 1 to 4 bytes of UTF-8, so we
control the message length:

| char | UTF-8 bytes | message length | blocks |
|---|---|---|---|
| `A` | 1 | 47 | 3 |
| `B` | 1 | 47 | 3 |
| `é` | 2 | 48 | 3 |
| `ü` | 2 | 48 | 3 |
| `€` | 3 | 49 | 4 |
| `𝄞` | 4 | 50 | 4 |

That gives two **equal-length pairs**, `(A, B)` and `(é, ü)`, and two
**length-shifted pairs** with the same block count, `(A, é)` at 47/48 and
`(€, 𝄞)` at 49/50. We send `ABéü€𝄞` in both rounds.

## Stage 1: recover `H`

Take two messages of the same length that differ only in their first
character. Same length means the same keystream positions and the same `L`, so
everything cancels in the tag difference except the first block:

```
T_A ⊕ T_B = (P_A ⊕ P_B)_block1 · H^4 = Δ · H^4
```

`Δ` is known (`"A" ⊕ "B"`), and multiplying by a known field element is linear
over GF(2). So each visible tag bit is one linear equation in the 128 unknown
bits of `X = H^4`. Each pair gives 64 equations, and the two pairs give 128,
which is enough to solve for `X` exactly.

Taking the fourth root is free in a field of characteristic 2: squaring is a
bijection, and `X^(2^128) = X`, so `H = X^(2^126)`, which is 126 squarings.

## Stage 2: recover the key from half the tags

Compare `"A|encrypted by <hex>"` (47 bytes) with `"é|encrypted by <hex>"`
(48 bytes). The suffix is identical but **shifted one byte to the right** in
the longer message, while the keystream stays where it is. Both messages have
3 blocks, so at every position they share, the keystream cancels in the XOR:

```
C_A[i] ⊕ C_é[i] = P_A[i] ⊕ P_é[i]        for i < 47
```

`P_A[i] ⊕ P_é[i]` is the key hex XORed with itself shifted by one position.
That is **linear in the key-hex bytes**. Only the 48th byte of the longer
message has nothing to cancel against, and it leaves one unknown keystream byte.
So the tag difference for a length-shifted pair is linear in:

- 256 bits of key hex,
- plus 8 bits of keystream for that pair.

Two such pairs give **128 equations** over **272 unknowns**. That is not enough
on its own, but lowercase hex is far from random bytes:

| char | hex | binary |
|---|---|---|
| `0`–`7` | `0x30`–`0x37` | `0011 0xxx` |
| `8`, `9` | `0x38`, `0x39` | `0011 100x` |
| `a`–`f` | `0x61`–`0x66` | `0110 0xxx` |

For every one of the 32 hex characters, bit 7 is 0, bit 5 is 1, and bit 6 ⊕
bit 4 = 1. That adds 96 equations: **224 equations, 48 free dimensions**. 2^48
candidates is far too many to brute force inside five minutes.

### The bit-3 trick

Look at bit 3 in the table: it is **1 only for `8` and `9`**. And when it is 1,
bits 6, 2 and 1 are forced to 0 as well.

So guess the set `S` of positions holding an `8` or a `9`. That fixes bit 3 of
all 32 characters: 32 more linear equations, which brings the 48 free
dimensions down to **16**. Each position in `S` adds 3 more equations on top.
Whatever survives (at most 2^16 candidates, usually far fewer) is filtered with
numpy, since every byte must be valid hex, and then confirmed with one AES call
each: the real key satisfies `AES_K(0) == H`.

The linear algebra alone does not reject bad guesses. We measured it: for small
`|S|`, nearly every wrong `S` still gives a consistent system (299 of 300 random
wrong guesses at `|S| = 3`). The hex filter and the `AES_K(0) == H` check are
what make the search sound.

Each hex digit is an `8` or a `9` with probability 1/8, so a random key has 4
of them on average. We search `|S| = 0, 1, …, 6` in order, 1,149,017 subsets.
That is cheap because the bit-3 equations are solved once up front, and each
guess only adds a handful of rows to a 16-dimensional system.

| | |
|---|---|
| keys with at most 6 digits in {8, 9} | **90.4 %** |
| expected connections | **1.11** |
| time to exhaust `|S| ≤ 6` | about 40 s |
| typical time when `|S|` is small | under 3 s |

When a key has more than six, the solver gives up after the search and
reconnects for a fresh key.

## Stage 3: recover the nonce

After submitting the key we send the same six characters again and read the
low nibbles, which completes all six tags. Knowing the key, we know every
plaintext, so strip the known part out of each tag:

```
E = T ⊕ GHASH_H(P) = (masked keystream terms) ⊕ S
```

For the 48-byte message (3 blocks) and the 49-byte message (4 blocks, the last
holding one byte):

```
E_48 = KS1·H^4 ⊕ KS2·H^3 ⊕ KS3·H^2 ⊕ S
E_49 = KS1·H^5 ⊕ KS2·H^4 ⊕ KS3·H^3 ⊕ KS4[0]·H^2 ⊕ S
```

Multiply the first by `H` and add:

```
E_49 ⊕ H·E_48 = KS4[0]·H^2 ⊕ S·(1 ⊕ H)
```

Every full keystream block cancels, leaving one unknown byte. For each of the
256 guesses we compute `S`, decrypt it to get `J0 = AES_K^-1(S)`, and invert
GCM's nonce derivation. For a 16-byte nonce, `J0 = GHASH_H(nonce)`, which is

```
J0 = ((N·H) ⊕ 128)·H     so     N = ((J0·H^-1) ⊕ 128)·H^-1
```

The right guess is the one whose nonce reproduces a full tag exactly.

## Solver

[`solve.py`](solve.py) is self-contained (Python 3, pycryptodome, numpy).

```
python3 solve.py HOST PORT
```

To try it locally:

```bash
DYN_FLAG='BHFlagY{local_test}' \
  socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 -u prob.py"
python3 solve.py 127.0.0.1 1337
```

A local run:

```
[*] attempt 1
[+] key   2741bba9df5f9ba2042290570eb10826  (3s)
[+] nonce 7e25332cda01fa7a791072db36900930
[+] BHFlagY{l0cal_tripler_test}
```

## Takeaways

- Nonce reuse in GCM does not only break confidentiality, it hands you `H`,
  and with `H` every tag becomes a polynomial you can do linear algebra on.
- Characters and bytes are different things. `for ch in input()` with a later
  `.encode()` let a 4-byte character move the plaintext against a fixed
  keystream, which turned "known plaintext suffix" into "linear in the key".
- Structured secrets are smaller than they look. A hex string carries 4 bits
  per byte, and the leftover bits are mostly fixed, which is free linear
  algebra. The one bit that is not fixed only varies for two digits out of 16,
  so guessing it is cheap.
- Count equations against unknowns before writing code. Here the count said
  "48 dimensions short" up front, which pointed straight at the hex structure.
