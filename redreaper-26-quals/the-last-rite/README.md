# The Last Rite

| Category | Difficulty | Points | Author |
|---|---|---|---|
| Reverse | IDK | 100 | DRX0 |

> Candles burn around an open grave. Speak the last rite.

**Flag:** `RxR{h0ll0w_bur13d_k1ll_e14678}`

## TL;DR

This is the big sibling of *Bone Machine*. A **register VM** with 3,684 encrypted instructions computes a branch-free ARX + S-box cipher over the input and compares the result with 48 expected bytes. Running z3 over the whole cipher at once stalls because of full diffusion. Instead, I recorded each of the 224 state updates symbolically and **ran the cipher backwards** from the expected output, solving one small equation per step. It takes about 1.5 seconds.

## Recon

```
$ objdump -h last_rite
  4 rxguard   0000027c  00000000004070b0   ...   (code)
  7 rxprog    00007320  0000000000409220   ...   (encrypted bytecode)
```

The prompts are encrypted. The only readable strings are `/proc/self/status` and `TracerPid:`.

## Protections

| Trick | Effect |
|---|---|
| Signal handlers on SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGTRAP | Makes dynamic analysis noisy |
| `TracerPid` check | If a debugger is attached, the key is XORed with `0x5ea1ed00` |
| Key = FNV-1a hash of the VM's own code (`rxguard`) | Any breakpoint (`int3`) or patch in the VM silently corrupts the key |
| FNV-gated alternate path (`0x401460`) | The same decoy trick as Bone Machine |

All three active protections disappear if you never run the binary, so the whole solve is static.

## The VM

`rxprog` is `0x7320 = 3684 × 8` bytes. Each 8-byte instruction is decrypted with a per-index hash of the key (multiply, xorshift, multiply, as in the solver). After decryption, the fields are:

```
byte0 - 9 -> index into a 0xe8-entry jump table
byte1 & 7 -> rd    byte2 & 7 -> rs    byte3 & 7 -> rt    bytes4..7 -> imm32
```

Mapping the jump-table targets gives a small RISC instruction set: `movi, mov, add/addi, sub, mul, and, or, xor, shli, shri, rol, roli, ld8, st8, ld32, st32, jmp, jnz, halt`. VM memory is the 0x400-byte global buffer at `0x4122f0`:

| Offset | Contents |
|---|---|
| `0x00` | input (up to 48 bytes) |
| `0x30` | 16-byte key |
| `0x40` | 48 expected bytes |
| `0x70` | length |
| `0x80` | S-box, built at runtime |
| `0x380+` | scratch area for junk stores |

## Deobfuscation

Emulating the VM showed:

- **No conditional branches are ever taken.** The 202 `jmp`s only shuffle the code's layout, so execution is one straight line ending at `halt`.
- There are junk instructions (`or r7,r7,r7`, `mov r7,r7`, `addi r7,r7,0`) and junk stores into the scratch area.
- The final check is `r0 |= state[k] ^ expected[k]` for all 12 words. A return of 0 means accepted.

After stripping the junk, the real work is 224 updates of the form "word `a` = f(word `a`, other words, key)":

```
w[a] *= odd_const                         (invertible mod 2^32)
w[a] += w[b]
w[a]  = rol(w[a], w[b] & 31) ^ f(key)
w[a] ^= rol(w[b], c)
w[a] ^= w[b] * (w[c] | 1)
w[a]  = SBOX[each byte of w[a]]           (the S-box is a permutation)
```

Every step can be undone if you know the other words.

## Inverting it

1. I did a forward symbolic pass with z3, giving each state word a new version on every store: `s3_7 = expr(s3_6, s8_2, ...)`.
2. The 12 final comparison terms fix the final version of every word.
3. Walking the steps in reverse, each step has exactly one unknown (the previous version of the word being written). z3 solves the arithmetic steps instantly. For S-box steps I used an inverse table, because z3 is slow with a 256-entry array.

The trailing zero padding came out clean (the flag is 30 bytes), which confirms the inversion.

## Dead ends

- Running z3 on the whole cipher at once: every output word depends on every input byte, and it never finished.
- I assumed a length of 31 because other lengths were rejected instantly. That turned out to be a coincidence: the length word isn't mixed into the state.

## Solve

```
$ pip install z3-solver
$ python3 solve.py last_rite
RxR{h0ll0w_bur13d_k1ll_e14678}
emulator check r0 = 0x0 (0 = accepted)
$ echo 'RxR{h0ll0w_bur13d_k1ll_e14678}' | ./last_rite
rite: [+] The dead rest. That's your flag.
```
