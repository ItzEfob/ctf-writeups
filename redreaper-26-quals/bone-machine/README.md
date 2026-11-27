# Bone Machine

| Category | Difficulty | Points | Author |
|---|---|---|---|
| Reverse | Hard | 100 | DRX0 |

> An old machine rattles in the ossuary.

**Flag:** `RxR{sp3ctr3_fr0st_dr34d_61f59c}`

## TL;DR

A static, stripped x86-64 binary runs a small **stack VM** over encrypted bytecode. A `ptrace` anti-debug check silently changes the bytecode decryption key, so instead of debugging I decoded and emulated the VM in Python. The default program checks one invertible equation per character. A second, larger program is hidden behind an FNV-1a gate that never opens. It decodes to a convincing-looking flag that turned out to be the **decoy**.

## Recon

```
$ file bone_machine
ELF 64-bit LSB executable, x86-64, statically linked, stripped
$ strings bone_machine
== BONE MACHINE ==
feed it the right words:
The machine rattles and opens. That is your flag.
Denied.
```

The `.text` reference to `== BONE MACHINE ==` leads straight to `main` (`0x401030`).

## What main does

1. **FNV-1a gate.** It hashes the 16-byte block at `0x407040`. If the hash equals `0xede6c641`, it swaps the bytecode pointer to a 0x126-byte program at `0x4050c0`. Nothing in the binary ever writes that block, so as shipped the gate never opens.
2. **Anti-debug.** It calls a raw `ptrace(PTRACE_TRACEME)` syscall (`0x65`). If that fails, meaning a debugger is attached, it XORs the decryption key at `0x407024` with `0xb0e000`. Under gdb you therefore decode garbage opcodes and get `Denied.`, a nice trap.
3. **VM loop.** It reads up to 128 bytes of input and interprets the bytecode. Each opcode byte is decrypted on fetch:

```python
x = (i * 0x9e3779b1) ^ key
x ^= x >> 15; x *= 0x2c1b3c6d; x ^= x >> 12
opcode = (x ^ code[i]) & 0xff
```

## The instruction set

| op | meaning |
|---|---|
| `91` | push `input[i]` |
| `a4` / `63` | push `i` / push `strlen(input)` |
| `5c` / `e7` / `18` | push key byte / table byte / expected length |
| `3a xx` | push immediate |
| `2d 7b c3 6f 04 b9` | add, sub, mul, xor, and, `!=` |
| `45` | pop and OR into a global "failed" flag |
| `d2` | `i++` |
| `8e xx` | if `i < pop()`, jump back |
| `f0` | halt (success if the failed flag is 0) |

## The visible program

Decoded, the default program is a 23-byte loop that checks:

```
(input[i] ^ k8[i & 7]) + 25*i == tbl[i]   (mod 256)
```

for 31 characters. It inverts directly: `input[i] = (tbl[i] - 25*i) ^ k8[i & 7]`.

## The hidden program (decoy)

Decoding the 0x126-byte gated program with the normal key produces clean bytecode: a length check (32) followed by blocks of `push input[i]; push A; xor; push B; !=; fail|=`. That makes `input[i] = A ^ B`, which gives `RxR{p4ss1ng_h4unt_sh4d0w_d0f690}`.

It looks more "real" than the visible one: it's bigger, encrypted, and hidden behind a gate. But the platform accepted the **visible** flag. The hidden program is a deliberate rabbit hole for anyone who finds the gate and assumes it guards the real answer.

## Lessons

- When a binary punishes debugging, emulate it statically.
- A hidden code path isn't automatically the real one. Run the binary on both candidates and submit what it actually accepts first.

## Solve

```
$ python3 solve.py bone_machine
visible program accepts: RxR{sp3ctr3_fr0st_dr34d_61f59c}
hidden program decodes to: RxR{p4ss1ng_h4unt_sh4d0w_d0f690} (decoy)
```
