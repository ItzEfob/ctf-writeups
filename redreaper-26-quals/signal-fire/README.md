# Signal Fire

| Category | Difficulty | Points | Author |
|---|---|---|---|
| Reverse | Medium | 100 | DRX0 |

> Light the signal fire.

**Flag:** `RxR{gr1m_b0g_v31l_df46cd}`

## TL;DR

The character checks don't happen in `main`. They happen inside **signal handlers**. `main` raises SIGUSR1 or SIGUSR2 once per character, then deliberately divides by zero, and the SIGFPE handler `siglongjmp`s back to print the verdict. The check itself is a per-character XOR/add that inverts in one line.

## Control flow

`main` (`0x401030`) does the following:

1. Installs handlers: SIGUSR1 → `0x401300`, SIGUSR2 → `0x401370`, SIGFPE → `0x4013e0`.
2. Calls `sigsetjmp`. If it returns `0x7e`, it prints `[+]` or `[-]` depending on a global "failed" flag at `0x408384`.
3. Otherwise it reads the input and sets `failed = strlen(input) ^ expected_len`.
4. For each index `i`, it calls `raise(i even ? SIGUSR1 : SIGUSR2)`.
5. It computes `(i + 0x7e) / global` where the global is 0. That `idiv` raises SIGFPE, whose handler calls `siglongjmp(env, 0x7e)`.

Stepping through this in a debugger means stopping on every one of those signals, which is the anti-analysis idea.

There's also the same FNV-gated decoy path as the author's other challenges (`0x401470`). It never runs.

## The check

Both handlers read the data block at `0x408020`: an 8-byte key `k8`, the expected length, and a table `tbl`. They are written differently (one subtracts, one XORs), but both reduce to:

```
in[i] ^ k8[i & 7] ^ byte(0xb1b7509a1e72f546 >> 8*(i & 7)) == (tbl[i] + 5*i) mod 256
```

so

```
in[i] = (tbl[i] + 5*i) ^ k8[i & 7] ^ byte(C >> 8*(i & 7))
```

## Solve

```
$ python3 solve.py signal_fire
RxR{gr1m_b0g_v31l_df46cd}
$ echo 'RxR{gr1m_b0g_v31l_df46cd}' | ./signal_fire
words: [+] The fire answers from the next hill. That's your flag.
```
