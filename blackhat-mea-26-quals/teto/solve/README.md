# teto — solver

Full chain: leak → widen → bit-write → shell. See the [writeup](../README.md)
for how and why.

## Requirements

| | |
| --- | --- |
| Python | 3.10+ |
| Packages | `pwntools` (`pip install -r requirements.txt`) |
| Target glibc | **2.39** (Ubuntu 24.04) |
| Challenge binary | `teto`, in the directory you run from, for local testing |

The glibc version is a hard requirement, not a suggestion — see *Porting* below.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
# against a live instance
python3 teto_exploit.py tcp.flagyard.com:1337

# against a local copy of the challenge
docker compose up -d            # from the challenge directory
python3 teto_exploit.py localhost:5000

# directly against the binary, no container
python3 teto_exploit.py
```

`--settle=<seconds>` raises the inter-step delay. It defaults to 0.06 locally
and is floored at 0.15 for remote targets. You should not normally need to
touch it: every step before the first width write blocks until the rendered
board matches the simulator, so the run is self-pacing. Raise it to `0.30` only
if you see a desync abort on a very slow link.

A full run plays ~104 pieces and takes 30–60 s.

## Files

| File | Role |
| --- | --- |
| `teto_exploit.py` | The exploit driver |
| `tetosim.py` | Faithful reimplementation of the game logic, plus an El-Tetris placement planner |

`tetosim.py` is not optional. The driver needs to know the exact board state to
choose placements, and it diffs the simulated board against the rendered frame
after every piece while `width == 10`, aborting on any divergence — so a
desync can't silently corrupt the write stage.

## Porting to another glibc

Two constants in `teto_exploit.py` are build-specific:

```python
RET_OFF    = 0x2A1CA   # main's return into __libc_start_call_main
TARGET_OFF = 0xEF3EA   # execvpe+0x42a: lea r11,/bin/sh @0xef409 ; call execve @0xef443
```

There's a runtime guard on `ret & 0xfff != 0x1ca`. If it trips, the target is
running a different glibc and both constants need re-deriving:

1. Run the exploit far enough to print `main ret`. Subtract the real
   `__libc_start_call_main` return offset for that build to get `RET_OFF`.
2. The write primitive can only **set** bits, so a usable target `T` must be a
   bitwise superset of the leaked return `A`. Enumerate every offset
   `⊇ (A & 0x1fffff)` and rank by `popcount(T ^ A)` — each differing bit costs
   one I piece, and you have 8 slots.
3. Pick the cheapest candidate that lands somewhere useful. `execvpe`'s exec
   path is convenient because it builds `argv` on the stack and calls `execve`
   with `/bin/sh` already loaded.

Section 6 of the writeup walks through this for glibc 2.39.

## Reliability

Deterministic. `rand()` is never seeded, so the piece order is identical every
run, and the leak removes any dependence on libc being 2 MiB-aligned. The only
non-determinism is network timing, which the frame-sync handles.
