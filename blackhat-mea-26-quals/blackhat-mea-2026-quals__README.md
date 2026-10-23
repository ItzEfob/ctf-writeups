# Black Hat MEA CTF 2026 Qualifiers

Played October 2026. Final score: 227 points.

| Challenge | Category | Idea |
| --- | --- | --- |
| [Popcnt Oracle](popcnt-oracle/) | Crypto | RSA popcount oracle leaks the binary expansion of `m/n`; repair the one-sided noise with redundant chains and a DFS |
| [TripleR](tripler/) | Crypto (hard) | AES-GCM nonce reuse plus multi-byte UTF-8 characters makes half-tags linear in the key |
| [teto](teto/) | Pwn | `set_cell` accepts `y == -1`, so the write lands on the `width` field that bounds it; one OR-bit per Tetris piece, up to `main`'s saved return |

All three challenges used per-instance dynamic flags, so each writeup shows how
to reach the flag on any instance, with a solver tested end-to-end against a
local copy of the challenge.

The crypto folders contain the original `prob.py`, a self-contained `solve.py`,
and a `README.md` with the full writeup. `teto/` ships the challenge source and
a two-file solver under `solve/`.
