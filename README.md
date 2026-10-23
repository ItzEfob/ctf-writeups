# CTF writeups

Writeups and solvers from CTFs I've played, one folder per competition.

Every writeup is tested end-to-end against a local copy of the challenge, and
targets challenges with per-instance dynamic flags — so each one shows how to
reach the flag on *any* instance, not just a hardcoded answer.

## Competitions

| Competition | Date | Result |
| --- | --- | --- |
| [Black Hat MEA CTF 2026 Qualifiers](blackhat-mea-2026/) | Oct 2026 | 227 pts |
| [pwnsec CTF 2026](pwnsec-2026/) | Oct 2026 | 1st place, human division |

## Writeups

### [Black Hat MEA CTF 2026 Qualifiers](blackhat-mea-2026/)

| Challenge | Category | Idea |
| --- | --- | --- |
| [Popcnt Oracle](blackhat-mea-2026/popcnt-oracle/) | Crypto | RSA popcount oracle leaks the binary expansion of `m/n`; repair the one-sided noise with redundant chains and a DFS |
| [TripleR](blackhat-mea-2026/tripler/) | Crypto (hard) | AES-GCM nonce reuse plus multi-byte UTF-8 characters makes half-tags linear in the key |
| [teto](blackhat-mea-2026/teto/) | Pwn | A Tetris clone whose bounds check *is* the field the write corrupts — one OR-bit per piece, all the way up to `main`'s saved return |

### [pwnsec CTF 2026](pwnsec-2026/)

Writeups in progress.

## Layout

```
<competition>/
├── README.md          competition index
└── <challenge>/
    ├── README.md      the writeup
    ├── prob.py        original challenge source, where provided
    └── solve.py       self-contained solver
```

Larger solvers get a `solve/` directory instead of a single `solve.py`.
