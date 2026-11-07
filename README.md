# CTF writeups

Writeups and solvers from CTFs I've played, one folder per competition.

Every solver is tested end-to-end against a local copy of the challenge or its
original attachments. For challenges with per-instance dynamic flags, the
writeup shows how to reach the flag on *any* instance, not just a hardcoded
answer. OSINT writeups document the investigation path instead.

## Competitions

| Competition | Date | Result |
| --- | --- | --- |
| [Black Hat MEA CTF 2026 Qualifiers](blackhat-mea-26-quals/) | Aug 2026 | 227 place |
| [chronosCTF 2026](chronos-26/) | Nov 2026 | TBD |

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
