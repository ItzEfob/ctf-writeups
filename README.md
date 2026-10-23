# CTF writeups

Writeups and solvers from CTFs I've played, one folder per competition.

Every writeup is tested end-to-end against a local copy of the challenge, and
targets challenges with per-instance dynamic flags — so each one shows how to
reach the flag on *any* instance, not just a hardcoded answer.

## Competitions

| Competition | Date | Result |
| --- | --- | --- |
| [Black Hat MEA CTF 2026 Qualifiers](blackhat-mea-26-quals/) | Aug 2026 | 227 place |

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
