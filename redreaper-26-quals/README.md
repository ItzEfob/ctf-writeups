# Red Reaper CTF 2026

Writeups for the challenges I worked on at Red Reaper CTF (November 2026). The PWN challenges solved during the event aren't covered here yet.

## Solved

| Challenge | Category | Difficulty | Points | Key technique |
|---|---|---|---|---|
| [Bone Machine](bone-machine/) | Reverse | Hard | 100 | Static emulation of an encrypted stack VM; ptrace anti-debug; FNV-gated decoy flag |
| [The Last Rite](the-last-rite/) | Reverse | IDK | 100 | Register VM with a self-hashing key; branch-free ARX + S-box cipher inverted step by step with z3 |
| [Signal Fire](signal-fire/) | Reverse | Medium | 100 | Checks hidden in SIGUSR1/SIGUSR2 handlers; exit via deliberate SIGFPE + `siglongjmp` |
| [Ticket](ticket/) | DFIR | Medium | 100 | Hash-only threat intel: sandbox report → YARA strings → original research (ZombieBoy) |
| [Robben's](robbens/) | DFIR | Medium | 100 | Cowrie log vs pcap clock skew, HTTP stream reassembly, Mirai XOR string table (SORA) |
| [The Catch That Wasn't](the-catch-that-wasnt/) | Satellite | Hard | 100 | Discoverer XIV / CORONA 9009, the first mid-air capsule recovery |
| [The Star Outside the Crop](the-star-outside-the-crop/) | Satellite | Hard | 100 | Hubble first light: picking the right ESA/Hubble catalog entry |
| [bloody](bloody/) | OSINT | Warm-up | | Anime location from a nameplate (*Another*, episode 9) |

## Unsolved (post-mortems)

| Challenge | Category | Difficulty | Points | Where it stalled |
|---|---|---|---|---|
| [The Last Transmission](the-last-transmission/) | OSINT | Hard | 496 | Ambiguous "direction" and death-count fields; ran out of attempts |
| [ghostframe96](ghostframe96/) | OSINT | | | All six fields found and corroborated; exact wording never matched |
| [AmanaPay](amanapay/) | DFIR | Insane | 451 | Key derivation for the first encrypted asset |

## Running the solvers

```
pip install z3-solver dpkt
python3 bone-machine/solve.py  bone_machine
python3 the-last-rite/solve.py last_rite
python3 signal-fire/solve.py   signal_fire
python3 robbens/solve.py       capture.pcap cowrie.json robben.rodata.bin
```

All of them are static. None execute the challenge binaries or any commands from the evidence.
