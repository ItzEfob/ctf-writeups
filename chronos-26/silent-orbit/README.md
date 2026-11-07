# Silent Orbit

**Category:** Network · **Difficulty:** Easy · **Points:** 120 · **Author:** Cosmin Gorea

> A state-sponsored actor suppressed telemetry at a satellite ground station. Identify
> the anomaly and find the suppressed record.

The card on the scoreboard mentions a Windows `telem_parser.exe`, but the zip I got
(`silent-orbit-cfdp.zip`) is a different version: a raw capture
(`civil_downlink.bin`), a `mission-profile.txt` with exact relay rules, a README and
`SHA256SUMS`. The README sets the real goal: rebuild the **CFDP NAK PDU** the normal
relay would have sent, and submit it as `CSCTF{UPPERCASE_HEX}`. A NAK is the "I'm
missing these byte ranges, resend them" message.

All the hashes in `SHA256SUMS` matched.

## How I approached it

The mission profile is basically a spec, so instead of poking at the bytes by hand I
wrote the relay it describes and logged a decision for every packet. That way I could
see exactly why each packet was accepted or skipped. Script:
[`silent-orbit-relay.py`](silent-orbit-relay.py).

The layers:

1. **Space Packets.** Each one has a 6-byte header, and its last field is the data
   length minus 1. Walking header → data → header splits the 3432 bytes into exactly
   **188 packets**, none truncated.
2. **Filter.** Keep only telemetry packets with PVN 0, APID `0x321`, no secondary
   header and sequence flags `11`.
3. **CFDP PDUs.** Keep only the target transaction `01/07/02` (one-byte IDs, version
   001, toward the receiver, acknowledged mode, no CRC, small file), where the declared
   length exactly fills the packet.
4. **State machine.** Wait for Metadata, collect File Data coverage, and take a
   snapshot at the first valid EOF.

## The decoys

- **Packet 1** has a perfectly valid Metadata PDU for `01/07/02`, but it's on **APID
  `0x012`**. It looks right and is supposed to be skipped.
- **Packet 2** is on the right APID but belongs to another transaction (`03/09/02`).
- At the end there's a duplicate (`[191,192)` twice) and overlapping chunks
  (`[0,2)`, `[1,4)`, `[0,4)`) to check that the coverage merging is correct.

The real Metadata is `07 0F 000000C0 00 00`: checksum type 15, file size **192**,
empty filenames. The EOF is `04 00 00000000 000000C0`, and it passes every check.

## Result

After merging, 12 single bytes never arrived:
5, 19, 35, 51, 68, 83, 101, 119, 138, 154, 171 and 187.

Building the NAK:

| Bytes | Meaning |
|---|---|
| `28` | version 001, directive, **toward sender**, acknowledged mode, no CRC, small file |
| `0069` | data-field length 105 = 1 + 8 + 12×8 |
| `00` | 1-byte entity/sequence-number lengths, no segmentation |
| `01 07 02` | source / sequence / destination |
| `08` | NAK directive |
| `00000000 000000C0` | scope [0, 192) |
| `00000005 00000006` … `000000BB 000000BC` | one pair per missing byte |

**Flag:**
```
CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}
```

## Notes to self

- The easiest bit to get wrong is the **direction bit** in the NAK's first byte. A NAK
  goes *toward the sender*, so it's `0x28`, not `0x20`.
- Logging a decision for every packet made the decoys obvious right away. Worth doing
  for any "follow this spec" challenge.
