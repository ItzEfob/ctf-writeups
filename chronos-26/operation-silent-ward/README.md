# Operation Silent Ward (unsolved)

**Category:** Network · **Difficulty:** Hard · **Points:** 872 · **Author:** Dragoș Bacitea · **Status:** not solved

> A compromised medical-imaging device leaked patient data across a hospital network.
> The DICOM capture, device configuration, access ledger, SNMP alerts and recovered
> exfiltration stream must be treated as corroborating evidence rather than independent
> answers.

Attachments: `hospital_network.pcap`, `dicom_device.xml`, `patient_records.csv`,
`snmp_trap.log`, `exfil_stream.bin`

Flag: `sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8]`

I didn't get the flag. I'm writing up what I found anyway, because most of the
reconstruction worked, and a couple of the techniques are worth keeping.

## What happened (the reconstruction)

The scanner (`MEDSCAN-XR400`, 10.20.30.45) was in bad shape according to its own config:
- factory-default DICOM login `admin/admin123`
- a default SNMP community string
- no firewall and no encryption
- a "backup server" at `198.51.100.42:8443` added to its config

The pcap (Sep 1, 00:00–01:30) shows the whole sequence:

| Time | Traffic | Meaning |
|---|---|---|
| 00:00–00:25 | 50 × DICOM **C-ECHO** → archive 10.20.40.10 | normal heartbeat |
| 00:25–00:30 | 20 × DICOM **C-STORE** → 198.51.100.42:104 | the leak |
| 00:31–01:21 | 30 × SNMPv2 traps → router, with the stolen community | the "unusual polling" |
| 01:22–01:30 | 15 × `POST /api/upload` from the **archive** → 198.51.100.42:8443 | second stage |

## Things I found

**1. The exfil stream is XOR-encrypted with the device serial.** The end of the file is
the string `MEDSCAN-XR400-2019` repeated, which is what XOR with a run of zero bytes
looks like. The start decodes to `198.51.100.42`. One byte in the middle had been
replaced by `EF BF BD` (the UTF-8 "replacement character"), meaning the file went through
a bad text conversion at some point. That turns 1 byte into 3 and shifts everything
after it against the key, so I re-aligned it. The full decode is the destination IP,
then `0x20??` (almost certainly port **8443** = `0x20FB`, with the lost byte being
`FB`), then the campaign tag `ward_exfil_2026`.

**2. scapy lied to me (sort of).** The file was 30 bytes bigger than my packet math
predicted. It turned out scapy *rebuilds* packets instead of showing the raw bytes: the
real SNMP packets encode sysUpTime in 4 bytes and scapy re-encodes it in 3. So that was
harmless, but from then on I parsed the pcap by hand.

**3. There's a hidden marker inside every C-STORE.** Each one has an oversized private
tag `(0009,1001)`: 8218 bytes, over the device's `max_dicom_payload` of 8192. It starts
with a 10-byte header ending in a big-endian length (`00 0F` = 15), and the next 15 bytes
XOR'd with the serial give:

```
PATRECORDS_LEAK
```

The rest is `DE AD` padding.

## Field values

| Field | Value | Sources |
|---|---|---|
| dicom_serial | `MEDSCAN-XR400-2019` | XML, exfil XOR key, marker XOR key |
| manifest_seed | `8842` | XML and the device's boot trap |
| anomaly_count | `20` | C-STOREs to the attacker: oversized, marked, valid checksums, no TCP gaps |
| leak_count | `90` (CSV) or `20` (marked leak ops) | `Leaked` × 90 in the CSV |
| snmp_iso_timestamp | ??? | 8 identical `[ANOMALY]` lines (Sep 1–8, 03:15) plus 1 boot trap |

## What I tried

Every `[ANOMALY]` timestamp, plus the boot-report one, with leak_count 90 and with 20.
Also leak_count 6, 15, 32 and 48, a trailing newline (as if hashed with `echo`), and a
16-hex-character version. None of them were accepted.

I also brute-forced about 33M field combinations to see if the 8 random-looking header
bytes in the marker were a digest of the answer. No match, so they're just filler.

## Where I think it breaks

The spec asks for "the" anomalous event, but the log has 8 identical ones and nothing
in the evidence picks out one of them. If I come back to this, I'd ask the organizers
which line is meant before trying more combinations.
