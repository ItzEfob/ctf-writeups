# Ticket

| Category | Difficulty | Points | Author |
|---|---|---|---|
| DFIR | Medium | 100 | odytr |

> Our Windows honeypot caught a file on 27 May 2026. Legal won't let us share the file, so all you get is what we put in the ticket:
> `sha256: 815eccf206bc39d67ad9c903c823cc76c59ebb5e0e24ff1028b5242c53686a3a`

**Flag:** `RxR{ZombieBoyTools_2017-05-09_RookIE_MS17-010}`

## TL;DR

There's no file, only a hash, so this is pure **threat-intel pivoting**: hash → public sandbox report → YARA hit → original research.

## Questions and answers

### 1. Which family is it really? (named after a toolkit)

AV engines give it generic names (`Malware-gen`, `GenericKD`, `TrojanDownloader.Agent`). Searching the hash finds it attributed to **ZombieBoy**. AlienVault named that family (July 2018) after **ZombieBoyTools**, the Chinese-language tool that delivers its first DLL using the leaked EternalBlue and DoublePulsar exploits.

The flag wanted the **toolkit** name, `ZombieBoyTools`, not the family name `ZombieBoy`.

### 2. When was the DLL compiled? (PE header, UTC)

A public Joe Sandbox report (analysis 781310) for this exact hash lists the PE header `TimeDateStamp`:

```
0x59115AA9 -> 2017-05-09 05:59:05 UTC
```

```python
>>> datetime.datetime.fromtimestamp(0x59115AA9, datetime.timezone.utc)
datetime.datetime(2017, 5, 9, 5, 59, 5, tzinfo=datetime.timezone.utc)
```

The same report identifies it as a 32-bit PE **DLL**.

### 3. Which product name is in the downloader's User-Agent?

The same report shows the community YARA rule **`MALWARE_Win_ZombieBoy`** (by ditekSHen, "Detects ZombieBoy Downloader") matching two strings:

```
$s1 = ":\Users\ZombieBoy\"     (PDB path)
$s2 = "RookIE/1.0"            (User-Agent)
```

The product name is **`RookIE`**.

### 4. Which bulletin patches the SMB exploits it shares with WannaCry?

ZombieBoy spreads with EternalBlue and loads its modules through DoublePulsar, the same SMBv1 exploitation WannaCry used. Both are fixed by Microsoft security bulletin **MS17-010**.

## Lessons

- With no sample, sandbox reports and YARA hit tables are the evidence. Joe Sandbox, MalwareBazaar and isMalicious are all searchable by hash.
- Read the question wording carefully: "named after a toolkit" wanted `ZombieBoyTools`, not the family name.
