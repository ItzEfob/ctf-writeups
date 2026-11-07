# chronosCTF 2026

Played November 2026. Final score: TBD

| Challenge | Category | Difficulty | Idea |
| --- | --- | --- | --- |
| [Cloudflare Deanon](cloudflare-deanon/) | OSINT | Easy / Medium / Medium | The origin answers on its own IP, so a Censys search for the site's unique `<title>` (excluding Cloudflare's ASN) finds it; the back office is on port 8080 |
| [Onion Deanon 1: ParsnipLocker](onion-deanon-1-parsniplocker/) | OSINT | Easy / Easy / Medium / Medium | The onion's self-signed certificate is also served on the public IP; one Censys fingerprint search finds the host and its unauthenticated panel |
| [Onion Deanon 2: DarkPigeon](onion-deanon-2-darkpigeon/) | OSINT | Easy | Shodan-style favicon hash: `mmh3` over `base64.encodebytes` (newline-wrapped, signed) |
| [The Layer That Wouldn't Die](the-layer-that-wouldnt-die/) | Forensics | Easy | `rm` only whites out the marker; unseal with the layer-2 marker as it stood when the seal was built, not the intruder's rev-B overwrite |
| [Silent Orbit](silent-orbit/) | Network | Easy | Implement the CFDP relay from the mission profile, skip the off-APID and wrong-transaction decoys, merge coverage, and serialize the NAK for the 12 missing bytes |
| [Operation Silent Ward](operation-silent-ward/) | Network | Hard | *Unsolved.* Decrypted the UTF-8-damaged exfil stream and found a serial-XOR'd `PATRECORDS_LEAK` marker in each C-STORE, but couldn't pin down "the" anomalous timestamp |

None of these used per-instance flags. The OSINT chains were live lookups against the
challenge infrastructure, so their writeups document the investigation path. The
forensics and network challenges shipped static attachments, and each `solve.py` is
tested end-to-end against the original files.

Every folder has a `README.md` with the full writeup. `onion-deanon-2-darkpigeon/`,
`the-layer-that-wouldnt-die/` and `silent-orbit/` also include a self-contained
`solve.py`. The other OSINT folders have no solver, since those steps were searches
rather than code. `operation-silent-ward/` documents the analysis and every attempt
that was tried.
