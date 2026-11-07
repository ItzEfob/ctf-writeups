# chronosCTF 2026

My writeups from chronosCTF (November 2026).

| Category | Challenge | Difficulty | Status | Writeup |
|---|---|---|---|---|
| OSINT | Cloudflare Deanon (3 tasks) | Easy / Medium / Medium | solved | [cloudflare-deanon.md](osint/cloudflare-deanon.md) |
| OSINT | Onion Deanon 1: ParsnipLocker (4 tasks) | Easy / Easy / Medium / Medium | solved | [onion-deanon-1-parsniplocker.md](osint/onion-deanon-1-parsniplocker.md) |
| OSINT | Onion Deanon 2: DarkPigeon | Easy | solved | [onion-deanon-2-darkpigeon.md](osint/onion-deanon-2-darkpigeon.md) |
| Forensics | The Layer That Wouldn't Die | Easy | solved | [the-layer-that-wouldnt-die.md](forensics/the-layer-that-wouldnt-die.md) |
| Network | Silent Orbit | Easy | solved | [silent-orbit.md](network/silent-orbit.md) |
| Network | Operation Silent Ward | Hard | not solved | [operation-silent-ward.md](network/operation-silent-ward.md) |

## Things I'll reuse

**Hidden services leak through their public IP.** All the OSINT deanon chains broke the
same way: the "hidden" server also answered on its public IP, and scanners had indexed
something unique about it.

| What leaks | Search |
|---|---|
| TLS certificate | Censys `host.services.cert.fingerprint_sha256 = "<sha256>"` |
| Page title | Censys `host.services.endpoints.http.html_title = "<title>"` |
| Favicon | Shodan `http.favicon.hash:<mmh3>` |

Then rule out the decoys: CDN ranges (Cloudflare is AS13335), public resolvers, Tor
relays, and hosts that only matched in the past.

**Other lessons:**
- **Container images:** `rm` in a later layer doesn't delete anything. Walk the layers
  in manifest order and read the config history.
- **XOR with a repeating key:** if a file ends in readable text repeating over and over,
  that's probably the key showing through zero bytes.
- **`EF BF BD` in a binary file** means it went through a bad UTF-8 conversion. One lost
  byte shifts everything after it.
- **scapy rebuilds packets** instead of showing the raw bytes. When the byte counts don't
  add up, parse the pcap by hand.
