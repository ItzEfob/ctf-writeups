# Onion Deanon 1: ParsnipLocker

**Category:** OSINT · **Author:** Covert Security · 4 chained tasks

ParsnipLocker is a (fictional) ransomware crew with a leak blog on a Tor hidden
service, served over HTTPS. The briefing's hint: a hidden service only stays hidden
"for as long as that server never says anything about itself anywhere else."

The onion address came from the recovered ransom note (case `PL-0091`):
`4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion`

Rules: Tor Browser only, passive, no scanning or probing.

---

## Task 1: Read the Certificate (Easy, 120 pts)

> Give the certificate's serial number in uppercase hex, without colons.

I opened the onion in Tor Browser. Because it's HTTPS on an onion, there's a
certificate to look at: click the icon next to the address bar, then **Connection
secure → More information → View Certificate**.

What stood out:

- The subject, issuer and SAN are all just the onion address, so it's **self-signed**.
- It's valid for 10 years (2026-10-21 to 2036-10-18), RSA 2048, with `CA: Yes`. That's
  what a quick `openssl req -x509` gives you.
- Serial: `6F:DB:E5:40:70:14:B7:6F:97:1F:AF:C7:E8:88:BD:66:FE:C5:D2:FD`

No hostname or email leaks in the name fields. But a self-signed certificate with a
random serial exists in exactly one place in the world, which turned out to matter.

**Flag:** `CSCTF{6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD}`

---

## Task 2: Fingerprint the Certificate (Easy, 133 pts)

> Give the SHA-256 fingerprint in uppercase hex with colons.

The viewer cuts the fingerprint off, so I downloaded the certificate (**PEM (cert)**
link) and hashed it myself:

```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
# sha256 Fingerprint=14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80
```

As a sanity check, the start of it matches what the browser showed, and so do the SHA-1
and the serial.

**Flag:** `CSCTF{14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80}`

---

## Task 3: Find the Origin (Medium, 403 pts)

> Find the clear-web IPv4 that presents the same leaf certificate. Not a Tor relay,
> resolver, CDN or historical host.

This is where the "says something about itself" hint comes in. Tor reaches the web
server on `127.0.0.1`, but if nginx is bound to all interfaces, the same site (with the
same certificate) is also reachable on the server's public IP, and scanners will have
seen it.

Shodan wanted a login for `ssl.cert.fingerprint:`, so I used Censys with the
fingerprint, without the colons:

```
host.services.cert.fingerprint_sha256 = "14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380"
```

Exactly one host came back, matched on 443:

- **185.146.87.136** (`cw185-adf-hg136.romania-webhosting.com`)
- AS203053, ClausWEB, Bucharest
- ports 22, 443 and 8080

I checked it against the decoys in the task text: it's a normal hosting provider (not
a CDN), not a public resolver, not a Tor relay, and the match is current. One thing I
almost got wrong: the IPs in Tor Browser's circuit popup are the relays on *my* side of
the connection, not the server.

**Flag:** `CSCTF{185.146.87.136}`

---

## Task 4: Find the Back Office (Medium, 407 pts)

> Find the internal negotiation panel and get its access token (a UUID). No path
> enumeration.

Before touching the server, I looked at the Censys host page again. The 8080 service
already had the HTML title **"ParsnipLocker Internal Ops"**, so I knew where to go.

`http://185.146.87.136:8080/` opens the "ParsnipLocker Internal Negotiation Panel"
("DO NOT EXPOSE. OPERATOR USE ONLY."). It lists victims PL-0091 to PL-0095 and shows
the token at the bottom:

```
Access Token: db133256-5ed2-44bd-aaec-652a5213be0f
```

**Flag:** `CSCTF{db133256-5ed2-44bd-aaec-652a5213be0f}`

---

## What went wrong for the operator

The onion was fine, but the same box exposed the HTTPS site on its public IP with a
unique self-signed certificate, plus an unauthenticated admin panel on 8080. One
certificate search was enough to find it.
