# Onion Deanon 2: DarkPigeon

**Category:** OSINT · **Author:** Covert Security · 4 chained tasks

DarkPigeon (fictional ransomware) runs its victim negotiation portal as a Tor hidden
service, onion only, with no clearnet domain. The victim, Coop & Crumb Birdseed
Wholesalers, wants to know where it's hosted so their lawyers can file a takedown.

Target: `http://schpqwd…kzsad.onion` (from the forum post). Tor Browser, passive only.

> Only the first task carried points (126). Tasks 2–4 showed **0 pts** on the
> scoreboard but still had to be solved to unlock the next one.

---

## Task 1: Read the Favicon (Easy, 126 pts)

> Get the portal's favicon and hash it the way Shodan does. Answer as a signed integer.

I knew Shodan indexes a favicon hash for every web server it sees, but I had to look up
exactly how it's computed. It's MurmurHash3 (32-bit, so signed in Python's `mmh3`) over
the **base64 of the file**, and specifically `base64.encodebytes`, which wraps lines at
76 characters and adds a newline at the end. Plain `b64encode` gives a different number.

The page source shows where the icon is:

```html
<link rel="icon" href="/favicon.ico" type="image/x-icon">
```

I opened `/favicon.ico` in Tor Browser and saved it with `Ctrl+S`. Before hashing, I
checked that I'd actually saved an icon and not an HTML error page:

```
$ file favicon.ico
MS Windows icon resource - 3 icons, 16x16 with PNG image data, 32x32 with PNG image data, ...
```

```python
import base64, mmh3
print(mmh3.hash(base64.encodebytes(open("favicon.ico", "rb").read())))
# -209798607
```

**Flag:** `CSCTF{-209798607}`

---

## Task 2: Hash the Favicon Again (Easy, 0 pts)

> Get the favicon's MD5 hash.

Same file, different hash:

```bash
$ md5sum favicon.ico
ad866421d43a616ab0e4dd089fc94b06  favicon.ico
```

**Flag:** `CSCTF{ad866421d43a616ab0e4dd089fc94b06}`

Looked like a throwaway step at first, but it turned out to matter for the next task.

---

## Task 3: Find the Origin (Medium, 0 pts)

> Find the clear-web IPv4 that serves the portal identified from the Task 1 favicon.
> No onion infrastructure, relays, historical hosts or guesses.

The idea is the same as the certificate pivot in Onion Deanon 1: if the portal's web
server also answers on its public IP, scanners will have indexed its favicon.

My first plan was Shodan with `http.favicon.hash:-209798607`, but search filters need an
account, so that didn't work. Censys Platform indexes favicons too, and it searches by
MD5, which explains why Task 2 exists. This query worked without logging in:

```
host.services.endpoints.http.favicons.hash_md5: "ad866421d43a616ab0e4dd089fc94b06"
```

One result, matched on port 80:

- **185.146.85.96** (`cw185-adf-he96.romania-webhosting.com`)
- AS203053, ClausWEB, Bucharest (same provider as the ParsnipLocker box, one /24 over)
- ports 22, 80 and 8080

It's a regular hosting server, not a Tor relay or onion infrastructure, and the match is
current, so it passes everything in the answer boundary.

**Flag:** `CSCTF{185.146.85.96}`

---

## Task 4: Find the Back Office (Medium, 0 pts)

> Find the operator's admin panel and get the decryption key for the Coop & Crumb case
> (a UUID). Use the origin from Task 3. No path enumeration or wordlists.

At this point I knew the pattern: both other labs had the operator panel sitting on port
8080 of the origin, and the Censys result showed 8080 open here too. Opening
`http://185.146.85.96:8080/` brought up the DarkPigeon admin panel with no login. I took
the decryption key from the **Coop & Crumb** row (case `CC-0417` on the portal), not
from the other victims listed.

**Flag:** `CSCTF{da4f9b9a-31c7-4b8f-91cb-1a5009d5f65b}`

---

## Script

[`solve.py`](solve.py) prints both hashes from a saved favicon (`pip install mmh3`):

```
$ python3 solve.py favicon.ico
Task 1 (Shodan mmh3): CSCTF{-209798607}
Task 2 (MD5):         CSCTF{ad866421d43a616ab0e4dd089fc94b06}
```

## What went wrong for the operator

Even with no clearnet domain, the portal's web server also listened on its public IP.
A custom favicon is a fingerprint, so one favicon search was enough to find the server,
and the admin panel was on the same machine with no authentication.
