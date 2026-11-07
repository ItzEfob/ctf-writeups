# Onion Deanon 2: DarkPigeon

**Category:** OSINT · **Author:** Covert Security

DarkPigeon (fictional ransomware) runs its victim negotiation portal as a Tor hidden
service, onion only. The victim, Coop & Crumb Birdseed Wholesalers, wants to know where
it's hosted so their lawyers can file a takedown.

Target: `http://schpqwd…kzsad.onion` (from the forum post). Tor Browser, passive only.

---

## Task 1: Read the Favicon (Easy, 126 pts)

> Get the portal's favicon and hash it the way Shodan does. Answer as a signed integer.

I knew Shodan indexes a favicon hash for every web server it sees, but I had to look up
exactly how it's computed. It's MurmurHash3 (32-bit, so signed in Python's `mmh3`) over
the **base64 of the file**, and specifically `base64.encodebytes`, which wraps lines at
76 characters and adds a newline at the end. Plain `b64encode` gives a different number.

The page source tells you where the icon is:

```html
<link rel="icon" href="/favicon.ico" type="image/x-icon">
```

I opened `/favicon.ico` in Tor Browser and saved it with `Ctrl+S`. Before hashing, I
checked that I'd actually saved an icon and not an HTML error page:

```
$ file favicon.ico
MS Windows icon resource - 3 icons, 16x16 with PNG image data, 32x32 with PNG image data, ...
```

6434 bytes, MD5 `ad866421d43a616ab0e4dd089fc94b06`. Then:

```python
import base64, mmh3
print(mmh3.hash(base64.encodebytes(open("favicon.ico", "rb").read())))
# -209798607
```

**Flag:** `CSCTF{-209798607}`

## Where it goes next

That number is directly searchable. `http.favicon.hash:-209798607` on Shodan (or
`icon_hash="-209798607"` on FOFA) finds every IP serving the same icon, so if the portal
also answers on its public IP, that's how you'd find it. It's the same idea as the
certificate search in Onion Deanon 1.
