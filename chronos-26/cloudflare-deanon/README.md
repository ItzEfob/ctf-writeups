# Cloudflare Deanon: NestEgg Capital

**Category:** OSINT · **Author:** Covert Security · 3 chained tasks (each solve unlocks the next)

The setup: NestEgg Capital is a fake investment site that takes deposits and then
charges "processing fees" to withdraw. The bank's fraud team says 14 customers lost
EUR 212,000. Police can only go after the hosting provider, and the site sits behind
Cloudflare, so the real server is hidden.

Target: `https://cs-adwi-covsec-lab-1.eu`. Rules: passive only, and the only things in
scope are the domain and the one host you find.

---

## Task 1: Read the Platform (Easy, 120 pts)

> Find the company registration number advertised by the platform. Submit it exactly
> as the site shows it.

I opened the site in my browser first. The header already shows a `Reg. No.` in the
top right, but I wanted to be sure it was the right number and not something
similar-looking, so I hit `Ctrl+U` and searched the source for `Reg`.

The same number appears in four places:

```html
<title>NestEgg Capital | Reg. No. NEC-7731-0049</title>
<meta name="description" content="NestEgg Capital, Reg. No. NEC-7731-0049. ...">
<div class="reg">Reg. No. NEC-7731-0049</div>
Licensed by the Lower Dunwich Financial Supervisory Board | Licence LD-FSB-2210 | Reg. No. NEC-7731-0049
```

The trust bar also has `LD-FSB-2210`. That's the licence number from the made-up
regulator, not the company registration, so I ignored it. I also grabbed `robots.txt`
while I was there (it's just Cloudflare's managed bot list) and noted that the page
loads `static.cloudflareinsights.com/beacon.min.js`, which confirms Cloudflare is in
front.

**Flag:** `CSCTF{NEC-7731-0049}`

---

## Task 2: Find the Origin (Medium, 406 pts)

> Find the real server hosting the site. Submit the one clear-web IPv4 origin.
> Not a Cloudflare edge, DNS resolver, historical address or a guess.

Cloudflare hides the origin in DNS, but it can't stop the origin from answering anyone
who connects to it directly. If the origin isn't locked down to Cloudflare's IP ranges,
internet scanners will have indexed it. The page title from Task 1 is unique, so I
searched for it.

Shodan was out without an account (`http.title:` filters need a login), so I used
Censys Platform:

```
host.services.endpoints.http.html_title = "NestEgg Capital | Reg. No. NEC-7731-0049"
  and not host.autonomous_system.asn = 13335
```

AS13335 is Cloudflare, so excluding it removes all the edge servers. One host came back:

- **185.146.86.118** (`cw185-adf-hf118.romania-webhosting.com`)
- AS203053, ClausWEB / CLAUS WEB srl, Bucharest
- open ports 22, 80 and 8080, with the title matched on port 80

I also tried searching certificates for the domain name
(`host.services.cert.names = "cs-adwi-covsec-lab-1.eu"`) and got nothing. That makes
sense in hindsight: the origin has no TLS at all. Cloudflare terminates HTTPS and talks
to the origin over plain HTTP.

That also explains my first verification attempt returning nothing. I used `https://`,
and `curl -s` swallowed the connection error. Plain HTTP worked:

```bash
curl -s -H "Host: cs-adwi-covsec-lab-1.eu" http://185.146.86.118/ | grep -o "<title>.*</title>"
```

**Flag:** `CSCTF{185.146.86.118}`

The mistake on the operator's side: port 80 on the origin accepts traffic from anyone,
not just from Cloudflare's ranges.

---

## Task 3: Find the Back Office (Medium, 410 pts)

> Find the operator's backend panel and get the hot wallet admin key. Use the origin
> from Task 2. No path enumeration or wordlists.

The Censys host page for `185.146.86.118` already listed a second web service on
**8080**. I opened `http://185.146.86.118:8080/` and the backend panel was right there
on the root page, with the hot wallet admin key on display. No login, and no guessing
paths.

<!-- TODO: add screenshot + key -->

**Flag:** `CSCTF{<admin key>}`
