# ghostframe96: the missing photographer (unsolved)

| Category | Difficulty | Points | Author |
|---|---|---|---|
| OSINT | | | |

> A solo urbex photographer, @ghostframe96, vanished after one last post dated 07.11.26. Find where he was standing, his real first name, birth date, what he studied, his job and his hobby.
>
> Format: `RxR{Location_FirstName_DD-MM-YYYY_Major_Job_Hobby}`

**Status:** ❌ unsolved. Every field has at least two sources, but we never matched the checker's exact wording.

## Pivot chain

1. **Last post (Instagram).** "Seven spokes, one heart… a ghost once lived like a king on Park Avenue… the last night they let the monsters in." That's **Eastern State Penitentiary**, Philadelphia: the radial seven-spoke plan, Al Capone's luxurious cell on "Park Avenue", and the end of the Halloween Nights season.
2. **GitHub `ghostframe96`**, with two repos:
   - `graduation-project`: a commit titled *"remove personal info"* replaced `Author: Khaled` in the README, but git history kept the original. The pre-2026 commits are authored by `Khaled <khaled@khaled-laptop>`. One commit on **2018-04-22** reads *"22 today and still debugging 🎂"*. The README says **B.Sc. Computer Science (Class of 2018)**.
   - `ghostframe96.github.io`: a portfolio ("I swapped the keyboard for a camera"), with `<meta name="author" content="Khaled">`, "© K. Lens Studio", and the status line "Back after 07.11."
3. **Instagram posts.** The Pripyat post says he turned 30 "this April, four days before" the 26 April Chernobyl anniversary, so his birthday is **22-04-1996**. The Hashima post says "a horror map I've cleared 100 times… same handle everywhere if you want to squad up 🎮". The bio reads "📷 Photographer".
4. **Steam `ghostframe96`.** The profile XML's hidden summary reads: *"📷 by day. 🎯 by night. I photograph abandoned places for a living, then come home and hold angles on Nuke. AWP main."* That points to Counter-Strike 2.

## Best answer (not accepted)

```
RxR{EasternStatePenitentiary_Khaled_22-04-1996_ComputerScience_Photographer_Gaming}
```

About 90 variants were also rejected: `CounterStrike`, `CS2`, `Gamer`, `VideoGames` and others for the hobby; `Philadelphia`, `FairmountAvenue` and `EasternState` for the location; `IT` and `CS` for the major; and ALL CAPS versions.

## Open questions

The data is consistent, so the mismatch is the expected wording of at least one field. My top suspects are the location (the exact spot he was standing) and the hobby term. Worth checking the official writeup when it's released.
