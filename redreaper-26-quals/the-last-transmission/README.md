# The Last Transmission (unsolved)

| Category | Difficulty | Points | Author |
|---|---|---|---|
| OSINT | Hard | 496 | Kirann |

> Beneath the stones, the silence remembers. Seven were heard. None returned. The door is open... but who called you?

**Status:** ❌ unsolved. We ran out of submission attempts.

## What we established

| Evidence | Finding |
|---|---|
| `the last record.txt` | A bridge over a river, defeat in June before 1690, ~1,200 prisoners taken east. This is the **Battle of Bothwell Bridge, 22 June 1679**. |
| `archival reference.pdf` | A Wikipedia extract confirming that ~1,200 prisoners were marched to Edinburgh and held at **Greyfriars Kirk** |
| `city fragment.jpg` | An 1890s OS map of Edinburgh's Old Town (Grassmarket, Greyfriars). Its EXIF `Copyright`/`Rights` fields hold the handle **`@LastSignal1679`**. |
| `final signal.txt` | "A prison behind gates… once part of a churchyard… search for the gate". This is the **Covenanters' Prison** gate in Greyfriars Kirkyard, with its 2007 plaque. |
| X account `@LastSignal1679` | Posts that repeat the story ("A bridge. A defeat. A journey east."), plus a Google Drive link to `archive.docx` |
| `archive.docx` | The twist: *"I don't want the name of the prison, nor any coordinates."* The real format is `RxR{the direction_the year_how many prisoners died}`, about the prison ship ***Crown of London***, wrecked off Deerness, Orkney, on 10 Dec 1679. |

## Attempts (all rejected)

| Flag | Reasoning |
|---|---|
| `RxR{Covenanters_Prison}` | Before we found the docx |
| `RxR{east_1679_209}` | "Journey east"; 257 shipped − 48 survivors (the Greyfriars plaque and Wikipedia) |
| `RxR{east_1679_200}` | The Orkney memorial's figure of "200 Covenanters" |

## What we probably got wrong

- **Direction:** the evidence says "east" twice, but the answer might be `south` (the prison is the *southern* section of the kirkyard, a field south of the church), or the ship's route (`north` to Orkney, bound `west` for the colonies).
- **Death count:** sources give 200, 208, 209 or 211 (*Cloud of Witnesses*).
- **Lesson:** with a 3-attempt limit, map out every plausible reading of an ambiguous field *before* submitting anything.
