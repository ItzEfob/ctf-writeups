# bloody (anime OSINT)

| Category | Difficulty | Points | Author |
|---|---|---|---|
| OSINT | (warm-up) | | |

> Three records contradict each other. One lists a name that the others refuse to acknowledge. Another describes an investigation that officially never happened. The last contains a timestamp but no date. These fragments originate from a Japanese animated series, buried among dozens of recorded episodes.
>
> Format: `RxR{name_episoid_how many rooms there_number on the Recorded tape}`

**Flag:** `RxR{Ayano_9_5_60}`

## Steps

1. **Read the nameplate.** The screenshot shows a Japanese house with a nameplate reading **綾野** (Ayano) and the hood of a black-and-white police car in the foreground.
2. **Reverse image search failed.** trace.moe and SauceNAO only returned ~85% matches from unrelated shows, which means no match. (Real hits are 90% or more.)
3. **Match the lore instead.** The challenge text fits ***Another*** (P.A. Works, 2012):
   - "A name the others refuse to acknowledge": class 3-3 treats one student as if they don't exist.
   - "The recorded tape": Katsumi Matsunaga's cassette, hidden in the old school building.
   - **Aya Ayano (綾野彩)** is an anime-only class 3-3 student. She and her family die in a car crash while fleeing Yomiyama, which explains the police car outside the Ayano house.
4. **Find the episode.** Episode **9** ("Body paint") covers both the Ayano family's death and the search for the tape in the old school building.
5. **Read the numbers on screen** (from watching the episode): **5** classrooms, and the number **60** on the recorded tape.

## Lessons

- When reverse image search fails, the challenge text is the strongest clue. Match the plot, then confirm with the visual details.
- "Dozens of recorded episodes" was misdirection: *Another* has 12 episodes.
