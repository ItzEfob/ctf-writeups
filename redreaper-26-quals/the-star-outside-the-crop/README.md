# The Star Outside the Crop

| Category | Difficulty | Points | Author |
|---|---|---|---|
| Satellite (OSINT) | Hard | 100 | SAK-TRA |

> A double star on a paired photograph: blurred together in the ground-based frame, cleanly separated in the orbital frame. He swears the marked pair was the spacecraft's pointing target.

**Flag:** `rxr{monkey_opo9005a_19900520_19900522_hd96755_30}`

## Identifying the image

This is **Hubble's first light**: the Wide Field/Planetary Camera's first image (20 May 1990, a focusing test), released next to a ground-based image of the same field from Las Campanas Observatory, Chile.

## The trap: two ESA/Hubble entries

ESA/Hubble has two nearly identical first-light comparisons:

| Id | Release date | What it shows |
|---|---|---|
| `opo9004a` | 20 May 1990 | "HST WF/PC first light image" (object: HD96755) |
| `opo9005a` | **22 May 1990** | "The resolving power of the HST": a **double star** blurred from the ground and split by Hubble |

The README's story (a double star that blurs together on the ground and separates in orbit) is exactly `opo9005a`'s description. The "two dates" on the filing card are also only different for this entry. My first attempt used `opo9004a` and was rejected.

## The five fields

| # | Field | Answer | Reasoning |
|---|---|---|---|
| 1 | ESA/Hubble media Id | `opo9005a` | The double-star comparison |
| 2 | Day the first image was taken | `19900520` | NASA timeline: WF/PC first light, 20 May 1990 |
| 3 | Catalog release date | `19900522` | The `opo9005a` entry's Release date field |
| 4 | Star at the centre of the full exposure | `hd96755` | The field is centred on the 8.2-magnitude star HD 96755 in open cluster NGC 3532. The crop shows only the double star, so the actual pointing target is *outside the crop* (hence the title). The monkey's claim is the lie. |
| 5 | Longer orbital exposure | `30` | First light included 1 s and 30 s exposures. The published comparison used the 30 s frame. |
