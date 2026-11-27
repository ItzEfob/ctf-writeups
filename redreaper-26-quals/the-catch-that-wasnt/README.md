# The Catch That Wasn't

| Category | Difficulty | Points | Author |
|---|---|---|---|
| Satellite (OSINT) | Hard | 100 | SAK-TRA |

> Two August flight cards stapled to one recovery receipt. The earlier card describes a camera-less capsule retrieved after it reached the ocean. The later receipt says the capsule was caught before it touched the water. The recovery plane almost stayed grounded while a cylinder was changed in its left engine.

**Flag:** `rxr{monkey_9009_pelican9_037_kappa}`

## Identifying the mission

- **Earlier card:** Discoverer XIII (10 August 1960). It was a camera-less CORONA test flight, and its capsule was recovered from the Pacific after splashdown.
- **Later receipt:** **Discoverer XIV** (launched 18 August, recovered 19 August 1960). This was the first mid-air recovery of an object returning from orbit, and the first CORONA film to come back. A C-119 snagged the capsule's parachute southwest of Hawaii.

## The four fields

| # | Field | Answer | Source |
|---|---|---|---|
| 1 | Internal mission number (launch ledger) | `9009` | NRO/CORONA records: Discoverer XIV = Mission 9009 (KH-1) |
| 2 | Recovery aircraft call sign | `pelican9` | CIA and USAF histories: C-119 "Pelican 9", Capt. Harold E. Mitchell, 6593rd Test Squadron |
| 3 | Aircraft short marking | `037` | Fairchild C-119J serial **51-8037** |
| 4 | Greek-letter word in the civil-space designation | `kappa` | The NRO's declassified report calls it "Discoverer XIV (1960 Kappa)". COSPAR ID 1960-010A |

## Traps

- Some sites caption a recovery photo "C-119J, 51-8039". That's a different aircraft in a stock photo. Pelican 9 itself was 51-8037.
- The `rxr{monkey_laugh_at_you}` "annotations" in the README are decoys.
