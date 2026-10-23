"""Faithful reimplementation of teto.c's game logic (width==10 regime).

Used to plan piece placements offline so the exploit driver always knows the
exact board state.  Mirrors collides()/lock_piece()/clear_lines() exactly,
including the quirks (set_cell's y==-1 escape, clear_lines' forward scan).
"""

WIDTH = 10
HEIGHT = 20
SIDE = 4

PIECES = [
    # I
    ["####............", ".#...#...#...#..", "####............", ".#...#...#...#.."],
    # O
    ["##..##..........", "##..##..........", "##..##..........", "##..##.........."],
    # T
    [".#..###.........", "#...##..#.......", "###..#..........", ".#..##...#......"],
    # S
    [".##.##..........", "#...##...#......", ".##.##..........", "#...##...#......"],
    # Z
    ["##...##.........", ".#..##..#.......", "##...##.........", ".#..##..#......."],
    # J
    ["#...###.........", "##..#...#.......", "###...#.........", ".#...#..##......"],
    # L
    ["..#.###.........", "#...#...##......", "###.#...........", "##...#...#......"],
]


def occupied(d, x, y):
    if x < 0 or x >= SIDE or y < 0 or y >= SIDE:
        return False
    return d[y * SIDE + x] == '#'


def cells(d):
    return [(x, y) for y in range(SIDE) for x in range(SIDE) if occupied(d, x, y)]


def piece_width(d):
    mx = -1
    for x, y in cells(d):
        if x > mx:
            mx = x
    return mx + 1 if mx >= 0 else 1


class Game:
    def __init__(self):
        self.board = [[0] * WIDTH for _ in range(HEIGHT)]
        self.width = 10
        self.height = 20

    def occupied_count(self):
        return sum(sum(r) for r in self.board)

    def collides(self, kind, nx, ny, nrot):
        d = PIECES[kind % 7][nrot & 3]
        for xx, yy in cells(d):
            x, y = nx + xx, ny + yy
            if x < 0:
                return True
            if y < 0:
                if x >= self.width:
                    return True
            elif x >= WIDTH:
                return True
            if y >= HEIGHT:
                return True
            if y >= 0 and self.board[y][x]:
                return True
        return False

    def lock(self, kind, px, py, rot):
        """Only models the in-board part; y==-1 writes go to `width` and are
        handled by the driver, not the board."""
        d = PIECES[kind % 7][rot & 3]
        for xx, yy in cells(d):
            x, y = px + xx, py + yy
            if x < 0 or y < -1 or x >= self.width or y >= HEIGHT:
                continue
            if y >= 0 and x < WIDTH:
                self.board[y][x] = 1

    def row_full(self, y):
        return all(self.board[y][x] for x in range(WIDTH))

    def clear_row(self, y):
        # memmove(base+stride, base, y*stride) with stride==2 == shift rows down
        for yy in range(y, 0, -1):
            self.board[yy] = list(self.board[yy - 1])
        self.board[0] = [0] * WIDTH

    def clear_lines(self):
        cleared = 0
        y = 0
        while y < HEIGHT:
            if self.row_full(y):
                self.clear_row(y)
                cleared += 1
            y += 1
        return cleared

    def spawn_x(self, kind):
        d = PIECES[kind % 7][0]
        x = WIDTH // 2 - piece_width(d) // 2
        return max(x, 0)

    def hard_drop(self, kind, px, rot=0):
        """Returns (ok, lines_cleared). ok==False means top-out."""
        py = -2
        if self.collides(kind, px, py, rot):
            return False, 0
        while py + 1 < HEIGHT and not self.collides(kind, px, py + 1, rot):
            py += 1
        if py < 0:
            return False, 0
        self.lock(kind, px, py, rot)
        return True, self.clear_lines()

    def clone(self):
        g = Game()
        g.board = [list(r) for r in self.board]
        g.width = self.width
        g.height = self.height
        return g


def heights(g):
    h = []
    for x in range(WIDTH):
        col = 0
        for y in range(HEIGHT):
            if g.board[y][x]:
                col = HEIGHT - y
                break
        h.append(col)
    return h


def holes(g):
    n = 0
    for x in range(WIDTH):
        seen = False
        for y in range(HEIGHT):
            if g.board[y][x]:
                seen = True
            elif seen:
                n += 1
    return n


def evaluate(g, lines, want_clear):
    h = heights(g)
    agg = sum(h)
    bump = sum(abs(h[i] - h[i + 1]) for i in range(WIDTH - 1))
    hl = holes(g)
    if want_clear:
        return -0.51 * agg + 0.76 * lines - 0.36 * hl - 0.18 * bump
    # stacking phase: no clears allowed, so pack densely and stay flat
    return -0.30 * agg - 1.2 * hl - 0.25 * bump


def best_column(g, kind, want_clear):
    """Pick the hard-drop column for a rot-0 placement.

    want_clear=False restricts to columns that keep col 9 empty, which makes
    row_full() permanently false and therefore clear_lines() a no-op.
    """
    d = PIECES[kind % 7][0]
    pw = piece_width(d)
    limit = WIDTH - pw if want_clear else (WIDTH - 1) - pw
    best, best_score = None, None
    for col in range(0, limit + 1):
        t = g.clone()
        ok, lines = t.hard_drop(kind, col)
        if not ok:
            continue
        if not want_clear and lines:
            continue
        s = evaluate(t, lines, want_clear)
        if best_score is None or s > best_score:
            best, best_score = col, s
    return best


def piece_sequence(n=140):
    import ctypes
    libc = ctypes.CDLL("libc.so.6")
    return [libc.rand() % 7 for _ in range(n)]


# ---------------------------------------------------------------- El-Tetris

def _row_transitions(b):
    t = 0
    for y in range(HEIGHT):
        prev = 1
        for x in range(WIDTH):
            cur = b[y][x]
            if cur != prev:
                t += 1
            prev = cur
        if prev != 1:
            t += 1
    return t


def _col_transitions(b):
    t = 0
    for x in range(WIDTH):
        prev = 0
        for y in range(HEIGHT):
            cur = b[y][x]
            if cur != prev:
                t += 1
            prev = cur
        if prev != 1:
            t += 1
    return t


def _wells(b):
    tot = 0
    for x in range(WIDTH):
        for y in range(HEIGHT):
            if b[y][x]:
                continue
            left = (x == 0) or b[y][x - 1]
            right = (x == WIDTH - 1) or b[y][x + 1]
            if left and right:
                d = 1
                yy = y + 1
                while yy < HEIGHT and not b[yy][x]:
                    d += 1
                    yy += 1
                tot += d * (d + 1) // 2
                break
    return tot


def eltetris(g, lines, landing_height):
    b = g.board
    return (-4.500158825082766 * landing_height
            + 3.4181268101392694 * lines
            - 3.2178882868487753 * _row_transitions(b)
            - 9.348695305445199 * _col_transitions(b)
            - 7.899265427351652 * holes(g)
            - 3.3855972247263626 * _wells(b))


def drop_row(g, kind, px, rot):
    py = -2
    if g.collides(kind, px, py, rot):
        return None
    while py + 1 < HEIGHT and not g.collides(kind, px, py + 1, rot):
        py += 1
    return py if py >= 0 else None


def best_placement(g, kind, want_clear, allow_rot=True):
    """Return (rot, col) for a rot-then-slam-left-then-step-right placement."""
    best, best_score = None, None
    rots = range(4) if allow_rot else [0]
    for rot in rots:
        d = PIECES[kind % 7][rot & 3]
        cs = cells(d)
        minx = min(x for x, _ in cs)
        pw = piece_width(d)
        ph = max(y for _, y in cs) - min(y for _, y in cs) + 1
        # after 'a'*7 the piece sits at its leftmost legal x
        maxx = max(x for x, _ in cs)
        lo = -minx
        hi = (WIDTH - 1) - maxx
        for col in range(lo, hi + 1):
            py = drop_row(g, kind, col, rot)
            if py is None:
                continue
            t = g.clone()
            t.lock(kind, col, py, rot)
            lines = t.clear_lines()
            if not want_clear and lines:
                continue
            lh = HEIGHT - (py + max(y for _, y in cs)) + (ph - 1) / 2.0
            s = eltetris(t, lines, lh)
            if best_score is None or s > best_score:
                best, best_score = (rot, col), s
    return best
