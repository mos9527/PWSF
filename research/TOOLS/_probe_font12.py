"""_probe_font12.py — 把 RenderDoc 那 4 个 draw 引用的字形裁出来拼成一行。

`_probe_font11.py` 证明了那张 512x512 BC3 像素字图集住在 `Text/*.txp` 里，
但没回答它画的是什么。RenderDoc 侧能拿到每个 quad 的 UV，换算成图集像素坐标
就是一个矩形；把这些矩形从图集里裁出来按顺序拼成一行，就能读出那段文本。

UV 来自 eventId 317 的 post-VS 顶点（12 float/顶点：xyzw / RGBA / uv / --），
换算：x512。同一个字形出现多次就是同一个字符重复。

输入：ANALYSIS/_font_txp_pixel_atlas.png  （RenderDoc export_texture 6091）
输出：ANALYSIS/_font_txp_pixel_eid317.png （拼好的那一行，3 倍放大）
"""

import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ATLAS = ROOT / "ANALYSIS" / "_font_txp_pixel_atlas.png"
OUT = ROOT / "ANALYSIS" / "_font_txp_pixel_eid317.png"

# (u0, v0, u1, v1) in atlas pixels, in draw order -- RenderDoc eventId 317,
# 14 quads, all sampling ResourceId::6091
QUADS = [(4, 144, 28, 192), (60, 144, 84, 192), (144, 96, 168, 144),
         (88, 144, 112, 192), (88, 144, 112, 192), (4, 0, 28, 48),
         (4, 0, 28, 48), (4, 0, 28, 48), (60, 96, 84, 144),
         (144, 144, 168, 192), (116, 144, 140, 192), (116, 144, 140, 192),
         (424, 96, 448, 144), (396, 96, 420, 144)]

SCALE = 3


def segment(atlas: Image.Image) -> list:
    """Split the atlas into character cells by ink projection.

    Rows first (a band of non-empty scanlines), then columns inside each band.
    Cells come back in reading order, which is the order the face was baked in
    -- ASCII first, then Latin-1, judging by what is in the image.
    """
    a = atlas.split()[-1]          # alpha
    w, h = a.size
    px = a.load()
    rows = [any(px[x, y] > 8 for x in range(w)) for y in range(h)]

    bands, y = [], 0
    while y < h:
        if rows[y]:
            y0 = y
            while y < h and rows[y]:
                y += 1
            bands.append((y0, y))
        else:
            y += 1

    cells = []
    for y0, y1 in bands:
        cols = [any(px[x, yy] > 8 for yy in range(y0, y1)) for x in range(w)]
        x = 0
        while x < w:
            if cols[x]:
                x0 = x
                while x < w and cols[x]:
                    x += 1
                cells.append((x0, y0, x, y1))
            else:
                x += 1
    return cells


def main() -> None:
    if not ATLAS.is_file():
        raise SystemExit(f"missing {ATLAS} -- export it from RenderDoc "
                         f"(export_texture 6091)")
    atlas = Image.open(ATLAS).convert("RGBA")
    print(f"{ATLAS.name}: {atlas.size} {atlas.mode}")

    cells = segment(atlas)
    print(f"{len(cells)} character cells by ink projection")
    # a baked ASCII+Latin-1 face is 0x20..0x7E (95) + 0xA0..0xFF (96) = 191
    print("  ascii 0x20..0x7E = 95, latin-1 0xA0..0xFF = 96, total 191")
    # a quad has padding, so match on the CENTRE, not the top-left corner
    def index_of(q):
        cx, cy = (q[0] + q[2]) / 2, (q[1] + q[3]) / 2
        for i, c in enumerate(cells):
            if c[0] <= cx <= c[2] and c[1] <= cy <= c[3]:
                return i
        return None

    for q in QUADS:
        if index_of(q) is None:
            print(f"  quad {q}: no ink at its centre (blank glyph?)")
    # decode: reading order == code point order, starting at 0x20.
    # caveat: a cell with no ink (space) is invisible to the projection, so
    # the mapping drifts by one from the first blank on.
    def ch(q):
        i = index_of(q)
        return "?" if i is None else (chr(0x20 + i) if i < 95 else "-")
    print("  decoded row: " + "".join(ch(q) for q in QUADS))

    cells = [atlas.crop(q) for q in QUADS]
    h = max(c.height for c in cells)
    out = Image.new("RGB", (sum(c.width for c in cells) * SCALE, h * SCALE),
                    (16, 16, 16))
    x = 0
    for c in cells:
        big = c.resize((c.width * SCALE, c.height * SCALE), Image.NEAREST)
        out.paste(big, (x, 0), big)
        x += c.width * SCALE
    out.save(OUT)
    print(f"{len(cells)} cells -> {OUT.name} ({out.size[0]}x{out.size[1]})")
    print("distinct cells: "
          f"{len(set(QUADS))} of {len(QUADS)} "
          f"(repeats: {[q for q in set(QUADS) if QUADS.count(q) > 1]})")


if __name__ == "__main__":
    main()
