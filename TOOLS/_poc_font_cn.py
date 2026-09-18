r"""PoC: add Chinese glyphs to FONT/0007ccd8.xpr and prove the whole chain.

What it exercises:
  XPR2 unpack -> FontData parse -> rasterise new glyphs from a system TTF ->
  blit into the atlas free rows -> append GLYPH_ATTR -> patch the translator ->
  repack -> re-encrypt -> reload and verify.

Two kinds of mapping are applied:

  1. Real hanzi at their true Unicode code points.  This is the path a real
     localisation uses, but it is not visible in game yet because the text is
     still the shipped English (the olang writer is calendar item 06).
  2. ASCII digits U+0030..U+0039 repointed at the Chinese numerals.  This is
     purely so the change is visible in game without a text rebuild: every
     number in the UI renders as 〇一二三四五六七八九.

Metrics are copied from the shipped ideographs (measured by _probe_font6.py):
    bitmap 58 px wide, advance 62, off 4, ink top at row 7, ink height ~52.

Usage:
    python _poc_font_cn.py             # build + verify into ..\BUILD
    python _poc_font_cn.py --install   # also back up and install into the game
    python _poc_font_cn.py --restore   # put the backup back
"""

import shutil
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_font import PwsfFont

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "BUILD"
TARGET = "0007ccd8"

TTF = Path(r"C:\Windows\Fonts\msyh.ttc")

# measured from the shipped ideographs
CELL_W, ADVANCE, OFF = 58, 62, 4
INK_TOP, INK_HEIGHT, INK_LEFT = 7, 52, 3
CALIBRATION_CHAR = "武"

DIGITS = "〇一二三四五六七八九"          # -> U+0030..U+0039
HANZI = ("和平行者潜入任务装备武器支援完成开始设置返回"
         "主菜单存档读取继续退出关卡难度评价时间剩余")


def calibrate(path: Path) -> tuple:
    """Pick the pixel size whose ink height matches the shipped glyphs, and the
    pen offset that lands the ink on the same row as them."""
    best = None
    for size in range(40, 80):
        f = ImageFont.truetype(str(path), size)
        img = Image.new("L", (240, 240))
        ImageDraw.Draw(img).text((40, 160), CALIBRATION_CHAR, font=f,
                                 fill=255, anchor="ls")
        box = img.getbbox()
        if box is None:
            continue
        h = box[3] - box[1]
        if best is None or abs(h - INK_HEIGHT) < abs(best[1] - INK_HEIGHT):
            best = (size, h, box)
    size, h, box = best
    # pen (40,160) produced ink starting at box[0], box[1]; shift so the ink
    # lands at (INK_LEFT, INK_TOP) inside the cell
    dx = 40 + (INK_LEFT - box[0])
    dy = 160 + (INK_TOP - box[1])
    print(f"calibrated: size={size}px ink_height={h} (target {INK_HEIGHT}), "
          f"pen=({dx},{dy})")
    return ImageFont.truetype(str(path), size), dx, dy


def render(ch: str, font, dx: int, dy: int, cell_h: int) -> Image.Image:
    img = Image.new("L", (CELL_W, cell_h))
    ImageDraw.Draw(img).text((dx, dy), ch, font=font, fill=255, anchor="ls")
    return img


def pristine() -> Path:
    """Always build from the untouched original, never from an installed build."""
    bak = GAME / "FONT" / f"{TARGET}.xpr.orig"
    return bak if bak.exists() else GAME / "FONT" / f"{TARGET}.xpr"


def build() -> Path:
    BUILD.mkdir(exist_ok=True)
    src = pristine()
    font = PwsfFont.load(src)
    before_glyphs = len(font.glyphs)
    before_cov = len(font.coverage())
    print(f"loaded {src.name}: {before_glyphs} glyphs, {before_cov} mapped "
          f"code points, {font.free_rows()} free rows")

    ttf, dx, dy = calibrate(TTF)

    cursor = [font.used_rows(), 0]
    print(f"writing new glyphs starting at row {cursor[0]} "
          f"(y={font.row_top(cursor[0])})")

    added = {}
    for ch in dict.fromkeys(DIGITS + HANZI):
        bmp = render(ch, ttf, dx, dy, font.cell)
        if bmp.getbbox() is None:
            raise SystemExit(f"{ch!r} rendered blank -- wrong font?")
        added[ch] = font.add_glyph(bmp, ADVANCE, cursor)

    # 1. real hanzi at their true code points
    for ch in HANZI:
        font.map_char(ord(ch), added[ch])
    # 2. ASCII digits repointed at the Chinese numerals (visible in game)
    for d, ch in enumerate(DIGITS):
        font.map_char(0x30 + d, added[ch])

    out = BUILD / f"{TARGET}.xpr"
    font.save(out)
    print(f"wrote {out}  ({out.stat().st_size} bytes, "
          f"original {src.stat().st_size})")
    print(f"  glyphs {before_glyphs} -> {len(font.glyphs)} "
          f"(+{len(font.glyphs) - before_glyphs})")
    print(f"  rows used {cursor[0]} -> {cursor[0] + 1}, "
          f"{font.free_rows()} rows still free")
    return out


def verify(built: Path) -> None:
    font = PwsfFont.load(built)
    print(f"\nreload {built.name}: version={font.version} "
          f"cMaxGlyph={font.max_glyph:#x} glyphs={len(font.glyphs)} "
          f"atlas={font.width}x{font.height}")

    problems = []
    for ch in HANZI:
        gi = font.translator[ord(ch)]
        if not gi:
            problems.append(f"U+{ord(ch):04X} {ch} unmapped")
            continue
        g = font.glyphs[gi]
        if font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv2)).getbbox() is None:
            problems.append(f"U+{ord(ch):04X} {ch} maps to a blank cell")
    for d, ch in enumerate(DIGITS):
        gi = font.translator[0x30 + d]
        g = font.glyphs[gi]
        if font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv2)).getbbox() is None:
            problems.append(f"digit {d} maps to a blank cell")

    # untouched glyphs must be bit-identical to the shipped ones.
    # name_hash stops at the first '.', so "0007ccd8.xpr.orig" keys the same
    # as "0007ccd8" and the backup decrypts correctly.
    orig = PwsfFont.load(pristine())
    for i in range(len(orig.glyphs)):
        if orig.glyphs[i] != font.glyphs[i]:
            problems.append(f"glyph[{i}] changed: {orig.glyphs[i]} -> {font.glyphs[i]}")
            break
    untouched = orig.atlas.crop((0, 0, orig.width, orig.row_top(orig.used_rows())))
    if untouched.tobytes() != font.atlas.crop(
            (0, 0, font.width, orig.row_top(orig.used_rows()))).tobytes():
        problems.append("the original atlas region was modified")

    strip = font.atlas.crop((0, font.row_top(orig.used_rows()) - 2,
                             1400, font.row_top(orig.used_rows()) + font.cell))
    strip.save(ROOT / "ANALYSIS" / "_font_poc_newrow.png")
    print(f"wrote {ROOT / 'ANALYSIS' / '_font_poc_newrow.png'}")

    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  " + p)
        raise SystemExit(1)
    print("verify OK: new glyphs present, shipped glyphs and atlas untouched")


def install(built: Path) -> None:
    dst = GAME / "FONT" / f"{TARGET}.xpr"
    bak = GAME / "FONT" / f"{TARGET}.xpr.orig"
    if not bak.exists():
        shutil.copy2(dst, bak)
        print(f"backed up -> {bak}")
    shutil.copy2(built, dst)
    print(f"installed -> {dst}")


def restore() -> None:
    dst = GAME / "FONT" / f"{TARGET}.xpr"
    bak = GAME / "FONT" / f"{TARGET}.xpr.orig"
    if not bak.exists():
        raise SystemExit("no backup found")
    shutil.copy2(bak, dst)
    print(f"restored {dst} from {bak}")


def main() -> None:
    if "--restore" in sys.argv:
        restore()
        return
    built = build()
    verify(built)
    if "--install" in sys.argv:
        install(built)


if __name__ == "__main__":
    main()
