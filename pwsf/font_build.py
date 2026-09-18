"""Build a PWSF font that covers a given set of Unicode code points.

Adds glyphs for whatever the caller needs and the shipped font does not already
have, rasterising them from a TrueType face into the free rows of the atlas.

Metrics are matched to the shipped ideographs rather than guessed:
the pixel size is chosen so the calibration glyph's ink height equals the
shipped one, and every glyph then shares one pen offset so relative
proportions are preserved.  See ANALYSIS/05_font.md sections 8 and 9.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from . import config
from .font import PwsfFont

# measured from the shipped ideographs by _probe_font6.py
CELL_W, ADVANCE = 58, 62
INK_TOP, INK_HEIGHT, INK_LEFT = 7, 52, 3
CALIBRATION_CHAR = "武"

DEFAULT_TTF = config.FONT_TTF

# whitespace the renderer handles itself -- it never reaches the glyph table
WHITESPACE = {0x20, 0x0A, 0x0D, 0x09}

# U+FF00 is unassigned in Unicode, so no font maps it: whatever it rasterises
# to IS that face's .notdef.  Comparing against it is the only way to tell a
# real glyph from a substitute -- msyh.ttc draws a tofu box rather than
# nothing, so "the bitmap came out blank" catches none of them (_probe_po4.py).
NOTDEF_PROBE = 0xFF00


def calibrate(ttf: Path, cell_h: int) -> tuple:
    best = None
    for size in range(40, cell_h + 12):
        f = ImageFont.truetype(str(ttf), size)
        probe = Image.new("L", (cell_h * 4, cell_h * 4))
        ImageDraw.Draw(probe).text((cell_h, cell_h * 2), CALIBRATION_CHAR,
                                   font=f, fill=255, anchor="ls")
        box = probe.getbbox()
        if box is None:
            continue
        h = box[3] - box[1]
        if best is None or abs(h - INK_HEIGHT) < abs(best[1] - INK_HEIGHT):
            best = (size, h, box)
    size, h, box = best
    dx = cell_h + (INK_LEFT - box[0])
    dy = cell_h * 2 + (INK_TOP - box[1])
    return ImageFont.truetype(str(ttf), size), dx, dy, size, h


def render(cp: int, face, dx: int, dy: int, cell_h: int) -> Image.Image:
    img = Image.new("L", (CELL_W, cell_h))
    ImageDraw.Draw(img).text((dx, dy), chr(cp), font=face, fill=255, anchor="ls")
    return img


def unrenderable(codepoints, face, dx: int, dy: int, cell_h: int) -> list:
    """The code points `face` has no glyph of its own for.

    Blank output and .notdef output both count: a substituted box would be
    pasted into the atlas as if it were a character, and the game would show
    tofu with no indication anything went wrong.
    """
    notdef = render(NOTDEF_PROBE, face, dx, dy, cell_h).tobytes()
    out = []
    for cp in codepoints:
        img = render(cp, face, dx, dy, cell_h)
        if img.getbbox() is None or img.tobytes() == notdef:
            out.append(cp)
    return out


def plan(codepoints, src: Path, ttf: Path = DEFAULT_TTF) -> dict:
    """What build_font would have to do, without writing anything.

    Used by po_lint so a translation the font cannot carry is caught before
    anything is compiled.  It rasterises through the same `render()` the
    builder uses, so its verdicts are the builder's verdicts.
    """
    font = PwsfFont.load(src)
    have = font.coverage()
    wanted = set(codepoints) - WHITESPACE
    missing = sorted(wanted - have)
    over = [c for c in missing if c > font.max_glyph]

    face, dx, dy, size, _ink = calibrate(ttf, font.cell)
    blank = unrenderable([c for c in missing if c <= font.max_glyph],
                         face, dx, dy, font.cell)

    per_row = max(1, font.width // (CELL_W + 1))
    return dict(wanted=len(wanted), covered=len(wanted & have),
                missing=missing, over=over, blank=blank,
                rows_needed=-(-len(missing) // per_row),
                free_rows=font.free_rows(), max_glyph=font.max_glyph,
                ttf_px=size)


def build_font(codepoints, src: Path, dst: Path, ttf: Path = DEFAULT_TTF,
               remap: dict = None, verbose: bool = True) -> dict:
    """Ensure `codepoints` are all renderable, write the result to `dst`.

    `remap` optionally repoints existing code points at the glyph of another
    character (used by the digit demo); it is applied after the new glyphs are
    added.  Returns a small report dict.
    """
    font = PwsfFont.load(src)
    have = font.coverage()
    missing = sorted(set(codepoints) - have - WHITESPACE)
    over = [c for c in missing if c > font.max_glyph]
    if over:
        raise ValueError(f"{len(over)} code points exceed cMaxGlyph "
                         f"U+{font.max_glyph:04X}, e.g. U+{over[0]:04X}")

    face, dx, dy, size, ink_h = calibrate(ttf, font.cell)
    if verbose:
        print(f"{src.name}: {len(have)} covered, {len(missing)} to add; "
              f"{font.free_rows()} free rows")
        print(f"  calibrated {ttf.name} at {size}px (ink {ink_h}px, "
              f"target {INK_HEIGHT}px)")

    bad = unrenderable(missing, face, dx, dy, font.cell)
    if bad:
        raise ValueError(f"{ttf.name} has no glyph for {len(bad)} code "
                         f"point(s): " + " ".join(f"U+{c:04X}" for c in bad))

    cursor = [font.used_rows(), 0]
    added = {}
    for cp in missing:
        gi = font.add_glyph(render(cp, face, dx, dy, font.cell), ADVANCE, cursor)
        font.map_char(cp, gi)
        added[cp] = gi

    for cp, source_char in (remap or {}).items():
        font.map_char(cp, font.translator[ord(source_char)])

    font.save(dst)
    report = dict(added=len(added), rows_used=cursor[0] + 1,
                  free_rows_left=font.free_rows(), glyphs=len(font.glyphs),
                  size=dst.stat().st_size)
    if verbose:
        print(f"  added {report['added']} glyphs -> {report['glyphs']} total, "
              f"{report['free_rows_left']} rows still free")
        print(f"  wrote {dst} ({report['size']} bytes)")
    return report


def verify_coverage(built: Path, codepoints) -> list:
    """Return the code points that still have no non-blank glyph."""
    font = PwsfFont.load(built)
    bad = []
    for cp in sorted(set(codepoints)):
        if cp in WHITESPACE:
            continue
        gi = font.translator[cp] if cp <= font.max_glyph else 0
        if not gi:
            bad.append(cp)
            continue
        g = font.glyphs[gi]
        if font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv2)).getbbox() is None:
            bad.append(cp)
    return bad
