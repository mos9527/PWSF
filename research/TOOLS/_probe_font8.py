"""Can we inherit the shipped metrics and repaint only the pixels?

The hybrid rebuild (05_font.md §12.4) keeps every shipped `off` / `advance` and
replaces the bitmap with one rasterised from our own TTF.  That is only safe if
the new ink fits the box the old metrics reserve: the engine draws a quad of
exactly `tu2 - tu1` pixels and then steps the pen by `advance + off`
(`font_glyph_metrics` @ 0x1400438B0), so ink wider than the shipped `width`
would spill into the next character.

This probe measures, per shipped code point, the ink our calibrated face
produces against the ink the shipped glyph has.  It writes nothing.
"""

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from PIL import Image, ImageDraw

from pwsf import config, font_build
from pwsf.font import PwsfFont

BANDS = [
    ("ASCII", 0x20, 0x7E),
    ("Latin-1", 0xA0, 0xFF),
    ("Latin ext / punct", 0x100, 0x2FFF),
    ("kana", 0x3000, 0x30FF),
    ("CJK", 0x3400, 0x9FFF),
    ("fullwidth", 0xFF00, 0xFF5E),
]


def band(cp: int) -> str:
    for name, lo, hi in BANDS:
        if lo <= cp <= hi:
            return name
    return "other"


def ink(img: Image.Image):
    return img.getbbox()


def render_wide(cp: int, face, dx: int, dy: int, cell_h: int) -> Image.Image:
    """Same pen as font_build.render, on a canvas too wide to clip anything."""
    img = Image.new("L", (cell_h * 3, cell_h))
    ImageDraw.Draw(img).text((dx, dy), chr(cp), font=face, fill=255, anchor="ls")
    return img


def main() -> None:
    config.require_game()
    src = config.pristine(config.FONT_DIR / f"{config.FONT_LARGE}.xpr")
    font = PwsfFont.load(src)
    face, dx, dy, size, ink_h = font_build.calibrate(config.FONT_TTF, font.cell)
    print(f"{src.name}: {font.num_glyphs} glyphs, cell {font.cell}")
    print(f"{config.FONT_TTF.name} calibrated at {size}px "
          f"(calibration ink {ink_h}px, target {font_build.INK_HEIGHT}px)\n")

    mapped = {c: g for c, g in enumerate(font.translator) if g}
    notdef = render_wide(font_build.NOTDEF_PROBE, face, dx, dy, font.cell).tobytes()

    stats = {name: Counter() for name, _lo, _hi in BANDS}
    stats["other"] = Counter()
    drift = {name: [] for name in stats}
    worst, box_mismatch, no_glyph, blank_orig = [], [], [], []

    for cp, gi in sorted(mapped.items()):
        g = font.glyphs[gi]
        if g.tu2 - g.tu1 != g.width:
            box_mismatch.append(cp)

        cell = font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv2))
        orig_ink = ink(cell)
        b = band(cp)
        stats[b]["mapped"] += 1
        if orig_ink is None:
            blank_orig.append(cp)
            stats[b]["blank in atlas"] += 1
            continue

        img = render_wide(cp, face, dx, dy, font.cell)
        new_ink = ink(img)
        if new_ink is None or img.tobytes() == notdef:
            no_glyph.append(cp)
            stats[b]["ttf has no glyph"] += 1
            continue

        orig_w = orig_ink[2] - orig_ink[0]
        new_w = new_ink[2] - new_ink[0]
        delta = new_w - orig_w
        drift[b].append(delta)
        # what matters is the box, not the shipped ink: the box is what the
        # inherited advance reserves
        if new_w > g.width:
            worst.append((new_w - g.width, cp, g.width, new_w))
            stats[b]["ink wider than box"] += 1

    print(f"{'band':18} {'mapped':>7} {'over box':>9} {'median d':>9} "
          f"{'min d':>6} {'max d':>6}")
    for name in [n for n, _l, _h in BANDS] + ["other"]:
        n = stats[name]["mapped"]
        if not n:
            continue
        d = sorted(drift[name])
        med = d[len(d) // 2] if d else 0
        print(f"{name:18} {n:7} {stats[name]['ink wider than box']:9} "
              f"{med:+9} {min(d) if d else 0:+6} {max(d) if d else 0:+6}")

    print(f"\nbox width == width field for all glyphs: "
          f"{'yes' if not box_mismatch else f'NO ({len(box_mismatch)})'}")
    print(f"shipped glyphs whose atlas cell is blank: {len(blank_orig)} "
          + " ".join(f"U+{c:04X}" for c in blank_orig[:10]))
    print(f"code points {config.FONT_TTF.name} cannot draw: {len(no_glyph)} "
          + " ".join(f"U+{c:04X}" for c in no_glyph[:10]))

    print(f"\n{len(worst)} code point(s) whose new ink does not fit the shipped box:")
    for over, cp, box_w, new_w in sorted(worst, reverse=True)[:15]:
        print(f"  U+{cp:04X} {chr(cp)!r:6} box {box_w:3}px, new ink {new_w:3}px "
              f"(+{over})")


if __name__ == "__main__":
    main()
