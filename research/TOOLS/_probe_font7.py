"""What a full font REPLACEMENT (not a top-up) has to satisfy.

`pwsf.font_build` only fills the free rows of the shipped atlas.  Replacing the
whole font means every GLYPH_ATTR becomes ours, so every rule the engine applies
to a GLYPH_ATTR becomes our problem.  This probe measures those rules against
the shipped files.

Where each rule comes from:

    font_glyph_metrics @ 0x1400438B0
        v15 = width; if width == trunc(metrics[0]) the glyph is reported as
        blank (off forced to 1, advance forced to width) -- that is how SPACE
        is encoded.  advance_total = advance + off, +1 more when advance ==
        width.  Code point 0x7490 is special-cased to a 1.15 * cell wide box.
    sub_140043BC0 @ 0x140043BC0
        the CPU blit copies trunc(metrics[0]) rows starting at tv1, and
        (tu2 - tu1) bytes per row -- the row pitch must be >= that, whatever
        tv2 says.
    font_init_load_all @ 0x140043410
        scale = trunc(metrics[0]) / metrics[0], i.e. exactly 1.0 for the
        shipped 67.0 -- GLYPH_ATTR pixels are screen pixels, there is no
        independent size knob.
    sub_140043B00 @ 0x140043B00 (called with 1 from 0x14008AC80, 0x14041A332,
        0x14041A581, 0x14041A998; back to 0 at 0x14041A48C/0x14041A672/
        0x14041AD66)
        g_font_index IS written at runtime, so g_font_small is reachable.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config
from pwsf.font import PwsfFont

CJK = [(0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF)]


def f32(bits: int) -> float:
    return struct.unpack(">f", struct.pack(">I", bits))[0]


def is_cjk(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in CJK)


def report(name: str, path: Path) -> dict:
    font = PwsfFont.load(config.pristine(path))
    cell_h = f32(font.metrics[0])
    blank_w = int(cell_h)
    mapped = {c: g for c, g in enumerate(font.translator) if g}

    print(f"\n=== {name}  {path.name} ===")
    print(f"atlas {font.width}x{font.height}   metrics {[f32(m) for m in font.metrics]}")
    print(f"glyphs {font.num_glyphs}   mapped code points {len(mapped)}   "
          f"cMaxGlyph U+{font.max_glyph:04X}")
    print(f"scale = trunc({cell_h}) / {cell_h} = {int(cell_h) / cell_h}")

    heights = sorted({g.tv2 - g.tv1 + 1 for g in font.glyphs})
    tops = sorted({g.tv1 for g in font.glyphs})
    pitch = sorted({b - a for a, b in zip(tops, tops[1:])}) if len(tops) > 1 else []
    print(f"row tops {tops[0]}..{tops[-1]} ({len(tops)} rows), pitch {pitch}, "
          f"glyph box heights {heights}")
    print(f"blit copies {blank_w} rows from tv1 -> pitch must be >= {blank_w}: "
          f"{'OK' if not pitch or min(pitch) >= blank_w else 'VIOLATED'}")

    g0 = font.glyphs[0]
    box0 = font.atlas.crop((g0.tu1, g0.tv1, g0.tu2, g0.tv2)).getbbox()
    print(f"glyph 0 (the out-of-range / unmapped fallback): {g0}  "
          f"ink={'none' if box0 is None else box0}")

    blanks = [i for i, g in enumerate(font.glyphs) if g.width == blank_w]
    print(f"glyphs with width == {blank_w} (engine treats as blank): {blanks}")
    for gi in blanks:
        cps = [c for c, g in mapped.items() if g == gi]
        print(f"    glyph {gi} <- " + " ".join(f"U+{c:04X}" for c in cps))

    special = mapped.get(0x7490)
    print(f"U+7490 (1.15x cell special case): "
          + (f"glyph {special} {font.glyphs[special]}" if special else "not mapped"))

    print("  sample metrics (cp: tu1,tv1,tu2,tv2 off width advance -> advance_total)")
    for ch in "AiW1 " + "\u6b66\u3042":
        gi = mapped.get(ord(ch))
        if not gi:
            print(f"    U+{ord(ch):04X} {ch!r}: unmapped")
            continue
        g = font.glyphs[gi]
        total = g.width if g.width == blank_w else g.advance + g.off + (g.advance == g.width)
        print(f"    U+{ord(ch):04X} {ch!r}: {g.tu1},{g.tv1},{g.tu2},{g.tv2} "
              f"off={g.off} w={g.width} adv={g.advance} -> {total}")

    widths = sorted({g.width for g in font.glyphs})
    cjk_w = sorted({g.width for c, g in ((c, font.glyphs[g]) for c, g in mapped.items())
                    if is_cjk(c)})
    print(f"all widths {widths[0]}..{widths[-1]} ({len(widths)} distinct); "
          f"CJK widths {cjk_w}")

    rows = (font.height - 1) // blit_pitch(pitch, blank_w)
    for w in (58, 62):
        per_row = font.width // (w + 1)
        print(f"  full rebuild capacity @ {w}px cells: {rows} rows x {per_row} "
              f"= {rows * per_row} glyphs")
    return dict(font=font, mapped=mapped, blank_w=blank_w)


def blit_pitch(pitch, blank_w: int) -> int:
    return min(pitch) if pitch else blank_w + 1


def demand() -> None:
    """Code points the current translation asks for, CJK split out."""
    po = sorted(config.PO_DIR.rglob("*.po"))
    if not po:
        print("\nno .po files under", config.PO_DIR)
        return
    cps = set()
    for p in po:
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.startswith("msgstr"):
                cps.update(ord(c) for c in line)
    han = {c for c in cps if is_cjk(c)}
    print(f"\n=== translation demand ({len(po)} .po files) ===")
    print(f"distinct code points in msgstr {len(cps)}, of which CJK {len(han)}")


def main() -> None:
    config.require_game()
    report("large (g_font_large, index 0)",
           config.FONT_DIR / f"{config.FONT_LARGE}.xpr")
    report("small (g_font_small, index 1)",
           config.FONT_DIR / f"{config.FONT_SMALL}.xpr")
    demand()


if __name__ == "__main__":
    main()
