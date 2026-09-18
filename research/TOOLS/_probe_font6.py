"""Probe: measure the ink box of the shipped CJK glyphs.

New glyphs have to sit on the same baseline as the existing ones, so instead of
eyeballing it, measure where the ink actually lands inside the 67px cell for a
sample of shipped ideographs and kana.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_font import PwsfFont

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
OUT = Path(__file__).resolve().parent.parent / "ANALYSIS"

SAMPLE = [0x6B66, 0x5668, 0x88C5, 0x5099, 0x4EFB, 0x52D9, 0x958B, 0x59CB,
          0x8A2D, 0x5B9A, 0x623B, 0x308A, 0x30A2, 0x0041, 0x0030]


def main() -> None:
    font = PwsfFont.load(GAME / "FONT" / "0007ccd8.xpr")
    print(f"cell={font.cell}px  atlas={font.width}x{font.height}")
    print(f"{'char':<6} {'idx':>5} {'box':<22} {'w':>3} {'adv':>4} {'off':>4} "
          f"{'ink rows (rel)':>16} {'ink cols (rel)':>16}")

    tops, bots = [], []
    for cp in SAMPLE:
        gi = font.translator[cp]
        if not gi:
            print(f"U+{cp:04X}  (unmapped)")
            continue
        g = font.glyphs[gi]
        cell = font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv2))
        bbox = cell.getbbox()
        if bbox is None:
            rel = "(blank)"
            cols = ""
        else:
            rel = f"{bbox[1]}..{bbox[3] - 1} (h={bbox[3] - bbox[1]})"
            cols = f"{bbox[0]}..{bbox[2] - 1} (w={bbox[2] - bbox[0]})"
            if 0x3000 <= cp:
                tops.append(bbox[1])
                bots.append(bbox[3])
        print(f"{chr(cp)!r:<6} {gi:>5} "
              f"({g.tu1},{g.tv1})-({g.tu2},{g.tv2})".ljust(30)
              + f"{g.width:>3} {g.advance:>4} {g.off:>4} {rel:>16} {cols:>16}")

    print(f"\nCJK/kana ink rows inside the cell: top {min(tops)}..{max(tops)}, "
          f"bottom {min(bots)}..{max(bots)}")
    print(f"reference: ink top = {round(sum(tops) / len(tops))}, "
          f"ink bottom = {round(sum(bots) / len(bots))}, "
          f"ink height = {round(sum(bots) / len(bots)) - round(sum(tops) / len(tops))}")

    strip = font.atlas.crop((0, 0, 0, 0))
    del strip
    # visual reference sheet of the sampled glyphs, scaled 2x
    from PIL import Image
    sheet = Image.new("L", (len(SAMPLE) * 64, font.cell))
    for i, cp in enumerate(SAMPLE):
        gi = font.translator[cp]
        if not gi:
            continue
        g = font.glyphs[gi]
        sheet.paste(font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv2)), (i * 64, 0))
    sheet.resize((sheet.width * 2, sheet.height * 2), Image.NEAREST).save(
        OUT / "_font_ref_glyphs.png")
    print(f"wrote {OUT / '_font_ref_glyphs.png'}")


if __name__ == "__main__":
    main()
