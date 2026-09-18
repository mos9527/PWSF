"""Which face should repaint the ideographs?

The hybrid rebuild (`pwsf.font_build.rebuild_font`) keeps the shipped western
glyphs and repaints the ideographs from our TTF, so the two have to sit next to
each other without looking like two fonts.  The shipped face is heavy; Microsoft
YaHei Regular is visibly lighter than it, Bold is not.

Builds the same corpus with both faces and writes the comparison strip to
ANALYSIS/_font_rebuild_weights.png.  Rows, top to bottom:

    shipped    the untouched font ('\u58eb' is a tofu box: it renders glyph 0,
               the fallback, because the shipped font never mapped it)
    msyh       rebuilt with Microsoft YaHei Regular
    msyhbd     rebuilt with Microsoft YaHei Bold

The strip is built from the atlas cells themselves, laid out at a fixed pitch --
it shows the glyph pixels, not the engine's spacing.  Spacing needs no picture:
the rebuild never changes a single `off` or `advance` (verified by
`pwsf.font_build.verify_rebuild`), so it cannot move the layout.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from PIL import Image

from pwsf import config
from pwsf.font import PwsfFont
from pwsf.font_build import rebuild_font, verify_rebuild

SAMPLE = "武器開発兵士作戦開始 ABC 123"
FACES = [Path(r"C:\Windows\Fonts\msyh.ttc"), Path(r"C:\Windows\Fonts\msyhbd.ttc")]
OUT = config.ANALYSIS_DIR / "_font_rebuild_weights.png"


def strip(font: PwsfFont, text: str) -> Image.Image:
    cells = []
    for ch in text:
        g = font.glyphs[font.translator[ord(ch)]]
        cells.append(font.atlas.crop((g.tu1, g.tv1, g.tu2, g.tv1 + font.cell)))
    out = Image.new("L", (sum(c.width + 2 for c in cells), font.cell))
    x = 0
    for c in cells:
        out.paste(c, (x, 0))
        x += c.width + 2
    return out


def main() -> None:
    config.require_game()
    src = config.pristine(config.FONT_DIR / f"{config.FONT_LARGE}.xpr")
    corpus = config.DUMP_OLANG_TSV
    codepoints = {ord(c) for c in
                  corpus.read_text(encoding="utf-8", errors="replace")}

    rows = [strip(PwsfFont.load(src), SAMPLE)]
    for ttf in FACES:
        if not ttf.is_file():
            print(f"skipping {ttf.name}, not installed")
            continue
        outdir = config.BUILD_DIR / f"_weights_{ttf.stem}"
        outdir.mkdir(parents=True, exist_ok=True)
        dst = outdir / src.name.replace(".orig", "")
        report = rebuild_font(codepoints, src, dst, ttf, verbose=False)
        problems = verify_rebuild(dst, src, report)
        print(f"{ttf.name:12} {report['ttf_px']}px  "
              f"{len(report['repainted'])} repainted, {len(report['added'])} "
              f"added, {report['rows_used']} rows, "
              f"{report['free_rows_left']} free  "
              + ("OK" if not problems else f"{len(problems)} PROBLEM(S)"))
        for p in problems[:5]:
            print("    " + p)
        rows.append(strip(PwsfFont.load(dst), SAMPLE))

    img = Image.new("L", (max(r.width for r in rows),
                          sum(r.height + 8 for r in rows)), 40)
    y = 0
    for r in rows:
        img.paste(r, (0, y))
        y += r.height + 8
    img.save(OUT)
    print(f"wrote {OUT} ({img.width}x{img.height})")


if __name__ == "__main__":
    main()
