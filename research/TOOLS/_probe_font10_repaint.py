"""Which Unicode bands `--rebuild-font` would repaint with the configured TTF.

Answers the "old font is still showing" question (2026-09-20): the shipped
atlas keeps its glyphs unless the rebuild repaints them, and repainting is
decided per band -- one overflowing glyph keeps the whole band shipped
(pwsf/font_build.py repaint_plan).  Run:

    python research/TOOLS/_probe_font10_repaint.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config                      # noqa: E402
from pwsf.font import PwsfFont               # noqa: E402
from pwsf.font_build import calibrate, repaint_plan  # noqa: E402


def main() -> None:
    src = config.pristine(config.FONT_DIR / f"{config.FONT_LARGE}.xpr")
    font = PwsfFont.load(src)
    face, dx, dy, size, ink = calibrate(config.FONT_TTF, font.cell)
    print(f"{src.name}: {config.FONT_TTF.name} calibrated at {size}px "
          f"(ink {ink}px, target 52px)")
    for name, v in sorted(repaint_plan(font, face, dx, dy).items()):
        head = ", ".join(f"U+{cp:04X}(+{over}px)" if over else f"U+{cp:04X}"
                         for cp, over in v["unfit"][:5])
        print(f"  {name:20} repaint={v['repaint']!s:5} "
              f"mapped={v['mapped']:3} blank={v['blank']:2} "
              f"unfit={len(v['unfit']):3}  {head}")


if __name__ == "__main__":
    main()
