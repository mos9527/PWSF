"""Build a PWSF font that covers a given set of Unicode code points.

Two modes:

`build_font` tops the shipped font up -- it adds glyphs for whatever the caller
needs and the font does not already have, into the free rows of the atlas.  The
643 shipped GLYPH_ATTRs and their atlas pixels are not touched.

`rebuild_font` lays the whole atlas out again from scratch, which buys the
rows the shipped layout wastes (60 rows usable against 51 free, ANALYSIS/
05_font.md §12.2) and lets the ideographs be repainted from our own face so
they match the ones we add.  Shipped code points keep their shipped `off` and
`advance`: those metrics are hand-tuned (space is a real 1px glyph with
advance 16, the digits are tabular) and the engine has no independent size
knob -- GLYPH_ATTR pixels are screen pixels (§12.1).

Metrics are matched to the shipped ideographs rather than guessed:
the pixel size is chosen so the calibration glyph's ink height equals the
shipped one, and every glyph then shares one pen offset so relative
proportions are preserved.  See ANALYSIS/05_font.md sections 8 and 9.
"""

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from . import config
from .font import PwsfFont

# measured from the shipped ideographs by _probe_font6.py / _probe_font7.py:
# a full-width glyph is a 58px bitmap drawn at pen+4, and the pen then steps
# by off + advance = 66
CELL_W, ADVANCE, OFF = 58, 62, 4
INK_TOP, INK_HEIGHT, INK_LEFT = 7, 52, 3
CALIBRATION_CHAR = "武"

# Repainting is decided per band, not per glyph: a band half in the shipped
# face and half in ours would be visibly inconsistent within one word.
# _probe_font8.py measures which bands fit; with msyh.ttc only the ideographs
# do, the Latin bands overflow their boxes by up to 11px.
BANDS = (("ASCII", 0x20, 0x7E), ("Latin-1", 0xA0, 0xFF),
         ("Latin ext / punct", 0x100, 0x2FFF), ("kana", 0x3000, 0x30FF),
         ("CJK", 0x3400, 0x9FFF), ("fullwidth", 0xFF00, 0xFF5E))
CJK_BANDS = ("CJK",)

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


def _rows_for(widths, atlas_w: int) -> int:
    """Rows the next-fit packing in add_glyph would use for these widths."""
    row, x = 1, 0
    for w in widths:
        if x + w > atlas_w:
            row, x = row + 1, 0
        x += w + 1
    return row


def plan(codepoints, src: Path, ttf: Path = DEFAULT_TTF,
         rebuild: bool = False) -> dict:
    """What build_font (or rebuild_font) would have to do, without writing.

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

    if rebuild:
        # a rebuild re-places the shipped glyphs too, at their shipped widths,
        # in the same code point order rebuild_font walks
        by_cp = {c: font.glyphs[g].width
                 for c, g in enumerate(font.translator) if g}
        by_cp.update({c: CELL_W for c in missing})
        widths = [font.glyphs[0].width] + [by_cp[c] for c in sorted(by_cp)]
        rows_needed = _rows_for(widths, font.width)
        free_rows = font.rows()
    else:
        per_row = max(1, font.width // (CELL_W + 1))
        rows_needed, free_rows = -(-len(missing) // per_row), font.free_rows()

    return dict(wanted=len(wanted), covered=len(wanted & have),
                missing=missing, over=over, blank=blank,
                rows_needed=rows_needed, free_rows=free_rows,
                max_glyph=font.max_glyph, ttf_px=size)


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


# ------------------------------------------------------------------ rebuild

def band_of(cp: int) -> str:
    for name, lo, hi in BANDS:
        if lo <= cp <= hi:
            return name
    return "other"


def render_wide(cp: int, face, dx: int, dy: int, cell_h: int) -> Image.Image:
    """`render` on a canvas nothing can be clipped by, for measuring ink."""
    img = Image.new("L", (cell_h * 3, cell_h))
    ImageDraw.Draw(img).text((dx + cell_h, dy), chr(cp), font=face, fill=255,
                             anchor="ls")
    return img


def cell_of(atlas: Image.Image, g, cell: int) -> Image.Image:
    """The shipped bitmap of `g`, the full row height the engine blits."""
    return atlas.crop((g.tu1, g.tv1, g.tu2, g.tv1 + cell))


def repaint_plan(font: PwsfFont, face, dx: int, dy: int) -> dict:
    """Which Unicode bands our face may repaint without breaking the layout.

    A repainted glyph keeps the shipped `off` and `advance`, so its ink has to
    fit the shipped box; ink wider than that would spill into the next
    character.  The verdict is per band because a band repainted only where it
    happens to fit would mix two typefaces inside one word.
    """
    notdef = render_wide(NOTDEF_PROBE, face, dx, dy, font.cell).tobytes()
    out = {}
    for cp, gi in ((c, g) for c, g in enumerate(font.translator) if g):
        g = font.glyphs[gi]
        b = out.setdefault(band_of(cp), dict(mapped=0, blank=0, unfit=[]))
        b["mapped"] += 1
        if cell_of(font.atlas, g, font.cell).getbbox() is None:
            b["blank"] += 1          # a spacer, there are no pixels to repaint
            continue
        img = render_wide(cp, face, dx, dy, font.cell)
        box = img.getbbox()
        if box is None or img.tobytes() == notdef:
            b["unfit"].append((cp, None))
        elif box[2] - box[0] > g.width:
            b["unfit"].append((cp, box[2] - box[0] - g.width))
    for b in out.values():
        b["repaint"] = not b["unfit"]
    return out


def _repainted(cp: int, g, shipped: Image.Image, face, dx: int, dy: int,
               cell: int) -> Image.Image:
    """Our face's glyph, placed in the shipped box on the shipped ink's left.

    Vertical placement comes from the shared pen, so every glyph keeps one
    baseline; only the horizontal position is matched to the shipped glyph.
    """
    wide = render_wide(cp, face, dx, dy, cell)
    box = wide.getbbox()
    ink = shipped.getbbox()
    left = 0 if ink is None else min(ink[0], g.width - (box[2] - box[0]))
    out = Image.new("L", (g.width, cell))
    out.paste(wide.crop((box[0], 0, box[2], cell)), (max(0, left), 0))
    return out


def rebuild_font(codepoints, src: Path, dst: Path, ttf: Path = DEFAULT_TTF,
                 repaint: tuple = None, verbose: bool = True) -> dict:
    """Lay the whole atlas out again, covering `codepoints` and all shipped ones.

    Nothing shipped is dropped: every code point the font already carries is
    carried again, with its `off` and `advance` untouched.  What changes is
    where the glyphs sit (the 9 shipped rows become as many as are needed, out
    of 60) and, for the bands `repaint_plan` clears, which face drew them.
    """
    font = PwsfFont.load(src)
    cell = font.cell
    atlas = font.atlas.copy()
    shipped = {c: font.glyphs[g] for c, g in enumerate(font.translator) if g}
    zero = font.glyphs[0]

    face, dx, dy, size, ink_h = calibrate(ttf, cell)
    bands = repaint_plan(font, face, dx, dy)
    if repaint is None:
        repaint = tuple(b for b, v in bands.items() if v["repaint"])

    wanted = set(codepoints) - WHITESPACE
    added = sorted(wanted - set(shipped))
    over = [c for c in added if c > font.max_glyph]
    if over:
        raise ValueError(f"{len(over)} code points exceed cMaxGlyph "
                         f"U+{font.max_glyph:04X}, e.g. U+{over[0]:04X}")
    bad = unrenderable(added, face, dx, dy, cell)
    if bad:
        raise ValueError(f"{ttf.name} has no glyph for {len(bad)} code "
                         f"point(s): " + " ".join(f"U+{c:04X}" for c in bad))

    if verbose:
        print(f"{src.name}: rebuilding {len(shipped)} shipped + {len(added)} "
              f"new code points into {font.rows()} rows")
        print(f"  calibrated {ttf.name} at {size}px (ink {ink_h}px, "
              f"target {INK_HEIGHT}px)")
        for name, v in sorted(bands.items()):
            verdict = "repaint" if name in repaint else "keep shipped pixels"
            why = "" if not v["unfit"] else \
                f" ({len(v['unfit'])} of {v['mapped']} would overflow their box)"
            print(f"    {name:18} {verdict}{why}")

    font.reset()
    cursor = [0, 0]
    # glyph 0 first: it is the fallback the engine draws for any code point the
    # translator does not map, so it has to keep index 0
    font.add_glyph(cell_of(atlas, zero, cell), zero.advance, cursor, off=zero.off)

    report = dict(inherited=[], repainted=[], added=[])
    for cp in sorted(set(shipped) | wanted):
        g = shipped.get(cp)
        if g is None:
            bitmap, off, adv = render(cp, face, dx, dy, cell), OFF, ADVANCE
            report["added"].append(cp)
        else:
            old = cell_of(atlas, g, cell)
            off, adv = g.off, g.advance
            if band_of(cp) in repaint and old.getbbox() is not None:
                bitmap = _repainted(cp, g, old, face, dx, dy, cell)
                report["repainted"].append(cp)
            else:
                bitmap = old
                report["inherited"].append(cp)
        try:
            font.map_char(cp, font.add_glyph(bitmap, adv, cursor, off=off))
        except ValueError as exc:
            raise ValueError(f"U+{cp:04X}: {exc} ({font.rows()} rows of "
                             f"{font.width}px hold about "
                             f"{font.rows() * (font.width // (CELL_W + 1))} "
                             f"full-width glyphs)") from None

    font.save(dst)
    report.update(glyphs=len(font.glyphs), rows_used=cursor[0] + 1,
                  free_rows_left=font.free_rows(), size=dst.stat().st_size,
                  repaint_bands=tuple(repaint), ttf_px=size)
    if verbose:
        print(f"  {len(report['inherited'])} inherited, "
              f"{len(report['repainted'])} repainted, "
              f"{len(report['added'])} added -> {report['glyphs']} glyphs in "
              f"{report['rows_used']} rows ({report['free_rows_left']} free)")
        print(f"  wrote {dst} ({report['size']} bytes)")
    return report


def verify_rebuild(built: Path, src: Path, report: dict) -> list:
    """Check a rebuild against the font it was made from.

    Inherited glyphs must come back byte-identical -- same metrics, same
    pixels -- because that is the whole basis for trusting that the western
    layout did not move.  Everything mapped must be non-blank, and nothing may
    trip the `width == trunc(metrics[0])` rule that makes the engine treat a
    glyph as a space (05_font.md §12.1).
    """
    new, old = PwsfFont.load(built), PwsfFont.load(src)
    problems = []

    if (new.width, new.height) != (old.width, old.height):
        problems.append(f"atlas {new.width}x{new.height}, "
                        f"was {old.width}x{old.height}")
    if new.metrics != old.metrics or new.max_glyph != old.max_glyph:
        problems.append("metrics or cMaxGlyph changed")

    blank_w = int(new.cell_height)
    for i, g in enumerate(new.glyphs):
        if g.width == blank_w:
            problems.append(f"glyph {i} is {blank_w}px wide, which the engine "
                            f"reads as a space")
        if (g.tv1 - 1) % new.cell or g.tv2 - g.tv1 != new.cell - 1:
            problems.append(f"glyph {i} is off the row grid: tv1={g.tv1} "
                            f"tv2={g.tv2}")

    for cp in report["inherited"]:
        a, b = old.glyphs[old.translator[cp]], new.glyphs[new.translator[cp]]
        if (a.off, a.width, a.advance) != (b.off, b.width, b.advance):
            problems.append(f"U+{cp:04X}: metrics changed {a} -> {b}")
        elif cell_of(old.atlas, a, old.cell).tobytes() != \
                cell_of(new.atlas, b, new.cell).tobytes():
            problems.append(f"U+{cp:04X}: inherited pixels differ")

    for cp in report["repainted"] + report["added"]:
        gi = new.translator[cp]
        if not gi:
            problems.append(f"U+{cp:04X}: not mapped")
        elif cell_of(new.atlas, new.glyphs[gi], new.cell).getbbox() is None:
            problems.append(f"U+{cp:04X}: glyph is blank")

    dropped = [c for c, g in enumerate(old.translator)
               if g and not new.translator[c]]
    if dropped:
        problems.append(f"{len(dropped)} shipped code point(s) lost, e.g. "
                        + " ".join(f"U+{c:04X}" for c in dropped[:5]))
    return problems


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


# ----------------------------------------------------------------------- cli

def main() -> None:
    ap = argparse.ArgumentParser(
        description="build or rebuild the PWSF font atlas")
    ap.add_argument("--rebuild", action="store_true",
                    help="lay the whole atlas out again instead of only "
                         "filling its free rows (ANALYSIS/05_font.md §12)")
    ap.add_argument("--chars-from", type=Path, metavar="FILE",
                    help="cover every code point in this UTF-8 file; "
                         "defaults to the translations in the .po corpus")
    ap.add_argument("--ttf", type=Path, default=DEFAULT_TTF)
    ap.add_argument("--outdir", type=Path, default=config.BUILD_DIR)
    ap.add_argument("--png", action="store_true",
                    help="also dump the atlas as a PNG to look at")
    args = ap.parse_args()
    config.require_game()

    if args.chars_from:
        codepoints = {ord(c) for c in
                      args.chars_from.read_text(encoding="utf-8", errors="replace")}
    else:
        from . import po_lint          # imports this module, so not at the top
        rep = po_lint.lint(check_font=False)
        codepoints = {ord(c) for t in rep.translations.values() for c in t}
    codepoints = {c for c in codepoints if c not in WHITESPACE}
    print(f"{len(codepoints)} distinct code point(s) to cover")

    stem = config.FONT_LARGE
    src = config.pristine(config.FONT_DIR / f"{stem}.xpr")
    args.outdir.mkdir(parents=True, exist_ok=True)
    dst = args.outdir / f"{stem}.xpr"

    if args.rebuild:
        report = rebuild_font(codepoints, src, dst, args.ttf)
        problems = verify_rebuild(dst, src, report)
    else:
        build_font(codepoints, src, dst, args.ttf)
        problems = ["no glyph for " + " ".join(f"U+{c:04X}" for c in bad)] \
            if (bad := verify_coverage(dst, codepoints)) else []

    if problems:
        print(f"\n{len(problems)} VERIFICATION FAILURE(S):")
        for p in problems[:15]:
            print("  " + p)
        raise SystemExit(1)
    print("verified: " + ("inherited glyphs byte-identical, everything mapped "
                          "non-blank" if args.rebuild else
                          "every code point has a non-blank glyph"))

    if args.png:
        png = args.outdir / f"{stem}_atlas.png"
        PwsfFont.load(dst).atlas.save(png)
        print(f"atlas -> {png}")


if __name__ == "__main__":
    main()
