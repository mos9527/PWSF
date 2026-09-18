r"""Compile the translated .po files back into game files.

    src/**/*.po --> po_lint --> olang rebuild --> re-encrypt --> BUILD/*.olang
                            \-> code points --> font rebuild --> BUILD/*.xpr
                                                             \-> BUILD/MANIFEST.tsv

Nothing is written unless `po_lint` comes back clean, and nothing that is
written is trusted: every rebuilt table is decrypted again and compared against
the pristine one slot by slot, so a translation that landed in the wrong place
-- or a string pool bug that disturbed an untranslated slot -- fails the build
instead of shipping.

The rebuild is offset-addressed, not fixed-width: `key[].str_off` points into a
string pool that is laid out from scratch here, so a translation may be any
length (PLANS/06 §5, evidence in olang_build's docstring).

Sources are read through `config.pristine()`, so building on top of an already
installed build still starts from the original English (PLANS/06 §8.1).

CODEC translations are collected and reported but not delivered: there is no
`briefing_build` yet.  The old note blamed `briefing_insn_decode` case
0x10/0x20 -- that was the wrong target.  The bytecode never has to be
re-emitted at all: no translatable text lives in it (ANALYSIS/03 §9.1).  What
blocks write-back is that a record may not change size, because `off3 ==
off0 - 4` in every one of the 2049 records and the gap to the next record is
only 0-15 bytes, while record offsets are addressed from outside through the
request word.  The fix is a size-preserving in-place rewrite of the string
pool and its offset table (ANALYSIS/03 §9.3), not a bytecode emitter.
They stay in the .po and cost nothing to carry.

Usage:
    python -m pwsf.po_import                 # lint, build, verify into BUILD/
    python -m pwsf.po_import --install       # ... and install it, in one go
    python -m pwsf.po_import --lang es       # write a different language slot
    python -m pwsf.po_import --skip-font     # text only, keep the shipped font
    python -m pwsf.po_import --rebuild-font  # re-lay the whole atlas out

`--install` hands the finished manifest to `pwsf.install`, so it inherits that
module's refusals: it will not write over a game file it cannot account for,
and it will not take a backup of anything but the recorded original.
"""

import argparse
import hashlib
from pathlib import Path

from . import config, po_lint, slots
from .font_build import (build_font, rebuild_font, verify_coverage,
                         verify_rebuild)
from .olang import parse, string_at
from .olang_build import OlangBuilder

MANIFEST = "MANIFEST.tsv"
MANIFEST_HEADER = "dest\tbuilt\tkind\tsize\tsha256\torig_sha256"


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def by_table(translations: dict) -> dict:
    """olang translations grouped by table stem; CODEC references dropped."""
    out = {}
    for ref, text in translations.items():
        parsed = slots.parse_ref(ref)
        if parsed.kind != slots.OLANG:
            continue
        out.setdefault(parsed.table, []).append((parsed, text))
    return {k: sorted(v, key=lambda it: (it[0].group, it[0].entry))
            for k, v in sorted(out.items())}


# ------------------------------------------------------------------- olang

def build_table(stem: str, items: list, lang: int, outdir: Path,
                verbose: bool = True) -> tuple:
    """Rebuild one .olang with `items` written into the `lang` slot."""
    builder = slots.builder(stem)
    written = []
    for ref, text in items:
        try:
            builder.set_text(ref.group, ref.entry, lang, text)
        except KeyError as exc:
            raise SystemExit(f"{stem}: {exc}") from None
        written.append((ref, text))

    dst = outdir / f"{stem}.olang"
    dst.write_bytes(slots.encrypt(stem, builder.serialize()))
    src = slots.olang_source_path(stem)
    if verbose:
        print(f"  {dst.name}  {len(written)} slot(s) rewritten, "
              f"{dst.stat().st_size} bytes (original {src.stat().st_size})")
    return dst, written


def verify_table(stem: str, built: Path, written: list, lang: int) -> list:
    """Re-read the built table: translations landed, nothing else moved."""
    problems = []
    rebuilt = parse(slots.decrypt(stem, built.read_bytes()), str(built))
    reader = OlangBuilder(rebuilt)
    for ref, text in written:
        try:
            got = reader.get_text(ref.group, ref.entry, lang)
        except KeyError as exc:
            problems.append(f"{ref}: vanished from the rebuilt table ({exc})")
            continue
        if got != text:
            problems.append(f"{ref}: rebuilt as {got!r}, expected {text!r}")

    orig = slots.table(stem)
    expected = {(ref.group, ref.entry) for ref, _ in written}
    if len(rebuilt.keys) != len(orig.keys):
        problems.append(f"{stem}: key table is {len(rebuilt.keys)} records, "
                        f"original has {len(orig.keys)}")
        return problems
    # key order is preserved by the serialiser, so index i means the same slot
    changed = 0
    for g in orig.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            e = orig.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                before = string_at(orig, orig.keys[ki][1])
                after = string_at(rebuilt, rebuilt.keys[ki][1])
                if before == after:
                    continue
                changed += 1
                if (g.key, e.key) not in expected:
                    problems.append(
                        f"{stem}: untranslated slot changed: group "
                        f"{g.key:#08x} entry {e.key:#08x} "
                        f"{before!r} -> {after!r}")
                elif orig.keys[ki][0] != lang:
                    problems.append(
                        f"{stem}: wrong language slot written: group "
                        f"{g.key:#08x} entry {e.key:#08x} "
                        f"key {orig.keys[ki][0]:#06x}")
    if changed != len(written):
        problems.append(f"{stem}: {changed} strings differ from the original, "
                        f"expected {len(written)}")
    return problems


# -------------------------------------------------------------------- font

def build_atlas(codepoints: set, outdir: Path, verbose: bool = True,
                rebuild: bool = False) -> tuple:
    stem = config.FONT_LARGE
    src = config.pristine(config.FONT_DIR / f"{stem}.xpr")
    dst = outdir / f"{stem}.xpr"
    if rebuild:
        report = rebuild_font(codepoints, src, dst, config.FONT_TTF,
                              verbose=verbose)
        problems = [f"font: {p}" for p in verify_rebuild(dst, src, report)]
        return dst, report, problems

    report = build_font(codepoints, src, dst, config.FONT_TTF, verbose=verbose)
    bad = verify_coverage(dst, codepoints)
    problems = ["font: no glyph for " + " ".join(f"U+{c:04X} {chr(c)}"
                                                 for c in bad[:10])] if bad else []
    return dst, report, problems


# -------------------------------------------------------------------- main

def manifest_row(built: Path, dest: Path, kind: str, orig: Path) -> str:
    rel = dest.relative_to(config.GAME_DIR).as_posix()
    return (f"{rel}\t{built.name}\t{kind}\t{built.stat().st_size}\t"
            f"{sha256(built)}\t{sha256(orig)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--po-dir", type=Path, default=config.PO_DIR)
    ap.add_argument("--outdir", type=Path, default=config.BUILD_DIR)
    ap.add_argument("--lang", default="en",
                    help="language slot to write the translations into "
                         f"({'/'.join(config.LANG_KEYS.values())}, default en)")
    ap.add_argument("--allow-ruby-drop", action="store_true",
                    help="see po_lint: demote dropped <R=...> to a warning")
    ap.add_argument("--skip-lint", action="store_true",
                    help="build even if the corpus does not pass po_lint")
    ap.add_argument("--skip-font", action="store_true",
                    help="do not rebuild the font atlas")
    ap.add_argument("--rebuild-font", action="store_true",
                    help="lay the whole atlas out again instead of filling "
                         "its free rows: more room, and the shipped "
                         "ideographs get repainted from the same face as the "
                         "new ones (ANALYSIS/05_font.md §12)")
    ap.add_argument("--install", action="store_true",
                    help="install the build straight after verifying it "
                         "(see pwsf.install)")
    ap.add_argument("--force", action="store_true",
                    help="with --install, overwrite game files whose content "
                         "is not recognised (the original may be lost)")
    args = ap.parse_args()
    config.require_game()
    lang = po_lint.lang_key(args.lang)

    rep = po_lint.lint(args.po_dir, lang, args.allow_ruby_drop,
                       check_font=not args.skip_font,
                       rebuild_font=args.rebuild_font)
    po_lint.print_report(rep)
    if rep.errors and not args.skip_lint:
        raise SystemExit("\nlint failed, nothing built (--skip-lint to override)")
    if not rep.translations:
        raise SystemExit("\nnothing translated yet, nothing to build")

    tables = by_table(rep.translations)
    if not tables:
        raise SystemExit("\nonly CODEC slots are translated, and CODEC "
                         "write-back is still blocked; nothing to build")

    args.outdir.mkdir(parents=True, exist_ok=True)
    print(f"\nbuilding into {args.outdir} ({config.LANG_KEYS[lang]} slot)")
    rows, problems, codepoints = [], [], set()
    for stem, items in tables.items():
        built, written = build_table(stem, items, lang, args.outdir)
        problems += verify_table(stem, built, written, lang)
        codepoints |= {ord(c) for _ref, text in written for c in text}
        rows.append(manifest_row(built, config.TEXT_DIR / built.name, "olang",
                                 slots.olang_source_path(stem)))

    if not args.skip_font:
        print(f"\n{len(codepoints)} distinct code points in the translations")
        built, _report, font_problems = build_atlas(codepoints, args.outdir,
                                                    rebuild=args.rebuild_font)
        problems += font_problems
        rows.append(manifest_row(built, config.FONT_DIR / built.name, "font",
                                 config.pristine(config.FONT_DIR / built.name)))
        if not font_problems:
            print("  verified: " + ("shipped metrics and inherited pixels "
                                    "unchanged, everything mapped non-blank"
                                    if args.rebuild_font else
                                    "every code point has a non-blank glyph"))

    if problems:
        print(f"\n{len(problems)} VERIFICATION FAILURE(S):")
        for p in problems[:15]:
            print("  " + p)
        raise SystemExit(1)

    (args.outdir / MANIFEST).write_text(
        "\n".join([MANIFEST_HEADER] + rows) + "\n", encoding="utf-8")
    print("\nverified: translations read back identical, every other slot "
          "byte-identical to the original")
    print(f"manifest -> {args.outdir / MANIFEST} ({len(rows)} file(s))")

    if not args.install:
        print("install with: python -m pwsf.install --install")
        return
    # imported here, not at the top: install reads the manifest format from
    # this module, so a module-level import would be circular
    from . import install
    print(f"\ninstalling into {config.GAME_DIR}")
    install.install(install.read_manifest(args.outdir), args.force)
    print("restore with: python -m pwsf.install --restore")


if __name__ == "__main__":
    main()
