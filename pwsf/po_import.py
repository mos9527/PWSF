r"""Compile the translated .po files back into game files.

    src/**/*.po --> po_lint --> olang rebuild --> re-encrypt --> BUILD/*.olang
                            \-> CODEC 0076531d.DAT: pools rewritten in place
                            \-> SLOT.DAT rebuilt
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

CODEC translations are written in place: a record may not change size, because
`off3 == off0 - 4` in all 2049 records, the gap to the next record is only
0-15 bytes, and record offsets are addressed from outside through the request
word (ANALYSIS/03 §9.2).  So `briefing_build` rewrites the string pool and the
u32 offset table and leaves everything else -- headers, bytecode, padding,
every other record -- alone.  No translatable text lives in the bytecode, so
the old `briefing_insn_decode` case 0x10/0x20 blocker was the wrong target.

That makes the pool budget a hard limit: the two English blocks hold 555 free
bytes over 358 records, so a translation longer than the English it replaces
does not fit.  `briefing_build` reports those records and leaves them in
English; `po_lint` reports them first, as errors, at lint time.

Usage:
    python -m pwsf.po_import                 # lint, build, verify into BUILD/
    python -m pwsf.po_import --install       # ... and install it, in one go
    python -m pwsf.po_import --lang es       # write a different language slot
    python -m pwsf.po_import --skip-font     # text only, keep the shipped font
    python -m pwsf.po_import --add-font      # fill the shipped atlas's free
                                             # rows instead of rebuilding it
                                             # (the CJK glyphs stay Japanese)

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
from . import briefing_build
from . import slotdat as S
from . import slotdat_build

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


def by_codec(translations: dict) -> dict:
    """CODEC translations, keyed by reference.

    Grouping by record is `briefing_build`'s job: it is the same call the
    build and the verification make, so all three agree on what a reference
    means.
    """
    out = {}
    for ref, text in translations.items():
        if ref.startswith(slots.CODEC + "/"):
            out[ref] = text
    return out


def by_slot(translations: dict) -> dict:
    """SLOT.DAT translations: {(table_id, group, entry): text}.

    These live in the olang tables embedded in SLOT.DAT (ANALYSIS/08 §7) and
    need a whole-container rebuild, not a per-file rewrite.
    """
    out = {}
    for ref, text in translations.items():
        parsed = slots.parse_ref(ref)
        if parsed.kind != slots.SLOT:
            continue
        out[(parsed.table, parsed.group, parsed.entry)] = text
    return out


def by_gtt(translations: dict) -> dict:
    """GTT translations: {(pool_id, block_off, line): text}.

    The GTT pools of SLOT.DAT (ANALYSIS/11) hold the in-mission radio and hint
    lines.  They ride along with the SLOT.DAT rebuild, because that is the
    container they live in -- the patcher writes them in place, so a pool
    never changes length.
    """
    out = {}
    for ref, text in translations.items():
        parsed = slots.parse_ref(ref)
        if parsed.kind != slots.GTT:
            continue
        out[(parsed.pool, parsed.block, parsed.line)] = text
    return out


# ------------------------------------------------------------------- olang

def build_table(stem: str, items: list, lang: int, outdir: Path,
                verbose: bool = True) -> tuple:
    """Rebuild one .olang with `items` written into the `lang` slot."""
    builder = slots.builder(stem)
    written = []
    identical = 0
    for ref, text in items:
        try:
            before = builder.get_text(ref.group, ref.entry, lang)
        except KeyError as exc:
            raise SystemExit(f"{stem}: {exc}") from None
        # A translation equal to the original changes no byte: writing it is a
        # no-op, and counting it in `written` would make `verify_table`'s
        # "changed == len(written)" compare against a number the file cannot
        # show. Machine translation does hand back the English for proper nouns
        # and for lines it gave up on, so this is common, not exceptional.
        if before == text:
            identical += 1
            continue
        builder.set_text(ref.group, ref.entry, lang, text)
        written.append((ref, text))

    dst = outdir / f"{stem}.olang"
    dst.write_bytes(slots.encrypt(stem, builder.serialize()))
    src = slots.olang_source_path(stem)
    if verbose:
        print(f"  {dst.name}  {len(written)} slot(s) rewritten, "
              f"{dst.stat().st_size} bytes (original {src.stat().st_size})")
        if identical:
            print(f"    {identical} slot(s) skipped: the translation is the "
                  f"original text verbatim")
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
    ap.add_argument("--skip", action="append", default=[], metavar="PART",
                    choices=["olang", "slot", "codec", "gtt"],
                    help="leave a corpus out of the build entirely: its file(s) "
                         "never reach the manifest, so `install` will not touch "
                         "them (repeatable, e.g. --skip codec)")
    ap.add_argument("--codec-skip-overflow", action="store_true",
                    help="a CODEC record whose pool cannot hold the "
                         "translation is left in English instead of failing "
                         "the build (records cannot move, ANALYSIS/03 §9.3)")
    # rebuilding is the default: filling only the free rows leaves the shipped
    # Japanese glyphs in place, so translated Chinese renders half in the
    # shipped face and half in ours -- the mixed atlas seen on 2026-09-20
    # (PLANS/06 §9.2)
    ap.add_argument("--rebuild-font", dest="rebuild_font", action="store_true",
                    default=True,
                    help="lay the whole atlas out again instead of filling "
                         "its free rows: more room, and the shipped "
                         "ideographs get repainted from the same face as the "
                         "new ones (default; ANALYSIS/05_font.md §12)")
    ap.add_argument("--add-font", dest="rebuild_font", action="store_false",
                    help="only fill the free rows of the shipped layout, "
                         "keeping every shipped glyph's pixels (gives the "
                         "mixed-typeface atlas back)")
    ap.add_argument("--install", action="store_true",
                    help="install the build straight after verifying it "
                         "(see pwsf.install)")
    ap.add_argument("--force", action="store_true",
                    help="with --install, overwrite game files whose content "
                         "is not recognised (the original may be lost)")
    ap.add_argument("--launch", action="store_true",
                    help="when everything is in place, start the game through "
                         "Steam (steam://run/<appid>) -- goes via Steam so the "
                         "overlay and cloud saves apply, and it runs "
                         "launcher.exe, i.e. the shim if one is installed")
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

    skip = set(args.skip)
    if skip:
        print(f"skipping: {', '.join(sorted(skip))} (its file(s) stay as they "
              f"are in the game)")
    tables = {} if "olang" in skip else by_table(rep.translations)
    codec_items = {} if "codec" in skip else by_codec(rep.translations)
    slot_items = {} if "slot" in skip else by_slot(rep.translations)
    gtt_items = {} if "gtt" in skip else by_gtt(rep.translations)
    if not tables and not slot_items and not codec_items and not gtt_items:
        raise SystemExit("\nnothing to build: no olang / SLOT / CODEC / GTT "
                         "slot is translated")

    args.outdir.mkdir(parents=True, exist_ok=True)
    print(f"\nbuilding into {args.outdir} ({config.LANG_KEYS[lang]} slot)")
    rows, problems, codepoints, notes = [], [], set(), []

    if codec_items and lang != config.LANG_EN:
        problems.append(
            f"{len(codec_items)} CODEC slot(s) "
            f"translated, but CODEC write-back only targets the English "
            f"block: a reference names the English record it came from, and "
            f"the {config.LANG_KEYS[lang]} copy sits in a record whose offset "
            f"the corpus does not carry")
        codec_items = {}

    if gtt_items and lang != config.LANG_EN:
        problems.append(
            f"{len(gtt_items)} GTT slot(s) translated, but GTT write-back only "
            f"targets the English line: a reference names the run the English "
            f"sits in, and the {config.LANG_KEYS[lang]} copies are the "
            f"suffix-merged fragments around it (ANALYSIS/11 §3)")
        gtt_items = {}

    if codec_items:
        print(f"\nCODEC: {len(codec_items)} line(s) in "
              f"{len(briefing_build.by_record(codec_items))} record(s) -- "
              f"rewriting the string pools in place")
        dat, st = briefing_build.rebuild(codec_items, lang, args.outdir)
        problems += briefing_build.verify(dat, codec_items, lang)
        codepoints |= {ord(c) for t in codec_items.values() for c in t}
        for g, off, need, budget in st.overflow:
            msg = (f"codec record {off:#x} (group {g}): the translations need "
                   f"{need} pool bytes, the record only has {budget}; records "
                   f"cannot move, so shorten one of its lines "
                   f"(ANALYSIS/03 §9.3)")
            (notes if args.codec_skip_overflow else problems).append(msg)
        rows.append(manifest_row(dat, config.BRIEFING_DAT, "codec",
                                 briefing_build.source_path()))
        print(f"  {st}")

    if slot_items or gtt_items:
        print(f"\nSLOT.DAT: {len(slot_items)} olang string(s), "
              f"{len(gtt_items)} GTT line(s) -- rebuilding the container "
              f"(this re-reads all 2,137 records twice)")
        dat, key, stats = slotdat_build.rebuild(slot_items, lang, args.outdir,
                                                gtt=gtt_items)
        problems += slotdat_build.verify(dat, key, slot_items, lang,
                                         gtt=gtt_items,
                                         dropped=stats["gtt_dropped_pools"],
                                         written=stats["gtt_written"])
        problems += [f"gtt: {p}" for p in stats.get("gtt_problems", ())]
        if stats["gtt_dropped"]:
            notes.append(
                f"{len(stats['gtt_dropped'])} SLOT.DAT record(s) "
                f"({', '.join(str(i) for i in stats['gtt_dropped'][:8])}) "
                f"could not be compressed into their slot with the GTT lines "
                f"translated: those lines stay English "
                f"(ANALYSIS/11 §5, slotdat_build._compress)")
        codepoints |= {ord(c) for t in slot_items.values() for c in t}
        codepoints |= {ord(c) for t in gtt_items.values() for c in t}
        # dest must be the LIVE game path, never S.dat_path(): that goes
        # through config.pristine, so once a .orig backup exists the manifest
        # would name the backup as the install target and install would
        # overwrite it with the build (that is how 002aba34.DAT.orig got
        # clobbered on 2026-09-20; the original survived only as .orig.orig).
        disc0 = config.DISC0_DIR
        rows.append(manifest_row(dat, disc0 / f"{S.STEM}.DAT", "slotdat",
                                 S.dat_path()))
        rows.append(manifest_row(key, disc0 / f"{S.STEM}.KEY", "slotdat",
                                 S.key_path()))
        print(f"  {stats['patched']} record(s) repacked, {stats['strings']} "
              f"string(s) written")

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
    for n in notes:
        print(f"  note: {n}")

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

    if args.launch:
        from .launch import launch_via_steam
        launch_via_steam()


if __name__ == "__main__":
    main()
