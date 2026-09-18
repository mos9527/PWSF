r"""Probe: the .po -> game-file pipeline, checked against the PoC that shipped.

`_poc_text_cn.py` hand-wrote eight Chinese strings into group 0x9B86AB of
009c9ea4 and the result was verified on real hardware.  Those same eight
strings now live in `src/olang/olang_03.po` as ordinary translations, so the
pipeline has an oracle: whatever `po_lint` + `po_import` produce must carry
exactly the PoC text in exactly those slots.

It must also produce MORE than the PoC did: the exporter merges by msgid, so
"Return to the title menu?" covers three further slots in group 0x596F30 that
the PoC never touched.  That difference is the point of merging, and this probe
pins it down rather than letting it look like a bug.

Checks, in order:

    1  po_lint is clean, and reports the slot / code point counts
    2  every translated slot reads back as its msgstr
    3  the eight PoC slots carry the PoC's exact strings
    4  the rebuilt table differs from the pristine one in those slots ONLY
    5  the rebuilt font keeps every shipped glyph mapping and adds the rest
    6  the manifest hashes match the files it lists

Run from anywhere:  python research/TOOLS/_probe_po3.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config, po_import, po_lint, slots
from pwsf.font import PwsfFont
from pwsf.font_build import WHITESPACE
from pwsf.olang import parse, string_at

TABLE = "009c9ea4"
GROUP = 0x9B86AB
OUT = config.BUILD_DIR / "_probe_po3"

# copied verbatim from _poc_text_cn.py -- the strings that were verified in game
POC = {
    0x0198DA: "不修改密码就离开吗？",
    0x3020BC: "玩家名一经确定便无法更改。",
    0x3F2C7B: "所选名称过短。\n请输入长度超过 %d 个字符的名称。",
    0x4C248F: "返回标题画面吗？",
    0x518104: "请输入玩家名。",
    0x51EEA1: "请修改密码。",
    0x5F42B2: "所选名称过短。\n请输入长度超过 %d 个字符的名称。",
    0x75BF6E: "其中包含本游戏无法使用的字词。",
}

problems = []


def check(ok: bool, message: str) -> None:
    if not ok:
        problems.append(message)


def main() -> None:
    config.require_game()
    lang = po_lint.lang_key("en")

    # 1 -------------------------------------------------------------- lint
    rep = po_lint.lint(lang=lang)
    s = rep.stats
    print(f"1  lint: {s['entries']} entries, {s['refs']} references, "
          f"{s['translated']} translated -> {s['olang_slots']} olang slots, "
          f"{s['codepoints']} code points")
    check(not rep.errors, f"lint reported {len(rep.errors)} error(s)")
    for p in rep.errors[:5]:
        problems.append("  " + str(p))
    if rep.errors:
        return

    # 2 --------------------------------------------------------- rebuild
    OUT.mkdir(parents=True, exist_ok=True)
    tables = po_import.by_table(rep.translations)
    built = {}
    for stem, items in tables.items():
        path, written = po_import.build_table(stem, items, lang, OUT,
                                              verbose=False)
        built[stem] = (path, written)
        for message in po_import.verify_table(stem, path, written, lang):
            problems.append(message)
    print(f"2  rebuilt {len(built)} table(s): "
          + ", ".join(f"{k} ({len(v[1])} slots)" for k, v in built.items()))

    check(TABLE in built, f"{TABLE} was not rebuilt")
    if TABLE not in built:
        return
    path, written = built[TABLE]
    rebuilt = parse(slots.decrypt(TABLE, path.read_bytes()), str(path))
    pristine = slots.table(TABLE)

    # 3 ------------------------------------------------------ PoC oracle
    texts = {(ref.group, ref.entry): text for ref, text in written}
    for entry, expected in POC.items():
        got = texts.get((GROUP, entry))
        check(got == expected,
              f"PoC slot {entry:#08x}: pipeline wrote {got!r}, "
              f"PoC verified {expected!r}")
    print(f"3  all {len(POC)} PoC-verified slots carry the PoC text, "
          f"character for character")

    # 4 ------------------------------------------- nothing else changed
    expected_refs = {str(ref) for ref, _ in written}
    differing = set()
    for g in pristine.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            e = pristine.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                if string_at(pristine, pristine.keys[ki][1]) == \
                        string_at(rebuilt, rebuilt.keys[ki][1]):
                    continue
                differing.add(f"olang/{TABLE}/{g.key:#08x}/{e.key:#08x}")
                check(pristine.keys[ki][0] == lang,
                      f"a non-English key changed: group {g.key:#08x} "
                      f"entry {e.key:#08x} key {pristine.keys[ki][0]:#06x}")
    check(differing == expected_refs,
          f"changed slots do not match the .po: "
          f"unexpected {sorted(differing - expected_refs)[:3]}, "
          f"missing {sorted(expected_refs - differing)[:3]}")
    merged_extra = sorted(r for r in differing
                          if f"/{GROUP:#08x}/" not in r)
    print(f"4  {len(differing)} of {len(pristine.keys)} strings differ from "
          f"pristine, all in the en slot; {len(merged_extra)} beyond the PoC's "
          f"{len(POC)} (msgid merge):")
    for r in merged_extra:
        print(f"     {r}")

    # 5 ----------------------------------------------------------- font
    stem = config.FONT_LARGE
    src = config.pristine(config.FONT_DIR / f"{stem}.xpr")
    dst, report, font_problems = po_import.build_atlas(
        {ord(c) for _r, t in written for c in t}, OUT, verbose=False)
    problems.extend(font_problems)
    before, after = PwsfFont.load(src), PwsfFont.load(dst)
    remapped = [cp for cp in before.coverage()
                if after.translator[cp] != before.translator[cp]]
    check(not remapped,
          f"{len(remapped)} shipped code point(s) were remapped, e.g. "
          + " ".join(f"U+{c:04X}" for c in remapped[:5]))
    check(len(after.glyphs) == len(before.glyphs) + report["added"],
          f"glyph count {len(after.glyphs)} != "
          f"{len(before.glyphs)} + {report['added']}")
    wanted = {ord(c) for _r, t in written for c in t} - WHITESPACE
    check(wanted <= after.coverage(),
          f"{len(wanted - after.coverage())} code point(s) still unmapped")
    print(f"5  font {stem}: {len(before.glyphs)} glyphs -> "
          f"{len(after.glyphs)} (+{report['added']}), "
          f"{len(before.coverage())} mappings kept, {report['free_rows_left']} "
          f"atlas rows still free")

    # 6 ------------------------------------------------------- manifest
    rows = [po_import.manifest_row(path, config.TEXT_DIR / path.name, "olang",
                                   slots.olang_source_path(TABLE)),
            po_import.manifest_row(dst, config.FONT_DIR / dst.name, "font", src)]
    (OUT / po_import.MANIFEST).write_text(
        "\n".join([po_import.MANIFEST_HEADER] + rows) + "\n", encoding="utf-8")
    from pwsf import install
    items = install.read_manifest(OUT)          # re-hashes and validates
    print(f"6  manifest: {len(items)} file(s), hashes verified, destinations "
          + ", ".join(str(i.dest.relative_to(config.GAME_DIR)) for i in items))

    print(f"\noutput in {OUT}")


if __name__ == "__main__":
    main()
    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems[:15]:
            print("  " + p)
        raise SystemExit(1)
    print("all checks passed")
