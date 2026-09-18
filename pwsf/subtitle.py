"""PWSF in-game subtitle extractor (AI weapon battle chatter).

Evidence chain, all read off the binary:

  subtitle_state_machine @ 0x14026BC00
      v3 = &xmmword_141884900           (sub_140052190 is `lea rax, g; retn`)
      switch (a1[29])                   mode 1..4
        mode 1 -> v3[13] @ 0x141884934
        mode 2 -> v3[11] @ 0x14188492C
        mode 3 -> v3[12] @ 0x141884930
        mode 4 -> v3[10] @ 0x141884928
      each flag picks a group key by value 1 or 2, and sets a1[31] = line count
      then, for v6 in 0 .. a1[31]-1:
          text_get(v4, v6, get_olang_lang_id(-1), &out)

  text_get @ 0x1400E6990 -> text_lookup @ 0x1400E6EB0 is the olang reader,
  so v4 is an olang *group key*, v6 the *entry key*, and the language id the
  *key id* -- exactly the three levels pwsf_olang already resolves.

  The same four flags are the install-slot selectors in path_resolve_install
  @ 0x140043DA0 (0x141884934 -> /AVD00003.PDT, 0x14188492C -> /AVD00000.PDT,
  0x141884930 -> /AVD00001.PDT, 0x141884928 -> /AVD00002.PDT), which is how
  each subtitle group is tied to a DLC voice pack.

Measured: slot 1 groups carry all six languages, slot 2 groups carry Japanese
only -- consistent with slot 2 being the JP-voice pack (not shipped on Steam,
which ships 171ae461 / 181ae463 / 191ae465 / 1a1ae467, i.e. slot 1).
"""

from . import config
from .crypto import name_hash
from .olang import load, string_at

GAME = config.GAME_DIR
OUT = config.SUBTITLE_TSV

LANG = config.LANG_KEYS

# (mode a1[29], flag address, DLC pack, flag value, group key, line count a1[31])
GROUPS = [
    (1, 0x141884934, "AVD00003", 1, 0x00BC4A75, 74),
    (1, 0x141884934, "AVD00003", 2, 0x00468863, 74),
    (2, 0x14188492C, "AVD00000", 1, 0x00E34675, 38),
    (2, 0x14188492C, "AVD00000", 2, 0x0029956A, 38),
    (3, 0x141884930, "AVD00001", 1, 0x00E9CBF5, 28),
    (3, 0x141884930, "AVD00001", 2, 0x00D36BFC, 28),
    (4, 0x141884928, "AVD00002", 1, 0x00903077, 32),
    (4, 0x141884928, "AVD00002", 2, 0x00430FFE, 32),
]

HEADER = "mode\tpack\tslot\tgroup\tline\tlang\tsrc\ttext"


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def collect():
    by_group = {g: [] for _, _, _, _, g, _ in GROUPS}
    for sub in ("MLG/Text", "EXLANG/Text"):
        for f in sorted((GAME / sub.replace("/", "\\")).glob("*.olang")):
            # read the pre-install original, never a build we put there
            tbl = load(config.pristine(f), name_hash(f.stem))
            for grp in tbl.groups:
                if grp.key not in by_group:
                    continue
                for ei in range(grp.entry_start, grp.entry_start + grp.entry_count):
                    e = tbl.entries[ei]
                    for ki in range(e.key_start, e.key_start + e.key_count):
                        k, off, _meta, _pad = tbl.keys[ki]
                        lang = LANG.get(k, f"u{k:#x}")
                        # EXLANG ships Portuguese in the Spanish slot (plan 01)
                        if sub == "EXLANG/Text" and lang == "es":
                            lang = "pt"
                        text = string_at(tbl, off).decode("utf-8")
                        by_group[grp.key].append((e.key, lang, f"{sub}/{f.name}", text))
    return by_group


def main() -> None:
    by_group = collect()
    rows, problems = [], []

    for mode, flag_ea, pack, slot, group, want_lines in GROUPS:
        found = by_group[group]
        if not found:
            problems.append(f"group {group:#08x} (mode {mode} slot {slot}) not found in any olang")
            continue
        lines = sorted({line for line, _, _, _ in found})
        if lines != list(range(want_lines)):
            problems.append(
                f"group {group:#08x}: entry keys {lines[:3]}..{lines[-1:]} "
                f"({len(lines)}) do not form 0..{want_lines - 1} as a1[31] demands"
            )
        for line, lang, src, text in sorted(found, key=lambda r: (r[0], r[1])):
            rows.append(
                f"{mode}\t{pack}\t{slot}\t{group:#08x}\t{line}\t{lang}\t{src}\t{esc(text)}"
            )

    OUT.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} rows -> {OUT}")

    for mode, flag_ea, pack, slot, group, want_lines in GROUPS:
        langs = {}
        for _line, lang, _src, text in by_group[group]:
            if text.strip():
                langs[lang] = langs.get(lang, 0) + 1
        summary = " ".join(f"{k}={v}" for k, v in sorted(langs.items())) or "(all empty)"
        print(f"  mode {mode} {pack} slot {slot} group {group:#08x} "
              f"flag {flag_ea:#x} lines {want_lines:3d}  nonempty: {summary}")

    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  " + p)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
