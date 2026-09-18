"""Probe: size and shape of the English-only corpus, to pick a .po split.

Counts per source table: English slots, how many are non-empty, and how many
distinct strings there are -- the duplicate rate decides whether entries should
be merged by msgid or kept one-per-slot.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt
from pwsf_olang import parse, string_at
from pwsf import config

GAME = config.GAME_DIR
ANALYSIS = Path(__file__).resolve().parent.parent / "ANALYSIS"
LANG_EN = 0x0D0E


def olang_rows():
    for sub in ("MLG/Text", "EXLANG/Text"):
        for f in sorted((GAME / sub.replace("/", "\\")).glob("*.olang")):
            src = config.pristine(f)   # never measure an installed build
            tbl = parse(bytes(buffer_xor_decrypt(bytearray(src.read_bytes()),
                                                 name_hash(f.stem))))
            rows = []
            for g in tbl.groups:
                for ei in range(g.entry_start, g.entry_start + g.entry_count):
                    e = tbl.entries[ei]
                    for ki in range(e.key_start, e.key_start + e.key_count):
                        if tbl.keys[ki][0] != LANG_EN:
                            continue
                        rows.append((g.key, e.key,
                                     string_at(tbl, tbl.keys[ki][1]).decode("utf-8")))
            yield sub, f.stem, rows


def main() -> None:
    print(f"{'source':<14} {'file':<10} {'en slots':>9} {'non-empty':>10} "
          f"{'distinct':>9} {'dup rate':>9} {'chars':>9}")
    grand = dict(slots=0, ne=0, chars=0)
    all_texts = []
    for sub, stem, rows in olang_rows():
        ne = [t for _, _, t in rows if t]
        distinct = set(ne)
        chars = sum(len(t) for t in ne)
        dup = 1 - len(distinct) / len(ne) if ne else 0
        print(f"{sub:<14} {stem:<10} {len(rows):>9} {len(ne):>10} "
              f"{len(distinct):>9} {dup:>8.0%} {chars:>9}")
        grand["slots"] += len(rows)
        grand["ne"] += len(ne)
        grand["chars"] += chars
        if sub == "MLG/Text":
            all_texts += ne

    print(f"\nolang total: {grand['slots']} en slots, {grand['ne']} non-empty, "
          f"{grand['chars']} chars")
    print(f"MLG only   : {len(all_texts)} non-empty, "
          f"{len(set(all_texts))} distinct "
          f"(dup rate {1 - len(set(all_texts)) / len(all_texts):.0%})")

    # CODEC
    lines = (ANALYSIS / "_briefing_lines.tsv").read_text(encoding="utf-8").splitlines()
    en = [l.split("\t") for l in lines[1:] if l.split("\t")[1] == "en"]
    texts = [c[10] for c in en if c[10].strip()]
    print(f"\ncodec      : {len(en)} en lines, {len(texts)} non-empty, "
          f"{len(set(texts))} distinct "
          f"(dup rate {1 - len(set(texts)) / len(texts):.0%}), "
          f"{sum(len(t) for t in texts)} chars")

    total = len(all_texts) + len(texts)
    print(f"\ngrand total to translate (MLG olang + codec): {total} entries")
    for chunk in (200, 300, 500, 800):
        print(f"  split at {chunk:>4} entries/file -> "
              f"{-(-total // chunk)} files")


if __name__ == "__main__":
    main()
