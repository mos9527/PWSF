"""Is the tail of SLOT.DAT really "the cutscenes"?

The 144 embedded olang tables split cleanly by the record they first appear
in.  Everything from record 1863 to the end (2,137) has a table id in
0x003af000..0x003b0a00, and nothing outside that record range has one.  This
probe checks the two halves are structurally different, which is what makes
"table id in that window" usable as the cutscene filter:

  * what magics do the pools of each region carry?  (cutscene records should
    be text-only -- the comic art itself lives in STAGEDAT.PDT)
  * how many resource entries, how big?
  * do any cutscene-id tables appear outside the region, or vice versa?

Writes the two corpora:
  _slot_olang_lines.tsv   everything, with the source record
  _cutscene_lines.tsv     the cutscene tables only
"""

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import slotdat as S

CUT_FIRST_REC = 1863


def esc(text: bytes) -> str:
    return (text.decode("utf-8", "replace")
            .replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\r", "\\r")
            .replace("\n", "\\n"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all-out",
                    default=str(C.ANALYSIS_DIR / "_slot_olang_lines.tsv"))
    ap.add_argument("--cut-out",
                    default=str(C.ANALYSIS_DIR / "_cutscene_lines.tsv"))
    args = ap.parse_args()

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    region = defaultdict(Counter)      # 'head'/'tail' -> magic counter
    entries_n = defaultdict(list)
    for rec in recs:
        # 2,137 records x up to ~470 MB of reads; only the head bytes of each
        # pool are needed, so this is cheap enough
        where = "tail" if rec.index >= CUT_FIRST_REC else "head"
        pools = S.pools(rec, ks)
        entries_n[where].append(len(pools))
        for _eid, _off, blob in pools:
            region[where][blob[:4]] += 1

    print("pool magics by region:")
    for where in ("head", "tail"):
        tot = sum(region[where].values())
        top = ", ".join(f"{m!r}={n}" for m, n in region[where].most_common(5))
        avg_ent = sum(entries_n[where]) / max(len(entries_n[where]), 1)
        print(f"  {where:<5} records={len(entries_n[where]):<5} pools={tot:<6} "
              f"avg entries/record={avg_ent:.1f}")
        print(f"         {top}")

    rows, first_seen, locations = S.embedded_olang()
    by_table = defaultdict(list)
    for r in rows:
        by_table[r.table_id].append(r)

    cut = {t for t in by_table if S.is_cutscene(t)}
    print(f"\ntables: {len(by_table)}   cutscene-id tables: {len(cut)}")
    outside = [t for t in cut
               if first_seen[(t, C.LANG_EN)] < CUT_FIRST_REC]
    inside_other = [t for t in by_table
                    if not S.is_cutscene(t)
                    and first_seen[(t, C.LANG_EN)] >= CUT_FIRST_REC]
    print(f"  cutscene-id tables first seen before record {CUT_FIRST_REC}: "
          f"{len(outside)}")
    print(f"  non-cutscene tables first seen at/after: {len(inside_other)}")

    en_cut = sum(1 for r in rows
                 if r.lang == C.LANG_EN and S.is_cutscene(r.table_id))
    print(f"  English cutscene rows: {en_cut}")

    # write both corpora
    def dump(path, keep):
        out = ["table_id\tlang\tgroup\tentry\tmeta\trecord\tlocations\ttext"]
        for r in rows:
            if not keep(r):
                continue
            key = (r.table_id, r.lang)
            locs = ";".join(f"{rec}:{eid:#010x}"
                            for rec, eid in locations[key])
            out.append("\t".join((
                f"{r.table_id:#010x}",
                C.LANG_KEYS.get(r.lang, f"{r.lang:#06x}"),
                f"{r.group:#08x}", f"{r.entry:#08x}", f"{r.meta:#06x}",
                str(first_seen[key]), locs, esc(r.text))))
        Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")
        print(f"wrote {path}  ({len(out) - 1} rows)")

    dump(args.all_out, lambda r: True)
    dump(args.cut_out, lambda r: S.is_cutscene(r.table_id))


if __name__ == "__main__":
    main()
