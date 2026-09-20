"""Use the shipped Japanese copy as a stand-in for Chinese.

_probe_slot27.py: the embedded pools are packed to ~99% of their slot, so a
translation that grows the pool by 20% fits in only 2 of 43 tables.  Whether
Chinese fits therefore comes down to one number -- how many bytes a CJK
translation takes next to the English source.

We do not have to guess: each table also ships a Japanese copy, and Japanese
is CJK too (3 bytes per character in UTF-8, same as Chinese).  So write the
Japanese strings into the English pool and see whether it still fits.  If it
does for Japanese it will do for Chinese, which is consistently a little
shorter than the Japanese localisation of the same line.

Also reports the per-string ja/en byte ratio, which is the number to watch
when translating.
"""

import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import olang
from pwsf.olang_build import OlangBuilder
from pwsf import slotdat as S


def rows_of(tbl):
    out = {}
    for g in tbl.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            if ei >= len(tbl.entries):
                continue
            e = tbl.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                if ki >= len(tbl.keys):
                    continue
                lang, so, meta, _pad = tbl.keys[ki]
                out.setdefault((g.key, e.key), {})[lang] = \
                    olang.string_at(tbl, so)
    return out


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    # (table_id, lang) -> (pool blob, slot capacity)
    loc = {}
    for rec in recs:
        pools = S.pools(rec, ks)
        for i, (eid, off, blob) in enumerate(pools):
            if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
                continue
            tbl = olang.parse(blob, f"slot/{rec.index}/{eid:#010x}")
            langs = {k[0] for k in tbl.keys}
            stop = (pools[i + 1][1] if i + 1 < len(pools)
                    else len(S.inflate(S.decrypt(S.read_block(rec), ks))))
            for lang in langs:
                loc.setdefault((tbl.table_id, lang), (blob, stop - off))

    tables = sorted(t for t, l in loc if S.is_cutscene(t) and l == C.LANG_EN)
    ja = C.LANG_KEYS and 0x0DB0
    print(f"cutscene tables: {len(tables)}")

    ratios = []
    overflow = []
    ok = 0
    for tid in tables:
        blob_en, cap = loc[(tid, C.LANG_EN)]
        if (tid, ja) not in loc:
            overflow.append((tid, "no japanese copy"))
            continue
        blob_ja, _ = loc[(tid, ja)]
        en_rows = rows_of(olang.parse(blob_en, ""))
        ja_rows = rows_of(olang.parse(blob_ja, ""))

        b = OlangBuilder(olang.parse(blob_en, ""))
        for (gk, ek), bylang in en_rows.items():
            src = bylang.get(C.LANG_EN, b"")
            dst = ja_rows.get((gk, ek), {}).get(ja)
            if not src or not dst:
                continue
            ratios.append(len(dst) / len(src))
            b.set_text(gk, ek, C.LANG_EN, dst.decode("utf-8", "replace"))
        built = b.serialize()
        if len(built) <= cap:
            ok += 1
        else:
            overflow.append((tid, f"{len(built)} > {cap} "
                                  f"(+{len(built) - cap} B)"))

    print(f"\nja/en byte ratio over {len(ratios)} strings:")
    if ratios:
        print(f"  mean {statistics.mean(ratios):.3f}  "
              f"median {statistics.median(ratios):.3f}  "
              f"p90 {sorted(ratios)[int(len(ratios) * 0.9)]:.3f}  "
              f"max {max(ratios):.3f}")
    print(f"\nJapanese-into-English rebuild fits the pool slot: "
          f"{ok}/{len(tables)}")
    for tid, why in overflow:
        print(f"  {tid:#010x}  {why}")


if __name__ == "__main__":
    main()
