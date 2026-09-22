"""Probe: what does the BUILT SLOT.DAT actually hold, line by line?

`po_import` prints one line per container; this re-reads the built
`002aba34.DAT` and counts the GTT lines that came out Chinese against the ones
that are still English -- and, for those, whether a translation existed at all
(the corpus is deduplicated by text, so an address may simply have no ref).

Usage:  python _probe_gtt_built.py [dat] [key]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt, po, slotdat as S, slots        # noqa: E402


def main() -> None:
    dat = Path(sys.argv[1] if len(sys.argv) > 1
               else "research/BUILD/002aba34.DAT")
    key = Path(sys.argv[2] if len(sys.argv) > 2
               else "research/BUILD/002aba34.KEY")
    if not dat.is_file():
        raise SystemExit(f"{dat} is missing; run python -m pwsf.po_import")

    # English text -> Chinese, as far as src/gtt goes
    src = {}
    for p, e in po.iter_entries(Path("src/gtt")):
        if e.msgstr.strip():
            src[e.msgid] = e.msgstr

    recs = S.load_index(key)
    state, inc = S.lcg_params(key)
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    # only the English pools are written to; the other five languages keep
    # their own pools and are out of scope (ANALYSIS/11 §1)
    pool_ids = set()
    for rec in recs:
        try:
            for eid, _o, _b in S.pools(rec, ks, dat):
                pool_ids.add(eid)
        except Exception:                            # noqa: BLE001
            continue
    keep = gtt.english_pools(pool_ids)

    zh = en = 0
    en_with_translation = en_no_translation = 0
    samples = []
    for rec in recs:
        try:
            pools = S.pools(rec, ks, dat)
        except Exception:                            # noqa: BLE001
            continue
        for eid, _off, blob in pools:
            if eid not in keep or len(blob) < 0x20 or blob[:4] != gtt.MAGIC:
                continue
            for b in gtt.parse(blob):
                for i in range(len(b.starts)):
                    t = b.line(i)
                    if not t:
                        continue
                    if any(c >= 0x80 for c in t):
                        zh += 1
                        continue
                    en += 1
                    s = t.decode("utf-8", "replace")
                    if s in src:
                        en_with_translation += 1
                        if len(samples) < 8:
                            samples.append(s[:44])
                    else:
                        en_no_translation += 1
    print(f"{dat}")
    print(f"  {len(keep)} English pools of {len(pool_ids)}")
    print(f"  GTT lines: {zh + en}   Chinese {zh}   English {en} "
          f"({100 * zh / (zh + en):.1f}% translated)")
    print(f"  of the English ones: {en_with_translation} have a translation "
          f"in src/gtt (duplicate address, no reference)")
    print(f"                       {en_no_translation} have none")
    if samples:
        print("  e.g.", samples)


if __name__ == "__main__":
    main()
