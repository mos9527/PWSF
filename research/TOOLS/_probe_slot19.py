"""Where the comic cutscene line actually lives, now that SLOT.DAT is open.

08_cutscene_text.md §1/§2: the pause-menu line is in olang, but the two
on-screen cutscene strings ("THEY'RE WILLING TO GIVE US AN OFFSHORE PLANT -
A PLACE WE CAN FINALLY PUT DOWN SOME ROOTS." and the bottom caption
"They're willing to give us an offshore plant") were in no exported corpus.

This probe walks the decrypted, inflated SLOT.DAT records, greps the exact
phrases, and reports which record / resource entry / offset holds them, plus
the KEY record that names it.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import slotdat as S

NEEDLES = (b"willing to give us an offshore plant",
           b"a place we can finally put down some roots",
           b"This is our chance to expand MSF")


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    print(f"records={len(recs)}  LCG state={state:#010x} inc={inc:#010x}")

    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)
    dat = S.dat_path()

    good = 0
    bad = []
    hits = []
    for rec in recs:
        blob = S.read_block(rec, dat)
        plain = S.decrypt(blob, ks)
        magic, hdr_size, const, comp, raw = S.parse_header(plain)
        if (hdr_size != S.REC_HDR or plain[16:18] != S.ZLIB_SIG
                or not 0 < comp <= rec.stored * S.SECTOR):
            bad.append((rec.index, "header"))
            continue
        try:
            out = S.inflate(plain, hdr_size, comp)
        except Exception as exc:                     # noqa: BLE001
            bad.append((rec.index, f"inflate: {exc}"))
            continue
        good += 1
        if len(out) != raw:
            bad.append((rec.index, f"size {len(out)} != raw {raw}"))
        low = out.lower()
        found = [(n, low.find(n.lower())) for n in NEEDLES]
        found = [(n, p) for n, p in found if p >= 0]
        if found:
            hits.append((rec, out, found))

    print(f"inflated ok: {good} / {len(recs)}   failures: {bad}")

    # 08_cutscene_text.md §4 left two records unexplained: their packed A
    # (the high 12 bits of +0x00) disagrees with the full copy at +0x0C.
    odd = [r for r in recs if r.a_copy != r.inflated]
    print(f"\nrecords where the packed A != the +0x0C copy: {len(odd)}")
    for r in odd:
        print(f"  rec {r.index}: packed A={r.inflated} copy={r.a_copy} "
              f"diff={r.a_copy - r.inflated}  stored sectors B={r.stored}")

    for rec, out, found in hits:
        count, entries, area = S.res_table(out)
        print(f"\n=== record {rec.index}  "
              f"start={rec.start} end={rec.end} A={rec.inflated} "
              f"B={rec.stored} id_hash={rec.id_hash:#010x}")
        print(f"    inflated {len(out)} bytes, {count} resource entries, "
              f"data area at +{area:#x}")
        kept = [e for e in entries if S.res_kept(e)]
        print(f"    entries matching the 0x2xxxxxxx filter: {len(kept)}")
        for e in entries:
            off = e[2] & 0x3FFFFFFF
            print(f"      id={e[0]:#010x} d1={e[1]:#010x} "
                  f"off={off:#x} -> abs {area + off:#x}  d3={e[3]:#010x}")
        for needle, p in found:
            # which entry owns this absolute offset?
            owner = None
            for e in entries:
                off = area + (e[2] & 0x3FFFFFFF)
                if off <= p:
                    if owner is None or off > area + (owner[2] & 0x3FFFFFFF):
                        owner = e
            print(f"    {needle.decode()!r} at +{p:#x}"
                  + (f"  entry id={owner[0]:#010x} off="
                     f"{owner[2] & 0x3FFFFFFF:#x}"
                     if owner else "  (no owning entry)"))
            print(f"      ...{out[max(0, p - 60):p + 160]!r}")


if __name__ == "__main__":
    main()
