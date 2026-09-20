"""Can a translated cutscene table fit back where it came from?

Write-back has to respect two fixed sizes (slotdat_load_and_verify
@ 0x1400A6290):

    inflated size <= A * 4096     A is the 12-bit field in SLOT.KEY
    compressed   <= B * 4096 - 16 B is the stored sector count; the next
                                  record starts at start + end, so B cannot
                                  grow without moving every later record

A cutscene record holds one RBX pool per language.  This probe asks, per
cutscene table:

  1. does OlangBuilder round-trip the embedded pool byte for byte?  (if not,
     nothing else matters)
  2. how big is the pool after a no-op rebuild?  `serialize()` drops the dead
     slack and re-deduplicates, so it is usually smaller than the original
  3. how big does it get with a Chinese translation?  Modelled as N CJK
     characters (3 bytes each in UTF-8) at several byte-size ratios, since real
     Chinese runs short in characters but 3 bytes per character
  4. does the result still fit the pool slot, and the record's A sectors?

usage: _probe_slot27.py [--ratios 0.8,1.0,1.2,1.5] [--limit N]
"""

import argparse
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import olang
from pwsf.olang_build import OlangBuilder
from pwsf import slotdat as S

POOL = "的一是在不了有和人这中大为上个国我以要他时来用们"


def fake_zh(nbytes: int, rng: random.Random) -> bytes:
    """A CJK string of about `nbytes` UTF-8 bytes (3 bytes per character)."""
    n = max(1, round(nbytes / 3))
    return "".join(rng.choice(POOL) for _ in range(n)).encode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ratios", default="0.8,1.0,1.2,1.5,1.8")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    ratios = [float(x) for x in args.ratios.split(",")]

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    # locate every embedded olang pool: (table_id, lang) -> first location
    loc = {}
    for rec in recs:
        pools = S.pools(rec, ks)
        for i, (eid, off, blob) in enumerate(pools):
            if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
                continue
            tbl = olang.parse(blob, f"slot/{rec.index}/{eid:#010x}")
            langs = {k[0] for k in tbl.keys}
            # pool slot = up to the next pool's offset, or end of the record
            stop = (pools[i + 1][1] if i + 1 < len(pools)
                    else len(S.inflate(S.decrypt(S.read_block(rec), ks))))
            for lang in langs:
                loc.setdefault((tbl.table_id, lang),
                               (rec, eid, off, blob, stop - off))

    targets = sorted(k for k in loc if S.is_cutscene(k[0])
                     and k[1] == C.LANG_EN)
    if args.limit:
        targets = targets[:args.limit]
    print(f"cutscene (table, en) pools: {len(targets)}")

    rng = random.Random(20260920)
    rt_bad = 0
    fits = {r: 0 for r in ratios}
    grew = 0
    worst = 0.0
    worst_t = None
    noop_save = 0
    noop_grew = 0

    for key in targets:
        rec, eid, off, blob, cap = loc[key]
        tbl = olang.parse(blob, f"slot/{rec.index}/{eid:#010x}")
        b = OlangBuilder(tbl)
        if b.serialize_exact()[:len(blob)] != blob:
            rt_bad += 1
            if rt_bad <= 3:
                print(f"  ROUND-TRIP FAIL {key[0]:#010x}")
        base = len(b.serialize())
        if base > cap:
            noop_grew += 1
        noop_save += len(blob) - base
        if cap and base / cap > worst:
            worst, worst_t = base / cap, key[0]
        for r in ratios:
            b2 = OlangBuilder(olang.parse(blob, ""))
            b2.texts = [fake_zh(max(3, len(t) * r), rng) if t else t
                        for t in b2.texts]
            got = b2.serialize()
            if len(got) <= cap:
                fits[r] += 1
        # inflated headroom inside the record
        if key == targets[0]:
            data = S.inflate(S.decrypt(S.read_block(rec), ks))
            print(f"\n  record {rec.index}: A={rec.inflated} sectors "
                  f"({rec.inflated * S.SECTOR} B), inflated {len(data)} B, "
                  f"headroom {rec.inflated * S.SECTOR - len(data)} B")
            print(f"  pool cap for {key[0]:#010x}: {cap} B, "
                  f"blob {len(blob)} B, no-op rebuild {base} B")

    print(f"\nround-trip failures: {rt_bad}/{len(targets)}")
    print(f"no-op rebuild saves {noop_save} B total "
          f"({noop_grew} pools grew past their cap)")
    print(f"worst no-op fill: {worst:.1%} of the pool slot "
          f"(table {worst_t:#010x})" if worst_t else "")
    print("\nfits the existing pool slot:")
    for r in ratios:
        print(f"  ratio {r:<4} {fits[r]:>3}/{len(targets)}")


if __name__ == "__main__":
    main()
