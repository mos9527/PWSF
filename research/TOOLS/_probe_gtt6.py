"""Probe: is there one GTT pool per language?

The needle hit twice, in two pools of the same record with slightly different
offsets -- 0x1c79f20b @0x494 and 0x1c79f2ad @0x497 -- which smells like one
pool per language, each holding the same n lines.

If so, the "fragments" seen in the English pool (`Je t\\xe2`, `rme en m`,
`K\\xc3\\xbcste -`) are NOT other languages: they are the shared pieces of a
single-language merge, and the pool really is a
shortest-common-superstring of that language's lines.

This probe prints the same block index out of every GTT pool of one record,
side by side, so the language split (or its absence) is visible.

Usage:  python _probe_gtt6.py [--rec 84] [--block 6]
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S          # noqa: E402

GTT = b"GTT\x00"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", type=int, default=84)
    ap.add_argument("--block", type=int, default=6)
    args = ap.parse_args()

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    for rec in recs:
        if rec.index != args.rec:
            continue
        for eid, _off, blob in S.pools(rec, ks):
            if blob[:4] != GTT:
                continue
            offs = [i for i in range(len(blob)) if blob.startswith(GTT, i)]
            print(f"\npool {eid:#010x}: {len(blob)} B, {len(offs)} blocks")
            for k in (args.block,):
                if k >= len(offs):
                    continue
                o = offs[k]
                end = offs[k + 1] if k + 1 < len(offs) else len(blob)
                n, pool_off, ident = struct.unpack_from("<III", blob, o + 4)
                pool = blob[o + pool_off:end]
                print(f"  block {k} n={n} id={ident:#x} pool={len(pool)}B")
                i = 0
                while i < len(pool):
                    j = pool.find(b"\x00", i)
                    if j < 0:
                        j = len(pool)
                    print(f"    {i:04x} {pool[i:j].decode('latin-1')!r}")
                    i = j + 1
            return


if __name__ == "__main__":
    main()
