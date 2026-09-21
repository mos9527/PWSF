"""Probe: the GTT header array, read as a function of n.

Established so far (blocks of pool 0x1c79f20b, record 84):

    +0x00 "GTT\\x00"
    +0x04 u32 n            number of lines in the block
    +0x08 u32 pool_off     header size == start of the (suffix-merged) pool
    +0x0c u32 id
    +0x10 u16 ?, u16 ?
    +0x14 u32 1
    +0x18 u32 0
    +0x1c u16 array, length = (pool_off - 0x1c)/2 = 4 + 10*n
             block0 n=3 -> 34, block1 n=5 -> 54, block2 n=2 -> 24, block3 n=1 -> 14

English line starts are visible in the pool (block 0: 0, 45, 75) so at least
some of those u16 are pool offsets.  This probe prints, for a set of blocks:
the n, the whole array, and every candidate string start in the pool (0, and
each offset right after a NUL), so the two can be matched by eye.

Usage:  python _probe_gtt4.py [--rec 84] [--pool 0x1c79f20b] [--blocks 6]
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S          # noqa: E402

GTT = b"GTT\x00"


def starts(pool: bytes):
    out = [0]
    for i, c in enumerate(pool):
        if c == 0 and i + 1 < len(pool) and pool[i + 1] != 0:
            out.append(i + 1)
    return out


def show(blob: bytes, o: int, end: int, tag: str) -> None:
    n, pool_off, ident = struct.unpack_from("<III", blob, o + 4)
    pool = blob[o + pool_off:end]
    arr = struct.unpack_from("<%dH" % ((pool_off - 0x1c) // 2), blob, o + 0x1c)
    print(f"\n=== {tag} @{o:#x}..{end:#x}  n={n} pool_off={pool_off:#x} "
          f"id={ident:#x}  pool={len(pool)}B")
    print("  array: " + " ".join(f"{v:#06x}" for v in arr))
    print("  as (u16 pairs) per line, skipping the 4-word prefix:")
    body = arr[4:]
    for i in range(0, len(body), 10):
        g = body[i:i + 10]
        if not g:
            break
        print(f"    line {i // 10}: " + " ".join(f"{v:#06x}" for v in g)
              + "   -> " + " ".join(
                  repr(pool[v:v + 14].split(b"\x00")[0].decode('latin-1'))
                  for v in g if v < len(pool)))
    print("  candidate string starts in pool: " +
          " ".join(f"{v:#x}" for v in starts(pool)))
    print("  pool text: " +
          repr(pool[:100].split(b"\x00")[0].decode("latin-1")))


def pool_text(blob: bytes, o: int, end: int, tag: str) -> None:
    """Every NUL-terminated run of a block's pool, with its offset."""
    n, pool_off, ident = struct.unpack_from("<III", blob, o + 4)
    pool = blob[o + pool_off:end]
    print(f"\n--- {tag} n={n} pool={len(pool)}B (block @{o:#x})")
    i = 0
    while i < len(pool):
        j = pool.find(b"\x00", i)
        if j < 0:
            j = len(pool)
        seg = pool[i:j]
        print(f"  {i:04x} len={len(seg):3d} {seg.decode('latin-1')!r}")
        i = j + 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", type=int, default=84)
    ap.add_argument("--pool", default="0x1c79f20b")
    ap.add_argument("--blocks", type=int, default=6)
    ap.add_argument("--start", type=int, default=0,
                    help="index of the first block to show")
    ap.add_argument("--pool-text", action="store_true",
                    help="print the pools split on NUL instead of the headers")
    args = ap.parse_args()
    want = int(args.pool, 0)

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    for rec in recs:
        if rec.index != args.rec:
            continue
        for eid, _off, blob in S.pools(rec, ks):
            if eid != want:
                continue
            offs = [i for i in range(len(blob)) if blob.startswith(GTT, i)]
            sel = offs[args.start:args.start + args.blocks]
            for k, o in enumerate(sel, start=args.start):
                end = offs[k + 1] if k + 1 < len(offs) else len(blob)
                if args.pool_text:
                    pool_text(blob, o, end, f"block {k}")
                else:
                    show(blob, o, end, f"block {k}")
            return


if __name__ == "__main__":
    main()
