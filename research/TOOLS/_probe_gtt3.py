"""Probe: solve the GTT block header (which u16 is which string).

A pool is a concatenation of blocks; each block is

    +0x00  "GTT\\x00"
    +0x04  u32  n
    +0x08  u32  pool_off   (== header size; block 0/3 -> 0x60 / 0x38)
    +0x0c  u32  ?          (0xd6 / 0x1b3 / 0xb4 / 0x61 -- looks like an id)
    +0x10  u16 ?, u16 ?
    +0x14  u32  1
    +0x18  u32  0
    +0x1c  u16 array ...   <- candidate (offset,len) table
    pool   NUL-separated, SUFFIX-MERGED: splitting on NUL yields fragments
           ("n.", "Cett", "e?") because a string may end inside a later one.

So extraction needs the real (offset, length) pairs.  This probe prints, for
one block, every u16 in the header together with what it would point at, so
the mapping can be read off instead of guessed.

Usage:  python _probe_gtt3.py [--rec 84] [--pool 0x1c79f20b] [--block 0]
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
    ap.add_argument("--pool", default="0x1c79f20b")
    ap.add_argument("--block", type=int, default=0)
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
            o = offs[args.block]
            end = offs[args.block + 1] if args.block + 1 < len(offs) \
                else len(blob)
            w = struct.unpack_from("<6I", blob, o)
            n, pool_off, ident = w[1], w[2], w[3]
            print(f"block @{o:#x}..{end:#x}: n={n} pool_off={pool_off:#x} "
                  f"id={ident:#x} @0x10=(u16 {w[4] & 0xFFFF:#x},"
                  f"{w[4] >> 16:#x}) @0x14={w[5]}")
            pool = blob[o + pool_off:end]
            print(f"pool: {len(pool)} B")
            print("  pool hex:")
            for i in range(0, len(pool), 16):
                row = pool[i:i + 16]
                print(f"    {i:04x}  {row.hex(' '):<47}  "
                      f"{''.join(chr(c) if 32 <= c < 127 else '.'
                                 for c in row)}")
            print("  header u16 from +0x1c, read as a pointer into the pool:")
            for p in range(0x1c, o + pool_off - o if False else pool_off, 2):
                v, = struct.unpack_from("<H", blob, o + p)
                rel = p - pool_off
                look = pool[v:v + 24] if v < len(pool) else b""
                look2 = pool[rel:rel + 24] if 0 <= rel < len(pool) else b""
                print(f"    +{p:#04x} {v:#06x} ({v:3d}) -> "
                      f"pool[{v}:] {look[:24]!r}"
                      + (f"   | as self-idx {rel}: {look2[:24]!r}"
                         if rel >= 0 else ""))
            return


if __name__ == "__main__":
    main()
