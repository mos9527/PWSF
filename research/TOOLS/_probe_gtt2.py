"""Probe: read one `GTT\\x00` pool end to end -- the hit from _probe_gtt1.

_probe_gtt1.py found the missing line:

    rec 84 pool 0x1c79f20b  "no one around" @0x494  "shooting practice" @0x4b6
    rec 88 pool 0x1c79f2ad  @0x497 / @0x4b9        (and again in rec 90 / 94)

so the in-mission radio text is in the GTT pools, not in any RBX/olang table.

This probe reads that pool: block boundaries (the magic repeats inside one
pool), the header of each block, and the NUL-separated string area -- which is
suffix-merged, so a raw split yields fragments (`n.`, `Cett`).

Usage:  python _probe_gtt2.py [--rec 84] [--pool 0x1c79f20b]
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S          # noqa: E402

GTT = b"GTT\x00"


def blocks(blob: bytes):
    """Offsets of every `GTT\\x00` inside one pool (a pool holds many blocks)."""
    out, i = [], 0
    while True:
        j = blob.find(GTT, i)
        if j < 0:
            break
        out.append(j)
        i = j + 1
    return out


def hexdump(blob: bytes, start: int, end: int) -> None:
    for off in range(start, min(end, len(blob)), 16):
        row = blob[off:off + 16]
        print(f"  {off:04x}  {row.hex(' '):<47}  "
              f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", type=int, default=84)
    ap.add_argument("--pool", default="0x1c79f20b")
    ap.add_argument("--blocks", type=int, default=6)
    args = ap.parse_args()
    want = int(args.pool, 0)

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    for rec in recs:
        if rec.index != args.rec:
            continue
        for eid, off, blob in S.pools(rec, ks):
            if eid != want:
                continue
            print(f"rec {rec.index} pool {eid:#010x}: {len(blob)} bytes")
            offs = blocks(blob)
            print(f"{len(offs)} GTT blocks at: "
                  f"{[hex(o) for o in offs[:16]]}")
            for n, o in enumerate(offs[:args.blocks]):
                end = offs[n + 1] if n + 1 < len(offs) else len(blob)
                w = struct.unpack_from("<6I", blob, o)
                print(f"\n--- block {n} @{o:#x} .. {end:#x} "
                      f"({end - o} B)")
                print(f"    u32: " + " ".join(f"{x:#010x}" for x in w))
                hexdump(blob, o, min(o + 0x38, end))
                pool_start = o + w[2]
                print(f"    string area @{pool_start:#x}:")
                hexdump(blob, pool_start, min(pool_start + 96, end))
                area = blob[pool_start:end]
                parts = area.split(b"\x00")
                print("    NUL-split: "
                      f"{[p.decode('latin-1') for p in parts[:12]]}")
            return


if __name__ == "__main__":
    main()
