"""Probe: prove a `GTT\\x00` block can be re-laid-out (ANALYSIS/11 §6.3).

`pwsf.gtt` reads a line as `pool[start : next NUL]`, with `start` taken from
the header array (`X` at group i = start of line i+1, `Y` = start of line
i+2).  A rebuild has to know *every* word that is a line start, so this
checks the invariants over every block of every pool first, then round-trips
a candidate builder:

  1. rebuild with the same texts      -> lines read back byte-identical
  2. rebuild with grown translations  -> every line fits, length unchanged

Usage:  python _probe_gtt_rebuild.py [--grow N]
"""
import argparse
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt                                # noqa: E402

GROUP, PREFIX = gtt.GROUP, gtt.PREFIX


def invariants(blocks) -> None:
    """Which header words are line starts?  Count how often each holds."""
    c = collections.Counter()
    u16_at_10 = collections.Counter()
    for eid, b, raw in blocks:
        n, arr, pool = len(b.starts), b.array, b.pool
        u16_at_10[struct.unpack_from("<HH", raw, 0x10)] += 1
        # the four leading words
        if n >= 2:
            first = arr[PREFIX + 3]                 # X of group 0 = line 1
            c["array[0..3] == start(line1)"] += \
                all(w == first for w in arr[:4])
            c["array[0..3] != start(line1)"] += \
                not all(w == first for w in arr[:4])
        else:
            c["n==1 array[0..3] values"] += 1
            c[f"  n==1 arr[:4]={tuple(arr[:4])} pool_len={len(pool)}"] += 1
        for i in range(n):
            g = arr[PREFIX + GROUP * i: PREFIX + GROUP * i + GROUP]
            if len(g) < GROUP:
                continue
            c["X copies agree (g[3]==g[4]==g[5])"] += (g[3] == g[4] == g[5])
            c["Y copies agree (g[6..9])"] += len(set(g[6:10])) == 1
            c["g[2] == 1"] += (g[2] == 1)
            if i + 1 < n:
                c["X(i) == start(line i+1)"] += (g[3] == b.starts[i + 1])
            if i + 2 < n:
                c["Y(i) == start(line i+2)"] += (g[6] == b.starts[i + 2])
            else:
                c["last groups zero-padded"] += (g[6] == 0 and g[3] == 0
                                                 or i + 1 < n)
    print("--- invariants over all blocks ---")
    for k, v in sorted(c.items(), key=lambda x: -x[1]):
        print(f"  {v:7}  {k}")
    print("  +0x10 u16 pair (top 6):", u16_at_10.most_common(6))


def build(blob: bytes, texts: dict) -> bytes:
    """Candidate rebuild: lay `texts` {line_index: bytes} out unmerged.

    Block length is preserved exactly: the runs are written back to back at
    the start of the pool and the rest is zero-filled, so the record's byte
    budget is untouched.
    """
    b = gtt.parse_block(blob, 0, len(blob))
    n = len(b.starts)
    runs = []
    for i in range(n):
        raw = texts.get(i)
        if raw is None:
            raw = b.line(i)
        if len(raw) > len(b.pool) - n:
            raise ValueError(f"line {i}: {len(raw)} B does not fit")
        runs.append(bytes(raw))
    body = bytearray(len(b.pool))
    starts, at = [], 0
    for i, r in enumerate(runs):
        starts.append(at)
        body[at:at + len(r)] = r
        at += len(r) + 1                    # the NUL
    if at > len(b.pool):
        raise ValueError(f"need {at} B, pool is {len(b.pool)} B")
    # header: rewrite every word we know to be a line start
    arr = list(b.array)
    for i in range(n):
        g = PREFIX + GROUP * i
        if g + GROUP > len(arr):
            break
        nx = starts[i + 1] if i + 1 < n else 0
        ny = starts[i + 2] if i + 2 < n else 0
        arr[g + 3] = arr[g + 4] = arr[g + 5] = nx
        arr[g + 6] = arr[g + 7] = arr[g + 8] = arr[g + 9] = ny
    if n >= 2:
        arr[0] = arr[1] = arr[2] = arr[3] = starts[1]
    head = bytearray(blob[:b.pool_off])
    struct.pack_into("<%dH" % len(arr), head, gtt.ARRAY_AT, *arr)
    return bytes(head) + bytes(body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--grow", type=int, default=0,
                    help="grow every line by N bytes in the round-trip test")
    args = ap.parse_args()

    blobs = list(gtt.pool_blobs())
    ids = {eid for _r, eid, _b in blobs}
    keep = gtt.english_pools(ids)

    blocks = []
    for rec, eid, blob in blobs:
        if eid not in keep:
            continue
        for b in gtt.parse(blob):
            blocks.append((eid, b, blob[b.off:b.end]))
    print(f"English blocks: {len(blocks)}")
    invariants(blocks)

    # ---- round-trip 1: unchanged texts
    same = diff = fail = 0
    for eid, b, raw in blocks:
        try:
            out = build(raw, {})
        except Exception as exc:             # noqa: BLE001
            fail += 1
            print("  build failed:", exc)
            continue
        if len(out) != len(raw):
            diff += 1
            continue
        nb = gtt.parse_block(out, 0, len(out))
        if [nb.line(i) for i in range(len(nb.starts))] == \
           [b.line(i) for i in range(len(b.starts))]:
            same += 1
        else:
            diff += 1
    print(f"\nround-trip (unchanged texts): {same} identical, {diff} differ, "
          f"{fail} failed")

    # ---- round-trip 2: every line grown by --grow bytes
    if args.grow:
        ok = bad = 0
        for eid, b, raw in blocks:
            n = len(b.starts)
            texts = {i: b.line(i) + b"!" * args.grow for i in range(n)}
            try:
                out = build(raw, texts)
            except ValueError:
                bad += 1
                continue
            nb = gtt.parse_block(out, 0, len(out))
            if [nb.line(i) for i in range(n)] == [texts[i] for i in range(n)]:
                ok += 1
            else:
                bad += 1
        print(f"round-trip (+{args.grow} B per line): {ok} ok, {bad} failed")


if __name__ == "__main__":
    main()
