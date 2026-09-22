"""Probe: can a `GTT\\x00` block be re-laid-out to lift the per-line budget?

Today `pwsf.gtt.patch` writes a translation *in place* inside the run the
English line occupies (ANALYSIS/11 §5), so a line may never grow past its
English byte length.  That budget is the reason 48 shouts (`Hm?`, `Huh?`)
cannot be translated at all.

Two facts make a rebuild possible:

* `a` / `b` in the header array are the line TIMING, not pointers (§3.1), so
  they need no fixup when strings move;
* `slotdat_build.repack_slot` rewrites every pool's entry offset, so a pool
  may change length -- the only hard limit left is "the record must still
  compress into its original sector count".

The cheap variant: drop the suffix merging.  A block's string pool is
`[fragment][line]\\0[fragment][line]\\0...` where the fragments are heads of
*other* languages' lines and no `X` points at them.  Laying the lines out
contiguously frees those bytes while keeping the block length EXACTLY as it
was -- zero extra bytes, so no compression risk whatsoever.

    capacity after rebuild = len(pool) - n          (n NULs)
    used today             = sum(len(line) + 1)
    slack                  = capacity - sum(len(line))

This measures that slack, then asks how many translations fit.

Usage:  python _probe_gtt_budget.py [--pool 0x1c767903 --block 0x790]
"""
import argparse
import collections
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt, po, slots                     # noqa: E402


def translations() -> dict:
    """{(pool, block, line): msgstr} out of src/gtt/*.po."""
    out = {}
    for p, e in po.iter_entries(Path("src/gtt")):
        if not e.msgstr.strip():
            continue
        for r in e.refs:
            try:
                parsed = slots.parse_ref(r)
            except Exception:                       # noqa: BLE001
                continue
            if getattr(parsed, "kind", None) == slots.GTT:
                out[(parsed.pool, parsed.block, parsed.line)] = e.msgstr
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=None, help="dump one pool's blocks")
    args = ap.parse_args()

    trans = translations()
    print(f"translations in src/gtt: {len(trans)}")

    blobs = list(gtt.pool_blobs())
    ids = {eid for _r, eid, _b in blobs}
    keep = gtt.english_pools(ids)
    print(f"GTT pools {len(ids)}, English {len(keep)}")

    blocks, nonascii = [], 0
    for rec, eid, blob in blobs:
        if eid not in keep:
            continue
        for b in gtt.parse(blob):
            lines = [b.line(i) for i in range(len(b.starts))]
            nonascii += sum(1 for l in lines if any(c >= 0x80 for c in l))
            blocks.append((eid, b, lines))

    print(f"blocks {len(blocks)}, lines {sum(len(l) for _e, _b, l in blocks)}, "
          f"lines starting with a non-ASCII fragment: {nonascii}")

    slack = [len(b.pool) - sum(len(x) + 1 for x in lines)
             for _e, b, lines in blocks]
    print(f"slack per block: min {min(slack)}  median "
          f"{statistics.median(slack):.0f}  max {max(slack)}  "
          f"total {sum(slack)} B")
    print("  blocks with slack == 0 (nothing to reclaim): "
          f"{sum(1 for s in slack if s == 0)}")

    # ---- the two budgets, per line
    now_over, c1_need, c1_cap, c1_tight = 0, 0, 0, []
    for eid, b, lines in blocks:
        n = len(lines)
        en = [len(x) for x in lines]
        zh = [len(gtt.to_game_text(trans[(eid, b.off, i)]))
              if (eid, b.off, i) in trans else en[i]
              for i in range(n)]
        now_over += sum(1 for i in range(n) if zh[i] > en[i])
        need, cap = sum(zh), len(b.pool) - n
        c1_need += need
        c1_cap += cap
        if need > cap:
            c1_tight.append((need - cap, eid, b.off, n, len(b.pool)))
    print()
    print(f"lines that VIOLATE today's in-place budget: {now_over}")
    print(f"rebuilt (unmerged, block length unchanged): "
          f"need {c1_need} B vs capacity {c1_cap} B "
          f"-> {c1_cap - c1_need} B to spare")
    print(f"blocks that still would not fit: {len(c1_tight)}")
    for d, eid, off, n, plen in sorted(c1_tight, reverse=True)[:10]:
        print(f"  pool {eid:#010x} block {off:#x}: short {d} B "
              f"({n} lines, pool {plen} B)")

    if args.pool:
        want = int(args.pool, 0)
        for eid, b, lines in blocks:
            if eid != want:
                continue
            n = len(lines)
            print(f"\npool {eid:#010x} block {b.off:#x}: n={n} "
                  f"pool_len={len(b.pool)} used="
                  f"{sum(len(x) + 1 for x in lines)} "
                  f"slack={len(b.pool) - sum(len(x) + 1 for x in lines)}")
            for i, l in enumerate(lines):
                z = trans.get((eid, b.off, i))
                zb = len(gtt.to_game_text(z)) if z else None
                print(f"  line {i}: en {len(l):3} B  zh {zb}  {l[:52]!r}")


if __name__ == "__main__":
    main()
