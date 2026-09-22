"""PoC: the re-laid-out GTT block (ANALYSIS/11 §5.2) -- end to end.

Runs the real `pwsf.gtt.patch` over every English pool and checks:

  1. length of every pool is unchanged (so the record budget is untouched);
  2. every translated line reads back;
  3. the 44 lines whose English is too short for Chinese (`Hm?`, `Huh?`,
     `What a haul!`) now take a translation -- that was impossible before.

Usage:  python _probe_gtt_rebuild2.py [--fill]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt, po, slots                     # noqa: E402

# plausible Chinese for the shouts the in-place budget could never hold
FILL = {
    "What a haul!": "收获不小！",
    "Hm?": "嗯？",
    "Huh?": "啊？",
}


def translations(fill: bool) -> dict:
    """{(pool, block, line): text} -- from src/gtt, plus the tiny shouts."""
    out, tiny = {}, []
    for p, e in po.iter_entries(Path("src/gtt")):
        for r in e.refs:
            try:
                parsed = slots.parse_ref(r)
            except Exception:                       # noqa: BLE001
                continue
            if getattr(parsed, "kind", None) != slots.GTT:
                continue
            if e.msgstr.strip():
                out[(parsed.pool, parsed.block, parsed.line)] = e.msgstr
            elif fill and e.msgid in FILL:
                out[(parsed.pool, parsed.block, parsed.line)] = FILL[e.msgid]
                tiny.append((parsed.pool, parsed.block, parsed.line, e.msgid))
    return out, tiny


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fill", action="store_true",
                    help="also translate the 3 sample shouts")
    args = ap.parse_args()

    trans, tiny = translations(args.fill)
    print(f"translations: {len(trans)}"
          + (f" (incl. {len(tiny)} previously impossible: "
             f"{[t[3] for t in tiny]})" if tiny else ""))

    blobs = list(gtt.pool_blobs())
    ids = {eid for _r, eid, _b in blobs}
    keep = gtt.english_pools(ids)

    same_len = shorter = longer = 0
    problems, checked = [], 0
    for rec, eid, blob in blobs:
        if eid not in keep:
            continue
        # one block at a time: the number of lines differs per block
        changes = {}
        for b in gtt.parse(blob):
            for li in range(len(b.starts)):
                if (eid, b.off, li) in trans:
                    changes[(b.off, li)] = trans[(eid, b.off, li)]
        if not changes:
            continue
        raw = {k: gtt.to_game_text(v) for k, v in changes.items()}
        out = gtt.patch(blob, raw, problems)
        if len(out) == len(blob):
            same_len += 1
        elif len(out) < len(blob):
            shorter += 1
        else:
            longer += 1
        problems += gtt.verify(out, raw)
        checked += len(raw)

    print(f"\npools patched {same_len + shorter + longer}: "
          f"{same_len} same length, {shorter} shorter, {longer} LONGER")
    print(f"lines checked: {checked}")
    print(f"problems: {problems[:6] if problems else 'none'} "
          f"({len(problems)} total)")
    if tiny:
        for pool, block, line, en in tiny:
            print(f"  {en!r} -> {FILL[en]!r} "
                  f"({len(gtt.to_game_text(FILL[en]))} B, English was "
                  f"{len(en)} B) written at gtt/{pool:#010x}/{block:#x}/{line}")


if __name__ == "__main__":
    main()
