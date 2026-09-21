"""Probe: why did a specific GTT pool not get written?

Isolates the write step from the container rebuild: take one pool out of the
pristine SLOT.DAT, apply `pwsf.gtt.patch` with the translation the .po holds,
and report what the patcher says.  Used for pools like 0x1c79f3cb that came
back English after a build that reported no error.

Usage:  python _probe_gtt9.py POOL [POOL ...]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt, po, po_lint, slots      # noqa: E402


def record_debug(idx: int) -> None:
    """Replay the rebuild for one record and say what happened to it."""
    from pwsf import config, slotdat as S, slotdat_build as B

    rep = po_lint.lint(Path("src"), check_font=False)
    by_table = B._norm_translations(
        {r: t for r, t in rep.translations.items()
         if r.startswith(slots.SLOT + "/")})
    gtt_by_pool = {}
    for ref, text in rep.translations.items():
        if not ref.startswith(slots.GTT + "/"):
            continue
        r = slots.parse_ref(ref)
        gtt_by_pool.setdefault(r.pool, {})[(r.block, r.line)] = text

    recs = S.load_index()
    rec = recs[idx]
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 * 2 + 4096
    ks = S.keystream(nd, state, inc)
    with open(S.dat_path(), "rb") as fh:
        fh.seek(rec.start * S.SECTOR)
        main = fh.read(rec.stored * S.SECTOR)
    plain = S.decrypt(main, ks)
    data = S.inflate(plain)
    pools = S.slot_pools(data)
    gtt_here = [eid for _i, eid, _o, b in pools
                if len(b) >= 0x20 and b[:4] == b"GTT\x00"]
    print(f"record {idx}: {len(pools)} pools, "
          f"{len(gtt_here)} GTT ({[f'{e:#010x}' for e in gtt_here][:5]})")
    print(f"  touches(olang): "
          f"{B.touches(data, by_table, config.LANG_EN)}")
    print(f"  touches(+gtt):  "
          f"{B.touches(data, by_table, config.LANG_EN, gtt_by_pool)}")
    print(f"  gtt pools with translations: "
          f"{[f'{e:#010x}' for e in gtt_here if e in gtt_by_pool][:5]}")
    patch = B.make_patch(by_table, config.LANG_EN, gtt_by_pool)
    data2 = B.repack_slot(data, patch)
    print(f"  repack changed: {data2 != data}  "
          f"inflated {len(data)} -> {len(data2)}")
    print(f"  patch problems: {list(patch.gtt_problems)[:4]}")
    need = rec.stored * S.SECTOR
    comp = B._compress(data2, 9)
    print(f"  need {need}, deflate9 {len(comp) + 16}, "
          f"slot {need} -> {'fits' if len(comp) + 16 <= need else 'OVER'}")


def main() -> None:
    if len(sys.argv) >= 3 and sys.argv[1] == "--rec":
        record_debug(int(sys.argv[2], 0))
        return
    if len(sys.argv) < 2:
        sys.exit("usage: _probe_gtt9.py POOL [POOL ...] | --rec N")
    want = {int(a, 0) for a in sys.argv[1:]}

    rep = po_lint.lint(Path("src"), check_font=False)
    by_ref = rep.translations
    per_pool = {}
    for ref, text in by_ref.items():
        if not ref.startswith(slots.GTT + "/"):
            continue
        r = slots.parse_ref(ref)
        per_pool.setdefault(r.pool, {})[(r.block, r.line)] = text

    found = 0
    for rec, eid, blob in gtt.pool_blobs():
        if eid not in want:
            continue
        found += 1
        texts = per_pool.get(eid, {})
        raw = {k: gtt.to_game_text(v) for k, v in texts.items()}
        blocks = gtt.parse(blob)
        print(f"\npool {eid:#010x} (record {rec}): {len(blocks)} blocks, "
              f"{len(texts)} translation(s)")
        offs = {b.off for b in blocks}
        missing = [k for k in raw if k[0] not in offs]
        if missing:
            print(f"  block offsets not present: "
                  f"{[f'@{m[0]:#x}' for m in missing][:6]}")
            print(f"  first blocks here: "
                  f"{[f'@{b.off:#x}' for b in blocks[:6]]}")
        probs = []
        out = gtt.patch(blob, raw, probs)
        print(f"  patched ok: {out != blob}  problems: {len(probs)}")
        for p in probs[:6]:
            print(f"    {p}")
        want.discard(eid)
        if out != blob:
            chk = gtt.verify(out, raw)
            print(f"  read back: {chk or 'identical'}")
        if not want:
            break
    print(f"\n{len(want)} pool(s) never seen" if want else "\nall found")


if __name__ == "__main__":
    main()
