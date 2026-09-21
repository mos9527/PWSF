"""Probe: read the BUILT (installed) SLOT.DAT and check the mission title.

Context: the load/save screen still shows

    "Opening / Investigate the Supply Facility"

in English although `src/slot/slot_12.po` has a translation for exactly that
slot and `research/BUILD/002aba34.DAT` was installed over the game file
(same size, same mtime, `002aba34.DAT.orig` present).

Two competing explanations:
  A) the built file really does carry the translation, so the save screen reads
     the title from somewhere else (STAGEDAT's own copy of
     `lang_mission_info`, or the save file itself)
  B) the build never carried it (translation written after the build), so there
     is nothing to explain yet

This probe settles A vs B by reading the built container itself instead of
trusting the .po.

Usage:  python _probe_slot_installed.py [--file research/BUILD/002aba34.DAT]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S          # noqa: E402
from pwsf import config                # noqa: E402

WANT_TABLE = 0x00514128                # lang_mission_info
WANT_GROUP = 0x215635
WANT_ENTRIES = (0xa7f464, 0xd19ef2, 0x0a7f464)
NEEDLES = [b"Investigate the Supply", b"shooting practice",
           b"no one around"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="research/BUILD/002aba34.DAT")
    args = ap.parse_args()
    dat = Path(args.file)
    if not dat.is_absolute():
        dat = Path(__file__).resolve().parent.parent.parent / dat
    print(f"container: {dat}  ({dat.stat().st_size} bytes)")

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    def pool_blobs():
        for rec in recs:
            try:
                for eid, off, blob in S.pools(rec, ks, dat):
                    yield rec.index, eid, blob
            except Exception as ex:          # noqa: BLE001 - report, keep going
                print(f"  record {rec.index}: {ex}")

    rows, first_seen, locations = S.embedded_olang(pool_blobs)
    print(f"rows: {len(rows)}   tables: {len(first_seen)}")

    en = config.LANG_EN if hasattr(config, "LANG_EN") else None
    print(f"LANG_EN = {en:#x}")

    shown = 0
    for r in rows:
        if r.table_id != WANT_TABLE or r.lang != en:
            continue
        if r.group != WANT_GROUP or r.entry not in WANT_ENTRIES:
            continue
        print(f"  slot/{r.table_id:#010x}/{r.group:#08x}/{r.entry:#08x} "
              f"lang={r.lang:#x}  {r.text[:80]!r}")
        shown += 1
    print(f"mission-title rows shown: {shown}")

    hits = []
    for r in rows:
        low = r.text.lower()
        for nd_ in NEEDLES:
            if nd_ in low:
                hits.append((r.table_id, r.group, r.entry, nd_))
    print("needle hits inside the built SLOT.DAT:", hits or "none")


if __name__ == "__main__":
    main()
