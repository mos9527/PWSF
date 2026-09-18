"""Probe: dump olang tables to confirm the string-extraction path."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash
from pwsf_olang import load, string_at

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")


def probe(rel: str, limit: int = 40) -> None:
    f = GAME / rel.replace("/", "\\")
    tbl = load(f, name_hash(f.stem))
    print(f"\n=== {rel}  table_id={tbl.table_id:#x}  groups={len(tbl.groups)} "
          f"entries={len(tbl.entries)} keys={len(tbl.keys)} pool={len(tbl.pool)}")
    print("  group keys:", ", ".join(f"{g.key:#x}" for g in tbl.groups[:20]))
    n = 0
    for s in tbl.strings():
        raw = string_at(tbl, s.offset)
        try:
            txt = raw.decode("ascii")
        except UnicodeDecodeError:
            txt = raw.hex()
        print(f"    g={s.group:#010x} e={s.entry:#010x} k={s.key:#010x} "
              f"off={s.offset:#x} meta={s.meta:#x} len={len(raw)}  {txt!r}")
        n += 1
        if n >= limit:
            break


if __name__ == "__main__":
    probe("MLG/Text/00d9bfd4.olang")
    probe("MLG/Text/009c9ea4.olang", limit=30)
