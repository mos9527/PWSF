"""Probe: inspect the dialogue-shaped tables (EXLANG 00c7f1dd / MLG 009c9ea4)."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash
from pwsf_olang import load, string_at

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
LANG = {0x0D0E: "en", 0x0D32: "fr", 0x0D45: "de", 0x0D94: "it", 0x0DB0: "ja", 0x0ED0: "es"}


def show(rel: str, groups: int = 3, per_group: int = 12, langs=("es",)) -> None:
    f = GAME / rel.replace("/", "\\")
    tbl = load(f, name_hash(f.stem))
    meta = Counter(k[2] for k in tbl.keys)
    print(f"\n=== {rel} groups={len(tbl.groups)} entries={len(tbl.entries)} "
          f"keys={len(tbl.keys)} pool={len(tbl.pool)} meta={dict(meta)}")
    epg = Counter(g.entry_count for g in tbl.groups)
    print(f"    entries-per-group histogram: {epg.most_common(8)}")
    for g in tbl.groups[:groups]:
        print(f"    --- group {g.key:#x} (count={g.entry_count})")
        shown = 0
        for i in range(g.entry_start, min(g.entry_start + g.entry_count, len(tbl.entries))):
            e = tbl.entries[i]
            for ki in range(e.key_start, e.key_start + e.key_count):
                k, off, m, _ = tbl.keys[ki]
                if LANG.get(k, "") not in langs:
                    continue
                print(f"      [{e.key:#x}] {string_at(tbl, off).decode('utf-8','replace')[:110]!r}")
                shown += 1
            if shown >= per_group:
                break


if __name__ == "__main__":
    show("EXLANG/Text/00c7f1dd.olang", groups=2, per_group=14)
    show("MLG/Text/009c9ea4.olang", groups=2, per_group=8, langs=("en",))
