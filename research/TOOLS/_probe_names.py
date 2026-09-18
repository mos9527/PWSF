"""Probe: where do the resolved names sit -- group level or entry level?"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash
from pwsf_olang import load, string_at

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
from pwsf import config
RES = config.ANALYSIS_DIR / "_keys_resolved.txt"

names = {}
for line in RES.read_text(encoding="utf-8").splitlines():
    if "\t" in line:
        k, v = line.split("\t", 1)
        names[int(k)] = v.split(" | ")[0]

for sub_file, in [("MLG/Text/009c9ea4.olang",), ("EXLANG/Text/00c7f1dc.olang",), ("MLG/Text/005184e3.olang",)]:
    f = GAME / sub_file.replace("/", "\\")
    tbl = load(f, name_hash(f.stem))
    gnamed = [(names.get(g.key, f"?{g.key:#x}"), g) for g in tbl.groups]
    print(f"\n=== {sub_file}  groups={len(tbl.groups)}  named={sum(1 for n,_ in gnamed if not n.startswith('?'))}")
    for n, g in gnamed[:14]:
        if n.startswith("?"):
            continue
        ent_names = [names.get(tbl.entries[i].key, f"?{tbl.entries[i].key:#x}")
                     for i in range(g.entry_start, min(g.entry_start + g.entry_count, len(tbl.entries)))]
        print(f"  GROUP {n:<24} entries={g.entry_count:<5} first={ent_names[:5]}")
        e = tbl.entries[g.entry_start]
        k0 = tbl.keys[e.key_start]
        print(f"      sample[{ent_names[0]}] = {string_at(tbl, k0[1]).decode('utf-8','replace')[:90]!r}")

    ec = Counter()
    for g in tbl.groups:
        for i in range(g.entry_start, min(g.entry_start + g.entry_count, len(tbl.entries))):
            if tbl.entries[i].key in names:
                ec[names[tbl.entries[i].key]] += 1
    print(f"  named entry keys: {sum(ec.values())} / {len(tbl.entries)}  top: {ec.most_common(8)}")
