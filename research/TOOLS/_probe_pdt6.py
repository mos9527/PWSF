"""Probe: match archive BST node keys against entry_name_hash of every IDB string.

Evidence source: ANALYSIS/_strings.tsv (49869 strings dumped from the IDB).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_names as N

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ROOT = Path(__file__).resolve().parent.parent
STRINGS = ROOT / "ANALYSIS" / "_strings.tsv"

TARGETS = [
    r"MLG\disc0_rel\ADEMO\0058cafb.pdt",
    r"MLG\disc0_rel\ADEMO\0018ef0c.pdt",
    r"MLG\disc0_rel\0001112d.PDT",
    r"MLG\disc0_rel\00b2b475.PDT",
    r"MLG\disc0_rel\00b2b4b6.PDT",
    r"MLG\disc0_rel\00b2b2a8.PDT",
    r"MLG\disc0_rel\009645fa.PDT",
    r"ms0\EU\DLCTEX\ad1af1fb.PDT",
    r"ms0\EU\DLCBGM\e41b91fb.PDT",
]

keymap = {}
dup = 0
with STRINGS.open(encoding="utf-8", errors="replace") as f:
    for line in f:
        ea, length, hexs = line.rstrip("\n").split("\t")
        raw = bytes.fromhex(hexs)
        h = N.entry_name_hash(raw)
        if h in keymap and keymap[h] != raw:
            dup += 1
        keymap.setdefault(h, raw)
print(f"loaded {len(keymap)} distinct hashes from {STRINGS.name} (collisions {dup})")

for rel in TARGETS:
    p = GAME / rel
    if not p.exists():
        print(f"\n=== {rel}: MISSING")
        continue
    try:
        arc = A.parse(p.read_bytes(), p.stem, str(p), max_entries=100000)
    except ValueError as e:
        print(f"\n=== {rel}: PARSE FAIL {e}")
        continue
    hits = [(nd, keymap.get(nd.key)) for nd in arc.nodes if nd.key in keymap]
    print(f"\n=== {rel}  count={arc.count}  resolved {len(hits)}/{arc.count}")
    for nd, nm in hits[:15]:
        e = arc.entries[nd.slot]
        print(f"      {nm.decode('latin-1'):<24} off={e.c:#x} size={e.a:#x} "
              f"sum={e.b:#010x}")
