"""Probe: resolve archive BST node keys back to entry names.

Hypothesis under test: node.key == entry_name_hash("<archive stem>.<ext>")
with ext drawn from g_ext_id_table (0x140F4C7D0).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_names as N

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
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

# sanity: the hash core must be invertible (small alphabet, short strings only)
for probe in [b"abc", b"SUB", b"a"]:
    h = N.entry_name_hash(probe)
    inv = N.invert(h, maxlen=len(probe), alphabet=b"abcSU")
    print(f"  entry_name_hash({probe!r}) = {h:#08x}  preimage_found={probe in inv}")

print()
for rel in TARGETS:
    p = GAME / rel
    raw = p.read_bytes()
    try:
        arc = A.parse(raw, p.stem, str(p), max_entries=100000)
    except ValueError as e:
        print(f"\n=== {rel}: PARSE FAIL {e}")
        continue
    table = {}
    for ext in N.EXT_IDS:
        table[N.entry_name_hash(f"{p.stem}.{ext}")] = f"{p.stem}.{ext}"
    hits = [(nd, table.get(nd.key)) for nd in arc.nodes if nd.key in table]
    print(f"\n=== {rel}  count={arc.count}  resolved {len(hits)}/{arc.count}")
    for nd, nm in hits[:12]:
        e = arc.entries[nd.slot]
        print(f"      {nm:<20} key={nd.key:#010x} slot={nd.slot} "
              f"off={e.c:#x} size={e.a:#x} sum={e.b:#010x}")
