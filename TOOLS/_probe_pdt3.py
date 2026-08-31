"""Probe: PDT/DAT container with the second-stage unmask applied (see pwsf_archive).

Validates plan 04 items A (entry count) and B (contiguous layout, no sector align).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
TARGETS = [
    r"MLG\disc0_rel\00b2b475.PDT",
    r"MLG\disc0_rel\0001112d.PDT",
    r"MLG\disc0_rel\00b2b4b6.PDT",
    r"MLG\disc0_rel\00b2b2a8.PDT",
    r"MLG\disc0_rel\009645fa.PDT",
    r"MLG\disc0_rel\ADEMO\0058cafb.pdt",
    r"MLG\disc0_rel\ADEMO\0018ef0c.pdt",
    r"ms0\EU\DLCTEX\ad1af1fb.PDT",
    r"ms0\EU\DLCBGM\e41b91fb.PDT",
]


def show(rel: str) -> None:
    p = GAME / rel
    if not p.exists():
        print(f"\n=== {rel}: MISSING")
        return
    raw = p.read_bytes()
    print(f"\n=== {rel}  size={len(raw):#x}  key={A.name_hash(p.stem):#010x}")
    try:
        arc = A.parse(raw, p.stem, str(p))
    except ValueError as e:
        print(f"    PARSE FAIL: {e}")
        return
    print(f"    hdr lo={arc.lo:#010x} hi={arc.hi:#010x} m={arc.m:#010x} "
          f"mode={arc.mode:#x} count={arc.count}")
    print(f"    hdr hex: {arc.hdr.hex(' ')}")
    print(f"    tables: index@{A.HDR_SIZE:#x}+{12*arc.count:#x}  "
          f"names@{arc.names_off:#x}+{24*arc.count:#x}  payload@{arc.names_off+24*arc.count:#x}")
    for i, e in enumerate(arc.entries[:8]):
        print(f"      idx[{i}] a={e.a:#010x} b={e.b:#010x} c={e.c:#010x}")
    for i, nd in enumerate(arc.nodes[:8]):
        print(f"      nam[{i}] key={nd.key:#010x} slot={nd.slot} "
              f"gt={nd.gt:#x} le={nd.le:#x}")
    # BST integrity: every non-zero child must land inside the node table
    lim = 24 * arc.count
    bad = [(i, nm, v) for i, nd in enumerate(arc.nodes)
           for nm, v in (("gt", nd.gt), ("le", nd.le))
           if v and not (0 <= v < lim)]
    print(f"    child offsets in range: {not bad}" + (f"  BAD={bad[:4]}" if bad else ""))
    slots = {nd.slot for nd in arc.nodes}
    print(f"    slots: min={min(slots) if slots else '-'} max={max(slots) if slots else '-'} "
          f"distinct={len(slots)}/{arc.count}  in-range={all(s < arc.count for s in slots)}")


for t in TARGETS:
    show(t)
