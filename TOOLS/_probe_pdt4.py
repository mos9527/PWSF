"""Probe: (1) do the >96-entry big PDTs self-consistently decode?
(2) is the BST node key == name_hash(entry name)?
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
from pwsf_crypto import name_hash

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
BIG = [
    r"MLG\disc0_rel\00b2b475.PDT",
    r"MLG\disc0_rel\00b2b4b6.PDT",
    r"MLG\disc0_rel\00b2b2a8.PDT",
    r"MLG\disc0_rel\009645fa.PDT",
    r"MLG\disc0_rel\002aba34.DAT",
]
OK = [
    r"MLG\disc0_rel\0001112d.PDT",
    r"MLG\disc0_rel\ADEMO\0058cafb.pdt",
    r"MLG\disc0_rel\ADEMO\0018ef0c.pdt",
    r"ms0\EU\DLCTEX\ad1af1fb.PDT",
    r"ms0\EU\DLCBGM\e41b91fb.PDT",
]

ALIGN = 0x800


def dump(rel: str, maxn: int = 100000) -> None:
    p = GAME / rel
    raw = p.read_bytes()
    print(f"\n=== {rel}  size={len(raw):#x}")
    try:
        arc = A.parse(raw, p.stem, str(p), max_entries=maxn)
    except ValueError as e:
        print(f"    FAIL: {e}")
        return
    hdr = arc.hdr
    f10, f14, f1a, f1c, f20, f24 = struct.unpack_from("<IIHII I".replace(" ", ""), hdr, 0x10)
    print(f"    mode={arc.mode:#x} count={arc.count} hdr[0x10]={f10:#x} "
          f"hdr[0x14]={f14:#x} hdr[0x1A]={f1a} hdr[0x1C]={f1c:#x} "
          f"hdr[0x20]={f20:#x} hdr[0x24]={f24:#x}")
    print(f"    names_off field {f20:#x} vs computed {arc.names_off:#x}  "
          f"MATCH={f20 == arc.names_off}")
    # index table self-consistency: offsets are 0x800-aligned and contiguous
    ok, prev_end = True, A.HDR_SIZE + 12 * arc.count + 24 * arc.count
    end = prev_end
    for i, e in enumerate(arc.entries):
        if e.c != end:
            print(f"      idx[{i}] offset {e.c:#x} != expected {end:#x}")
            ok = False
            break
        end = (e.c + e.a + ALIGN - 1) & ~(ALIGN - 1)
    print(f"    index chain contiguous(align {ALIGN:#x}): {ok}  "
          f"tail={end:#x} filesize={len(raw):#x} MATCH={end == len(raw) or (end >> 12) == (len(raw) >> 12)}")
    lim = 24 * arc.count
    bad = sum(1 for nd in arc.nodes
              for v in (nd.gt, nd.le) if v and not (0 <= v < lim))
    slots = sorted(nd.slot for nd in arc.nodes)
    print(f"    bst children bad={bad}  slots distinct={len(set(slots))} "
          f"range=[{slots[0]},{slots[-1]}] in-range={slots[-1] < arc.count}")
    for i, e in enumerate(arc.entries[:6]):
        print(f"      idx[{i}] off={e.c:#x} size={e.a:#x} sum={e.b:#010x}")


print("################ big containers (count > 96) ################")
for t in BIG:
    dump(t)
print("\n################ known-good containers ################")
for t in OK:
    dump(t)

print("\n################ name_hash hypothesis ################")
for probe in ["SUBTITLE", "subtitle", "SUBTITLE.TXT", "MOVIE", "SCRIPT"]:
    h = name_hash(probe)
    hit = []
    for rel in OK + BIG:
        p = GAME / rel
        if not p.exists():
            continue
        try:
            arc = A.parse(p.read_bytes(), p.stem, str(p), max_entries=100000)
        except ValueError:
            continue
        for nd in arc.nodes:
            if nd.key == h:
                e = arc.entries[nd.slot]
                hit.append((rel, e.c, e.a))
    print(f"  name_hash({probe!r}) = {h:#010x}  hits={hit[:4]}")
