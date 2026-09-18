"""决定性诊断：扇区 349 / 350 在 k=0,1,2 下的真实内容。

把两种互斥的判据摆在一起：
  (a) 魔数锚点：k=0 下扇区 350 有 5 个 6f 45 62 4e
  (b) 文本连贯：扇区 349 尾部 "Regarde ça, Snake.\\n" 是否接得上扇区 350 开头
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import MT19937, name_hash, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
raw = F.read_bytes()
PAGE = 4096
key = name_hash(F.stem)
MAGIC = b"\x6f\x45\x62\x4e"

mt = MT19937(key)
mt.advance(20)
KS = struct.pack("<%dI" % (8 * PAGE // 4),
                 *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF for _ in range(8 * PAGE // 4)])


def dec(p, k):
    blk = raw[p * PAGE:(p + 1) * PAGE]
    return bytes(a ^ b for a, b in zip(blk, KS[k * PAGE:(k + 1) * PAGE]))


def show(p, k, lo=0, hi=160):
    d = dec(p, k)
    print(f"\n--- 扇区 {p}  k={k}  偏移 {lo:#x}..{hi:#x} ---")
    for o in range(lo, hi, 16):
        c = d[o:o + 16]
        print(f"  {p * PAGE + o:08x}  {' '.join(f'{b:02x}' for b in c):<47}  "
              + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))
    mg = [o for o in range(0, PAGE, 16) if d[o:o + 4] == MAGIC]
    print(f"  魔数命中位置(扇区内)：{[hex(x) for x in mg]}")


print("########## 扇区 349 尾部（记录头所在） ##########")
for k in (0, 1):
    show(349, k, lo=0xFA0, hi=0x1000)

print("\n\n########## 扇区 350 开头 ##########")
for k in (0, 1, 2):
    show(350, k, lo=0, hi=0xA0)

print("\n\n########## 连贯性检验：349 尾部 + 350 开头 ##########")
for k35 in (0, 1, 2):
    tail = dec(349, 0)[0xFB0:]          # 349 的记录头/文本在 k=0 下成立
    head = dec(350, k35)[:64]
    j = tail + head
    try:
        s = j.decode("utf-8")
        print(f"  349(k=0) + 350(k={k35}) -> utf8 OK : {s[:90]!r}")
    except UnicodeDecodeError as e:
        print(f"  349(k=0) + 350(k={k35}) -> utf8 BAD @{e.start}: "
              f"{j[max(0, e.start - 10):e.start + 20]!r}")

print("\n\n########## 扇区 350 在 k=0 下的 5 个魔数处是否是真记录？ ##########")
d350 = dec(350, 0)
u32 = lambda o: struct.unpack_from("<I", d350, o)[0]
for o in [x for x in range(0, PAGE, 16) if d350[x:x + 4] == MAGIC]:
    v10 = o + 12
    if v10 + 16 > PAGE:
        continue
    o0, o1, o2, o3 = u32(v10), u32(v10 + 4), u32(v10 + 8), u32(v10 + 12)
    p1, p2 = v10 + o1, v10 + o2
    cnt = (p2 - p1) // 4 if p2 > p1 else 0
    txt = ""
    if 0 < cnt < 64 and p2 < PAGE:
        q = p2 + u32(p1)
        try:
            txt = d350[q:q + 60].split(b"\x00")[0].decode("utf-8")[:36]
        except UnicodeDecodeError:
            txt = "<不可解码>"
    print(f"  MAGIC@{o:#06x} v10={v10:#06x} off=({o0},{o1},{o2},{o3}) "
          f"n={cnt:<4} 首句={txt!r}")
