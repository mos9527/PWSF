"""Probe: 0076531d.DAT 头部结构 —— 按 sub_1400A3230 (0x1400A3230) 的实证语义解释。

sub_1400A3230(u8 *a1, int a2):
    if (!a2) dword_141103D48 = a1[0] | a1[1]<<8 | a1[2]<<16;   // u24 LE
    i  = (u32*)(a1+4);  while (*i != -1) ++i;  v5 = count      // -1 结尾的 u32 数组
    v7 = i+1; ... *v7 = v4;                                    // +8 是运行时计数槽
    v10 = a1 + 12;                                             // 真正的头部
    v2[0] = a1+4 ; *(u32*)(v2+8) = v5
    v3[0] = v10
    v11   = v10 + u32@(v10+0)
    v3[1] = v10 + u32@(v10+4)
    v3[2] = v10 + u32@(v10+8)
    v3[3] = v10 + u32@(v10+12)
    v2[2] = v11 + 4
    v2[3] = v11 + u32@(v11) + 8
"""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"

raw = bytearray(F.read_bytes())
key = name_hash(F.stem)
dec = bytes(buffer_xor_decrypt(bytearray(raw), key))
n = len(dec)
print(f"{F.name} size={n:#x} ({n}) sectors={n >> 12} key={key:#010x}")

u32 = lambda o: struct.unpack_from("<I", dec, o)[0]


def show(off, size=16):
    c = dec[off:off + size]
    return f"{off:06x}  " + " ".join(f"{b:02x}" for b in c)


print("\n--- head ---")
for off in range(0, 0x60, 16):
    c = dec[off:off + 16]
    print(show(off) + "  " + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))

print("\n--- sub_1400A3230 解释 (a1 = base+0) ---")
a1 = 0
print(f"  u24 id @+0      = {dec[0] | dec[1] << 8 | dec[2] << 16:#08x}")
print(f"  dword @+4       = {u32(4):#010x}   (数组终止符?)")
print(f"  dword @+8       = {u32(8):#010x}   (运行时计数槽)")
v10 = a1 + 12
o0, o1, o2, o3 = u32(v10), u32(v10 + 4), u32(v10 + 8), u32(v10 + 12)
print(f"  v10             = {v10:#x}")
print(f"  u32@(v10+0)={o0:<6} -> v11   = {v10 + o0:#x}")
print(f"  u32@(v10+4)={o1:<6} -> v3[1] = {v10 + o1:#x}")
print(f"  u32@(v10+8)={o2:<6} -> v3[2] = {v10 + o2:#x}")
print(f"  u32@(v10+12)={o3:<6} -> v3[3] = {v10 + o3:#x}")

v11 = v10 + o0
print(f"  u32@(v11)  ={u32(v11):<6} -> v2[2] = v11+4 = {v11 + 4:#x}"
      f"   v2[3] = {v11 + u32(v11) + 8:#x}")

# v3[1] 表：从 v3[1] 起，看是否是一串递增 u32
t = v10 + o1
print(f"\n--- v3[1] 表 @{t:#x} ---")
vals = [u32(t + 4 * i) for i in range(24)]
print("  " + " ".join(str(v) for v in vals))
inc = all(vals[i] < vals[i + 1] for i in range(len(vals) - 1))
print(f"  递增 = {inc}")

# 试探：以 v3[2] 为文本池基址，取表项作偏移
pool = v10 + o2
print(f"\n--- 以 v3[2]={pool:#x} 为基址，表项作偏移 ---")
for i in range(12):
    p = pool + vals[i]
    s = dec[p:p + 48].split(b"\x00")[0]
    try:
        txt = s.decode("utf-8")
    except UnicodeDecodeError:
        txt = repr(s)
    print(f"  [{i:3}] off={vals[i]:<6} @{p:#x}  {txt[:60]}")

print(f"\n--- v3[2] 附近原文 ---")
for off in range(pool, pool + 0x60, 16):
    c = dec[off:off + 16]
    print(show(off) + "  " + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))
print("  utf8:", dec[pool:pool + 96].decode("utf-8", "replace"))

print(f"\n--- v3[3] @{v10 + o3:#x} ---")
p3 = v10 + o3
for off in range(p3, p3 + 0x40, 16):
    c = dec[off:off + 16]
    print(show(off) + "  " + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))

print(f"\n--- v11 @{v11:#x} / v2[2] @{v11 + 4:#x} ---")
for off in range(v11, v11 + 0x40, 16):
    c = dec[off:off + 16]
    print(show(off) + "  " + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))
