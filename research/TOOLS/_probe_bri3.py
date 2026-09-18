"""Probe: 在 0076531d.DAT 中枚举所有符合 sub_1400A3230 语义的记录头。

模型（来自 0x1400A3230）：
    v5  = 从 a1+4 开始到首个 0xFFFFFFFF 的 u32 个数
    v10 = a1 + 12 + 8*v5
    v11   = v10 + u32@(v10+0)
    v3[1] = v10 + u32@(v10+4)      <- u32 偏移表
    v3[2] = v10 + u32@(v10+8)      <- UTF-8 文本池
    v3[3] = v10 + u32@(v10+12)
判据：v3[1] < v3[2]，(v3[2]-v3[1]) % 4 == 0，表严格递增且首项为 0，
      且 v3[2] 起的文本可 UTF-8 解码。
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
dec = bytes(buffer_xor_decrypt(bytearray(F.read_bytes()), name_hash(F.stem)))
N = len(dec)
u32 = lambda o: struct.unpack_from("<I", dec, o)[0]


def jp_ratio(b: bytes) -> float:
    """UTF-8 可解码比例（按 0x00 截断前的片段）"""
    s = b.split(b"\x00")[0]
    if not s:
        return 0.0
    try:
        s.decode("utf-8")
        return 1.0
    except UnicodeDecodeError as e:
        return e.start / len(s)


found = []
for a1 in range(0, min(N, 0x40000), 4):
    # v5: 扫描 -1 终止的 u32 数组
    p = a1 + 4
    v5 = 0
    while p + 4 <= N and u32(p) != 0xFFFFFFFF:
        v5 += 1
        p += 4
        if v5 > 256:
            break
    if v5 > 256:
        continue
    v10 = a1 + 12 + 8 * v5
    if v10 + 16 > N:
        continue
    o0, o1, o2, o3 = (u32(v10), u32(v10 + 4), u32(v10 + 8), u32(v10 + 12))
    p1, p2 = v10 + o1, v10 + o2
    if not (0 <= p1 < p2 < N):
        continue
    if (p2 - p1) % 4 or not (4 <= p2 - p1 <= 0x20000):
        continue
    cnt = (p2 - p1) // 4
    vals = [u32(p1 + 4 * i) for i in range(cnt)]
    if vals[0] != 0:
        continue
    if any(vals[i] >= vals[i + 1] for i in range(cnt - 1)):
        continue
    if jp_ratio(dec[p2:p2 + 64]) < 1.0:
        continue
    found.append((a1, v5, v10, o0, o1, o2, o3, p1, p2, cnt))

print(f"命中记录头 {len(found)} 个")
print(f"{'a1':>8} {'v5':>3} {'v10':>8} {'off0':>7} {'off1':>5} {'off2':>7} {'off3':>7} "
      f"{'tbl':>8} {'pool':>8} {'n':>5}")
for a1, v5, v10, o0, o1, o2, o3, p1, p2, cnt in found[:60]:
    print(f"{a1:8x} {v5:3} {v10:8x} {o0:7} {o1:5} {o2:7} {o3:7} {p1:8x} {p2:8x} {cnt:5}")

print("\n--- 前 3 个记录的首行 ---")
for a1, v5, v10, o0, o1, o2, o3, p1, p2, cnt in found[:3]:
    print(f"\n[a1={a1:#x}] {cnt} 行")
    for i in range(min(cnt, 8)):
        s = dec[p2 + vals[i]:].split(b"\x00")[0]
        print(f"   {i:3}  {s.decode('utf-8', 'replace')[:70]}")
