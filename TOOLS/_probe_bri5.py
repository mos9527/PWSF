"""Probe: 全文件枚举符合 sub_1400A3230 (0x1400A3230) 语义的 BRIEFING 记录。

两步法：
  1) 以 v10 为主序扫全文件，用 4 个偏移做廉价筛（p1<p2、长度 4 对齐、表递增、首项 0、
     池首串能 UTF-8 解码）；
  2) 反推 a1：v10 = a1 + 12 + 8*v5，且 u32@(a1+4+4*v5) 必须是首个 -1。
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
ND = N // 4
dw = list(struct.unpack("<%dI" % ND, dec[:ND * 4]))
MAXV5 = 512
FIRST = b"\x00"


def pool_text(p2: int, limit: int = 4096) -> bytes | None:
    """取 p2 起到第一个 NUL 的字节；超长或不可解码则返回 None"""
    e = dec.find(b"\x00", p2, min(N, p2 + limit))
    if e < 0:
        return None
    s = dec[p2:e]
    try:
        s.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s


cands = []
for i in range(0, ND - 4):
    o0, o1, o2, o3 = dw[i], dw[i + 1], dw[i + 2], dw[i + 3]
    if o1 >= o2 or o2 - o1 > 0x20000 or (o2 - o1) < 4 or ((o2 - o1) & 3):
        continue
    v10 = 4 * i
    p1 = v10 + o1
    p2 = v10 + o2
    if p2 >= ND:
        continue
    cnt = (p2 - p1) // 4
    if cnt < 1 or cnt > 4096:
        continue
    j0 = p1 // 4
    if dw[j0] != 0:
        continue
    ok = True
    prev = 0
    for k in range(1, cnt):
        v = dw[j0 + k]
        if v <= prev:
            ok = False
            break
        prev = v
    if not ok:
        continue
    s = pool_text(p2)
    if s is None or len(s) < 2 or len(s) > 2000:
        continue
    cands.append((v10, o0, o1, o2, o3, p1, p2, cnt))

print(f"候选 v10 位置 {len(cands)} 个")

recs = []
for v10, o0, o1, o2, o3, p1, p2, cnt in cands:
    hit = None
    for v5 in range(0, MAXV5 + 1):
        a1 = v10 - 12 - 8 * v5
        if a1 < 0 or a1 + 4 >= N:
            break
        # a1 必须 4 对齐
        if a1 & 3:
            continue
        if dw[(a1 + 4 + 4 * v5) // 4] != 0xFFFFFFFF:
            continue
        # 该 -1 必须是第一个
        good = True
        for k in range(v5):
            if dw[(a1 + 4 + 4 * k) // 4] == 0xFFFFFFFF:
                good = False
                break
        if good:
            hit = (a1, v5)
            break
    if hit:
        recs.append((hit[0], hit[1], v10, o0, o1, o2, o3, p1, p2, cnt))

recs.sort()
print(f"确认记录 {len(recs)} 个\n")
print(f"{'#':>4} {'a1':>8} {'v5':>4} {'v10':>8} {'off0':>7} {'off1':>5} {'off2':>7} "
      f"{'off3':>7} {'tbl':>8} {'pool':>8} {'n':>5}  {'a1/16':>7}")
for i, (a1, v5, v10, o0, o1, o2, o3, p1, p2, cnt) in enumerate(recs[:80]):
    print(f"{i:4} {a1:8x} {v5:4} {v10:8x} {o0:7} {o1:5} {o2:7} {o3:7} "
          f"{p1:8x} {p2:8x} {cnt:5}  {a1 / 16:7.2f}")

print("\n--- 每条记录的首行 ---")
for i, (a1, v5, v10, o0, o1, o2, o3, p1, p2, cnt) in enumerate(recs[:40]):
    s = pool_text(p2)
    print(f"[{i:3}] a1={a1:#07x} n={cnt:<4} {s.decode('utf-8')[:64] if s else ''}")
