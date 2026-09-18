"""诊断：解密块模型修正。

旧模型（错误）：每个扇区都用 keystream 偏移 0。
新模型（待验证）：请求 = (起始扇区 S, 扇区数 N=4*(HIBYTE+1))，
                 解密对 [S*4096, (S+N)*4096) 用**连续** keystream，
                 即块内第 k 个扇区用 keystream 偏移 k*4096。

因此同一扇区 F 可能有 4 种（甚至更多）合法 keystream 偏移，
取决于它所属的块起点。本脚本对每个扇区在 k=0..K 中选可解码性最优者。
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import MT19937, name_hash, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
raw = F.read_bytes()
N, PAGE = len(raw), 4096
key = name_hash(F.stem)

mt = MT19937(key)
mt.advance(20)
KMAX = 16
KS = struct.pack("<%dI" % (KMAX * PAGE // 4),
                 *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                   for _ in range(KMAX * PAGE // 4)])


def dec_sector(p: int, k: int) -> bytes:
    """扇区 p，假设它是块内第 k 个扇区 -> keystream 偏移 k*4096"""
    blk = raw[p * PAGE:(p + 1) * PAGE]
    return bytes(a ^ b for a, b in zip(blk, KS[k * PAGE:(k + 1) * PAGE]))


print("=== 扇区 350 (file 0x15e000) 用不同 k 解密 ===")
for k in range(8):
    d = dec_sector(350, k)
    head = d[:48]
    magic = "MAGIC" if head[:4] == b"\x6f\x45\x62\x4e" else "     "
    try:
        s = head.split(b"\x00")[0].decode("utf-8")
        show, ok = s[:40], "utf8-OK"
    except UnicodeDecodeError:
        show, ok = repr(head[:20]), "utf8-BAD"
    print(f"  k={k}  {magic}  {ok:8} {show}")

print("\n=== 扇区 349 (file 0x15d000) 用不同 k 解密（对照）===")
for k in range(8):
    d = dec_sector(349, k)
    head = d[:48]
    magic = "MAGIC" if head[:4] == b"\x6f\x45\x62\x4e" else "     "
    try:
        s = head.split(b"\x00")[0].decode("utf-8")
        show, ok = s[:40], "utf8-OK"
    except UnicodeDecodeError:
        show, ok = repr(head[:20]), "utf8-BAD"
    print(f"  k={k}  {magic}  {ok:8} {show}")


# ---------- 全文件：为每个扇区选最优 k ----------
def score(d: bytes) -> float:
    """可解码性得分：UTF-8 可解码的 256 字节窗口占比 + 魔数加权"""
    n = ok = 0
    for o in range(0, len(d) - 256, 256):
        n += 1
        try:
            d[o:o + 256].decode("utf-8")
            ok += 1
        except UnicodeDecodeError:
            pass
    s = ok / n if n else 0.0
    if d[:4] == b"\x6f\x45\x62\x4e":
        s += 10.0
    return s


best = []
for p in range(N // PAGE):
    scores = [(score(dec_sector(p, k)), k) for k in range(KMAX)]
    s, k = max(scores)
    best.append((p, k, s))

import collections
print("\n=== 最优 k 的分布 ===")
print("  ", dict(collections.Counter(k for _, k, _ in best)))

print("\n=== 前 40 个扇区的最优 k 序列 ===")
print("  " + " ".join(str(k) for _, k, _ in best[:40]))
print("\n=== 扇区 340..360 的最优 k 序列 ===")
print("  " + " ".join(f"{p}:{k}" for p, k, _ in best[340:361]))

# 用修正后的 k 重新解密，统计记录与台词
dec = bytearray(raw)
for p, k, _ in best:
    dec[p * PAGE:(p + 1) * PAGE] = dec_sector(p, k)

import pwsf_briefing as B
recs = B.iter_records(bytes(dec))
nbad = sum(1 for r in recs for t in r.lines if "\ufffd" in t)
print(f"\n=== 用最优 k 重新解密 ===")
print(f"  记录 {len(recs)}  台词 {sum(r.n_lines for r in recs)}  "
      f"不可解码台词 {nbad}")
old = B.iter_records(bytes(B.decrypt_sectors(raw, key)))
nbad_old = sum(1 for r in old for t in r.lines if "\ufffd" in t)
print(f"  （旧模型：记录 {len(old)}  台词 {sum(r.n_lines for r in old)}  "
      f"不可解码台词 {nbad_old}）")
