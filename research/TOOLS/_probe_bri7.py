"""Probe: 验证 0076531d.DAT 的「每扇区独立解密」假设 + 语言分区 + 记录元数据。

对比两种假设：
  A. 每 4096 扇区用「块内偏移 0」的密钥流独立解密   （本次扫描采用）
  B. 每 16384 字节（4 扇区）连续解密
若 A 成立而 B 不成立 -> 文件在打包时就是逐扇区加密的。
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


def keystream(nbytes):
    mt = MT19937(key)
    mt.advance(20)
    return struct.pack("<%dI" % (nbytes // 4),
                       *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                         for _ in range(nbytes // 4)])


KS4K = int.from_bytes(keystream(PAGE), "little")
KS16K = int.from_bytes(keystream(4 * PAGE), "little")

sect = [None] * (N // PAGE)
sect16 = [None] * (N // (4 * PAGE) + 1)
for p in range(N // PAGE):
    b = raw[p * PAGE:(p + 1) * PAGE]
    sect[p] = ((int.from_bytes(b, "little") ^ KS4K).to_bytes(PAGE, "little"))
for q in range(N // (4 * PAGE)):
    b = raw[q * 4 * PAGE:(q + 1) * 4 * PAGE]
    sect16[q] = ((int.from_bytes(b, "little") ^ KS16K).to_bytes(4 * PAGE, "little"))


def printable(b):
    return sum(1 for x in b if 0x20 <= x < 0x7F or x in (9, 10, 13)) / len(b)


def utf8ok(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


print("=== 假设 A（逐扇区） vs 假设 B（4 扇区连续） 前 12 扇区可解码性 ===")
print(f"{'sector':>7} {'A utf8':>7} {'A pr':>6} | {'blk':>4} {'B utf8':>7} {'B pr':>6}")
for p in range(12):
    a, b = sect[p], sect16[p // 4][(p % 4) * PAGE:(p % 4 + 1) * PAGE]
    print(f"{p:7} {str(utf8ok(a)):>7} {printable(a):6.3f} | "
          f"{p // 4:4} {str(utf8ok(b)):>7} {printable(b):6.3f}")

# 整文件统计
ua = sum(1 for s in sect if utf8ok(s))
ub = sum(1 for q in range(N // (4 * PAGE))
         for k in range(4) if utf8ok(sect16[q][k * PAGE:(k + 1) * PAGE]))
pa = sum(printable(s) for s in sect) / len(sect)
print(f"\nA: 整扇区 UTF-8 可解码 {ua}/{len(sect)}   平均 printable {pa:.3f}")

# ---------- 语言分区 ----------
import re

LANG_HINT = [
    ("ja", re.compile(r"[぀-ヿ一-鿿]")),
    ("es", re.compile(r"[¿¡ñáéíóúü]")),
    ("pt", re.compile(r"[ãõçâêôà]")),
    ("fr", re.compile(r"[àâçéèêëîïôûùüÿœ]")),
    ("de", re.compile(r"[äöüßÄÖÜ]")),
    ("it", re.compile(r"[àèéìòù]")),
]


def guess(b):
    s = b.decode("utf-8", "ignore")
    best, bn = "-", 0
    for name, rx in LANG_HINT:
        c = len(rx.findall(s))
        if c > bn:
            best, bn = name, c
    return best, bn


print("\n=== 每扇区语言猜测（UTF-8 可解码的扇区） ===")
rows = []
for p, s in enumerate(sect):
    if not utf8ok(s):
        rows.append((p, "?", 0))
        continue
    g, c = guess(s)
    rows.append((p, g, c))
cur, start = rows[0][1], 0
zones = []
for p, g, c in rows[1:]:
    if g != cur:
        zones.append((start, p - 1, cur))
        cur, start = g, p
zones.append((start, rows[-1][0], cur))
for a, b, g in zones:
    print(f"  扇区 {a:5} .. {b:5}  ({b - a + 1:4} 个, {hex(a * PAGE)}..{hex((b + 1) * PAGE)})  -> {g}")
