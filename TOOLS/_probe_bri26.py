"""_probe_bri26 —— 逐扇区判定「解密后是否为文本 / 原文是否为文本 / 都不是」。

目的：_probe_bri25 发现有 54 处「无记录扇区空隙」。本脚本判断这些扇区
到底是 (a) 解密后是文本但不含记录、(b) 根本没加密（原文即文本）、
还是 (c) 用别的密钥/方式加密。

文本性判据：UTF-8 可解码字节占比（严格解码，非 replace）。
"""
import collections

from pwsf_briefing import SECTOR, decrypt_sectors
from pwsf_crypto import name_hash

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

raw = open(DAT, "rb").read()
key = name_hash("0076531d")
dec = bytes(decrypt_sectors(raw, key))
nsec = len(raw) // SECTOR
print(f"文件 {len(raw):#x}  扇区 {nsec}  key={key:#010x}")


def utf8_ratio(b: bytes) -> float:
    """严格 UTF-8 解码，返回能解码的字节占比。"""
    i = n = 0
    L = len(b)
    while i < L:
        c = b[i]
        if c < 0x80:
            i += 1
            n += 1
        elif 0xC2 <= c <= 0xDF and i + 1 < L and 0x80 <= b[i+1] <= 0xBF:
            i += 2
            n += 2
        elif 0xE0 <= c <= 0xEF:
            if i + 2 < L and 0x80 <= b[i+1] <= 0xBF and 0x80 <= b[i+2] <= 0xBF:
                i += 3
                n += 3
            else:
                i += 1
        elif 0xF0 <= c <= 0xF4:
            if i + 3 < L and all(0x80 <= b[i+k] <= 0xBF for k in (1, 2, 3)):
                i += 4
                n += 4
            else:
                i += 1
        else:
            i += 1
    return n / L if L else 0.0


rows = []
for s in range(nsec):
    o = s * SECTOR
    a = utf8_ratio(dec[o:o + SECTOR])
    b = utf8_ratio(raw[o:o + SECTOR])
    rows.append((s, a, b))

bins = collections.Counter()
for s, a, b in rows:
    if a > 0.90:
        k = "解密后是文本"
    elif b > 0.90:
        k = "原文即文本(未加密)"
    elif a > 0.70:
        k = "解密后偏文本"
    elif b > 0.70:
        k = "原文偏文本"
    else:
        k = "两者都不是"
    bins[k] += 1
print("\n分类统计：", dict(bins))

print("\n=== 「两者都不是」的扇区（前 80 个）===")
bad = [s for s, a, b in rows if a <= 0.70 and b <= 0.70]
print(f"共 {len(bad)} 个")
print(bad[:80])

print("\n=== 「原文即文本」的扇区 ===")
rawtxt = [s for s, a, b in rows if b > 0.90]
print(f"共 {len(rawtxt)} 个:", rawtxt[:60])

print("\n=== 「解密后偏文本」(0.70<a<=0.90) ===")
mid = [(s, round(a, 3)) for s, a, b in rows if 0.70 < a <= 0.90]
print(f"共 {len(mid)} 个:", mid[:60])

print("\n=== 抽查：空隙扇区 (已知不含记录) 的两种比值 ===")
for s in (15, 16, 80, 98, 99, 104, 120, 128, 135, 147):
    a, b = rows[s][1], rows[s][2]
    print(f"  s{s:5d}  解密后 {a:.3f}  原文 {b:.3f}")
