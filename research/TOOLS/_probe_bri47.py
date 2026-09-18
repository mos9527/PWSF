"""_probe_bri47.py —— 解密粒度模型的穷举判决

待判模型（keystream 以 4096 字节扇区为最小 I/O 单位）：
  M1  per-4096        每个扇区独立 mt_seed(key)+advance(20)，偏移 0 起
  M2  continuous      全文件一条连续密钥流
  M3  grp16384        每 16384 字节（4 扇区）一组，组内连续；组起点 16384 对齐
  M4  grp16384x       每 16384 字节一组，组内连续；组起点 4096 对齐
  M5  per-8192        每 8192 字节一组

判据：
  a) 记录头魔数 ``6f 45 62 4e`` 在 16 字节栅格上的命中数（真记录 2049 条）；
  b) 512 字节窗口的 UTF-8 严格可解码数；
  c) 全文件可打印字节占比。

背景：_probe_bri8.py 已证 M1 胜 M2；本轮补齐 M3/M4/M5，用于核对
``briefing_dat_load`` 里 ``buffer_xor_decrypt(buf, dword_14117C094 << 12, key)``
（dword_14117C094 = 4*页数 >= 4，经 briefing_dat_request_pages 取证）。
"""
import struct
import sys

from pwsf_crypto import MT19937, name_hash, XOR_CONST

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")
REC_MAGIC = b"\x6f\x45\x62\x4e"
KEY = name_hash("0076531d")


def keystream(nwords, key):
    mt = MT19937(key)
    mt.advance(20)
    return [(mt.next() ^ XOR_CONST) & 0xFFFFFFFF for _ in range(nwords)]


def build(raw, block, per_block_reset):
    """block: 每个加密单元的字节数；per_block_reset: 单元内是否连续（False=每 4096 重置）"""
    unit = 4096 if not per_block_reset else block
    ks = keystream(unit // 4, KEY)
    out = bytearray(raw)
    for base in range(0, len(raw), block):
        if per_block_reset:
            ks = keystream(block // 4, KEY)
        for s in range(base, min(base + block, len(raw)), 4096):
            blk = raw[s:s + 4096]
            if per_block_reset:
                k = ks[(s - base) // 4:(s - base) // 4 + len(blk) // 4]
            else:
                k = ks[:len(blk) // 4]
            dec = bytearray(blk)
            for i, w in enumerate(k):
                j = i * 4
                dec[j] ^= w & 0xFF
                dec[j + 1] ^= (w >> 8) & 0xFF
                dec[j + 2] ^= (w >> 16) & 0xFF
                dec[j + 3] ^= (w >> 24) & 0xFF
            out[s:s + len(blk)] = dec
    return bytes(out)


def score(data):
    magic = sum(1 for a in range(0, len(data) - 28, 16)
                if data[a:a + 4] == REC_MAGIC)
    wins = 0
    for a in range(0, len(data) - 512, 512):
        try:
            data[a:a + 512].decode("utf-8")
            wins += 1
        except UnicodeDecodeError:
            pass
    pr = sum(1 for b in data[::7] if 32 <= b < 127 or b in (9, 10, 13)) / (len(data) // 7 + 1)
    return magic, wins, pr


def main():
    raw = open(DAT, "rb").read()
    print(f"文件 {len(raw)} 字节 = {len(raw)/4096:.2f} 扇区   key={KEY:#010x}\n")
    models = [
        ("M1 per-4096", 4096, False),
        ("M2 continuous(全文件)", len(raw) // 4096 * 4096, True),
        ("M3 grp16384 (16384 对齐)", 16384, True),
        ("M4 grp8192 (8192 对齐)", 8192, True),
    ]
    print(f"{'模型':28s} {'魔数(16B栅格)':>14s} {'UTF8窗口':>10s} {'可打印比':>9s}")
    for name, blk, reset in models:
        d = build(raw, blk, reset)
        m, w, pr = score(d)
        print(f"{name:28s} {m:14d} {w:10d} {pr:9.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
