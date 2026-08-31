"""PWSF BRIEFING / CODEC 数据解析（MLG/disc0_rel/0076531d.DAT）

证据链（IDA, imagebase 0x140000000）
----------------------------------
briefing_dat_load            0x1400A5570  读盘 + buffer_xor_decrypt
briefing_dat_request         0x1400A54E0  (buf, 起始扇区, 扇区数)
briefing_dat_request_pages   0x140804220  分页请求；req 字打包为
                                          idx(bit0-7) | 扇区(bit8-23) | ((页数-1))(bit24-31)
sub_140804080                0x140804080  sub_1408C57D0(缓冲区 + 16*idx)
sub_1408C57D0                0x1408C57D0  ``codec thread`` 的建立点
sub_1400A3230                0x1400A3230  记录头解析（本模块格式的直接来源）
sub_1400A4770                0x1400A4770  字节码操作数解码（低 4 位 = 长度/长度模式）
sub_1400A35C0                0x1400A35C0  字节码解释器（op 0x30/0x60/0x70）

解密
----
key = name_hash("0076531d.DAT") = name_hash("0076531d")
文件在磁盘上按 **4096 字节扇区分别加密**：每个扇区都用
``buffer_xor_decrypt(sector, 4096, key)``（内部 mt_seed(key) + mt_advance(20)）。
实证：_probe_bri8.py 的 A/B 测试，逐扇区 1519 个 512B 窗口可 UTF-8 解码，
4 扇区连续只有 579 个；file+0x1700 处在逐扇区解出记录头魔数 ``6f 45 62 4e``。

> 疑点（未验证）：briefing_dat_load 里是
> ``buffer_xor_decrypt(buf, dword_14117C094 << 12, key)``，
> 而 ``dword_14117C094 = (HIBYTE(req)+1) << 2 >= 4``（见 0x14080426D 起的汇编）。
> 与「逐扇区」的事实不符，逐扇区解密应发生在 op=7 的 I/O 工作线程里
> （sub_14045DF30(req, 7, ...)），该函数尚未定位。**不作为结论使用。**

语言归属
--------
**本模块不判定语言。** 已取证的事实：

* `lang_get_language_id()` @ 0x140027B40 返回 0=en / 1=fr / 2=de(gr) /
  3=it / 4=es,pt / 6=ja；
* 记录头内**没有**语言字段——各扇区段的记录头逐字节同构，只有长度不同；
* 语言只体现在寻址参数上：请求字 = idx(bit0-7) | 扇区(bit8-23) |
  (页数-1)(bit24-31)（汇编 0x14080422A / 0x140804271 / 0x14080427B），
  由 sub_1408045E0(ctx, a2) 的 a2 提供；
* `sub_1405E07CB` 读的 dword_141495DE0 静态为全 0xFFFFFFFF（运行时填充），
  且 rsi 是 imagebase（lea rsi, cs:140000000h），不是语言索引；
* `sub_14007BE00` 的筛选量 dword_1410A26F8 在 sub_1400CA720 里两处均被
  赋值为常量 0x180A20（块类型标签），与语言无关。

故 Record 只提供 script_class()（Unicode 层面的客观归类），不提供 lang。

记录头（28 字节，起始处 16 字节对齐）
------------------------------------
```
+0x00  u24  id                      -> dword_141103D48 (sub_1400A3230, a2==0)
+0x03  u8   flags / 语言或类别       （语义未验证）
+0x04  u32  -1      -1 结尾 u32 数组的终止符（本文件所有记录均为空数组 -> v5=0）
+0x08  u32  运行时计数槽（运行时被写 0；磁盘上的值无意义）
+0x0C  u32  off0    -> v11   = v10 + off0   （脚本区）
+0x10  u32  off1    -> v3[1] = v10 + off1   （u32 偏移表）
+0x14  u32  off2    -> v3[2] = v10 + off2   （UTF-8 文本池）
+0x18  u32  off3    -> v3[3] = v10 + off3
```
其中 ``v10 = a1 + 12 + 8*v5``。文本池是 NUL 结尾串的连续区，第 i 串的偏移就是
偏移表第 i 项；串数 = (v3[2] - v3[1]) / 4。

脚本区（off0）
--------------
```
v11     = v10 + off0
pool    = v11 + 4                                  (xmmword_141103D70, A->pool)
entry   = v11 + u32@(v11) + 8                      (A->entry)
tbl     = a1 + 4                                   (A->tbl)
```
字节码由 sub_1400A4770 解码：``op & 0xF`` 为 0..12 时即长度，13/14/15 分别表示
后随 u8 / u16 / u24 长度。解释器按 ``op & 0xF0`` 分派：0x30 文本、0x60 外部调用、
0x70 按 id 调子程序。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from pwsf_crypto import MT19937, name_hash, XOR_CONST

SECTOR = 4096
REC_MAGIC = b"\x6f\x45\x62\x4e"



__all__ = [
    "SECTOR", "REC_MAGIC", "Record", "Briefing",
    "load", "parse", "decrypt_sectors", "iter_records",
]


def _keystream(nbytes: int, key: int) -> bytes:
    mt = MT19937(key)
    mt.advance(20)
    return struct.pack("<%dI" % (nbytes // 4),
                       *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                         for _ in range(nbytes // 4)])


def decrypt_sectors(raw: bytes, key: int, sector: int = SECTOR) -> bytearray:
    """逐扇区 MT 解密。最后一个不完整的扇区按实际长度处理。"""
    ks = _keystream(sector, key)
    out = bytearray(raw)
    for off in range(0, len(raw), sector):
        blk = raw[off:off + sector]
        out[off:off + len(blk)] = bytes(a ^ b for a, b in zip(blk, ks))
    return out


@dataclass
class Record:
    """一条 BRIEFING 记录 = 一组台词 + 一段脚本字节码。"""
    off: int            # 文件内绝对偏移（== 16 * idx）
    sector: int         # 所在扇区
    idx: int            # off // 16，即 sub_140804080 里的 LOBYTE(req)
    id24: int           # +0x00 u24
    flags: int          # +0x03 u8（语义未验证）
    v10: int            # 头部基准
    off0: int           # -> 脚本区
    off1: int           # -> 偏移表
    off2: int           # -> 文本池
    off3: int
    table: list         # u32 偏移表
    lines: list         # 解码后的台词（str）
    script_off: int     # pool = v11 + 4
    entry_off: int      # entry = v11 + u32@(v11) + 8
    end: int = -1       # 记录结束（下一条记录起点或扇区末），回填
    problems: list = field(default_factory=list)

    @property
    def n_lines(self) -> int:
        return len(self.lines)

    def script_end(self, data) -> int:
        """脚本字节码的结束位置。

        入口是一条 ``op=0x8e/0x8d`` 的包裹指令（sub_1400A4770 的 case 13/14），
        其长度字段给出脚本体长度；再与下一条记录起点取小，避免越界。
        """
        e = self.entry_off
        if e < 0 or e + 4 > len(data):
            return min(self.script_off, len(data))
        lo = data[e] & 0x0F
        if lo == 13:
            n, body = data[e + 1], e + 2
        elif lo == 14:
            n = int.from_bytes(data[e + 1:e + 3], "little")
            body = e + 3
        elif lo == 15:
            n = int.from_bytes(data[e + 1:e + 4], "little")
            body = e + 4
        else:
            n, body = lo, e + 1
        end = body + n
        if 0 < self.end > self.entry_off:
            end = min(end, self.end)
        return min(end, len(data))

    def script_class(self) -> str:
        """字符集归类 —— **仅陈述 Unicode 层面的客观事实**，不是语言判定。

        * ``kana``  : 含假名或汉字
        * ``latin`` : 纯拉丁字母及标点
        * ``-``     : 两者皆无（数字/符号/空）

        语言（en/fr/de/it/es/ja）**无法从本文件判定**：记录头内没有语言字段
        （各扇区段的记录头逐字节同构，只有长度不同），语言只在运行时的寻址
        表里体现，见模块文档顶部「语言归属」一节。
        """
        import re
        s = "".join(self.lines)
        if re.search(r"[぀-ヿ一-鿿]", s):
            return "kana"
        if re.search(r"[A-Za-z]", s):
            return "latin"
        return "-"

    def voice_ids(self, data: bytes):
        """脚本字节码内出现的语音资源 ID（如 v_bri_kaz0010_000_0）。

        只扫本记录的脚本区（到 script_end 为止），不越界到后续记录。
        """
        import re
        a, b = self.script_off, self.script_end(data)
        if not (0 <= a < b <= len(data)):
            return []
        seg = data[a:b]
        return [m.decode("ascii", "replace")
                for m in re.findall(rb"[a-z]_[a-z]{3}_[A-Za-z0-9_]{6,}", seg)]


@dataclass
class Briefing:
    path: Path
    key: int
    data: bytes
    records: list

    def __len__(self):
        return len(self.records)


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u24(buf, off):
    return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16)


def parse_record(buf, a1: int) -> Record | None:
    """按 sub_1400A3230 的语义解析 a1 处的记录头；不合法返回 None。"""
    if a1 + 28 > len(buf):
        return None
    if _u32(buf, a1 + 4) != 0xFFFFFFFF:
        return None
    v5 = 0
    v10 = a1 + 12 + 8 * v5
    if v10 + 16 > len(buf):
        return None
    o0, o1, o2, o3 = (_u32(buf, v10), _u32(buf, v10 + 4),
                      _u32(buf, v10 + 8), _u32(buf, v10 + 12))
    p1, p2, v11 = v10 + o1, v10 + o2, v10 + o0
    prob = []
    if not (0 <= p1 < p2 < len(buf)):
        return None
    if not (o1 < o2) or ((o2 - o1) & 3):
        return None
    cnt = (p2 - p1) // 4
    if cnt < 1 or p2 + 4 * cnt > len(buf) + 4:
        return None
    table = [_u32(buf, p1 + 4 * i) for i in range(cnt)]
    if any(table[i] >= table[i + 1] for i in range(cnt - 1)):
        return None                      # 魔数碰撞产生的假阳性
    # 文本池：从 p2 起按偏移表取 NUL 结尾的 UTF-8 串
    end = p2
    for v in table:
        e = buf.find(b"\x00", p2 + v, min(len(buf), p2 + v + 8192))
        if e < 0:
            return None                  # 假阳性
        end = max(end, e + 1)
    if table[0] != 0:
        prob.append("table[0] != 0")
    lines = []
    for v in table:
        e = buf.find(b"\x00", p2 + v, min(len(buf), p2 + v + 8192))
        raw = b"" if e < 0 else buf[p2 + v:e]
        lines.append(raw.decode("utf-8", "replace"))
    if v11 + 8 > len(buf):
        return None
    # 脚本区入口必须是合法字节码。这是剔除魔数碰撞假阳性的决定性判据：
    # 实测入口合法 2049 条 -> 台词 100% 可解码；入口非法 614 条 -> 601 条含乱码
    # （_probe_bri18.py）。假阳性的 off0 是随机大数，entry_off 会越界。
    entry = v11 + _u32(buf, v11) + 8
    if not (v11 + 4 <= entry < len(buf)):
        return None
    op = buf[entry]
    if op & 0xF0 == 0 or op not in (0x8D, 0x8E):
        return None
    lo = op & 0x0F
    if lo == 13:
        n, body = buf[entry + 1], entry + 2
    elif lo == 14:
        n, body = int.from_bytes(buf[entry + 1:entry + 3], "little"), entry + 3
    else:
        n, body = lo, entry + 1
    if body + n > len(buf):
        return None
    return Record(
        off=a1, sector=a1 // SECTOR, idx=a1 // 16,
        id24=_u24(buf, a1), flags=buf[a1 + 3],
        v10=v10, off0=o0, off1=o1, off2=o2, off3=o3,
        table=table, lines=lines,
        script_off=v11 + 4, entry_off=v11 + _u32(buf, v11) + 8,
        problems=prob,
    )


def iter_records(buf) -> list:
    """按魔数 REC_MAGIC 在 16 字节对齐位置扫描全部记录。"""
    recs = []
    n = len(buf)
    for a1 in range(0, n - 28, 16):
        if buf[a1:a1 + 4] != REC_MAGIC:
            continue
        r = parse_record(buf, a1)
        if r is not None:
            recs.append(r)
    # 回填 end：下一条记录起点，但不得越过所在扇区（扇区是独立解密单元，
    # 跨扇区的记录尾不保证有意义——这一条本身也是待验证的假设）
    for i, r in enumerate(recs):
        nxt = recs[i + 1].off if i + 1 < len(recs) else len(buf)
        sector_end = (r.sector + 1) * SECTOR
        r.end = min(nxt, sector_end)
    return recs


def parse(data: bytes, name: str = "0076531d.DAT", path: Path | None = None) -> Briefing:
    key = name_hash(name)
    return Briefing(path=path, key=key, data=data, records=iter_records(data))


def load(path: str | Path) -> Briefing:
    p = Path(path)
    raw = p.read_bytes()
    data = bytes(decrypt_sectors(raw, name_hash(p.stem)))
    return Briefing(path=p, key=name_hash(p.stem), data=data,
                    records=iter_records(data))


if __name__ == "__main__":
    import argparse
    import collections
    import sys

    ap = argparse.ArgumentParser(description="PWSF BRIEFING / CODEC 提取")
    ap.add_argument("dat", nargs="?",
                    default=r"C:\Program Files (x86)\Steam\steamapps\common"
                            r"\MGS_PW\mgspw\MLG\disc0_rel\0076531d.DAT")
    ap.add_argument("-o", "--out", help="输出 TSV")
    a = ap.parse_args()

    br = load(a.dat)
    print(f"{br.path.name}  size={len(br.data):#x}  key={br.key:#010x}  "
          f"扇区={len(br.data) // SECTOR}  记录={len(br.records)}")

    bad = [r for r in br.records if r.problems]
    if bad:
        print(f"  异常记录 {len(bad)} 条，例如：")
        for r in bad[:5]:
            print(f"    {r.off:#x}: {r.problems}")

    # 字符集归类（客观事实，非语言判定）
    cnt = collections.Counter(r.script_class() for r in br.records)
    print("\n记录字符集归类：", dict(cnt))
    print("台词总数：", sum(r.n_lines for r in br.records))
    nv = sum(1 for r in br.records if r.voice_ids(br.data))
    print("含语音 ID 的记录：", nv)

    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="") as f:
            f.write("sector\toff\tidx\tline\tscript_class\tvoice_ids\ttext\n")
            for r in br.records:
                vids = "|".join(sorted(set(r.voice_ids(br.data))))
                for i, t in enumerate(r.lines):
                    t1 = t.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
                    f.write(f"{r.sector}\t{r.off:#x}\t{r.idx}\t{i}\t"
                            f"{r.script_class()}\t{vids}\t{t1}\n")
        print("已写出：", a.out)
