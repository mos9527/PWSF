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

语言归属（已解决）
------------------
**文件由 2 组 x 6 个连续语言块构成**，每种语言的同一段台词各存一份：

```
组1（v_bri，主 CODEC 通话）              组2（v_fop / v_myo 等）
  ja  sec   0-127  248 条                  ja  sec 877-901   87 条
  en  sec 148-287  270 条                  en  sec 901-922   88 条
  fr  sec 288-439  258 条                  fr  sec 924-945   80 条
  de  sec 440-590  254 条                  de  sec 945-968   84 条
  it  sec 591-735  251 条                  it  sec 968-990   84 条
  es  sec 736-876  258 条                  es  sec 990-1011  87 条
```

决定性证据（`_probe_bri40.py`）：同一语音 ID `v_bri_amd0010_000_0`
在 6 个记录里分别是日/英/法/德/意/西的**同一段台词**：

```
sec 47  建国以来、<R=祖国,ニカラグア>が自分達の意志で…
sec192  Since it was founded, my country has not once…
sec335  Depuis qu’il existe, mon pays n’a jamais pu…
sec488  Seit es gegründet wurde, konnte mein Land…
sec636  Fin dalla sua nascita, il mio paese non ha mai…
sec780  Desde su fundación, mi país nunca ha podido…
```

此前"按语音 ID 做跨段对齐"之所以被误判为证伪，是因为用了错误的分块边界。

* 记录头内确实**没有**语言字段（各块记录头逐字节同构），语言是**位置**属性；
* `lang_get_language_id()` @ 0x140027B40 仍给出 0=en 1=fr 2=de 3=it
  4=es,pt 6=ja 的编号，与本文件的块序一致（ja 在最前）；
* `dword_141495DE0` @ `sub_1405E07CB` 是 **TOPIC -> 请求字** 表，运行时由
  `sub_14025A6C0` 从脚本 token 流填充（token 类型 3918807 = 0x3BCB57），
  **不是**语言索引——这条线索是死路，勿再追。

`Record.lang` 取块表；`Record.lang_by_text` 用停用词词频独立判定，
两者不一致时 `Record.lang_conflict` 为 True（本文件仅约 2%）。

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
两套解码器（**不可混用**）
~~~~~~~~~~~~~~~~~~~~~~~~~~
* ``sub_1400A4770``（已更名 ``briefing_insn_operand``）——解释器主循环用的
  **操作数/长度**解码：``op & 0xF`` 为 0..12 时即长度，13/14/15 分别表示后随
  u8 / u16 / u24。它**不认识** ``0x07``（字符串字面量）。
* ``sub_1400A4B40``（已更名 ``briefing_insn_decode``）——**完整**指令解码，
  用于表达式与实参区。多出：``op & 0xC0 == 0xC0`` 是 1 字节；``op & 0xF0 == 0``
  时按低操作码表取长度，其中 ``0x07`` = 后随 u8 长度的字符串字面量。

字节码遍历**必须**用后者，否则一遇到 ``0x07`` 就失步（实测：改用完整规则后
能解出 0x6d 的记录从 8 条涨到 843 条）。

解释器 ``sub_1400A35C0``（``briefing_script_run``）按 ``op & 0xF0`` 分派：

* ``0x30``：``acc = sub_14013CD90(payload)``。
  **``sub_14013CD90`` 不是文本取值器，而是 RPN 表达式求值器（栈机）**——
  它压入操作数，遇到 ``op & 0xE0 == 0xA0`` 的字节就按 ``op & 0x1F`` 取
  运算符（-、~、+、-、*、/、%、<<、>>、==、!=、<、<=、>、>=、|、&、^、
  ||、&&、!）作用于栈顶两项。
* ``0x60``：外部调用。``payload[0..2]`` = u24 处理器 id，在
  ``qword_141103DF0`` 表里查函数，实参由 ``sub_1400A53D0(payload+3, &n)``
  构造后调用。
* ``0x70``：按 id 调子程序（``sub_1400A3980`` 查表 -> 递归 ``sub_1400A35C0``）。

顶层结构（实测，记录 0）：入口 ``8e`` 包裹 -> ``6e``（外部调用，载荷 = 实参
RPN + C 串语音 ID）-> 再套 ``8e`` -> ``6e`` -> ``8e`` -> 一串 ``0x6d``。
故 ``0x6d`` 在**第 5 层**，遍历必须递归到至少这个深度。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import MT19937, name_hash, XOR_CONST

SECTOR = 4096
REC_MAGIC = b"\x6f\x45\x62\x4e"

#: 语言块表（_probe_bri44/45.py 取证）。(组, 语言, 记录起始偏移, 记录结束偏移)
#: 边界取实测的首尾记录偏移；块之间的填充区归入前一块。
LANG_BLOCKS = [
    (1, "ja", 0x000000, 0x07F280),
    (1, "en", 0x0944B0, 0x11F180),
    (1, "fr", 0x120270, 0x1B79B0),
    (1, "de", 0x1B8230, 0x24E2B0),
    (1, "it", 0x24F390, 0x2DF5B0),
    (1, "es", 0x2E0680, 0x36C900),
    (2, "ja", 0x36D0B0, 0x385540),
    (2, "en", 0x385620, 0x39A4D0),
    (2, "fr", 0x39C830, 0x3B1240),
    (2, "de", 0x3B1590, 0x3C8080),
    (2, "it", 0x3C83E0, 0x3DE0A0),
    (2, "es", 0x3DE3F0, 0x3F3230),
]

#: 语言判定的高频虚词表（_probe_bri43/44.py：块内逐记录一致率 96~100%）
_STOPWORDS = {
    "ja": "の に は を が と で も から まで です ます だ な か ね よ 私 俺 君 "
          "こと それ この その そう いる ある する れる".split(),
    "en": "the you and to of is that I a it in we for on be do not have with "
          "this what but they my me your".split(),
    "fr": "le la les de des un une est et vous nous je que qui pour dans pas "
          "il elle sur avec ne ce mais ou comme plus tout sont être avoir "
          "fait".split(),
    "de": "der die das den dem und ich nicht ist sind zu ein eine wir sie für "
          "auf mit es auch aber noch nur schon kann hat habe wird "
          "werden".split(),
    "it": "il lo la i gli le di a da in con su per tra fra che non più come "
          "ma se sono ho hai abbiamo questo quello mi ti ci vi del "
          "della".split(),
    "es": "el los las la de del un una que y en a con por para no es son lo "
          "se como pero más mi tu este esta hemos tengo su sus".split(),
}
_STOPWORDS = {k: [w.lower() for w in v] for k, v in _STOPWORDS.items()}
LANGS = list(_STOPWORDS)

#: 富文本标记 <R=表示,よみ> —— 振假名（ruby）
RUBY_RE = None  # 惰性编译，见 ruby()

__all__ = [
    "SECTOR", "REC_MAGIC", "LANG_BLOCKS", "LANGS", "Record", "Briefing",
    "load", "parse", "decrypt_sectors", "iter_records",
    "block_of", "judge_lang",
]


def block_of(off: int):
    """按文件偏移返回 (组, 语言)；落在块间填充区时归入前一块。"""
    best = None
    for g, lang, lo, hi in LANG_BLOCKS:
        if lo <= off <= hi:
            return g, lang
        if off > hi:
            best = (g, lang)
    return best if best else (None, None)


def judge_lang(text: str):
    """用停用词频独立判定语言 -> (语言, 各语言千分得分 dict)。

    仅作交叉校验用；权威来源是 :data:`LANG_BLOCKS`。
    """
    import collections
    import re
    ws = collections.Counter(re.findall(r"[^\W\d_]+", text.lower(), re.UNICODE))
    sc = {k: sum(ws[w] for w in v) for k, v in _STOPWORDS.items()}
    tot = sum(sc.values()) or 1
    sc = {k: v * 1000 // tot for k, v in sc.items()}
    return max(sc, key=lambda k: sc[k]), sc


# ----------------------------------------------------------------------
# 字节码
# ----------------------------------------------------------------------
#: ``0x6d`` 指令的处理器 id（逐行演出信息：行号 / 说话人 / 时间轴）
ID_CUE = 0x3B91EB

#: 载荷需要递归下钻的 opcode（包裹指令）
_WRAP_OPS = {0x8D, 0x8E, 0x6E, 0x6F, 0x7A, 0x87}


def _oper(data, i):
    """sub_1400A4770 的**操作数**解码 -> (长度, 载荷起点)。

    这条简化规则只适用于解释器 `sub_1400A35C0` 走的那条路径。遍历整段
    字节码必须用 `sub_1400A4B40` 的完整规则（见 :func:`_decode`）——
    否则遇到 op ``0x07``（后随 u8 长度的字符串字面量）就会失步。
    """
    lo = data[i] & 0x0F
    if lo == 13:
        return data[i + 1], i + 2
    if lo == 14:
        return struct.unpack_from("<H", data, i + 1)[0], i + 3
    if lo == 15:
        return (data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16), i + 4
    return lo, i + 1


def _decode(data, i, end):
    """sub_1400A4B40 的**完整**指令解码 -> (载荷起点, 下一条, 载荷长度)。

    | op 形态 | 长度 |
    |---|---|
    | ``op & 0xC0 == 0xC0`` | 1 字节（无载荷；``a3 = (op & 0x3F) - 1``）|
    | ``op & 0xF0 in {0x30,0x50,0x60,0x70,0x80}`` | 低 4 位 13/14/15 -> 后随 u8/u16/u24 长度，否则低 4 位即长度 |
    | ``op & 0xF0 == 0x40`` | 低 4 位 == 0xF 时 2 字节，否则 1 字节 |
    | ``op & 0xF0 == 0x90`` | 1 字节 |
    | ``op & 0xF0 == 0`` | 低操作码：0 终止；1/14 -> 3；2/3/4 -> 2；6/8 -> 4；**7 -> 2 + u8 长度**；9/10/13 -> 5；15 -> 9 |
    """
    op = data[i]
    if op & 0xC0 == 0xC0:
        return i + 1, i + 1, 0
    hi = op & 0xF0
    if hi:
        if hi in (0x30, 0x50, 0x60, 0x70, 0x80):
            lo = op & 0x0F
            if lo == 13 and i + 1 < end:
                n, p = data[i + 1], i + 2
            elif lo == 14 and i + 2 < end:
                n, p = struct.unpack_from("<H", data, i + 1)[0], i + 3
            elif lo == 15 and i + 3 < end:
                n = data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16
                p = i + 4
            else:
                n, p = lo, i + 1
            return p, p + n, n
        if hi == 0x40:
            return i + 1, i + 2 if (op & 0x0F) == 0x0F else i + 1, 0
        return i + 1, i + 1, 0          # 0x90 / 0x10 / 0x20 / 其它：1 字节
    if op == 0:
        return i + 1, i, 0              # 终止
    if op in (1, 14):
        return i + 1, i + 3, 0
    if op in (2, 3, 4):
        return i + 1, i + 2, 0
    if op in (6, 8):
        return i + 1, i + 4, 0
    if op == 7:                          # 字符串字面量：后随 u8 长度（含 NUL）
        n = data[i + 1] if i + 1 < end else 0
        return i + 2, i + 2 + n, n
    if op in (9, 10, 13):
        return i + 1, i + 5, 0
    if op == 15:
        return i + 1, i + 9, 0
    return i + 1, i + 1, 0


def walk_bytecode(data, start, end, depth=0, out=None, maxdepth=8):
    """递归遍历字节码。见 :meth:`Record.walk_script`。"""
    out = [] if out is None else out
    i = start
    while i < end:
        body, nxt, ln = _decode(data, i, end)
        if nxt <= i:
            break
        # 嵌套指令声明的长度偶尔会比父容器的边界多 1 字节（实测记录 0：
        # 外层 8e 声明 382 -> 终 0x78d；其内 6e 声明 378 -> 终 0x78a；
        # 再内的 8e 声明 361 -> 终 0x78b）。故钳到父边界，不要因此中断。
        if body > end:
            break
        if body + ln > end:
            ln = end - body
        nxt = min(nxt, end)
        out.append((i, data[i], ln, body, depth))
        if data[i] in _WRAP_OPS and depth < maxdepth and ln > 0:
            walk_bytecode(data, body, body + ln, depth + 1, out, maxdepth)
        i = nxt
    return out


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
    group: int = 0          # 所属语言块组（1 = v_bri 主体，2 = v_fop/v_myo）
    lang: str = ""          # 语言（权威：LANG_BLOCKS 位置判定）
    lang_by_text: str = ""  # 语言（交叉校验：停用词频判定）

    @property
    def n_lines(self) -> int:
        return len(self.lines)

    @property
    def lang_conflict(self) -> bool:
        """两种语言判据是否不一致（本文件约 2%，多为无实词的短记录）。"""
        return bool(self.lang and self.lang_by_text
                    and self.lang != self.lang_by_text)

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

    # ------------------------------------------------------------------
    # 脚本字节码
    # ------------------------------------------------------------------
    def walk_script(self, data: bytes, maxdepth: int = 8):
        """递归遍历脚本字节码，返回 [(偏移, opcode, 长度, 载荷起点, 深度)]。

        必须递归：``0x6d`` 指令不在顶层，而是嵌在 ``0x6e`` 的载荷里，
        外面还包着 ``0x8d``/``0x8e``（`sub_1400A4B40` 的 case 0x80）。
        长度解码见 :func:`_decode`。

        起点是 **``entry_off``（`A->entry`）而不是 ``script_off``（`A->pool`）**：
        解释器 `sub_1400A3040` 取的就是 entry；pool 开头的 4 字节是数据，
        从那里起步会立刻撞上 ``0x00`` 终止符。
        """
        start = self.entry_off if self.entry_off > 0 else self.script_off
        return walk_bytecode(data, start, self.script_end(data),
                             maxdepth=maxdepth)

    def cues(self, data: bytes):
        """从 ``0x6d`` 指令抽出逐行演出信息 -> [(行号, 说话人 ID, 起, 止)]。

        ``0x6d`` = op ``0x60`` + u8 长度（外部调用），处理器 id 为 u24
        ``0x3B91EB``。载荷 = ``[u24 id][args...]``，args 布局（实测 20 字节）：

        ```
        args[0..1] = 07 06            常量前缀
        args[2..5] = 说话人 ID (u32)  高字节恒 0x0e；同一说话人重复出现
        args[6]    = 行号（0 起）      100% 命中（_probe_bri49.py [4]）
        args[7]    = 00
        args[8..11]= 5a 69 26 b2      全文件常量
        args[12,13]= 01 01
        args[14,15]= 开始时刻 u16 LE  与上一行的「止」严格相等
        args[16]   = 01
        args[17,18]= 结束时刻 u16 LE
        args[19]   = 00
        ```
        """
        out = []
        for off, op, ln, body, depth in self.walk_script(data):
            if op != 0x6D or ln < 23 or body + ln > len(data):
                continue
            p = data[body:body + ln]
            if (p[0] | p[1] << 8 | p[2] << 16) != ID_CUE:
                continue
            a = p[3:]
            if len(a) < 20:
                continue
            out.append((
                a[6],                                        # 行号
                a[2] | a[3] << 8 | a[4] << 16 | a[5] << 24,  # 说话人 ID
                a[14] | a[15] << 8,                          # 起
                a[17] | a[18] << 8,                          # 止
            ))
        out.sort(key=lambda x: x[0])
        return out

    def ruby(self):
        """台词里的振假名标记 ``<R=表示,よみ>`` -> [(表示, よみ)]（去重保序）。"""
        global RUBY_RE
        import re
        if RUBY_RE is None:
            RUBY_RE = re.compile(r"<R=([^,>]*),([^>]*)>")
        seen, out = set(), []
        for t in self.lines:
            for disp, yomi in RUBY_RE.findall(t):
                if (disp, yomi) not in seen:
                    seen.add((disp, yomi))
                    out.append((disp, yomi))
        return out


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
    # 回填 end：下一条记录起点。
    # 注意**不能**按扇区截断——扇区只是磁盘上的加密单元，解密后文件是
    # 连续字节流，记录可以（且确实会）横跨多个扇区。早期的扇区截断会让
    # 大记录的脚本字节码被砍掉，实测只有 6 条记录能解出完整的 0x6d 序列，
    # 去掉截断后是 81 条（_probe_bri49.py）。
    for i, r in enumerate(recs):
        r.end = recs[i + 1].off if i + 1 < len(recs) else len(buf)
    # 回填语言：权威来源是 LANG_BLOCKS 的位置归属，再用停用词频独立判定
    # 一次作为交叉校验（_probe_bri44.py：块内一致率 96~100%）
    for r in recs:
        r.group, r.lang = block_of(r.off)
        r.lang_by_text = judge_lang("\n".join(r.lines))[0]
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

    from . import config

    ap = argparse.ArgumentParser(description="PWSF BRIEFING / CODEC 提取")
    ap.add_argument("dat", nargs="?", default=str(config.BRIEFING_DAT))
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

    print("\n语言块分布（权威 = LANG_BLOCKS 位置归属）")
    for lang in LANGS:
        for g in (1, 2):
            grp = [r for r in br.records if r.lang == lang and r.group == g]
            if not grp:
                continue
            print(f"  组{g} {lang}  记录 {len(grp):4d}  "
                  f"sec {grp[0].sector:4d}-{grp[-1].sector:4d}  "
                  f"行 {sum(r.n_lines for r in grp):6d}")

    conf = [r for r in br.records if r.lang_conflict]
    print(f"\n两种语言判据冲突：{len(conf)} / {len(br.records)} 条"
          f"（{len(conf)*100//max(1,len(br.records))}%）")

    print("台词总数：", sum(r.n_lines for r in br.records))
    nv = sum(1 for r in br.records if r.voice_ids(br.data))
    print("含语音 ID 的记录：", nv)
    nc = sum(1 for r in br.records if r.cues(br.data))
    print("含 0x6d 演出信息的记录：", nc)
    nr = sum(len(r.ruby()) for r in br.records)
    print("含 <R=> 振假名的记录：", nr)

    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="") as f:
            f.write("group\tlang\tsector\toff\tidx\tline\t"
                    "t_start\tt_end\tspeaker\tvoice_ids\ttext\n")
            for r in br.records:
                vids = "|".join(sorted(set(r.voice_ids(br.data))))
                cue = {c[0]: c for c in r.cues(br.data)}
                for i, t in enumerate(r.lines):
                    t1 = (t.replace("\\", "\\\\")
                           .replace("\n", "\\n").replace("\t", "\\t"))
                    c = cue.get(i)
                    ts, te, sp = (c[2], c[3], f"{c[1]:#010x}") if c else ("", "", "")
                    f.write(f"{r.group}\t{r.lang}\t{r.sector}\t{r.off:#x}\t"
                            f"{r.idx}\t{i}\t{ts}\t{te}\t{sp}\t{vids}\t{t1}\n")
        print("已写出：", a.out)
