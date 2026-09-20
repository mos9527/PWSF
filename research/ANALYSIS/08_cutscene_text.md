# 08 · 过场（comic cutscene）文字 —— 已在 `SLOT.DAT` 里找到

状态：**XOR 已破，容器已全量解压**。载荷上叠了**两层**异或：

1. `buffer_xor_decrypt(v5, B << 12, name_hash("002aba34"))` —— 一直都对的那一层
2. 一层 LCG 掩码，`s ← 48828125 * s + inc`（`48828125 == 5**11`），
   状态由 **`SLOT.KEY` 的头 12 字节**派生（§5.5）

2,137 条记录 **2,137 条全部解压成功**（`_probe_slot19.py`）。截图里那句台词就
在**记录 1874**，见 §5.7。剩下的活儿是把资源条目的结构定下来并导出语料（§8）。

实现在 `pwsf/slotdat.py`。

---

## 1. 现象

2026-09-18 实机截图（暂停覆盖层下的漫画过场）同时出现两段英文：

| 位置 | 文字 | 字形 |
|---|---|---|
| 气泡（漫画分镜内） | `THEY'RE WILLING TO GIVE US AN OFFSHORE PLANT - A PLACE WE CAN FINALLY PUT DOWN SOME ROOTS.` | 漫画手写体，全大写 |
| 画面底部 | `They're willing to give us an offshore plant` | 游戏正文字体 |

同屏的暂停对话框 `The game is currently paused.\nSkip the cutscene and proceed?`
**在 olang 里**（`MLG/Text/009c9ea4.olang`，group `0x3ced95` / entry `0x155479`），
所以过场本身的两段文字并不是 olang 的疏漏——它们来自别处。

---

## 2. 已导出语料全部落空

| 语料 | 行数 | `offshore` / `some roots` / `willing to give` |
|---|---:|---|
| `_dump_olang.tsv`（17 个 olang 文件全量） | 137,358 | 0 |
| `subtitle_ingame.tsv` | 4,128 | 0 |
| `_briefing_lines.tsv`（BRIEFING.DAT 全部 1,011 扇区） | 24,438 | 只有一条**不同的**台词：`v_fop_kaz_1580_000_0` "…cooped up on an offshore plant all day" |

olang 侧无漏网：`_dump_olang.tsv` 的来源文件恰好等于磁盘上全部 17 个
`.olang`（`MLG/Text` 14 个 + `EXLANG/Text` 3 个）。

---

## 3. `g_mount_table` —— 哈希文件名的明文对照表（**本轮新解**）

`g_mount_table` @ `0x140e9d6e0`，**208 字节/槽**；
基址指针 `g_mount_table_ptr` @ `0x140ea4220`。

字段：`+0x00` 文件名（磁盘上是哈希名），`+0x20` 目录。

槽 0..21 是零售 disc0 的一套，槽 22..43 **用同样的布局重复一遍，但写的是
`host0:` 调试名**——这就是哈希名的明文对照：

| 槽 | 磁盘文件 | 调试名 | 内容（本轮实测） |
|---:|---|---|---|
| 0 | `009645fa.PDT` (511 MB) | `STAGEDAT.PDT` | 关卡数据；557 条目，`mtsq/mtfa/mtar/gcx/dar/qar/psq/cnf`… |
| 1 | `002aba34.DAT` (544 MB) | `SLOT.DAT` | 见 §5 |
| 3 | `0001112d.PDT` (105 MB) | `BGM.PDT` | Ogg Vorbis |
| 4 | `00b2b2a8.PDT` (279 MB) | `VOICEBF.PDT` | Ogg Vorbis（briefing 语音） |
| 5 | `00b2b4b6.PDT` (82 MB) | `VOICERT.PDT` | Ogg Vorbis（realtime 语音） |
| 6 | `00b2b475.PDT` (2.8 MB) | `VOICEPS.PDT` | Ogg Vorbis |
| 13 | `002aba34.KEY` (42,752 B) | `SLOT.KEY` | `SLOT.DAT` 的索引，见 §4 |
| 14 | `0076531d.DAT` (4 MB) | `BRIEFING.DAT` | CODEC / 简报，见 03 号文档 |

步长的硬证据：`slotdat_load_and_verify` @ `0x1400A6290` 三处调用
`name_hash(g_mount_table_ptr + 208)`，而 `briefing_dat_load` @ `0x1400A5570`
（`0x1400A5656`）用 `g_mount_table_ptr + 0xB60 = +208*14`，两者分别落在
`002aba34.DAT` 与 `0076531d.DAT` 上，与上表一致。

整个 bank 按地区/语言版本重复若干遍（`0x140e9faa0` 起是第二遍）。

> 旧文档只在速查表里顺带提过 "SLOT.DAT / STAGEDAT.PDT"
> （`PLANS/00_overview.md` §磁盘速查、`01_olang_text.md` §1），
> 没有给出槽位对照，也没有给出证据。本节补上。

---

## 4. `SLOT.KEY` 索引 —— **已打通**

解密：普通的 `buffer_xor_decrypt`，`key = name_hash("002aba34") = 0x1E62A92B`
（与 olang / 归档同一套，见 `00_overview.md`）。

布局（42,752 字节，无余数）：

```
+0x00   12 B   头  ba be 9e c7 b1 c1 41 df b9 43 6a b0
+0x0c   20 B   × 2137 条记录
```

记录是**位域打包**的，不是四个 u16：

| 偏移 | 类型 | 含义 |
|---|---|---|
| `+0x00` | u32 | 低 20 位 = 起始扇区；高 12 位 = `A` |
| `+0x04` | u32 | 低 20 位 = 结束扇区；高 12 位 = `B` |
| `+0x08` | u32 | 哈希（条目标识） |
| `+0x0C` | u32 | `A` 的完整副本 |
| `+0x10` | u32 | `B` 的完整副本 |

自洽校验（`_probe_slot5.py`，2,137 条）：

```
start[i+1] == end[i]              2136 / 2136
end[last] == 132948               == 002aba34.DAT 的扇区数（544,555,008 / 4096）
+0x10 == 高 12 位 of +0x04        2137 / 2137
+0x0C == 高 12 位 of +0x00        2135 / 2137
A >= B                            2137 / 2137
B == end - start                  1748 / 2137
sum A = 312,775 扇区（1222 MiB）   sum B = 119,500 扇区（467 MiB）   比 2.62
```

> 起止扇区必须按 **20 位**读：扇区号最大 132,948，按 u16 读会在 65535 处截断，
> `end[last]` 就对不上文件大小。20 位读法下 `end[last]` 与文件扇区数**精确相等**，
> 这是布局正确的决定性判据。

**A / B 的含义已由 §5.4 证实**（不依赖密钥）：`B` = 存储（压缩后）扇区数，
`A` = 解压后扇区数，`end - start - B` 是扇区对齐的填充。

**已解释（本轮）**：`+0x0C` 与 `+0x00` 高 12 位在 2 条记录上不一致 ——
`A` 只有 12 位，这两条是**超过 4095 扇区的大记录**，`+0x00` 装不下就截断了，
`+0x0C` 那份完整副本才是真值：

| 记录 | `+0x00` 高 12 位 | `+0x0C` 副本 | 差 | 解压后大小 |
|---:|---:|---:|---:|---:|
| 1764 | 1759 | 5855 | 4096 | 23,982,080 = 5855 × 4096 |
| 1847 | 1095 | 5191 | 4096 | 21,260,880 ≤ 5191 × 4096 |

（`_probe_slot19.py`。这也顺带解释了 §5.4 里 `dec[0x0f]` 有 2 个取值的现象：
这两条的解压后大小越过了 2²⁴。）

---

## 5. `SLOT.DAT` 载荷 —— 格式已解，XOR 密钥未解

### 5.1 读取链（IDA）

```
slotdat_load_and_verify @ 0x1400A6290    校验：解头 → zlib uncompress → 比对大小
slotdat_stream_pump    @ 0x1400A56D0    状态机 0..4，按 4096 字节页 memmove
slotdat_stream_load    @ 0x1400A6560    状态机 0..3，真正发起读
slotdat_stream_read_more @ 0x1400A68A0  续读下一页
   └ io_submit_slot_read @ 0x14008B1D0
       └ io_cmd_slot_read @ 0x140120970   → io_cmd_build(cmd=16) → io_cmd_submit
           └ io_cmd_dispatch @ 0x14045D600  case 0x10
```

`slotdat_stream_load` 状态 1 的调用把记录的三个字段一次性交给 IO：

```
dest, start(记录起始扇区), B(存储扇区数), A(解压后扇区数),
解压上下文, 记录哈希, flags, key = name_hash(g_mount_table_ptr + 208)
```

### 5.2 载荷 = XOR ⊕ **zlib inflate**

`sub_14011A030` 建的对象由 `sub_14045B030(v, "1.2.3.f_pw", 88)` 初始化
（要求首字节 `'1'`、长度 88、`windowBits = 15`、窗口在 `+1352`、
状态申请 9544 字节），配合二进制里的
`" inflate 1.2.3 Copyright 1995-2005 Mark Adler "`（`0x140d72ca0`）——
就是 zlib。`sub_14045B490` 是 `uncompress`，`sub_140119F10` 是 `inflate`。
**载荷是压缩的**，§4 的 A/B 假设成立。

### 5.3 记录头（16 字节）

```
+0x00  u16   常量
+0x02  u16   头长度            slotrec_hdr_size @ 0x140119EB0
+0x04  u32   常量
+0x08  u32   压缩后大小        slotrec_comp_size @ 0x14002A530
+0x0C  u32   解压后大小        slotrec_raw_size  @ 0x140037CB0
+0x10        zlib 流
```

判读依据：`slotdat_load_and_verify` 里
`v15 = *(u32*)(v5+12)` 与 `slotrec_uncompress_checked(v5 + hdr, comp, dst, dstlen)`
的返回值比较，而后者是 `zlib_uncompress(dst, &dstlen, src, srclen)` 成功后
写回的**实际解压字节数**——所以 `+0x0C` 是解压后大小，`+0x08` 是它的源长度。

### 5.4 KEY 的 A/B 与记录头的对应 —— **无关键据**

每条记录都用**同一条**、从记录偏移 0 起始的密钥流（证据：全部 2137 条记录的
前 8 个密文字节完全相同）。于是对任意两条记录 i、j 和任意字节 p：

```
plain_i[p] ^ plain_j[p] == cipher_i[p] ^ cipher_j[p]
```

**密钥是什么都成立**，所以可以在不知道密钥的前提下验证结构。
`_probe_slot12.py` 对全库 2137 条记录的逐字节取值数：

| 字节 | 00 01 02 03 04 05 06 07 | 08 | 09 | 0a | 0b | 0c | 0d | 0e | 0f | 10 11 | 12… |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 取值数 | 全 1 | 256 | 252 | 56 | 1 | **16** | 251 | 85 | 2 | 全 1 | 35→246 |

* 00–07 恒定 → 头的前 8 字节是常量
* 08..0b 的低字节全变、高字节恒定 → 一个 < 16 MiB 的大小字段
* 0c..0f 同理；**0x0c 只有 16 个取值** ⇒ 解压后大小恒为 16 的倍数
* **10、11 恒定** → 头长度是 16，zlib 流从 `+0x10` 起（首两字节恒定）

与 KEY 记录交叉验证（`_probe_slot10.py` / `_probe_slot12.py`，全 2137 条）：

```
dec[0x0a] ^ (((B*4096) - 16) >> 16)   == 0x1f    唯一值
dec[0x0b]                              == 0x6f    唯一值（压缩大小 < 16 MiB）
dec[0x0e] ^ (A >> 4)                   == 0xba    唯一值（取 A & 0xF != 0 的记录）
dec[0x0f]                              ∈ {0xe6, 0xe7}
```

即 `+0x08 ≈ B*4096 - 16`、`+0x0C ∈ ((A-1)*4096, A*4096]`。
**`B` = 存储扇区数、`A` = 解压后扇区数，至此不是假设而是实测。**

### 5.5 第二层 XOR —— LCG 掩码（**已解**）

前面那张"已被排除"的表**每一条都对，但方向错了**：密钥确实就是
`name_hash("002aba34")`，问题是载荷上还叠了**第二层**异或。

链路（IDA）：

```
slotdat_stream_load @ 0x1400A6560 状态 1
    → io_submit_slot_read(..., v17 = sub_14008AE50(), ...)   ← 多出来的这个参数
io_cmd_dispatch @ 0x14045D600 case 0x10
    v28 = *(cmd + 40);                 // slotdat_keyctx() 的返回值
    *(file + 204) = *(qword *)v28;     // [0] = LCG 状态, [4] = 增量
    *(file + 212) = v28[2];
    *(file + 8) |= *(file + 208) ? 0x40 : 0x100;
```

`0x40` 正是 `entry_payload_transform @ 0x140123E90` 的 LCG 支路：

```
for each dword:  *(u32 *)p ^= state;  p += 4;  state = 48828125 * state + inc;
```

而 `sub_14008AE50()`（已更名 `slotdat_keyctx`）只有一句
`lea rax, xmmword_1410C7A10+0Ch` —— 正是
`slotdat_key_load @ 0x14008B330` 把 `SLOT.KEY` 的 12 字节头读进来、**就地**
用 `name_hash("002aba34")` 解开的那块静态缓冲。于是：

```
d0, d1, d2 = SLOT.KEY 解开头 12 字节的三个 u32 = c79ebeba, df41c1b1, b06a43b9
             （密文 d6 8d ef bb e7 c3 98 8c 26 73 12 ab）
v     = d1 ^ d0                                  ← packfile_derive_xor_key @ 0x140123DB0
state = v | ((v ^ 0x6576) << 16)   = 0x1aff7f0b
inc   = d2 * v                     = 0xa250aff3      （48828125 == 5**11）
```

> **是派生，不是直接存。** `sub_140123DB0` 本来服务于包文件头
> （`STAGEDAT.PDT` 之类走同一函数），SLOT 这条路径复用了它。
> 直接把 `(d0, d1)` 当 (state, inc) 解是错的 —— `_probe_slot16.py` 有实测。

验证（`_probe_slot17.py`：20 组候选 × 8 个相位，唯一命中）：

```
LCG 流 bytes[8..17]    = 5d ac 1f 6f 3c 92 ba e6 bf 35
§5.4 无关键据实测修正量 =       1f 6f       ba e6            ✔ 四个字节全中
dec[0x10..0x11] ^ (bf,35) = 78 da                            ✔ zlib 头
```

两层都是纯异或、可交换，且每条记录都从记录偏移 0 起用同一条流 ⇒ 合成一条
密钥流、生成一次、按长度切片即可。实现：`pwsf/slotdat.py`。

> 顺带排掉一个假线索：`entry_payload_unmask @ 0x140124000` 名字像第二层，
> 实际只累加 CRC（`dword_1409BEE20` 表 + `0x3FC47CDA`），**不写回缓冲区**，
> 是校验不是变换。

#### 旧记录：曾经以为是"密钥流不同"（保留推翻依据）

上一版把宝全押在"换一个 MT 种子"上，穷举了这些，**全部 0 命中**
（`_probe_slot8/9/10/11/12/13/14.py`，判据统一为
`u16@+2 ∈ [8,512]` 且 `0 < comp ≤ B*4096` 且 `(A-1)*4096 < raw ≤ A*4096`）：

| 候选 | 数量 | 命中 |
|---|---:|---:|
| `name_hash("002aba34")` | 1 | 0 |
| 二进制内全部字符串的 `name_hash` + 磁盘上全部文件名 | 44 632 | 0 |
| 同一密钥流的起始输出下标（不同 `mt_advance`）0..300 000 | 300 001 | 0 |
| 起始下标 × 未知异或常量（0..2^20，16 位一致性 + 头长度） | 2^20 | 0 |
| 第二层 `name_hash` 异或（44 632 × advance 0/5） | 89 264 | 0 |
| `SLOT.KEY` 头三个 u32 / 记录哈希 / 0 / 1 / `~key` / `XOR_CONST` | 6 | 0 |
| 同一密钥流的字节移位 s ∈ [1, 8 MiB]（`_probe_slot14.py`） | 8 M | 0 |
| LCG 参数代数反解，`k0=0`（`_probe_slot15.py`） | 65 536 | 0 |

**推翻依据**：这些搜索全都是在"只有一层异或"的前提下做的，所以它们真正
证明的是「不存在能单独解释载荷的 MT 流」。载荷的 `dec` 与正确明文差的那 4
个字节（0x1f/0x6f/0xba/0xe6）**不是**任何 MT 流的片段，而是 LCG 的 `s2`/`s3`
—— 换了搜索空间才命中。

`_probe_slot15.py` 其实已经走到了门口：它纯用数据（不碰 IDA）把 LCG 参数
代数反解出来，唯一候选就是

```
flg=0xda  s0=0x1aff7f0b  s1=0xa0d6f672  s2=0x6f1fac5d  s3=0xe6ba923c
          inc=0xa250aff3
```

与后来从 `packfile_derive_xor_key` 读出来的值**一模一样**。它当时报 0 命中
纯粹是判据写死了 zlib 魔数 `78 9c`，而真值是 `78 da`（该判据已修）。
**数据侧反解与代码侧读值互证** —— 这条链路现在是双保险的。

### 5.6 解压后槽位的内容

`slotdat_find_res_entry @ 0x1400A61F0` 说明解压后的槽里有一张资源表。逐字
对一遍反编译（`v1 = *(a1+16)` 是解压后缓冲）：

```
u32  @ +0            条目数 count
条目 @ +8            每条 16 字节（4 个 dword），不是 +4
     dword0  id
     dword2  偏移 & 0x3FFFFFFF（相对数据区）
数据区 = base + ((16*count + 4103) & ~0xFFF)     4096 对齐
筛选   : id != 0 且 (id & 0xFF000000) != 0x7F000000 且 (id & 0x7F000000) == 0x20000000
命中后 : slotdat_parse_res_entry(data + (entry[2] & 0x3FFFFFFF), id, a1)
```

漫画过场的文字就在这张表里（§5.7）。注意 §5.6 的筛选条件在记录 1874 上
一个都没命中，但文字确实在条目里 —— 这条筛选大概是挑"需要安装"的那类
资源，而不是穷举，别拿它当枚举条件。

---

### 5.7 过场台词的位置（**本轮结果**）

`_probe_slot19.py` 全量解压 2,137 条记录后按原句 grep，命中**记录 1874**：

```
rec 1874  start=108442 end=108448 A=13 B=6  id_hash=0x7ae85cf8
    解压后 51,200 字节，9 个资源条目，数据区在 +0x1000
    条目 id=0x5da82688  off=0x1e10  → 绝对 +0x2e10
      +0x457e  "They're willing to give us an offshore plant "
      +0x49fe  "a place we can finally put down some roots. \nThis is our chance to expand MSF."
```

三段都对上了截图：气泡里的
`THEY'RE WILLING TO GIVE US AN OFFSHORE PLANT - A PLACE WE CAN FINALLY PUT DOWN SOME ROOTS.`
就是这两条串起来的（大写是漫画字体自己转的），底部那行
`They're willing to give us an offshore plant` 是**第一条串的前半** ——
即气泡文字与底部字幕**同源**，不是两套语料。

储存形态是 NUL 分隔的字符串池（一个条目一池），典型的一段：

```
…\x00\x00Then perhaps I should call you John?\x00\x00They're willing to give us an offshore plant \x00
Thus surpassing her to become the hero\nknown as Big Boss.\x00Toppling the pro-American Somoza regime.\x00…
```

同一条记录里还混着别的东西（"Voiceprint analysis"、"Sandinista National
Liberation Front"），所以这池子是该段过场**共用**的文案表，不是逐句字幕。

> `offshore` 全库共 21 处命中，分布在记录 24/28/30/36/66/84/88/90/94/1863/
> 1874/2075，其中一批是「Mother Base is an offshore plant…」的 UI 说明文，
> 只有 1874 是过场台词。别拿关键词直接导出，先看记录。

---

## 6. 已排除的去处（逐个实测）

| 容器 | 实测内容 | 命中 |
|---|---|---|
| 17 个 `.olang` | UI / 游戏内字幕 | 0 |
| `BRIEFING.DAT` | 2,049 记录 / 24,438 行，1,011 扇区全覆盖 | 0 |
| `ADEMO/*.pdt` 35 个 | **231 个 `la3`（音频）+ 35 个 `txp`（贴图），无文本条目** | 0 |
| `BGM/VOICEBF/VOICERT/VOICEPS` 4 个容器 | 3,217 个 `bgp` 条目，解密后全是 `SP?\0` 头 + `OggS`/`vorbis`，带 `251922 PW_EN` 之类标签 → **语音音频** | 0 |
| `MMV00000.PDT` 的 `SUBTITLE` 条目 | 该文件根本不在磁盘上（见 02 号 §6.1 与本文 §7） | — |
| **`SLOT.DAT`** | 2,137 条记录，2,137 条全部解压（本轮） | **过场台词在记录 1874（§5.7）** |

`ADEMO` 只有贴图和音频这一条很关键：漫画分镜的**气泡文字要么烘焙进 `txp`，
要么来自别的容器**，两种都还没证据，不要下结论。—— 现在有证据了：气泡文字
是**文本**，在 `SLOT.DAT` 里，不是贴图。

---

## 7. 对 02 号 §6.1 的收窄

02 号文档 §6.1 的结论是「影片字幕在 Steam 版不可提取，因为数据不存在」。
**该结论本身没错但范围过宽**：它证明的是
「归档里没有名为 `SUBTITLE` 的条目，`MMV00000.PDT` / `BKD00000.PDT` 未随包发布」。

本轮截图证明**过场底部字幕实机确实在显示**，所以
「过场字幕的数据不存在」是错的——数据存在，只是不走
`subtitle_load_resources` @ `0x14026BDE0` 那条 `SUBTITLE` 通路。
02 号已加 §6.4 记录这次收窄。

---

## 8. 下一步

~~1. 解掉 `SLOT.DAT` 的额外变换。~~ **已完成（§5.5）。**
~~2. 导出过场语料。~~ **已完成（§7）。**

1. **写回**：`pwsf.slotdat_build` 还不存在，但路已经探明并有实测数据，
   见 `research/PLANS/08_cutscene_writeback.md`。两条路的结论：

   | 方案 | 结果 |
   |---|---|
   | 就地（池长度不变，尾部补零） | **29/43 张过场表放不下**，最坏 +1,462 B |
   | 重排池 + 重新压缩 + 重建容器 | **可行**，34 个记录里只有 9 个 `B` 变化，总账 **A +4 / B −9 扇区（文件小 36 KB）** |

   就地不行是硬约束：池长度由**下一个条目的 off** 决定，而池已经装到
   99.3%（`_probe_slot27.py`）。中文按字节算并不会更省——用现成的**日文
   副本**代跑（同为 CJK，3 字节/字），`ja/en` 字节比 **中位数 1.125**、均值
   1.687（`_probe_slot28.py`）。

   重排反而更小，是因为原池之间有 padding，紧凑重排 + `zlib -9` 省回来的
   比译文涨的多。
2. **`FEL\x07` 块**：过场记录里还有 181 个（§7.3），条目表是 8/12 字节交替，
   疑似分镜时间轴/字幕排版。解开它才能回答"哪条串进气泡、哪条走底部字幕"。
3. **`GTT\x00` 池**（462 个，全在记录 0..870 那半边）：另一种文本容器，
   池里是**后缀合并**的字符串（按 NUL 切开会出现 `n.` / `Cett` 这种碎片），
   首串是 `GTT`、接着 `01 00 00 00 / 0x38 / 0x65`。没解，不影响过场提取。
4. `STAGEDAT.PDT` 的 mode 0x40（`04_archive.md` §6 疑点 2）走的是同一个
   `entry_payload_transform` + `packfile_derive_xor_key`，派生输入换成它自己的
   40 字节包文件头 —— 按 §5.5 的套路应该也能开。

---

## 7. 语料（**本轮产出**）

### 7.1 SLOT.DAT 里装的是 .olang

`slotdat_parse_res_entry @ 0x14008CF10` 是"安装资源"那条路：读条目载荷的
`0x8000` 标志位、占一个槽位、再调 `sub_1400A59A0`，**压根不碰字符串**。所以
它回答不了"哪些条目是台词"。改从数据侧普查（`_probe_slot20.py`）：336 条记录
里有 707 个"NUL 分隔的可打印串池"，而每个池的**第一条串是容器魔数**——
`RBX\0`、`GTT\0`，或者干脆就是台词。

**`RBX\0` 就是 `01_olang_text.md` 那个格式。** 过场台词不是什么私有格式，
是 .olang 表被塞进了 SLOT.DAT —— 这才是磁盘上 17 个 `.olang` 永远搜不到它
的原因。

记录 1874 的 6 个池全是 `RBX\0`，且**表头逐字节相同**，只有字符串池不同：
同一张表的 6 种语言。

### 7.2 规模与去重

| | |
|---|---:|
| RBX 池总数 | 4,458（全部解析成功，0 失败） |
| 去重后 `(table_id, lang)` | 865 = **144 张表 × 6 语言** + 1 张非文本表 |
| 副本总数 | 4,680 |
| **副本内容不一致的** | **0** |
| 去重后英文行 | 15,469 |
| 其中过场（43 张表） | 1,928 |

同一张表在多个记录里各存一份（不同 region 构建）。**4,680 个副本两两比对
全部一致**（`_probe_slot23.py`，blake2b 摘要），所以引用只用 `table_id`，
写回时把所有副本一起打补丁。

语言键 `0x34bc87`（240 行，每张串都是 `b"\x01"`）不是文本，已排除。

### 7.3 过场的判定

两个判据**双向完全吻合**（`_probe_slot25.py`）：

| | 记录 0..1862 | 记录 1863..2137 |
|---|---|---|
| 池数 | 14,001 | 1,076 |
| 主要魔数 | `RBX` 4,188 / `MDPX` 2,399 / `Mtar` 965 … | `RBX` 270 / **`FEL\x07` 181** |
| 平均条目数/记录 | 7.5 | 3.9 |

* `table_id ∈ [0x003af000, 0x003b0a00)` 的表，**第一次出现都在记录 ≥ 1863**
* 记录 ≥ 1863 里出现的表，**`table_id` 全在这个窗口**

而且 §1 截图那句就在窗口内的 `0x003af54d`。尾部记录只有文本（`RBX`）和
`FEL\x07`，没有模型/贴图——漫画画面本身在别处（`STAGEDAT.PDT`），这正是
"过场记录"该有的样子。

判据落在 `pwsf.slotdat.is_cutscene()`。**它是启发式**：两条证据互相印证且
内容全是叙事对话，但还没拿到 IDA 侧的确认（二进制里没有 `comic` /
`cutscene` 字样，`0x140FD2E30` 附近的 `SEXCOMICS` 属于脏话过滤词表）。

### 7.4 产物

| 文件 | 内容 |
|---|---|
| `research/ANALYSIS/_slot_olang_lines.tsv` | 全量 91,793 行（144 张表 × 6 语言） |
| `research/ANALYSIS/_cutscene_lines.tsv` | 过场 11,215 行（43 张表 × 6 语言） |

列：`table_id / lang / group / entry / meta / record / locations / text`
（`locations` 是所有副本的 `记录:池id`，用 `;` 分隔，写回时照着改）。

导出 .po（**默认已开启**，`--slot none` 可关）：

```
python -m pwsf.po_export                 # olang + codec + slot(all)
python -m pwsf.po_export --slot cutscene # 只过场 1,927 slots -> 1,858 条
```

默认跑出来 src 下 42 个 .po / 16,332 条（其中 slot 10,073 条）。
重新导出会**保留已有译文**（`existing_translations()` 按 msgid 回填，
`--fresh` 可关）—— 否则每轮重导都会把已翻的扔掉。

引用语法 `slot/<table_id>/<group>/<entry>` 已进 `pwsf.slots.parse_ref()`，
`slot_sources()` 也就绪。**还没有写回**，见 `PLANS/08_cutscene_writeback.md`。

---

## 9. 复现

```powershell
cd d:\PWSF
python research\TOOLS\_probe_demo1.py   # ADEMO 条目类型普查 + grep
python research\TOOLS\_probe_demo2.py   # 全 disc0 容器的条目类型直方图
python research\TOOLS\_probe_demo3.py   # 3,217 个 bgp 解密 + grep（约 60 s）
python research\TOOLS\_probe_demo4.py   # bgp 内部结构（证明是 Ogg 语音）
python research\TOOLS\_probe_slot1.py   # SLOT.KEY / SLOT.DAT 解密模型 A/B
python research\TOOLS\_probe_slot2.py   # SLOT.KEY 首版解析（u16，已被 slot5 更正）
python research\TOOLS\_probe_slot3.py   # 预生成密钥流 → 全量扫 SLOT.DAT
python research\TOOLS\_probe_slot4.py   # SLOT.DAT 载荷密钥候选穷举（全否）
python research\TOOLS\_probe_slot5.py   # SLOT.KEY 位域布局与自洽校验（本文 §4）
python research\TOOLS\_probe_slot6.py   # 载荷 = XOR ⊕ zlib：首次试解（本文 §5.2）
python research\TOOLS\_probe_slot7.py   # SLOT.DAT 扇区 0 与密钥流取证
python research\TOOLS\_probe_slot8.py   # 密钥 × 扇区偏移网格（头自洽判据，全否）
python research\TOOLS\_probe_slot9.py   # 密钥流起始下标 0..300000 扫描（全否）
python research\TOOLS\_probe_slot10.py  # 无关键据：A/B 与记录头的交叉验证（§5.4）
python research\TOOLS\_probe_slot11.py  # 二进制全部字符串 + 全部文件名做密钥（全否）
python research\TOOLS\_probe_slot12.py  # 逐字节取值指纹 + 相位×常量搜索（§5.3/§5.4）
python research\TOOLS\_probe_slot13.py  # 第二层 name_hash 异或（全否）
python research\TOOLS\_probe_slot14.py  # 重测修正量 + 移位假设（全否）
python research\TOOLS\_probe_slot15.py  # LCG 参数代数反解（k0=0 全否）
python research\TOOLS\_probe_slot16.py  # SLOT.KEY 头当 (state,inc)：错，实测
python research\TOOLS\_probe_slot17.py  # 20 组候选 × 8 相位：**唯一命中**
python research\TOOLS\_probe_slot18.py  # 端到端：两层 XOR + zlib，全量 2137
python research\TOOLS\_probe_slot19.py  # 全量解压 + 过场台词定位（记录 1874）
python research\TOOLS\_probe_slot20.py  # 文本池普查：GTT / RBX 魔数
python research\TOOLS\_probe_slot21.py  # dump GTT / RBX 池头 + 记录 1874 全部池
python research\TOOLS\_probe_slot22.py  # 用 pwsf.olang 解析全部 RBX 池（含语言）
python research\TOOLS\_probe_slot23.py  # 去重 + 4,680 个副本一致性校验
python research\TOOLS\_probe_slot24.py  # 144 张表的清单
python research\TOOLS\_probe_slot25.py  # 过场区间验证 + 导出两份语料
python research\TOOLS\_probe_slot26.py  # FEL\x07 块初探（下一步）
python research\TOOLS\_probe_slot27.py  # 就地写回的余量：池已装到 99.3%
python research\TOOLS\_probe_slot28.py  # ja/en 字节比 —— 日文代跑只 14/43 放得下
python research\TOOLS\_probe_slot29.py  # 重排 + 重压：A +4 / B -9 扇区（可行）
```

实现在包里，探针只做取证：

```python
from pwsf import slotdat as S
recs  = S.load_index()                       # 2,137 条 KEY 记录
state, inc = S.lcg_params()                  # 0x1aff7f0b, 0xa250aff3
ks    = S.keystream(ndwords, state, inc)     # 两层合成
plain = S.decrypt(S.read_block(recs[1874]), ks)
data  = S.inflate(plain)                     # 解压后的槽
```

> `002aba34.DAT` 在游戏运行时被独占打开，探针会报
> `PermissionError`，退出游戏再跑。

## 10. IDA 符号更进（IDB 已保存）

### 第一版（2026-09-18）

| 地址 | 旧名 | 新名 |
|---|---|---|
| `0x140e9d6e0` | （无名） | `g_mount_table` |
| `0x140ea4220` | `off_140EA4220` | `g_mount_table_ptr` |
| `0x1400a6290` | `bigdat_load_and_verify` | `slotdat_load_and_verify` |

并在 `0x140e9d6e0` 与 `0x1400a6339` 写入注释，记录槽位对照与 208 字节步长。

### 第二版

| 地址 | 旧名 | 新名 |
|---|---|---|
| `0x140119eb0` | `sub_140119EB0` | `slotrec_hdr_size`（记录头 `+0x02` u16） |
| `0x14002a530` | `sub_14002A530` | `slotrec_comp_size`（记录头 `+0x08` u32） |
| `0x140037cb0` | `sub_140037CB0` | `slotrec_raw_size`（记录头 `+0x0c` u32） |
| `0x140119ec0` | `sub_140119EC0` | `slotrec_uncompress_checked` |
| `0x14011a030` | `sub_14011A030` | `zlib_inflate_alloc` |
| `0x140119f10` | `sub_140119F10` | `zlib_inflate_run` |
| `0x140119ff0` | `sub_140119FF0` | `zlib_inflate_free` |
| `0x14045b030` | `sub_14045B030` | `zlib_inflate_init_`（`inflateInit2_`，windowBits 15） |
| `0x14045b490` | `sub_14045B490` | `zlib_uncompress` |
| `0x1400a6560` | `sub_1400A6560` | `slotdat_stream_load` |
| `0x1400a68a0` | `sub_1400A68A0` | `slotdat_stream_read_more` |
| `0x1400a56d0` | `sub_1400A56D0` | `slotdat_stream_pump` |
| `0x1400a61f0` | `sub_1400A61F0` | `slotdat_find_res_entry` |
| `0x14008cf10` | `sub_14008CF10` | `slotdat_parse_res_entry` |
| `0x14008cc60` | `sub_14008CC60` | `slotdat_install_block` |
| `0x14008b1d0` | `sub_14008B1D0` | `io_submit_slot_read` |
| `0x140120970` | `sub_140120970` | `io_cmd_slot_read` |
| `0x140120a40` | `sub_140120A40` | `io_cmd_submit17` |
| `0x140120ac0` | `sub_140120AC0` | `io_cmd_submit16` |
| `0x14045df30` | `sub_14045DF30` | `io_cmd_build` |
| `0x14045d120` | `sub_14045D120` | `io_cmd_submit` |
| `0x14045d600` | `sub_14045D600` | `io_cmd_dispatch` |

注释：`0x1400a6290` 记记录头三个字段与「XOR ⊕ zlib」，
`0x14011a030` 记 zlib 版本串与 windowBits，三个 `slotrec_*` 记各自偏移。

### 挂载表补记

`g_mount_table` 是 **6 个 bank × 22 槽 × 208 字节 = 27 456 字节**，
区间 `0x140e9d6e0 .. 0x140ea4220`（`g_mount_table_ptr` 就在这个区间的末尾）。
bank 0/2/4 = `disc0:` 哈希名，bank 1/3/5 = `host0:` 调试名。
**6 个 bank 的槽 1 都是 `002aba34.DAT` 或 `SLOT.DAT`**，
所以 `name_hash` 只可能是 `0x1E62A92B`——§5.5 的排除是穷尽的。
（这条结论本身没错：第一层密钥确实只有它一个可能。错的是"只有一层"。）

### 第三版（本轮，XOR 破译）

| 地址 | 旧名 | 新名 |
|---|---|---|
| `0x14008ae50` | `sub_14008AE50` | `slotdat_keyctx`（返回 SLOT.KEY 解开头所在的静态缓冲） |
| `0x14008b330` | `sub_14008B330` | `slotdat_key_load` |
| `0x14008b580` | `sub_14008B580` | `slotdat_key_load_host0` |
| `0x140123db0` | `sub_140123DB0` | `packfile_derive_xor_key`（`v=d1^d0`；state\|inc） |
| `0x140123cc0` | `sub_140123CC0` | `lcg_xor_dwords`（`s = 48828125*s + inc`） |
| `0x14010f8b0` | `sub_14010F8B0` | `mt_seed_std`（`mt_seed` + `mt_advance(20)`） |
| `0x14010f5c0` | `sub_14010F5C0` | `buffer_xor_decrypt_cont`（复用已有 MT 状态） |
| `0x140121050` | `sub_140121050` | `io_read_complete_xform_cond` |
| `0x1401210b0` | `sub_1401210B0` | `io_read_complete_xform` |

注释写在 `0x14008ae50` / `0x140123db0` / `0x140123e90` / `0x1400a6290`，
记录派生公式与"两层 XOR + zlib"的结论。IDB 已保存。

### 第四版（语料轮）

新增认识但没有更名（`slotdat_parse_res_entry` 保持原名，它在 §7.1 里已被
证伪为文本解析路径）：

| 地址 | 结论 |
|---|---|
| `0x14008cf10` `slotdat_parse_res_entry` | 安装资源，不碰字符串；读条目载荷 `+0` 的 `0x8000` 标志，占 8 个槽位之一（每槽 24 字节 @ `qword_1410E7D18+131560`），再调 `sub_1400A59A0` |
| `0x140124000` `entry_payload_unmask` | CRC 累加（`dword_1409BEE20` + `0x3FC47CDA`），不写回缓冲 |
| `0x140d68230` / `0x140fd2e30` | `SEXCOMICS` —— 脏话过滤词表，**与过场无关**（别被它误导） |
