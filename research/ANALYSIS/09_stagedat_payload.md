# 09 · STAGEDAT（009645fa.PDT）payload 与内嵌文本表

起因：实机里 Miller 的无线电台词

```
There's no one around - why not try some shooting practice?
```

在**所有已提取语料里都找不到**。于是把「能搞到但没收集的语料」逐个预览了一遍，
顺带打通了 `009645fa.PDT`（明文名 `STAGEDAT.PDT`，487 MB / 557 条目）——
它是全盘唯一的 mode 0x40 容器，payload 此前解不了（`04_archive.md` §6.2）。

---

## 1 结论速览

| 来源 | 状态 | 有没有那句 |
|---|---|---|
| 17 个 `.olang`（137,358 行） | 已提取 | ❌ |
| `subtitle_ingame.tsv`（4,128 行） | 已提取 | ❌ |
| `0076531d.DAT` BRIEFING（24,438 行，完整明文也 grep 过） | 已提取 | ❌ |
| `002aba34.DAT` SLOT（144 表 / 91,793 行 / 6 语，完整） | 已提取 | ❌ |
| `009645fa.PDT` STAGEDAT 内嵌文本（**本次新挖 97,989 行**） | 本次打通 | ❌ |
| 主归档 `0001112d` / `00b2b2a8` / `00b2b475` / `00b2b4b6` | 音频 + 二进制，无文本 | ❌ |
| ADEMO / ADEMOHQ 任务包（6.4 GB，`FEL\x07`） | 二进制资源，抽样无文件名/文本 | ❌ |
| `ms0\EU\DLC*`（TEXT 道具说明 / BGM 元数据 / VOICE 音频） | 有少量英文，已看 | ❌ |
| 全盘 **21.4 GB 原始字节** | 明文直搜 | ❌（说明它是加密存的） |

**那句仍没找到。** 剩下的盲区只有：ADEMOHQ 的 `FEL` 容器（未破格式，抽样
不像文本）、SP/Ogg 纯音频包，以及「这句根本不在本盘数据里」的可能。

---

## 2 mode 0x40 的 payload 解扰（已破）

`entry_payload_transform` @ `0x140123E90`，mode 0x40 分支：

```c
v6 = *(u32*)(pkg + 196);          // 状态
v7 = *(u32*)(pkg + 200);          // 增量
for (每个完整 dword) { *p ^= v6; v6 = v7 + 48828125 * v6; }
*(u32*)(pkg + 196) = v6;          // 状态写回 —— 跨条目延续
```

写回提示「跨条目延续」，但实测**不是**：判据是条目自带的 CRC-32
（`entry.b == crc32(payload[:size & ~3])`，`04_archive.md` §4），三种候选：

| 候选 | 初值 | CRC 结果 |
|---|---|---|
| **A 每条独立，用派生值** | `s = hi^lo; state = s \| ((s ^ 0x6576) << 16); inc = m*s` | **6/6 通过** |
| B 从表尾继续、跨条目递推 | 表尾 state | 0/6 |
| C 只做 MT 层 | — | 0/6 |

派生式与头/索引/名字表用的 `sub_140123DB0` 完全相同，只是**每条重新播种**。
证据脚本：`_probe_stagedat.py`。

---

## 3 payload 里面是 zlib，zlib 里面是内嵌文件归档

```
payload -> buffer_xor_decrypt(name_hash(stem))
        -> LCG（上节）
        -> u32 + zlib(0x78 0xda)
        -> 内嵌文件归档
```

内嵌归档布局 —— **不是肉眼对齐出来的**，是穷举搜出来的
（`_probe_inner_layout.py`，判据：`count` 个文件 + 字节刚好吃满）：

```
u32  count
每项: name    NUL 结尾，然后 4 字节对齐
      u32     size
      data    从下一个 16 字节边界开始
      1 字节  0x00，不计入 size
```

搜过的组合：`pad ∈ {4,8,16}` × `extra u32 ∈ {0,1,2,3}` × `align ∈ {4,8,16,32}`
× `tail ∈ {0,1,nul}`，只有 `pad=4 extra=0 align=16 tail=1` 存活，且在
entry 1 / 7 / 11 / 15 / 23 / 27 / 31 上一致。

---

## 4 STAGEDAT 里装了什么

557 条目 → 92 个合法内嵌归档 / 465 个非归档（模型、音频、贴图）：

| 扩展名 | 数量 | 体积 | 内容 |
|---|---:|---:|---|
| `.la3` | 5,255 | 40.9 MB | UI 布局，少量文字（REGION 名、制作名单） |
| `.sep` | 1,372 | 502.1 MB | `SP` 容器，纯 Ogg 语音（无字幕轨） |
| `.mdp` | 1,102 | 7.3 MB | 模型 |
| **`.olang`** | **738** | **5.8 MB** | **RBX 文本表：97,989 条，其中 127,778 行（含重复）** |
| `.mtar` / `.mtsq` | 320 / 320 | 21.3 MB | 动画 / 序列 |
| `.ohd` | 284 | 2.3 MB | Spirit AI 数据；`spirit_lang_data_*.ohd` 是**明文台词表**（战斗喊话，156 条英文） |
| `.png` / `.eft` / 其他 | — | — | 图标、特效 |

内嵌 olang 表名 276 种（×6 语）：`lang_mission_info`（任务说明，含 Target
Practice 系列）、`lang_stagetelop`、`lang_briefing`、`lang_myouter_*`（Mother
Base 队员吐槽）、`lang_item_text`、`lang_weapon_text` 等。

**与 SLOT.DAT 的重合**：97,990 条里有 61.3% 与 `_slot_olang_lines.tsv` 相同
（同一批表，table_id 一致，如 `lang_stagetelop` == SLOT 表 `0x00147608`），
**10,570 条是 SLOT 之外的新文本**。

---

## 5 产物与用法

```
ANALYSIS/_stagedat_files.tsv     每个内嵌文件（含偏移/大小/魔数）
ANALYSIS/_stagedat_olang.tsv     每张内嵌 olang 的全部字符串（97,989）
ANALYSIS/_pkgscan_kinds.tsv      全盘每个 payload 的分类（4,647 条）
ANALYSIS/_pkgscan_files.tsv      全盘内嵌文件（9,054）
ANALYSIS/_pkgscan_olang.tsv      同上 olang 文本
ANALYSIS/_pkgscan_hits.tsv       needle 命中（本次为 0）
```

```powershell
python research\TOOLS\_probe_stagedat.py          # CRC oracle：证明 LCG 播种方式
python research\TOOLS\_probe_inner_layout.py 15   # 布局穷举（带条目号）
python research\TOOLS\_probe_stagedat_inner.py --container MLG/disc0_rel/009645fa.PDT \
                                              --dump-dir research\BUILD\x --dump-ext ohd
python research\TOOLS\_probe_pkg_scan.py --jobs 8 --skip-exlang   # 全盘 payload 分类 + 并行 + 日志
python research\TOOLS\_probe_pkg_peek.py "MLG\disc0_rel\009645fa.PDT" --zlib-text
python research\TOOLS\_probe_textscan.py --jobs 8 --filter disc0_rel  # 非容器文件（raw + name_hash）
```

---

## 6 IDA 侧的三条结论

1. **`olang_register_table` @ `0x14003add0`** 只拼 `MLG/Text/<name>.olang`
   （`lang_get_language_id()==6` 时拼 `JPN/Text/`），也就是只注册磁盘那 17 张表。
   IDB 里 `lang_*` 字面量只有 `kotodamaedit_lang__helptext` 和
   `charaedit_lang__suit_equip_help` 两个无关的 —— 所以内嵌表的名字**不是**
   二进制里的字符串，是运行时枚举归档得到的，IDA 无法直接列出「有哪些表」。
2. **`FEL\x07` 在 `.text` / `.rdata` / `.data` 里都搜不到**（`py_eval` 逐段
   `bytes.find`）。所以 ADEMOHQ 那 6.4 GB 不是 exe 拿这个魔数直接解析的，
   要么走了别的中间层，要么这批包在 Steam 版里根本没被读。
3. **BRIEFING 是完整的**：`pwsf.briefing` 解析出 2049 条记录、`problems` 为 0、
   字节覆盖 4,142,432 / 4,142,432（100%）。没有漏记录，也就不存在「藏在
   BRIEFING 里没导出的段落」。

## 7 顺带找到的：无线台字幕其实是**明文表**

`ms0\EU\DLCVOICE\171ae461.PDT`（= `AVD00000`）的 entry 1 解密后就是一个
定长、NUL 填充的多语言字幕表：

```
Lock disengaged. | Verrouillage dé… | Sperre gelöst. | Blocco disattivato. | Seguro desbloqueado.
Reinitializing platform. | Flamethrower engaged. | Launching S mines. | ...
```

四个 AVD 包（`171ae461` / `181ae463` / `191ae465` / `1a1ae467`）各一张，
47 KB / 24 KB / 18 KB / 20 KB。它们对应 `04_archive.md` §5 里
`subtitle_load_resources` 遍历的 85 个槽 —— `BKD00000`（`8b1ae97*`）按该节
的记录**未随包发布**，所以盘上只有这 4 张 DLC 的。

全盘明文 payload 扫描（`_probe_txt_payload.py`，判据：非零字节中 ≥90% 可打印，
只看前 64 KiB 因为两层解扰都是从偏移 0 开始的顺序流）：**73 个明文 payload，
全部在 `ms0\EU\` 的 DLC 里**，本体一个都没有。那句台词也不在其中。

## 8 还没破的

1. **`FEL\x07`（ADEMOHQ 6.4 GB / ADEMO 209 MB）**：任务包 payload，内部无文件名、
   无 RBX、无 zlib 头（只有零散 0x78da），形似压缩过的模型/音频资源。
   抽样 3 个容器 × 若干条目，无 `.olang` / `lang_` 字样。**没有证据表明它装文本。**
2. **`SP` 容器**（DLCVOICE、`.sep`）：头部 `SP`+版本，载荷就是 Ogg，没有文本子文件。
3. 那句台词本身：若它确实来自本盘，只可能在 1 里；下一步要么从 IDA 反查这条
   codec 条的文本来源函数，要么确认截图是否出自别的版本 / 打了别的 MOD。

---

## 9 §1/§8 的覆盖面补正（2026-09-21，**旧结论保留，覆盖缺口已填**）

§1 那张表的「ADEMO / ADEMOHQ ❌」和 §8.1 的「抽样无文本」都是**欠扫**的结论，
不是全量结论。判据：

| 旧扫描 | 上限 | 后果 |
|---|---|---|
| `_probe_pkg_scan.py --budget-mb 512 --max-entry-mb 256` | 每容器 512 MB、单条目 256 MB | 12 个巨型条目（259~518 MB）**从未解密** |
| `_probe_textscan.py --budget-mb 512 --max-entry-mb 128` | 单条目 128 MB | 同上，且更严 |
| 两者都带 `--skip-exlang` | — | **EXLANG 的 `0001112d` / `00b2b2a8` / `00b2b475` / `00b2b4b6` 四个包 0 条命中**（446 MB） |

实测（`_probe_fel_cover.py / _probe_gap.py`）：

```
任务包在盘上 6,635 MB | 从未检索 3,952 MB（60%），集中在 12 个条目
全盘容器 payload 7,617 MB | 从未进 _pkgscan_kinds.tsv 的 4,400 MB / 3,229 条目
```

补扫结果（纯 Python MT 5.6 MB/s，改用 **ProcessPoolExecutor ×24**，32C/191 GB 机器）：

* 12 个巨型任务包条目全解密 + needle 搜：118 s，**0 命中**
* 全盘 3,229 个漏网条目（含 zlib 解压后再搜）：117 s，**0 命中**
* 另查：`EXLANG/disc0_rel/0076531d.DAT`（比 MLG 那份大 24,416 B，非逐字节副本）
  也解密搜过，0 命中（脚本 `_probe_briefing_exlang.py`）；根目录 exe 明文直搜 0 命中；
  UTF-16LE/BE 直搜 0 命中；`no one` / `nobody` / `why not` 模糊检索 0 命中。

**所以 §1 的"❌"现在成立，但理由从"抽样没看到"变成"7.6 GB payload 全量解密
检索过"。** §8.1 剩下的「FEL 内部成员没破」这条也在 §10 里合上了。

---

## 10 `FEL\x07` 是什么（2026-09-21）

SLOT.DAT 的过场记录里也有同样的块（181 个，208 B ~ 7 KB，`_probe_slot26.py`），
拿它当小样本正好把格式读到底（`_probe_fel2.py`）。头 48 字节**全盘一致**：

| 偏移 | 值 | 说明 |
|---|---|---|
| `+0x00` | `46 45 4c 07` | 魔数 `FEL\x07` |
| `+0x04` | `0` | |
| `+0x08` | `00 00 04 04` | |
| `+0x0c` | `300` | 常量，所有 FEL 都一样 |
| `+0x10` | `0x8a0`（SLOT）/ `0x6c80`（ADEMO） | 数据区相关长度 |
| `+0x14` | `u16 n1, u16 n2` | SLOT `(1,1)`；ADEMO `(51,52)` |
| `+0x18` | 表 | SLOT：`u32`；ADEMO：51 个 `u16`（`0x1a00|idx`，是 0..51 的一个排列） |
| `+0x30` | `u32` 偏移表 | 递增、步长 8/12 交替 → 记录长度交替 |

记录本体 = `u16 opcode, u16 size, size-4 字节操作数`：SLOT 样例里
`op=3,size=8`（1 个 u32）、`op=4,size=0xc`（2 个 u32）交替出现 ——
**是脚本/命令流，不是文本**。ADEMO 那边 `+0x80` 起是 `(u16 idx, u16 offset)`
对（offset 均 < payload 长度），`+0x150` 之后是成片的 u16/u32 数值表
（0x6000 处是 `0a64/1502` 这类成对 u32），像动画/模型/媒体的索引数据。

### 10.1 「FEL 里有没有文本」—— 证否

| 范围 | 判据 | 结果 |
|---|---|---|
| ADEMO + ADEMOHQ 全部 532 条目 / 6,635 MB | 全解密，统计每个 payload 最长 ASCII 串（`_probe_fel_cover.py --sweep --all --ascii --procs 24`，116 s） | **含 ≥12 字符 ASCII 串的 payload：0** |
| SLOT.DAT 全部 181 个 FEL 块 | 同上，阈值放宽到 8（`_probe_fel2.py --slot-all`） | **0** |

即 FEL 既不含那句台词，也不含任何可读文本。

### 10.2 IDB 侧：没人按这个魔数分派

* `METAL GEAR SOLID PEACE WALKER.exe`（18,409,032 B）里 `FEL\x07` 出现 **0 次**；
  `FEL` 的 17 次命中全在脏话词表（`FELCH` / `FELATIO` / `FELLATIO` …）。
* 立即数 `0x074C4546` / `0x004C4546`：**0 处**（`search_text` 全图扫）。
* 没有 `FEL` 字面量字符串。→ FEL 是作为「已知类型」整块交给子系统的。
* 条目 id 也不走文本通路：`slotdat_find_res_entry` @ `0x1400A61F0` 只收
  `(id & 0x7F000000) == 0x20000000` 的条目，而 FEL 池的 id 是
  `0x5e395f10` / `0x5e325ef1` / `0x5e525ef3` / `0x5e625f73` /
  `0x5e325df5` / `0x5e925df8`（`& 0x7F000000 = 0x5E000000`），不在该类里。
* ADEMO / ADEMOHQ 文件名一一对应、209 MB vs 6.4 GB，由
  `path_resolve_install` @ `0x140043DA0` 的 `/ADEMO` `/ADEMOHQ` 分支选；
  pt 语言下它们与 `/CAMO` 一样**不**改走 `EXLANG` → 是「安装」用的一对画质档。

### 10.3 还剩什么

盘上所有容器 payload（7.6 GB）现在都解密 + needle 检索过，FEL 也证否了，
那句 Miller 台词**在本盘数据里不存在**。剩下的解释只有：截图来自别的版本 /
打了别的 MOD，或这句是运行时拼出来的（非静态语料）。要继续就只能从 IDA 反查
「任务内无线台字幕」的取文本函数，看它到底读哪个 group / 哪张表。
