# PWSF 计划总览

目标二进制：`METAL GEAR SOLID PEACE WALKER.exe`（Steam，x64，原生 D3D11 + MediaFoundation）
```
base 0x140000000  size 0x1964000
md5    5bfe6b2cdbb77c3f0f3cff05fcad22bd
sha256 5bc5756166e611d7f15e84e8032ac417771a9633d8cc072dab20a7613e588fff
IDB    C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw\*.i64
```

## 工作原则（来自 AGENTS.md）

1. 一切结论从二进制取证，**不猜**；未验证的写「未验证」并列出疑点。
2. 积极改名 IDA 符号，证据写进 `ANALYSIS/`。
3. 长任务拆成 `PLANS/` 下的多个计划文件。

## 加密总览（三类资源同一套）

```
key = name_hash(basename)
  └─ name_hash @ 0x14010F450：取最后一个 '/' ':' '\\' 之后的子串，
     到第一个 '.' 或 '\0' 为止； h = 7477*c + 144751*h (mod 2^32)

解密 = mt_seed(key) → mt_advance(20)（实际跳过 5 个输出）→ 逐 dword 异或
       (mt_next() ^ 0xB9D3018F)，尾部 1~3 字节用最后一个 keystream 的低字节
  ├─ buffer_xor_decrypt        @ 0x14010F4C0   （一次性，olang / xmx / xsx）
  └─ sub_14010F8B0 + sub_14010F5C0 @ 0x14010F8B0/0x14010F5C0
                                               （拆分式，PDT/DAT 归档，可复用 MT 状态）
```

## 模块进度

| # | 模块 | 状态 | 文档 | 计划 |
|---|---|---|---|---|
| 01 | UI 文字（olang / RBX） | ✅ 提取已打通 | [01_olang_text.md](../ANALYSIS/01_olang_text.md) | [01_ui_text.md](01_ui_text.md) |
| 02 | 字幕 | 🟡 部分 | [02_movie_subtitle.md](../ANALYSIS/02_movie_subtitle.md) | [02_subtitle.md](02_subtitle.md) |
| 03 | CODEC（`0076531d.DAT`） | 🟢 台词已全量提取；🟡 语言归属未解决 | [03_codec.md](../ANALYSIS/03_codec.md) | [03_codec.md](03_codec.md) |
| 04 | 归档 PDT/DAT | ✅ 已打通 | [04_archive.md](../ANALYSIS/04_archive.md) | [04_archive.md](04_archive.md) |

> 03 现状：容器格式已打通，2,049 条记录 / 24,438 行台词已导出到
> `ANALYSIS/_briefing_lines.tsv`，**0 个不可解码字符**。
> **尚缺语言归属**（语言不在记录内，只在运行时寻址表里），
> 因此 TSV 不输出语言列。

> 04 曾阻塞 02 与 03，现已解除：138 个容器 / 134 个有效 / 113,348 条目 /
> 2,042 个 payload CRC-32 全通过。

## 磁盘速查

```
mgspw\
├─ MLG\Text\*.olang        14 个   UI/文本表（en fr de it ja es 六语言槽）
├─ MLG\data\Mov\*.xmx/.xsx         影片（MP4） + 音轨（Ogg Vorbis）
├─ MLG\data\hqMov\*.xmx/.xsx       高清影片
├─ MLG\data\Vib\*.BIN              振动
├─ MLG\disc0_rel\*.DAT/.PDT/.KEY   游戏主体归档（SLOT.DAT / STAGEDAT.PDT …）
├─ MLG\disc0_rel\ADEMO|ADEMOHQ|CAMO
├─ EXLANG\Text\*.olang      3 个   葡萄牙语文本表（写在 es 槽）
├─ EXLANG\data\{Mov,hqMov}\        pt 专有影片
├─ FONT\*.xpr                      字体
├─ Text\*.txp                      字形贴图
├─ SHADER\x64\
└─ ms0\EU\DLC{BGM,TEX,VOICE}\*.PDT
```

## 工具（`TOOLS/`）

| 文件 | 作用 |
|---|---|
| `pwsf_crypto.py` | `name_hash` / `MT19937`(自定义 LCG 播种) / `buffer_xor_decrypt` |
| `pwsf_olang.py` | RBX 容器解析（三级索引 + 字符串池） |
| `pwsf_archive.py` | PDT/DAT 归档解析 + payload 解密 + CRC-32 校验 |
| `pwsf_names.py` | `entry_name_hash` / `str_hash24` / 67 项扩展名表 / 哈希反演 |
| `pwsf_briefing.py` | BRIEFING/CODEC：逐扇区解密 + 记录头解析 + 台词导出 |
| `pwsf_archive_index.py` | 全盘容器索引 → `ANALYSIS/_archive_index.tsv` |
| `_probe_*.py` | 各阶段取证脚本（保留作为证据） |
