# 计划 02 · 字幕提取

状态：**A 线（游戏内字幕）已打通并导出；B 线（影片字幕）因 Steam 版无数据收尾**。

## 已完成

- [x] 确认 `.xmx` = MP4(H.264)、`.xsx` = Ogg Vorbis，且都用 `name_hash` 解密
- [x] 确认字幕正文 = 归档包内名为 `SUBTITLE` 的条目（NUL 结尾文本）
- [x] 确认游戏内字幕 = olang group（8 个常量，**已汇编核对**）
- [x] 还原字幕上下文结构与 `subtitle_slot_name` 的偏移算法
- [x] `TOOLS/pwsf_subtitle.py` → `ANALYSIS/subtitle_ingame.tsv`（4,128 行）

## 分两条线

### A. 游戏内字幕（✅ 已完成）

olang group 常量，来自 `subtitle_state_machine` @ `0x14026BC00`，
**十六进制以 `mov ebp, imm32` 的字节为准**（旧版本此表 8 个值全部抄错，
详见 [02 号文档 §6.2](../ANALYSIS/02_movie_subtitle.md)）。
`v3[10..13]` 同时是 `path_resolve_install` 里的 DLC 安装槽选择器：

| 模式 `a1[29]` | 标志 | DLC 包 | 槽 1 group | 槽 2 group | 行数 `a1[31]` |
|---|---|---|---|---|---|
| 1 | `0x141884934` | `AVD00003.PDT` | `0x00BC4A75` | `0x00468863` | 74 |
| 2 | `0x14188492C` | `AVD00000.PDT` | `0x00E34675` | `0x0029956A` | 38 |
| 3 | `0x141884930` | `AVD00001.PDT` | `0x00E9CBF5` | `0x00D36BFC` | 28 |
| 4 | `0x141884928` | `AVD00002.PDT` | `0x00903077` | `0x00430FFE` | 32 |

槽 1 的四组六语言俱全（加 EXLANG 葡语副本，写在 es 槽），槽 2 的四组只有日文
非空——槽 2 是日语语音 DLC。Steam 版发布的是槽 1，故实机生效的是槽 1 四组。

- [x] 按这 8 个 group 键从 olang 筛出全部字幕行 —— 8/8 命中，
      entry 键均构成 `0 .. a1[31]-1` 的连续区间
- [x] 导出 `ANALYSIS/subtitle_ingame.tsv`（4,128 行，含空行保持行号对齐）
- [x] 定位承载文件：`MLG/Text/009c9ea4.olang` + `EXLANG/Text/00c7f1dd.olang`
      —— 不需要走 `g_olang_slots` 运行时注册链
- [ ] 用 `str_hash24` 反查这 8 个 group 的名字（若在二进制串表中）
      —— 仅为可读性，不阻塞提取与回写

### B. 影片字幕（~~阻塞于计划 04~~ 04 已打通）

**04 已完成**（见 [04_archive.md](../ANALYSIS/04_archive.md)），归档层不再阻塞。
新取得的证据：

- [x] `subtitle_load_resources` @ `0x14026BE10`：**17×5 = 85 个槽**，
      每槽 `archive_set_package` + `archive_open_entry(h, "SUBTITLE", 1, 0)`，
      读出后 `strlen` + `memcpy` 存到 `a1+768+8*(5*v4+v6)`
- [x] 包名由 `subtitle_slot_name` @ `0x1401B9DF0` 生成：最多 5 个（16 B/个，
      运行时填在 `ctx+0`），85 字节索引表在 `ctx+100`，取值须 `<= 4`
- [x] 逻辑包名 → 真实文件的语言槽重定向（`path_resolve_install` @ `0x140043DA0`）：

  | 逻辑名 | 槽 0 | 槽 1 | 槽 2 | 槽 3 |
  |---|---|---|---|---|
  | `/BKD00000.PDT` | 8b1ae9c3 | 8b1ae97b | 8b1ae97c | 8b1ae97d |
  | `/AVD00000.PDT` | 181ae4ab | **181ae463** | 181ae464 | — |
  | `/AVD00001.PDT` | 191ae4ad | **191ae465** | 191ae466 | — |
  | `/AVD00002.PDT` | 1a1ae4af | **1a1ae467** | 1a1ae468 | — |
  | `/AVD00003.PDT` | 171ae4a9 | **171ae461** | 171ae462 | — |

  Steam 版只发布槽 1 → `ms0\EU\DLCVOICE\{181ae463,191ae465,1a1ae467,171ae461}.PDT`
  （均已确认存在）；`BKD00000`（8b1ae97*）**未随包发布**。

- [x] **上述 4 个包已解出，但条目里没有 `SUBTITLE`**
      （`entry_name_hash("SUBTITLE") = 0x68878e` 无命中；
      条目 key 是 `0x0017afc1..` 的连续序列，是语音条目）

### B 线定性收尾（已实证，见 02 号文档 §6.1）

- [x] **全盘 134 个有效容器 / 113,348 条目中 `SUBTITLE` 零命中**（索引脚本
      `KNOWN` 已含该名，头读取 8 MiB >> 名字表最大 55 KiB，无截断漏检）
- [x] `DLCVOICE` 下 4 个 AVD 真实文件（171ae461/181ae463/191ae465/1a1ae467，
      共 180 条目，CRC 100% 通过）**条目名全部未解析**，无一为文本类
- [x] 唯一候选 `BKD00000.PDT`（8b1ae97*）未随 Steam 版发布

> **影片字幕数据在 Steam 版不存在**——不是格式问题，是发行内容缺失。
> B 线就此收尾，不再投入逆向。

**剩余待办**

- [ ] `str_hash24` 反查 8 个 group 的名字（可读性，不阻塞）
- [ ] 回写（rebuild）：与计划 01 待办 3 是同一套 olang 序列化器，合并推进
- [ ] `subtitle_ctx_update` @ `0x1401B9F60` 的 85 槽填充规则：仅在
      「确认存在影片字幕包」的前提下才有意义，当前**已降级为不必做**

## 需要回答的问题

- ~~`SUBTITLE` 条目是纯文本还是带时间码的二进制？~~
  **该问题失效**：全盘无此条目，无法实证。仅保留代码侧结论
  （`subtitle_load_resources` 只做 `strlen` + `memcpy`，倾向纯文本）。
- ~~`v4` 到底是什么？~~ **已闭合**：`v4` = olang group 键，汇编逐条核对
  （`mov ebp, imm32` → `mov ecx, ebp` → `call text_get`，中途 `ebp` 无修改），
  8 组全部在 `MLG/Text/009c9ea4.olang` 命中，行数与 `a1[31]` 精确吻合。

## 复现

```powershell
cd d:\PWSF\TOOLS
python pwsf_subtitle.py
```
