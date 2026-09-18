# 08 · 过场（comic cutscene）文字 —— 尚未提取，已定位到 `SLOT.DAT`

状态：**语料未提取**。已把所有能读的容器逐个排除，剩下唯一的去处是
`002aba34.DAT`（= `SLOT.DAT`，544 MB）。本轮打通了它的索引
`002aba34.KEY`（= `SLOT.KEY`），卡点收窄到**载荷本身的编码**。

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

两个尚未解释的观测，**不要当结论用**：

* `B == end - start` 只有 1748/2137。`sum(end - start) = 132,947` 而
  `sum B = 119,500`，即有 13,447 扇区的余量——B 像是"实际存储扇区数"，
  区间里另有填充，但填充规则未验证。
* `+0x0C` 与高 12 位在 2 条记录上不一致，原因未查。

`A >= B` 恒成立且 `sum A / sum B = 2.62`，与 "A = 解压后扇区数、
B = 存储扇区数" 一致 → **载荷很可能是压缩的**。这条尚未直接验证，
只作为 §5 的工作假设。

---

## 5. `SLOT.DAT` 载荷 —— **卡点**

每条记录的**密文**开头 20 字节在各记录间完全相同：

```
63 4c 9e 66 24 f4 0f f3 | 9a df | 66 74 | 3b c8 | de 55 | 20 cf 79 76 | ...
                          ^^^^^          ^^^^^           逐记录变化
```

常量前缀 ⇒ 密钥流是**容器级常量**（不随记录变化）。已试过的候选全部失败
（`_probe_slot4.py`，判据 = 可打印串数 / 最长可打印串 / 可打印比，
四个样本记录）：

```
name_hash("002aba34") / ("SLOT") / ("slot") / ("SLOT.DAT") / 0
SLOT.KEY 头的三个 u32（0xC79EBEBA / 0xDF41C1B1 / 0xB06A43B9）
各记录 +0x08 的哈希本身
```

全部得到 0.366~0.375 的可打印比、最长可打印串 8~13 字节——与原始密文
（0.377）无差别，即**都不是**。单字节 XOR 也被排除：`9e` 与 `0f` 的最高位
与其余字节矛盾，不存在使 8 字节全可打印的常量。

结论：要么密钥来自尚未定位的地方，要么载荷先压缩后加密（§4 的 `A/B` 支持后者），
两者都要继续反 `0x1400A56D0` / `0x1400A6560` / `0x1400A68A0` 这组
`SLOT.DAT` 流式读取函数。

---

## 6. 已排除的去处（逐个实测）

| 容器 | 实测内容 | 命中 |
|---|---|---|
| 17 个 `.olang` | UI / 游戏内字幕 | 0 |
| `BRIEFING.DAT` | 2,049 记录 / 24,438 行，1,011 扇区全覆盖 | 0 |
| `ADEMO/*.pdt` 35 个 | **231 个 `la3`（音频）+ 35 个 `txp`（贴图），无文本条目** | 0 |
| `BGM/VOICEBF/VOICERT/VOICEPS` 4 个容器 | 3,217 个 `bgp` 条目，解密后全是 `SP?\0` 头 + `OggS`/`vorbis`，带 `251922 PW_EN` 之类标签 → **语音音频** | 0 |
| `MMV00000.PDT` 的 `SUBTITLE` 条目 | 该文件根本不在磁盘上（见 02 号 §6.1 与本文 §7） | — |

`ADEMO` 只有贴图和音频这一条很关键：漫画分镜的**气泡文字要么烘焙进 `txp`，
要么来自别的容器**，两种都还没证据，不要下结论。

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

1. **反 `SLOT.DAT` 的读取链**：`sub_1400A56D0` → `sub_1400A6560` /
   `sub_1400A68A0`（`sub_14008B150(1, g_mount_table_ptr + 208, 1, 0, 0x2000)`
   打开挂载槽 1，按页 memmove 进大缓冲）。目标是找出解压/解密函数与密钥来源。
2. **顺带解掉 `STAGEDAT.PDT` 的 mode 0x40 载荷**：`entry_payload_transform`
   @ `0x140123E90` 读 `pkg+196`（LCG 状态）与 `pkg+200`（增量）。
   `archive_index_load` @ `0x1401238C0` 里 `sub_140123DB0` 把派生值写进**栈上**
   的 `v27`/`v28`，**没有**落到 `pkg+196/200`，所以初值另有出处，尚未定位。
   （这条对应 `04_archive.md` §6 疑点 2。）
3. 两条都通了再全量 grep 截图那句话，确定气泡与底部字幕各自的归属。

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
```

> `002aba34.DAT` 在游戏运行时被独占打开，探针会报
> `PermissionError`，退出游戏再跑。

## 10. 本轮 IDA 符号更进（IDB 已保存）

| 地址 | 旧名 | 新名 |
|---|---|---|
| `0x140e9d6e0` | （无名） | `g_mount_table` |
| `0x140ea4220` | `off_140EA4220` | `g_mount_table_ptr` |
| `0x1400a6290` | `bigdat_load_and_verify` | `slotdat_load_and_verify` |

并在 `0x140e9d6e0` 与 `0x1400a6339` 写入注释，记录槽位对照与 208 字节步长。
