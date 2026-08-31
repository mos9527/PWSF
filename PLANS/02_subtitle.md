# 计划 02 · 字幕提取

状态：**影片/音频已解；字幕正文受限于归档格式（计划 04）**。

## 已完成

- [x] 确认 `.xmx` = MP4(H.264)、`.xsx` = Ogg Vorbis，且都用 `name_hash` 解密
- [x] 确认字幕正文 = 归档包内名为 `SUBTITLE` 的条目（NUL 结尾文本）
- [x] 确认游戏内字幕 = olang group（8 个常量），**01 号工具已可直接提取**
- [x] 还原字幕上下文结构与 `subtitle_slot_name` 的偏移算法

## 分两条线

### A. 游戏内字幕（不阻塞）

olang group 常量，来自 `subtitle_state_machine` @ `0x14026BC00`：

| 模式 `a1[29]` | 条件 | group 键 | 行数 `a1[31]` |
|---|---|---|---|
| 1 | `v3[13]==1` / `==2` | `0x00BC5075` / `0x00468563` | 74 |
| 2 | `v3[11]==1` / `==2` | `0x00E33255` / `0x00298E82` | 38 |
| 3 | `v3[12]==1` / `==2` | `0x00E9C6FC` / `0x00D37BFC` | 28 |
| 4 | `v3[10]==1` / `==2` | `0x00903F77` / `0x0043895A` | 32 |

- [ ] 在 `ANALYSIS/_dump_olang.tsv` 中按这 8 个 group 键筛出全部字幕行
- [ ] 用 `str_hash24` 反查这 8 个 group 的名字（若在二进制串表中）
- [ ] 导出 `ANALYSIS/subtitle_ingame.tsv`

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

**待办**

- [ ] 反 `subtitle_ctx_update` @ `0x1401B9F60`，确定 85 槽的填充规则，
      弄清那 5 个包名到底是哪 5 个（`MMV00000.PDT` 是其中之一，见
      `music_package_open_mmv` @ `0x14026C000`）
- [ ] 确认 Steam 版是否根本就没有影片字幕包（4 个 AVD 包都在 `DLCVOICE`
      目录下，且不含 `SUBTITLE`）——**不得推断，需实证**
- [ ] 若确有字幕包，抽出 `SUBTITLE` 条目文本，解析时间轴字段
      （需反 `sub_1401D27F0` / `sub_1401CFE60` 确认消费方式）
- [ ] 与 `.xmx`/`.xsx` 解密后的影片对齐，导出 `ANALYSIS/subtitle_movie.tsv`

## 需要回答的问题

- `SUBTITLE` 条目是**纯文本**还是**带时间码的二进制**？
  `subtitle_load_resources` 里只做了 `strlen` + `memcpy`，
  倾向于纯文本（时间轴可能在别处，或由 `sub_1401D27F0` 另算）。
  **必须实际解出一个条目才能确认，不得推断。**
