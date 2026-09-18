# 计划 01 · UI 文字提取

状态：**提取链路已打通**，剩余为收尾与回写。

## 已完成

- [x] 逆向 `name_hash` / `mt_seed`(自定义 LCG) / `buffer_xor_decrypt`
- [x] 用 Python 复现，**17 个 olang 文件全部通过 `RBX\0` 魔数校验**
- [x] 还原三级索引 + 字符串池 + 语言键映射
- [x] 实证葡萄牙语占用 `es` 槽（`EXLANG\Text\*.olang`）
- [x] 全量导出 137358 行 → `ANALYSIS/_dump_olang.tsv`
- [x] `str_hash24` 反查 141 个键名（`SNAKE` `MILLER` `pw_briefing_topic` …）

## 待办

### 1. 解出运行时加载表清单（阻塞：不知道哪个表用于哪个场景）

`textlang_resolve_olang_paths` @ `0x1400859B0` 只注册 2 个表，
但 `MLG\Text\` 下有 14 个。其余由 `olang_register_table` @ `0x14003ADD0` 注册：

```
olang_register_table(a1, list, count)
  记录 = 132 字节：char name[128]; u32 id;       （步长 132 = 33 dwords）
  while (*(u32*)rec == 6695812 && launcher_get_ctrltype() != 4) 跳过
  path = (lang_get_language_id()==6 ? "JPN/Text/" : "MLG/Text/") + name + ".olang"
  ctx  = { id, name_hash(name) }
  file_request_async(path, olang_load_decrypt_and_install, ctx, 0, 16, 1)
```

**下一步**
1. 反 `sub_140076AA0`（调用方，size 0x6A3）→ 确认 `list` 的来源
2. 反 `systemdat_parse_text_name` @ `0x1401BE230` 的调用链，确认名字长度 15 的来源
3. 目标：拿到 14 个表各自的**用途名**（`pw_common` / `pw_briefing_topic` 这类）

### 2. `key[].meta` 语义

`0x402` 与 `0x1` 两种值。实测多数文件按 group 恒定，但 `009c9ea4` 有 9 个 group、
`00c7f1dc` 有 37 个 group 内部混用。
**下一步**：从 `text_get` @ `0x1400E6990` 的调用方反查该返回值的用途。

### 3. 回写（rebuild）工具 —— ✅ 已完成

`pwsf.olang_build`，取证见 [01 号文档 §6.5](../ANALYSIS/01_olang_text.md)。

- [x] 重新布局字符串池（去重、NUL 结尾），重算 `str_off` / 三表偏移
- [x] 重新 XOR 加密（同 key），`table_id` 保持不变
- [x] `serialize_exact()` 与原文件**字节一致**；`serialize()` 重新解析后
      逐三元组等价（`_probe_olang3.py`，17/17）
- [x] **端到端实机验证通过**：`_poc_text_cn.py` 改写 8 条 UI 文本 + 自动补
      32 个字形，实机显示中文（证据图 `ANALYSIS/_text_poc_ingame.png`）

### 4. 内联标记规范化

文本含 `<I=...>` 图标/按键引用（如 `<I=AIM>` `<I=DEC>`
`<I=item_exp_IT_EQ_LOVE_CBOARD_R1>`）。

> **换行是真实 `0x0A`，不是字面 `\n`**（此前记反了）。`_probe_olang4.py`
> 扫全部 137,358 条：含 `0x0A` 的 4,289 条，含字面反斜杠-n 的 **0 条**，
> 另有 181 条含 `0x0D`。之前的误判源于 `_probe_dump.py` 会把真实换行
> 转义成 `\n` 写进 TSV，光看 TSV 分辨不出来。

**下一步**：枚举全部 `<I=...>` 取值并建表，确保回写时不破坏。
