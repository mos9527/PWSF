# 计划 06 · 语料整理（.po）与编译工具链

状态：**设计阶段**。提取侧已全部打通（01/02/03/05），本计划负责把提取结果
整理成可翻译的 `.po`，再编译回游戏可读的二进制。

---

## 1. 语料只有两个来源（别重复计数）

| 来源 | 产物 | 规模 | 说明 |
|---|---|---|---|
| olang / RBX | `ANALYSIS/_dump_olang.tsv` | 137,358 行 | UI 文字**和**游戏内字幕都在这里 |
| BRIEFING / CODEC | `ANALYSIS/_briefing_lines.tsv` | 24,438 行 / 2,049 记录 | 独立语料，字节码内嵌 |

> ⚠️ `ANALYSIS/subtitle_ingame.tsv` **不是第三个来源**，它是 olang 的一个视图
> （同样出自 `009c9ea4.olang` + `00c7f1dd.olang`，见 02 号文档 §6.2）。
> 导出 `.po` 时若把它当独立语料会产生重复条目。它的价值在于给字幕行
> 附上 mode / pack / slot 这层语义，应作为**注释**并进 olang 条目。

影片字幕不在列——Steam 版无该数据（02 号 §6.1）。

## 2. PO 键设计

`msgctxt` 必须能唯一定位回二进制里的插槽，且人类可读：

```
olang    olang/<table_id>/<group>/<entry>      例 olang/009c9ea4/00bc4a75/0000
codec    codec/<group>/<sector>/<idx>/<line>   例 codec/1/0/0/0
```

- `msgid` = 英文原文（olang 取 en 槽；CODEC 取 en 语言块，见 03 号 §语言归属）
- `msgstr` = 译文
- `#:` 引用写 `源TSV:行号`，便于回溯
- `#.` 提取注释按来源附加语义：
  - olang 字幕行：`subtitle mode=N pack=AVD0000N slot=N`
  - CODEC：`speaker=0x0e28dce6 voice=v_bri_kaz0010_000_0 t=473..1490`
  - 其余六语言的现有译文一并作为参考注释，译者可对照

拆成多个 `.po`（按 table_id / 按 CODEC 记录段）以便分工，用 `.pot` 作模板。

## 3. 必须逐字保留的内联标记

| 标记 | 出处 | 规模 |
|---|---|---|
| `<I=...>` 按键/图标引用 | olang（01 号 §4） | 需枚举建表 |
| 字面 `\n` 换行 | olang | 全量 |
| `<R=表示,よみ>` 振假名 | CODEC（03 号） | 188 种 / 330 次 / 270 条记录 |

`<R=>` 是日文振假名，中文译本大概率整体去掉；但**去掉是显式决策**，
必须由校验器报出来而不是默默丢失。

## 4. 目标语言槽（待定）

Steam 版 6 个槽：`en fr de it ja es`。已实证 EXLANG 把葡语写进 `es` 槽
（01 号 §已完成），所以"占用一个现有槽"是本作已有的做法。

- [ ] 确认 launcher 如何选语言（`lang_get_language_id` @ `0x140027B40`
      与 `g_launcher_config+13` 的 `"pt"` 判断，见 `path_resolve_install`）
- [ ] 决定中文占哪个槽；注意 `lang_id == 6`（日语）分支在 Steam 版走不通
      （JPN 目录与日语字体都未发布，见 05 号 §1），**不要选它**

## 5. 编译回写链

```
.po ──┬─> olang 序列化器 ─> 重新 XOR 加密 ─> MLG/Text/*.olang     [计划 01 待办 3]
      ├─> CODEC 字节码回写                                        [受阻，见下]
      └─> 码点汇总 ─────> 字库构建器 ─> FONT/0007ccd8.xpr         [计划 05]
```

**olang 侧**：字符串池是偏移寻址（`key[].str_off`），译文变长只需重排池子，
不存在定长槽限制。重算三表偏移与 `group_count`，`table_id` 保持不变。

**CODEC 侧受阻**：台词内嵌在字节码流里，而 `briefing_insn_decode` 的
`case 0x10 / 0x20` 长度规则未反（03 号 §2），重新发射指令有把脚本写跑飞的
风险。两条备选：

1. 先反完那两个 case，再做真回写；
2. 只对 CODEC 走 detour（hook 取字符串处），文本侧仍由 `.po` 统一管理。

> 即便 CODEC 最终走 detour，`.po` 管线也不变——只是后端换一个投递方式。

## 6. 校验器（编译前必须全过）

- [ ] 内联标记逐字相等（`<I=...>` 数量与取值；`<R=>` 的去留需显式声明）
- [ ] **码点全部落在字库覆盖集合内** —— 与计划 05 的字库构建互为闭环，
      校验器直接读重建后的 `FontData` 转换表
- [ ] olang 往返等价：重新解析应逐字段等于序列化输入
- [ ] 行号/行数守恒：字幕组的 entry 键必须仍是 `0..a1[31]-1` 连续区间
      （02 号 §6.2）；CODEC 的 `0x6d args[6]` 行号必须与原记录一致
- [ ] 空串守恒：现有空行（如字幕 74 行里 6 行为空）应保持为空，
      否则会在实机上多出不该显示的行

## 7. 工具（待写，`TOOLS/`）

| 文件 | 作用 |
|---|---|
| `pwsf_po_export.py` | 两个 TSV → `.pot` / `.po`（含注释与参考译文） |
| `pwsf_po_import.py` | `.po` → 中间 TSV（编译器的输入） |
| `pwsf_po_lint.py` | §6 的全部校验，非零退出即阻断编译 |
| `pwsf_olang_build.py` | 中间 TSV → `.olang`（序列化 + 加密） |
| `pwsf_font_build.py` | 码点集合 + TTF → 重建 `FONT/*.xpr`（计划 05） |
| `pwsf_install.py` | 备份原文件、写入、校验，可一键还原 |

## 8. 顺序

1. **字库 PoC**（计划 05）—— 先证明 XPR2 往返 + 加字形 + 实机渲染这条路通
2. `pwsf_po_export.py` + `pwsf_po_lint.py`（olang 部分）
3. `pwsf_olang_build.py` + 往返等价校验
4. 端到端小样：改几条 UI 文字 → 编译 → 实机看
5. CODEC 侧按 §5 的两条备选择一推进
