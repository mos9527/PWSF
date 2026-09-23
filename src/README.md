# PWSF 翻译工作区

原文一律取**英文**。文件由 `pwsf.po_export` 生成，可随时重新生成。
重新导出会**按 `msgid` 回填已有译文**（`--fresh` 可关），但会删掉不再存在的
条目引用 —— 先提交再重跑更稳妥。

```
olang/olang_NN.po  UI 文字 + 游戏内字幕    4 个文件 /  1,461 条   能写回
codec/codec_NN.po  CODEC / 简报台词       15 个文件 /  5,911 条   能写回
slot/slot_NN.po    SLOT.DAT 内嵌文本      24 个文件 /  9,566 条   能写回
stage/stage_NN.po  STAGEDAT 内嵌文本      12 个文件 /  4,522 条   能写回
gtt/gtt_NN.po      SLOT.DAT 的 GTT 池      6 个文件 /  2,238 条   能写回
MANIFEST.tsv       分块索引（条目数 / 覆盖槽位数 / 原文字符数）
```

合计 23,698 条。一个文件约 400 条，可以一人认领一个文件并行推进。

> 2026-09-23：codec 从 4,746 涨到 5,911 —— CODEC 容器里还藏着第二种
> 记录格式（脚本按引用共享），此前被提取器的入口白名单误杀，585 条记录、
> 约 1,200 句台词补收进语料，详见 `research/ANALYSIS/03_codec.md` §10。

`slot/` 里带 `#. comic cutscene` 注释的那 1,858 条是**过场（漫画）台词**，
主体在 `slot_05`–`slot_10`；其余是同一批内嵌文本里的 UI 说明文。
它们的文本不在磁盘那 17 个 `.olang` 里，而是塞在 `MLG/disc0_rel/002aba34.DAT`
中，详见 [`research/ANALYSIS/08_cutscene_text.md`](../research/ANALYSIS/08_cutscene_text.md)。

## `gtt/` 是任务内无线台台词（有字节上限）

`gtt/` 是 **SLOT.DAT** 里 462 个 `GTT\x00` 池装的台词：任务里 Miller / Kaz 的
无线电呼叫、提示、"往北走"这类喊话。它原先谁都没提取过 ——
`slotdat_find_res_entry` 只认 `0x20` 类资源 id，而 GTT 池是 `0x1c` 类。
格式与来龙去脉见
[`research/ANALYSIS/11_gtt_text.md`](../research/ANALYSIS/11_gtt_text.md)。

**每条有字节上限**：写回是原地的，译文的字节数不能超过它替掉的英文行，上限标在
条目上（`budget N B`，中位 43 B，98% 的行 ≥12 B）。超了 `po_lint` 报
`gtt-budget` 并指出是哪条 —— 改短，或者留空让它保持英文。`Hm?` `Huh?` 这类
只有 3~4 字节的极短喊话基本放不下中文，直接留英文即可。

换行照常：`\n` 在游戏里是两个字符，行数要和原文一致。

## `stage/` 是只读语料（暂时）

`stage/` 是 **STAGEDAT**（`MLG/disc0_rel/009645fa.PDT`）里那 738 张内嵌 olang
表：任务说明、关卡提示、Mother Base 队员吐槽、道具/武器说明文。其中 10,570 条
在别处都没有。

它**现在还写不回**：`po_import` 会跳过 `stage/...` 引用，`po_lint` 会给你一条
`stage-readonly` 警告。翻了不会出错、也不会进游戏——先翻着，等写回链路打通。
格式与来龙去脉见
[`research/ANALYSIS/09_stagedat_payload.md`](../research/ANALYSIS/09_stagedat_payload.md)。

> 以前这里有份 `pwsf.pot`，现在默认不再生成 —— 它只是所有语料合并成的空
> 模板，`po_lint` / `po_import` 都不读它，在里面翻译不生效。需要时 `--pot`。

## 怎么翻

只填 `msgstr`，其余行都别动：

```po
#: olang/0005ee2f/0xc6de03/0x069574
msgid "Screen Display"
msgstr "画面显示"
```

- `#:` 是这条文本在游戏里的**全部**位置。一条 `msgstr` 会写回所有这些位置。
- `msgstr` 留空 = 未翻译，导入时该槽位保持英文原样，可以分批交付。
- `#.` 只在 CODEC 出现，给的是 `speaker` 与 `timeline`，用来判断语境和时长。

> 默认**不附带其他语言的参考译文**——它们会让文件膨胀近一倍，而 LLM 译者
> 读它们纯属浪费 context。确实需要时重新导出：
> `python -m pwsf.po_export --ref-langs fr,de,it,es`

## 硬性规则

1. **`<I=...>` 原样保留**。这是手柄按键/图标引用（如 `<I=DEC>`、`<I=△>`），
   改动或翻译它会让游戏显示不出图标。
2. **`%d` `%s` 一类格式符原样保留**，数量和顺序都不能变。
   带这类占位符的条目标了 `#, c-format`。
3. **换行用真实换行**，在 `.po` 里就是 `\n`。原文几行，译文尽量也几行——
   游戏不会自动折行，超长会被裁掉。
4. 原文为空的槽位没有导出，不用管。
5. **`msgid` 和 `#:` 一个字都别改**。导入器拿 `#:` 当写回地址，
   并要求 `msgid` 与游戏里的英文原文逐字符相同；改了就整条被拒绝。

这几条不靠自觉，`python -m pwsf.po_lint` 会全部查出来（连 `\0`、
把 `<I=DEC>` 写成 `<I=DEC` 都查），有 error 时编译直接不放行。

## 翻完怎么看效果

```powershell
python -m pwsf.po_import --install   # 一条龙：体检 + 编译 + 备份 .orig + 装进游戏
python -m pwsf.install --restore     # 不想要了就还原
```

想分步走：`po_lint` 只体检，`po_import` 只编译到 `research/BUILD`，
`install --install` 只安装。

只译了几条也能跑：未填 `msgstr` 的槽位保持英文，可以边翻边看。

## 为什么同一句英文只出现一次

olang 侧重复率 46%，所以按 `msgid` 合并了：一条译文自动覆盖所有引用位置。
好处是「OK」「返回」这类短词在全游戏里必然一致。
如果发现某条在不同场景需要不同译法，把那条的 `#:` 拆成两条目并分别翻译，
导入器按 `#:` 定位，拆开不影响写回。

> 实测：`Return to the title menu?` 一条译文写进了 4 个槽位
> （见 `research/PLANS/06_localization_pipeline.md` §9）。
> 同一个 `#:` 出现在两条目里且译文不同会被 `po_lint` 报 `conflict`。

## CODEC 的两个注意事项

- 即使加了 `--ref-langs` 也**取不到其他语言的参考译文**。各语言的台词分处不同
  扇区，跨语言对齐键至今未解（见 `research/ANALYSIS/03_codec.md`），无法可靠配对，
  宁可不给也不给错。
- **一条记录装不下就得改短**。CODEC 的台词存在「文本池」里，每条记录能用的
  字节数是固定的（`off3 - off2`），游戏按记录的文件偏移去寻址，记录**不能搬家**。
  实测两个英文块 358 条记录只剩 **555 字节**余量，所以译文必须比英文**短**
  （中文一般没问题：olang 侧实测字节比中位 0.75）。超了 `po_lint` 会报
  `codec-budget` 并指出是哪条记录，把它改短即可；`po_import` 默认因此拒绝构建，
  加 `--codec-skip-overflow` 则让那条记录留在英文、其余照常编译。
  细节见 `research/ANALYSIS/03_codec.md` §9。

## 字库

译文用到的汉字由 `pwsf.font_build` 在编译时自动统计并补进字体图集，
翻译时**不需要考虑字数限制**。当前主字体约有 3,100 个空位，
而日文全量文本也只用到 1,560 个汉字，余量充足。

两个例外，`po_lint` 会直接报 `font` 错误而不是让你在实机上看到豆腐块：

- 码点超过 `U+FF5E` 的字进不了字形转换表，全角 `￥`（U+FFE5）就是一个；
- 字体源 `msyh.ttc` 里没有的字（生僻字、私用区）。

## 有一批文字**不要译**

游戏除了 `FONT\*.xpr` 那两张字库，还有第三张字形图集：藏在 `Text\*.txp` 里的
一张 512×512 像素字，只有 ASCII + 拉丁字母，**一个汉字都没有**。olang 每条记录
的 `meta` 字段决定它用哪张：`meta == 1` 走像素字，`meta == 0x402` 走上面那两张。

这类槽位（2,051 个）**默认不导出**，所以你在 `.po` 里看不到
`PRESS START BUTTON`、`BUTTON CONFIG`、`PRISONER`、`MOTHER BASE` 这类短标签——
**这是有意的**，它们保持英文（日文版也是这么处理的）。

如果哪条被你手工加了进去并填了中文，`po_lint` 会报：

```
pixel-font   drawn with the ASCII/Latin-1 pixel atlas in Text/*.txp,
             which has no glyph for U+4E0B 下 ... -- leave this slot English
```

想看这批到底是什么（或坚持要导）：`python -m pwsf.po_export --pixel-font`。
前因后果见 `research/ANALYSIS/05_font.md` §15。
