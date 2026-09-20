PWSF - PEACE WALKER SANS FRONTIERS
---
METAL GEAR SOLID PEACE WALKER (STEAM) 本土化工作

# Goal
- [x] UI 文字【提取】 → `research/ANALYSIS/_dump_olang.tsv`（137,358 行）
- [x] 字幕文字【提取】 → `research/ANALYSIS/subtitle_ingame.tsv`（4,128 行）
      影片字幕在 Steam 版无数据，见 `research/ANALYSIS/02_movie_subtitle.md` §6.1
- [x] CODEC【提取】 → `research/ANALYSIS/_briefing_lines.tsv`（24,438 行）
- [x] 写回链路实机验证：olang 文本 + 字体扩字形
- [x] 汉化管线闭环：`pwsf.po_lint` / `po_import` / `install`，见 `research/PLANS/06` §9
- [x] 可分发补丁 `pwsf.patch`：整文件打包 + 两个静态 `.bat`（install/restore），
      不校验游戏原版哈希，见 `research/PLANS/07` 与 `README.md` §给别人装
- [x] CODEC 回写：`pwsf.briefing_build` —— ~~卡在 `briefing_insn_decode` 的
      `case 0x10/0x20` 长度规则~~ 旧卡点**已推翻**（`ANALYSIS/03_codec.md` §9）：
      可译文本根本不在字节码里。实际做法 = 原地重写文本池 + 重建 u32 偏移表，
      记录尺寸与偏移一字不变（记录由另一个脚本文件的 TOPIC→req 表按文件偏移
      寻址，搬不了家）。已接进 `po_lint` / `po_import`，产物 `0076531d.DAT`。
      硬约束：池预算几乎用满（两个 en 块 358 条记录只剩 555 字节），
      译文必须比英文短，超了由 `po_lint` 的 `codec-budget` 点名（§9.4）
- [ ] CODEC 实机验证：`python -m pwsf.po_import --install` 装一份改过的
      `0076531d.DAT`，进 CODEC 通话核对中文台词与语音（§9.5）
- [x] 过场（漫画）文字【提取】：`SLOT.DAT` 两层 XOR（MT + LCG）已破，2,137
 条记录全量解压；内嵌 144 张 `.olang` 表（其中 43 张是过场，英文 1,928 行）
 → `_cutscene_lines.tsv` / `_slot_olang_lines.tsv`，见
 `research/ANALYSIS/08_cutscene_text.md` §5.5 / §7
- [x] 过场文字【写回】：`pwsf.slotdat_build`（重排池 + 重压 + 重建容器），
 已接进 `po_import`；端到端实测文件 +0 字节、2,137 条记录全部读回校验通过，
 见 `research/PLANS/08_cutscene_writeback.md`
- [ ] 实机验证：把重建后的 `SLOT.DAT`/`SLOT.KEY` 装进游戏跑一次过场
 （`python -m pwsf.install --install`），确认漫画气泡与底部字幕都出中文

# Layout
```
pwsf/        工具包。成熟实现放这里，模块名不带前缀（pwsf.crypto 等）
src/         翻译工作区（.po）
research/
  ANALYSIS/  逆向文档（编号 01..07）+ 提取产物 + 证据图
  PLANS/     工作拆分，00_overview.md 是索引
  TOOLS/     _probe_* 取证脚本、_poc_* 端到端验证、pwsf_* 兼容垫片
  BUILD/     重打包产物（gitignore）
```

# Rules
- 使用 IDA MCP 获取+更新证据
- 积极更进 IDA 符号名
- 一切实现【务必】收集【完整】证据链
- 【绝不】guess，【一定】从二进制发现实现逻辑
- 发现【一定】撰写各自模块文档，放在 `research/ANALYSIS` 目录下
- 长上下文工作需要breakup成多个计划文件，放在 `research/PLANS` 目录下

# Conventions
- 路径一律走 `pwsf.config`，【不要】再硬编码游戏目录
- `research/TOOLS/_probe_*.py` 是**证据**，保留不删；文档里的每个数字都要能由
  对应探针复现，新结论先写探针再写文档
- 成熟能复用的实现【移入】`pwsf/` 包；`research/TOOLS/pwsf_*.py` 是垫片，别在
  那里写逻辑
- 模块 docstring 里写清结论来自哪个 IDA 地址
- 改动二进制前先备份 `.orig`，并提供 `--restore`
- 推翻旧结论时【保留】错误记录与推翻依据（例：`02_movie_subtitle.md` §6.2）

# Status
- UI 文字、游戏内字幕、CODEC 台词、过场（漫画）文字已全量提取
- 汉化管线 olang 与过场两侧都已闭环：在 `.po` 里填译文 → 校验 → 编译
  （重建文本表 / 重建 `SLOT.DAT`（544 MB）+ 自动补字形，`--rebuild-font`
  可整表重建字库）→ 备份后装入游戏 → 一键还原
- CODEC 已闭环：2049 条记录 / 24,438 行全量导出，`briefing_build` 原地重写
  文本池写回 `0076531d.DAT`（产物与原文等长，改动仅限目标记录的池区间）。
  唯一硬约束是池预算：两个 en 块只剩 555 字节余量，译文必须比英文短
  （`ANALYSIS/03_codec.md` §9）

过场文字不在磁盘那 17 个 `.olang` 里，而是塞在 `MLG/disc0_rel/002aba34.DAT`
（`SLOT.DAT`）内嵌的 144 张 olang 表中 —— 详见
`research/ANALYSIS/08_cutscene_text.md`。

# Layout (detail)
```
src/         翻译工作区，40 个分块 .po（olang 4 + codec 12 + slot 24）
             译者须知见 src/README.md
```

# Config
`pwsf/config.py` 会自动探测 Steam 库（含 `libraryfolders.vdf` 里的额外库）
并定位游戏目录，通常无需配置。需要覆盖时按优先级：

1. 环境变量 `PWSF_GAME_DIR` / `PWSF_FONT_TTF` / `PWSF_PO_DIR` / `PWSF_OUT_DIR`
2. 仓库根的 `pwsf.local.json`（已 gitignore）

```json
{
  "game_dir": "D:/Games/MGS_PW/mgspw",
  "font_ttf": "font/LXGW975YuanSC-500W.ttf"
}
```

字体默认用仓库自带的 `font/LXGW975YuanSC-500W.ttf`，跨平台一致、不依赖系统
中文字体；只有在 `font/` 缺失时才回退到系统字体（Windows `msyh.ttc`、
macOS `PingFang.ttc`、Linux 扫描 Noto/WenQuanYi）。相对路径一律按仓库根解析，
所以 `pwsf.local.json` 可以带着相对路径在机器之间搬。

```powershell
python -m pwsf.config                  # 查看当前解析结果
python -m pwsf.config --init           # 按当前解析结果生成 pwsf.local.json
python -m pwsf.config --init --force   # 覆盖已有文件
python -m pwsf.config --print-default  # 只打印内容，不落盘
```

`--init` 写出的是**全部**可覆盖项（`game_dir` / `font_ttf` / `po_dir` /
`out_dir` / `po_chunk`），填的是此刻探测到的值，改哪项删哪项都可以。

# Commands
全部在仓库根执行。

```powershell
# 提取
python -m pwsf.subtitle          # 游戏内字幕 -> research/ANALYSIS/subtitle_ingame.tsv
python -m pwsf.briefing -o research/ANALYSIS/_briefing_lines.tsv    # CODEC 台词
python -m pwsf.archive_index     # 全盘归档索引

# 翻译语料
python -m pwsf.po_export                           # 英文原文 -> src/ 下 42 个 .po
python -m pwsf.po_export --chunk 200               # 改分块粒度
python -m pwsf.po_export --ref-langs fr,de,it,es   # 附带其他语言参考译文
python -m pwsf.po_export --slot cutscene           # 只带过场语料（43 张表）
python -m pwsf.po_export --slot none               # 不带 SLOT.DAT 内嵌语料
python -m pwsf.po_export --fresh                   # 不保留已有译文（默认保留）
python -m pwsf.po_export --pixel-font              # 连没有汉字的像素字槽位也导出

# 汉化管线：校验 -> 编译 -> 安装
python -m pwsf.po_import --install   # 一条龙：体检 + 编译 + 复验 + 装进游戏
python -m pwsf.po_import --install --launch  # ... 再顺手通过 Steam 开游戏
python -m pwsf.install --restore     # 还原

python -m pwsf.launch --dry-run     # 看启动命令（不真的跑）
python -m pwsf.launch --status      # 启动器状态：原厂 / shim

python -m pwsf.po_lint             # 只体检，有 error 就别编译
python -m pwsf.po_import           # 只编译 -> research/BUILD/*.olang + *.xpr + MANIFEST.tsv
python -m pwsf.install             # 只看状态，不写任何东西
python -m pwsf.install --install    # 只装已编译好的产物
```

`po_import` 会先跑 `po_lint`，不过不编译；构建完再把产物解密回来逐槽位复验，
**除声明要改的槽位外必须与原文逐字节相同**。`install` 靠清单里的哈希判断
现场文件是原文、是本次构建、还是别的东西，认不出来就拒绝写入。
设计与实测见 `research/PLANS/06_localization_pipeline.md`。

```powershell
# 证据脚本（数字都由它们复现）
python research\TOOLS\_probe_po3.py   # 全链，以 PoC 实机产物为标尺
python research\TOOLS\_probe_po4.py   # 每条校验各自触发，正确译文不报
python research\TOOLS\_probe_po5.py   # 安装状态机与拒绝路径
python research\TOOLS\_probe_bri53.py # CODEC 池预算 + 写回是恒等变换
python research\TOOLS\_probe_bri54.py # CODEC 回写端到端（含 lint 拦截）
```

# Translation workflow
```
src/
  olang/olang_01..04.po   UI 文字 + 游戏内字幕    1,461 条   能写回
  codec/codec_01..12.po   CODEC / 简报台词        4,746 条   能写回（池预算紧，见下）
  slot/slot_01..24.po     SLOT.DAT 内嵌文本       9,566 条   能写回（过场 1,858 条）
  MANIFEST.tsv            分块索引
```

合计 15,773 条。**只改这三个子目录里的 `.po`**，往 `msgstr ""` 里填中文。

> 另有 2,051 个槽位**不导出**：`key.meta == 1` 的文字用 `Text/*.txp` 里那张
> 512×512 像素字图集绘制，一个汉字都没有，保持英文
> （`ANALYSIS/05_font.md` §15）。`--pixel-font` 可强行导出，`po_lint` 会对译了
> 中文的报 `pixel-font`。

| 文件 | 谁写的 | 能不能动 |
|---|---|---|
| `src/**/*.po` | `po_export` 生成，你翻译 | ✅ 只改 `msgstr`；`msgid` / `#:` 一个字都别动 |
| `src/MANIFEST.tsv` | `po_export` | ❌ 每次导出覆盖 |
| `research/BUILD/*` | `po_import` | ❌ 中间产物 |
| 游戏目录 `*.orig` | `install` | ❌ 原文件备份，`--restore` 要用它 |

完整一轮：

```powershell
# 1. 翻 —— 编辑 src/<olang|codec|slot>/*.po 的 msgstr
# 2. 体检（有 error 就别往下走）
python -m pwsf.po_lint
# 3. 编译 + 复验，产物进 research/BUILD/
python -m pwsf.po_import
# 4. 备份并装进游戏
python -m pwsf.install --install
# 5. 不想要了就还原
python -m pwsf.install --restore
```

第 3、4 步可以合并成 `python -m pwsf.po_import --install`；
想装完立刻开游戏就再加 `--launch`。

只译了几条也能跑：未填 `msgstr` 的槽位保持英文，可以边翻边看。

只想翻过场：`python -m pwsf.po_export --slot cutscene` 重新导出，
`src/slot/` 就只剩过场那 5 个文件（已有译文按 msgid 回填，不会丢）。

> `po_export` **默认不再生成 `pwsf.pot`**。它把所有语料合并成一份空模板，
> 只是给翻译平台导入用的；`po_lint` / `po_import` 都不会读它，在里面翻译
> 没有任何效果。需要时用 `--pot`。

细节与硬性规则（`<I=...>`、格式符、换行）见 `src/README.md`。

# 补丁打包（已实现，见 `research/PLANS/07` 与 `README.md` §给别人装）
`po_lint` / `po_import` / `install` 已落地（见计划 06 §9），「装一份汉化」
已从跑命令变成发补丁：

1. `pwsf/patch.py` 复用 `po_import` 的构建与 `MANIFEST.tsv`，打成
   `research/BUILD/pwsf_patch/`：只含被替换的游戏文件 + 清单 + `files.tsv`
   （`dest,payload` 两列，给 `.bat` 解析）+ 食用说明 + 两个静态 `.bat`。
2. 整文件打包，不做 delta：`_probe_patch1.py` 实测 SLOT.DAT 改 17.4%（544MB
   散在 109 处）、字体重建改 51%（17MB / 3408 处），且都嵌套加密/压缩，
   delta 既不小也不好做。
3. **不校验游戏原版哈希**：安装器只做「无 `.orig` 先备份 + 覆盖」，玩家
   自己确认 Steam 游戏是最新原版（验证完整性）。理由与取舍见 PLANS/07。
   开发侧 `pwsf.install` 仍保留 `verify_game=True` 的严格状态机。
4. 备份与还原沿用 `config.BACKUP_SUFFIX`（`*.orig`）与 `pwsf.install`
   那套（`pwsf.install --restore` 与成品补丁的 `restore.bat` 互为可逆）。
5. 入口 `python -m pwsf.patch [--build [--zip] | --install | --restore]`；
   PoC `_poc_text_cn.py` 保留作证据，不再作为安装手段。
6. 静态 `.bat` 放 `tools/build/`，打包时 `shutil.copy2` 进包，不再内嵌生成。

# Packages
| 模块 | 作用 |
|---|---|
| `pwsf.config` | 路径与常量，支持环境变量 / `pwsf.local.json` 覆盖 |
| `pwsf.crypto` | `name_hash`、游戏定制播种的 MT19937、`buffer_xor_decrypt` |
| `pwsf.olang` / `pwsf.olang_build` | RBX 文本表读 / 写（往返字节一致） |
| `pwsf.briefing` | CODEC / BRIEFING 容器与字节码遍历 |
| `pwsf.briefing_build` | CODEC 写回：文本池原地重写 + 偏移表重建 + 复验 |
| `pwsf.archive` / `pwsf.archive_index` | PDT / DAT 归档，payload 解密 + CRC-32 |
| `pwsf.names` | `entry_name_hash` / `str_hash24` / 扩展名表 |
| `pwsf.xpr` / `pwsf.font` / `pwsf.font_build` | XPR2 容器、ATG 字体、字形补齐与整表重建 |
| `pwsf.subtitle` | 游戏内字幕导出 |
| `pwsf.po` / `pwsf.po_export` | gettext `.po` 读取与语料导出 |
| `pwsf.slots` | `.po` 引用 ↔ 二进制槽位，校验与写回共用 |
| `pwsf.po_lint` | 译文编译前的全部校验，error 即阻断 |
| `pwsf.slotdat` / `pwsf.slotdat_build` | `SLOT.DAT`（过场文字所在）：两层 XOR 解密 / 重建整个容器 |
| `pwsf.po_import` | 译文 → 重建 olang + SLOT.DAT + 字体 + 清单 |
| `pwsf.install` | 按清单备份 / 写入 / 校验 / 还原 |
| `pwsf.launch` | 启动游戏；`--install-shim` 用自编 shim 顶替 Steam 启动器 |

`research/TOOLS/pwsf_*.py` 只是指向本包的兼容垫片，让既有探针零改动运行。

# Launch
```powershell
python -m pwsf.launch             # 直接启动
python -m pwsf.launch --steam     # 走 Steam（steam://run/2492660）
python -m pwsf.launch --dry-run   # 只打印命令
python -m pwsf.launch --wait      # 挂到游戏退出
python -m pwsf.launch -- -lan fr  # 换参数（-- 之后原样传给游戏）
```

两个坑它替你绕掉了：**工作目录必须是游戏目录**（字体按 `"."` 查找），
且 `-lan` 必须给、必须拼对（`en fr gr it sp pt`），否则会静默落到日语分支
——而日语资源在 Steam 版并未发布。

`--steam` 与直接启动的区别：走 Steam 的话 overlay、云存档、手柄配置都在，
且跑的是 `launcher.exe`（装了 shim 就是 shim）；没装 Steam 或想绕开它时
用默认方式。完整参数说明见 `research/ANALYSIS/07_launch_args.md`。

## 跳过 Steam 启动器
Steam 点「开始游戏」跑的是 `launcher\launcher.exe`（一个 Unity IL2CPP
前端）。可以把它换成我们自己编的小 shim，直接起游戏：

```powershell
python -m pwsf.launch --install-shim   # 编译 + 备份 launcher.exe.orig + 替换
python -m pwsf.launch --status         # 当前是原厂启动器还是 shim
python -m pwsf.launch --restore-shim   # 还原
python -m pwsf.launch --build-shim     # 只编译到 research/BUILD/
```

- 需要 Visual Studio 的 `cl`（自动探测 `VsDevCmd.bat`）
- 源码 `pwsf/shim/launcher_shim.c`，**不反编译原启动器**，只是「切目录 →
  起游戏 → 等它退出」，等退出是为了让 Steam 一直显示「运行中」
- 编出来是 `/subsystem:windows`，不会闪控制台窗口
- 行为由 `launcher\pwsf_launch.ini` 控制（`dir` / `exe` / `args`），
  改启动参数改 ini 就行，不用重新编译
- 备份与还原沿用全局约定：`launcher.exe.orig` + `--restore-shim`

shim 的功能验证（`_probe_cl.py` 与 shim 源码里的说明）：以 `cmd.exe` 代替
游戏跑一遍，检查读 ini、切工作目录、CreateProcess、等待并回传退出码。

# 从哪读起
- `research/PLANS/00_overview.md` — 模块进度与加密总览
- `research/ANALYSIS/01_olang_text.md` — 文本表格式与写回
- `research/ANALYSIS/05_font.md` — 字体格式与扩字形
- `research/PLANS/06_localization_pipeline.md` — 汉化管线设计
- `research/ANALYSIS/08_cutscene_text.md` — 过场文字：`SLOT.DAT` 两层 XOR + 内嵌 olang
- `src/README.md` — 译者须知
