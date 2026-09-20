# Peace Walker Sans Frontiers

> [!WARNING]
> AI 大模型使用: Claude Opus 5, Tencent Hunyuan 4-dev, Tencent Hunyuan 3

METAL GEAR SOLID PEACE WALKER（Steam 版）本土化工具链。

游戏的文本、字体、归档格式全部从 x64 二进制逆向取得。证据链在
`research/ANALYSIS/`，逐条给出 IDA 地址；工作拆分在 `research/PLANS/`。
所有结论都要求实证，不接受推断。

当前状态：**UI 文字、游戏内字幕、CODEC 台词、过场（漫画）文字已全量提取**；
汉化管线**olang 与过场两侧都已闭环**——在 `.po` 里填译文 → 校验 →
编译（重建文本表 / 重建 `SLOT.DAT`（544 MB）+ 自动补字形，`--rebuild-font`
可整表重建字库）→ 备份后装入游戏 → 一键还原。
CODEC 回写仍卡在字节码长度规则上（能提取，不能写回）。

过场文字不在磁盘那 17 个 `.olang` 里，而是塞在 `MLG/disc0_rel/002aba34.DAT`
（`SLOT.DAT`）内嵌的 144 张 olang 表中 —— 详见
[`research/ANALYSIS/08_cutscene_text.md`](research/ANALYSIS/08_cutscene_text.md)。

## 目录

```
pwsf/        工具包（成熟、可复用的实现）
src/         翻译工作区，42 个分块 .po（olang 4 + codec 12 + slot 26）
             译者须知见 src/README.md
research/
  ANALYSIS/  逆向文档 + 提取产物 + 证据图
  PLANS/     工作拆分，00_overview.md 是索引
  TOOLS/     取证脚本：_probe_* 是证据，_poc_* 是端到端验证
  BUILD/     重打包产物（gitignore）
```

## 安装

Python 3.13，除字体构建用到的 Pillow 外无第三方依赖。

```powershell
pip install pillow
```

## 配置

`pwsf/config.py` 会自动探测 Steam 库（含 `libraryfolders.vdf` 里的额外库）
并定位游戏目录，通常无需配置。需要覆盖时按优先级：

1. 环境变量 `PWSF_GAME_DIR` / `PWSF_FONT_TTF` / `PWSF_PO_DIR` / `PWSF_OUT_DIR`
2. 仓库根的 `pwsf.local.json`（已 gitignore）

```json
{
  "game_dir": "D:/Games/MGS_PW/mgspw",
  "font_ttf": "C:/Windows/Fonts/simhei.ttf"
}
```

```powershell
python -m pwsf.config                  # 查看当前解析结果
python -m pwsf.config --init           # 按当前解析结果生成 pwsf.local.json
python -m pwsf.config --init --force   # 覆盖已有文件
python -m pwsf.config --print-default  # 只打印内容，不落盘
```

`--init` 写出的是**全部**可覆盖项（`game_dir` / `font_ttf` / `po_dir` /
`out_dir` / `po_chunk`），填的是此刻探测到的值，改哪项删哪项都可以。

## 常用命令

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

# 汉化管线：校验 -> 编译 -> 安装
python -m pwsf.po_import --install   # 一条龙：体检 + 编译 + 复验 + 装进游戏
python -m pwsf.install --restore     # 还原

python -m pwsf.po_lint             # 只体检，有 error 就别编译
python -m pwsf.po_import           # 只编译 -> research/BUILD/*.olang + *.xpr + MANIFEST.tsv
python -m pwsf.install             # 只看状态，不写任何东西
python -m pwsf.install --install    # 只装已编译好的产物
```

`po_import` 会先跑 `po_lint`，不过不编译；构建完再把产物解密回来逐槽位复验，
**除声明要改的槽位外必须与原文逐字节相同**。`install` 靠清单里的哈希判断
现场文件是原文、是本次构建、还是别的东西，认不出来就拒绝写入。
设计与实测见
[`research/PLANS/06_localization_pipeline.md`](research/PLANS/06_localization_pipeline.md)。

```powershell
# 证据脚本（数字都由它们复现）
python research\TOOLS\_probe_po3.py   # 全链，以 PoC 实机产物为标尺
python research\TOOLS\_probe_po4.py   # 每条校验各自触发，正确译文不报
python research\TOOLS\_probe_po5.py   # 安装状态机与拒绝路径
```

## 翻译流程：动哪些文件

```
src/
  olang/olang_01..04.po   UI 文字 + 游戏内字幕    1,513 条   能写回
  codec/codec_01..12.po   CODEC / 简报台词        4,746 条   只能看，写回没做
  slot/slot_01..26.po     SLOT.DAT 内嵌文本      10,073 条   能写回（过场 1,858 条）
  MANIFEST.tsv            分块索引
```

合计 16,332 条。**只改这三个子目录里的 `.po`**，往 `msgstr ""` 里填中文。

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

第 3、4 步可以合并成 `python -m pwsf.po_import --install`。

只译了几条也能跑：未填 `msgstr` 的槽位保持英文，可以边翻边看。

只想翻过场：`python -m pwsf.po_export --slot cutscene` 重新导出，
`src/slot/` 就只剩过场那 5 个文件（已有译文按 msgid 回填，不会丢）。

> `po_export` **默认不再生成 `pwsf.pot`**。它把所有语料合并成一份空模板，
> 只是给翻译平台导入用的；`po_lint` / `po_import` 都不会读它，在里面翻译
> 没有任何效果。需要时用 `--pot`。

细节与硬性规则（`<I=...>`、格式符、换行）见
[`src/README.md`](src/README.md)。

## 下一步：把管线包成补丁

`po_lint` / `po_import` / `install` 已落地（见计划 06 §9），下一步把
「装一份汉化」从跑三条命令变成发一个补丁。给实现者的指示：

1. 新增 `pwsf/patch.py`：复用 `po_import` 的构建与 `MANIFEST.tsv`，
   打成 `research/BUILD/pwsf_patch/`，只含被替换的游戏文件 + 清单 + 校验和，
   不要整目录打包
2. 清单已记原始文件哈希（`orig_sha256`），`pwsf.install` 的判据照搬即可；
   再补上 `pwsf/` 的 git 描述，好让玩家报的问题能对上版本
3. 备份与还原**不要另造**：沿用 `config.pristine` / `config.BACKUP_SUFFIX`
   与 `pwsf.install` 那套状态机（拒绝路径见 `_probe_po5.py`）
4. 入口 `python -m pwsf.patch [--build|--install|--restore|--verify]`，
   PoC 脚本 `_poc_text_cn.py` 保留作证据，不再作为安装手段
5. 面向不装 Python 的玩家再包一层（zip + 一个 `.bat`，或单文件可执行）
6. 设计与实机结论写成 `research/PLANS/07_patch.md`，并把本节替换成实际命令

## 包结构

| 模块 | 作用 |
|---|---|
| `pwsf.config` | 路径与常量，支持环境变量 / `pwsf.local.json` 覆盖 |
| `pwsf.crypto` | `name_hash`、游戏定制播种的 MT19937、`buffer_xor_decrypt` |
| `pwsf.olang` / `pwsf.olang_build` | RBX 文本表读 / 写（往返字节一致） |
| `pwsf.briefing` | CODEC / BRIEFING 容器与字节码遍历 |
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

`research/TOOLS/pwsf_*.py` 只是指向本包的兼容垫片，让既有探针零改动运行。

## 直接启动游戏（绕过启动器）

**工作目录必须是游戏目录**，否则字体加载失败（安装根目录默认是 `"."`）。

```powershell
cd "C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
& ".\METAL GEAR SOLID PEACE WALKER.exe" -lan en -region eu -selfregion EU -ctrltype XS
```

`-lan` 必须给且拼对（`en fr gr it sp pt`），否则会静默落到日语分支，
而日语资源在 Steam 版并未发布。完整参数说明见
[`research/ANALYSIS/07_launch_args.md`](research/ANALYSIS/07_launch_args.md)。

## 从哪读起

- [`research/PLANS/00_overview.md`](research/PLANS/00_overview.md) — 模块进度与加密总览
- [`research/ANALYSIS/01_olang_text.md`](research/ANALYSIS/01_olang_text.md) — 文本表格式与写回
- [`research/ANALYSIS/05_font.md`](research/ANALYSIS/05_font.md) — 字体格式与扩字形
- [`research/PLANS/06_localization_pipeline.md`](research/PLANS/06_localization_pipeline.md) — 汉化管线设计
- [`research/ANALYSIS/08_cutscene_text.md`](research/ANALYSIS/08_cutscene_text.md) — 过场文字：`SLOT.DAT` 两层 XOR + 内嵌 olang
- [`src/README.md`](src/README.md) — 译者须知
