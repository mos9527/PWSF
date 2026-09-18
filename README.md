# PWSF — Peace Walker Sans Frontiers

> [!IMPORTANT]
> AI Usage Disclaimer: Claude Opus 5, Tencent Hunyuan 4-dev, Tencent Hunyuan 3

METAL GEAR SOLID PEACE WALKER（Steam 版）本土化工具链。

游戏的文本、字体、归档格式全部从 x64 二进制逆向取得。证据链在
`research/ANALYSIS/`，逐条给出 IDA 地址；工作拆分在 `research/PLANS/`。
所有结论都要求实证，不接受推断。

当前状态：**UI 文字、游戏内字幕、CODEC 台词已全量提取；olang 与字体的写回
链路均已实机验证**——改文本 + 自动补字形 → 装入游戏 → 正常显示中文。

## 目录

```
pwsf/        工具包（成熟、可复用的实现）
src/         翻译工作区，16 个分块 .po；译者须知见 src/README.md
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
python -m pwsf.po_export                           # 英文原文 -> src/ 下 16 个 .po
python -m pwsf.po_export --chunk 200               # 改分块粒度
python -m pwsf.po_export --ref-langs fr,de,it,es   # 附带其他语言参考译文
```

字体与文本的写回目前由 `research/TOOLS/` 下的 PoC 脚本驱动；
统一的 `po_import` / `lint` / `install` 还在做，见
[`research/PLANS/06_localization_pipeline.md`](research/PLANS/06_localization_pipeline.md)。

```powershell
cd research\TOOLS
python _poc_text_cn.py             # 构建 + 校验到 research/BUILD
python _poc_text_cn.py --install   # 备份 .orig 后装入游戏
python _poc_text_cn.py --restore   # 还原
```

## 下一步：管线闭环后做补丁

计划 06 的 `po_import` / `po_lint` / `install` 全部落地后，接着把「装一份汉化」
从跑脚本变成发一个补丁。给实现者的指示：

1. 新增 `pwsf/patch.py`：`src/` 的 `.po` → lint（计划 06 §6，不过不许继续）→
   构建 olang 与字体 → 产出 `research/BUILD/pwsf_patch/`，只包含被替换的游戏
   文件、一份清单和校验和，不要整目录打包
2. 清单里记原始文件的哈希与 `pwsf/` 的 git 描述；安装前比对原始哈希，
   游戏更新导致不匹配时**拒绝安装**，不要硬写覆盖
3. 安装与还原沿用既有约定：`config.pristine` / `config.BACKUP_SUFFIX` 的
   `.orig` 备份、`config.installed_backups()`，别另造一套备份机制
4. 入口为 `python -m pwsf.patch [--build|--install|--restore|--verify]`，
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
| `pwsf.xpr` / `pwsf.font` / `pwsf.font_build` | XPR2 容器、ATG 字体、字形补齐 |
| `pwsf.subtitle` | 游戏内字幕导出 |
| `pwsf.po` / `pwsf.po_export` | gettext `.po` 读取与语料导出 |

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
- [`src/README.md`](src/README.md) — 译者须知
