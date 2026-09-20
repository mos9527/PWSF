# tools/ —— 机翻工具链

独立于 `pwsf` 包，只做三件事：扫术语、定术语表、批量机翻 `src/*.po`。

```
poio.py          极简 .po 读写（保持原文件字节与换行风格）
scan_terms.py    扫全部 msgid：抽候选专名、查术语表覆盖率与漏网高频词
terms.tsv        术语表，245 条。机翻一致性的唯一依据
translate.py     批量机翻：分批调 API → 本地校验 → 自动修复 → 写回
```

依赖：`pip install requests`。密钥用环境变量，不要写进仓库：

```powershell
$env:OPENROUTER_API_KEY = "sk-or-v1-..."
```

## 一次完整流程

```powershell
# 1. 看一眼会发给模型的 prompt（不花钱）
python tools/translate.py --dry-run

# 2. 小步试跑，确认质量与术语生效
python tools/translate.py --group olang --limit 40

# 3. 正式批量（按分区跑，别一次全开）
python tools/translate.py --group olang --workers 6
python tools/translate.py --group slot  --workers 6
python tools/translate.py --group codec --workers 6   # 最严：有字节预算

# 3.5 codec 有字节预算，翻完基本必然要压一轮
python research\TOOLS\_probe_codec_budget.py              # 行级账目，超在哪一行
python research\TOOLS\_probe_codec_budget.py --shrink-all # 把比英文长的译文压回去
python research\TOOLS\_probe_codec_budget.py --fix        # 压完仍超的记录，记录级精修

# 4. 回到 pwsf 管线验收
python -m pwsf.po_lint
python -m pwsf.po_import --install
```

`codec-budget` 是硬 error（记录不能搬家，`ANALYSIS/03` §9.2），不压到
`po_lint` 通过就编译不了。判据很朴素：只要每行译文都比对应英文短，
`need` 就必然 ≤ 英文用量 ≤ `budget`，所以 `--shrink-all` 是根治，
`--fix` 只是给压不动的记录补刀（模型压不到的最后几十字节要人工改）。

## translate.py

| 参数 | 默认 | 说明 |
|---|---|---|
| `--file` | — | 指定 .po，可多次；与 `--group` 二选一 |
| `--group` | — | `olang` / `codec` / `slot`，逗号分隔 |
| `--limit N` | — | 最多处理多少条（试跑用） |
| `--batch` | 25 | 每请求多少条。太大模型会漏换行，20~30 合适 |
| `--workers` | 4 | 并发 |
| `--model` | `deepseek/deepseek-v4.1-flash` | |
| `--reasoning` | `none` | 关思考，省钱。`low/medium/high/omit` |
| `--thinking` | 关 | `--thinking` 才打开模型侧 thinking |
| `--context` | 关 | 把 `#.` 注释（说话人/时间轴）一起发给模型 |
| `--force` | 关 | 已译的也重翻 |
| `--include-all` | 关 | 连代号/数字也送翻（默认跳过 744 条） |
| `--no-terms` / `--no-repair` / `--no-shrink` | — | 关掉对应环节 |

流水线每批走四步：

1. **注入术语**——只注入本批文本里命中的术语，长串优先
2. **校验**——`<I=XX>`、`%d` 占位符、换行数、空译文
3. **重译修复**——不过的条目单独重发一轮（`REPAIR_SYSTEM`）
4. **压缩**——CODEC 译文 UTF-8 超过英文的再压一轮（池预算只剩 555 字节）

已填 `msgstr` 的条目自动跳过，随时中断随时续跑；失败明细进 `tools/translate.log`。

> 一个文件只由一个进程写：**不要**同时开两个 `translate.py` 跑同一批文件。
> 进程内同一文件的多个批次是安全的（按文件串行 + 每次重读磁盘最新内容，
> 见 `poio.commit`），但两个进程之间没这层保护。按 `--group` 分开跑即可。
>
> 历史 bug：写回曾拿启动时的行快照当基底整文件重写，同文件多批并发会
> 互相覆盖，表现为 diff 位置每轮都变且不累积。2026-09 修掉，改成
> `poio.commit` 重读 + per-file lock。

## 术语表 terms.tsv

```
en	zh	cat	note	[ci=1]
Snake	SNAKE	char	主角自称/他人称呼，全篇统一
Design Specs	开发规格	sys		ci=1
```

- `cat`：`char` 人物 / `org` 组织 / `place` 地点 / `mech` 机体 / `sys` 系统 /
  `ui` 界面 / `item` 物品 / `weapon` 武器 / `other`
- `zh` 写成英文 = 原样保留（人名走这一路）
- 第 5 列 `ci=1` 才忽略大小写

### 命名规则

- **人名按 MGS3 重制官方写法保留全大写**：`SNAKE`、`NAKED SNAKE`、
  `BIG BOSS`、`THE BOSS`、`ZERO`、`EVA`、`SIGINT`
- **PW 独有角色用中文音译**：帕兹、卡兹、奇科、阿曼达、休伊、斯特兰奇洛夫、
  科尔德曼、加尔维斯、塞西尔、扎多尔诺夫
- 组织缩写一律保留：`MSF`、`CIA`、`FOX`、`Cipher`、`CQC`、`GMP`
- 系统名词意译：`Mother Base` 母基地、`Heroism` 英雄度、`EXTRA OPS` 额外任务
- 西语地名意译：`Isla del Monstruo` 怪物岛、`Puerto del Alba` 黎明港

### 匹配规则（别乱改）

默认匹配**「原形 或 全大写」+ 词边界**，这是实测定下来的：

- UI 文本大量全大写（`MOTHER BASE`、`DESIGN SPECS`、`TARGET`），不覆盖就漏
- 但小写常是另一个词：真蛇 `snake`(14)、`the end`(34)、`us`(138)、
  `staff`(90)、`boss him around`——全大写化会译错

所以只有语义稳定的词才标 `ci=1`（39 条）。`Snake`/`Boss`/`US`/`The End`/
`Staff`/`Zero` **必须保持大小写敏感**。

## scan_terms.py

```powershell
python tools/scan_terms.py                          # 候选专名 top 120
python tools/scan_terms.py --all                    # 全量写 terms_candidates.tsv
python tools/scan_terms.py --terms tools/terms.tsv  # 覆盖率 + 漏网高频词
```

`--terms` 输出两部分：术语表里 0 命中的条目（可删或改写法），以及
语料里高频但术语表没收的词（该补的补）。加完术语再跑一次，直到剩下的
都是噪声（`I`/`C`/`R` 单字母、`FF4040` 颜色码、`MO_MODEL_VIEWER_` 内部串）。

## 已知取舍

脱离上下文逐条翻译，多义词必然有误译。缓解手段是 prompt 规则 8
（`plant` = 工厂/发电站、`magazine` = 杂志）和术语表，但**不能根除**。
建议 `codec` 跑完先抽查一批再进 `po_import`；`po_lint` 只管格式合规，
不管译得对不对。
