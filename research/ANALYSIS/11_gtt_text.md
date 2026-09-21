# 11 · `GTT\x00`：SLOT.DAT 里的第二套文本容器

起因：实机里 Miller 的无线电台词

```
There's no one around - why not try
some shooting practice?
```

在所有已提取语料里都找不到（09 §1），全盘容器 payload 也全量解密搜过了
（09 §9、§10），FEL 也证否了。**它其实一直在 SLOT.DAT 里，装在一个我们从没
解析过的池类型 `GTT\x00` 中** —— 08 §8.3 早就记下「462 个，没解」，一直没动。

```
rec 84 / pool 0x1c79f20b / block 0x440
"There's no one around - why not try\nsome shooting practice?"
```

---

## 1 结论速览

| 项 | 值 |
|---|---|
| 位置 | `002aba34.DAT`（SLOT.DAT）记录 **0..365**，**216 个池**（跨记录重复出现 462 次） |
| 池 id 类别 | `0x1c??????`（对比：文本 RBX = `0x20??????`、FEL = `0x5e??????`） |
| **一个文案集 = 每种语言一个池** | 36 个集 × 6 个池；英文是 base id，其余按固定偏移：`fr +0x24`、`de +0x37`、`it +0x86`、`+0xa2`、`es +0x1c2` |
| 英文池的行数 | 36 个池 → 8,136 行 |
| **去重后英文语料** | **2,238 条** → `ANALYSIS/_gtt_lines.tsv`（只导英文，与 olang / CODEC 一致） |
| 与 BRIEFING 完全相同 | **0** 条 |
| 与 SLOT 的 RBX 文本 / STAGEDAT / 17 张 olang | 96 / 4 / 8 条 |
| 在 STAGEDAT 内嵌文件里 | **0 个**（`_stagedat_files*.tsv` 里 `47545400` 计数为 0） |

> 第一版把 6 种语言一起导了，出来 11,118 条里混着法/德/意/西（≈5 倍水分）。
> 判据是所有 181 个池按上面的偏移能聚成 36 组、无单例，且每组的 base 池
> 恰好是纯 ASCII 那一批；`pwsf.gtt.english_pools()` 就是这个规则。

内容是**任务内无线台/提示台词**：`Miller here. Do you copy, Snake?` /
`I'm sending this from the offshore\nplant - our Mother Base.` /
`The signal is unidirectional.` / `That area is not part of the mission.` /
`Stay focused on the mission, Snake.` / `Head north.` … 平均长度 46 字符。

## 2 为什么之前没看到

* `slotdat_find_res_entry` @ `0x1400A61F0` 只收 `(id & 0x7F000000) == 0x20000000`
  的池 —— GTT 是 `0x1c` 类，**根本不进这条资源通路**；我们的提取（`pwsf.slotdat.
  embedded_olang`）只认 `RBX\x00` 开头的池。
* exe 里同样没有 `GTT\0` 魔数（`find_bytes` 0 处）、没有 `545447` 立即数、
  没有 `GTT` 字面量 —— 与 FEL 一样，是按「已知类型」交给子系统的。

## 3 格式

一个池是**若干个 GTT 块首尾相接**（池 0x1c79f20b 有 98 个块）。块头：

| 偏移 | 类型 | 说明 |
|---|---|---|
| `+0x00` | `47 54 54 00` | `GTT\x00` |
| `+0x04` | u32 | `n` = 本块的行数 |
| `+0x08` | u32 | `pool_off` = 头长度 = 字符串区起点 |
| `+0x0c` | u32 | id（每块不同，用途未定） |
| `+0x10` | u16, u16 | 未定 |
| `+0x14` | u32 | 恒 1 |
| `+0x18` | u32 | 恒 0 |
| `+0x1c` | u16 数组 | 长度 `4 + 10*n` |

数组布局（n=1/2/3/5 四个块上一致，长度严格 `4+10n`）：

```
[0..3]          = 4 份「第 1 行」的起始偏移
之后每行 10 个: [a, b, 1, X, X, X, Y, Y, Y, Y]
                 X = 第 i+1 行起始偏移，Y = 第 i+2 行起始偏移
                 最后一组是零填充
```

### 3.1 `a` / `b` 是时间轴（`_probe_gtt8.py`）

一开始以为是「指向共享尾巴的指针」—— 那是**数值大小撞车**的错觉：池内偏移和帧号
都是小整数。判决实验：

| 假设 | 判据 | 结果 |
|---|---|---|
| 指针 / 偏移 | 必须 `< len(pool)` | `a` 越界 618 次、`b` 越界 3,672 次 → **死** |
| LZ77 距离 | 距离 ≤ 当前位置 | 同样被越界否掉 |
| **时间轴** | 单调、`a[i+1] >= b[i]`、`(b-a)` 随行长增长 | `a[i+1]-b[i]` 中位 **3**（0~7 占绝大多数，13,602 组里只有 24 个负值）；`(b-a)/行长` 中位 **1.35** → **成立** |

即 `[起始帧, 结束帧, 1, X,X,X, Y,Y,Y, Y]`。帧率未定（30 fps 约 22 字/秒，
60 fps 约 45 字/秒，都合理）。样例：

```
a= 58 b=117 dur= 59  len=48  'the drug will eventually put the e...'
a=119 b=201 dur= 82  len=64  'So one way to get past an enemy is...'
a=201 b=240 dur= 39  len=31  'and then wait for them to drop.'
```

> 这条推翻了下面 §6 记的「未证风险」：**改英文串不会连带影响其它语种** ——
> `a`/`b` 不是指针，而且每种语言各有自己的池（同组池字节数完全相同、内容各异）。

字符串区是**后缀合并**的：一段 NUL 串 = 「共享片段」紧接「一整行本语言」，
例如

```
0040 len=34 'Je t\xe2The signal is unidirectional.'
             ^^^^^ fr 头        ^^^^^^^^^^^^^^^^^^^^^^^^ 英文整句 @0x45
0063 len=69 "rme en mI'll be giving you commands and advice\nthrough this channel."
```

所以**一行 = `pool[start : 下一个 NUL]`**，start 取头里的 X（第 0 行是 0）。
其它语言只剩「头片段」（`Je t\xe2` / `rme en m` / `K\xc3\xbcste -` /
`marittima, la` / `de la pl`），尾巴靠共享 —— 这也是 08 §8.3 说的
「按 NUL 切开会出现 `n.` / `Cett` 这种碎片」的原因。

## 4 复现

```powershell
python research\TOOLS\_probe_gtt1.py                 # 找池 + needle（首次命中）
python research\TOOLS\_probe_gtt2.py                 # 单块：块边界 + 头 + 字符串区
python research\TOOLS\_probe_gtt3.py --block 3       # 头部 u16 逐项当偏移试读
python research\TOOLS\_probe_gtt4.py --pool-text     # 池按 NUL 分段（看合并）
python research\TOOLS\_probe_gtt5.py                 # 提取 -> ANALYSIS/_gtt_lines.tsv
```

## 5 未闭合

## 5 写回（已实现：`pwsf/gtt.py`）

**策略：原地改写，池长度一字不变。** 理由：头部那两个未识别的 u16（`a` / `b`）
有的会超出池长度（block 1 的 `b = 324` > 池 312 B），所以它们不是池内偏移，也
不能按「相对 X 的偏移」重算；唯一安全的做法就是让每个偏移继续指向原来的位置。

于是约束和 CODEC 一样（03 §9）：**一条译文的字节数不得超过它替掉的英文行**。
新字节落在原偏移上，剩下的原行程补零，收尾那个 NUL 还在原处。

| 环节 | 实现 |
|---|---|
| 语料 | `python -m pwsf.gtt` → `ANALYSIS/_gtt_lines.tsv`（2,238 行，带 pool/block/id/budget/record） |
| 引用 | `gtt/<pool_id>/<block_off>/<line>`，如 `gtt/0x1c79f20b/0x440/0` |
| 导出 | `po_export` → `src/gtt/gtt_01..06.po`（`--gtt none` 可关） |
| 体检 | `po_lint` 的 **`gtt-budget`**：超预算是 ERROR，不给编译 |
| 编译 | `po_import` → `slotdat_build.rebuild(..., gtt=...)`，GTT 池和 RBX 池一起重排 |
| 复验 | 重建后的容器再读一遍：译文读回一致、其它 48,666 行仍是英文 |

预算实测（英文 2,238 条）：最小 4 B、中位 43 B、最大 99 B；`>=12 B` 98%、
`>=24 B` 89%、`>=36 B` 66%、`>=48 B` 40%。`<12 B` 只有 48 条（就是 `Hm?`
`Huh?` 那类极短喊话），绝大多数行放得下中文。

证据：

* `_probe_gtt7.py` —— 462 个池全量**往返字节一致**；改一条只动那条的行程
  （37 B），长度不变，超预算写入被拒绝。
* `_poc_gtt_writeback.py` —— 端到端：一条中文写进重建的 SLOT.DAT（2 个区域副本
  记录被重排，7 s），读回 `周围没人——要不要\n练练射击？`，其余 GTT 行全部完好，
  `slotdat_build.verify` 无问题。
* `_poc_gtt_writeback.py --lint` —— 超预算译文被 `gtt-budget` 拦下（87 B vs 9 B），
  符合预算的放行。

## 6 未闭合

1. **只出英文**：其它 5 语只有头片段（`Je t\xe2` / `rme en m` / `K\xc3\xbcste -`），
   `a` / `b` 含义未定 —— 没有 `--ref-langs` 参考译文，也**不能**写非英语槽位
   （`po_lint` 报 `target`）。
2. `+0x0c` 的 id 用途未知（很可能是台词 id；写回时原样保住）。
3. **打破长度限制**得先解出 `a` / `b`，才能重排池（整池重建、放弃合并）。
   在那之前超预算的行只能保持英文。
4. ~~未证风险：`a`/`b` 若是指向英文串的共享尾巴指针，改英文会连带影响其它语种。~~
   **已推翻（§3.1）**：`a`/`b` 是时间轴，且每种语言各有自己的池，改英文不影响
   其它语种。剩下只需做一次普通实机验证：装一份带 GTT 译文的构建，看任务里
   Miller 那句是不是中文、显示时长是否够读。
