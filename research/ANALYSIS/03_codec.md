# 03 · CODEC / BRIEFING（`MLG/disc0_rel/0076531d.DAT`）

状态：**容器格式、语言归属、逐行演出信息均已打通**。

```
2,049 条记录   24,438 行台词   1,750 条记录含语音 ID   1,011 个扇区
报告：ANALYSIS/_briefing_lines.tsv        工具：pwsf.briefing
台词 100% 可 UTF-8 解码（0 个替换字符）
语言归属：2 组 x 6 语言块（ja/en/fr/de/it/es），块内一致率 96~100%
逐行演出信息：843 条记录 / 10,667 行（行号 + 说话人 + 时间轴）
```

---

## 1. 数据位置与解密

`briefing_dat_load` @ `0x1400A5570`：

```asm
1400A5656  mov     rcx, cs:off_140EA4220      ; "009645fa.PDT"（表首项）
1400A565D  add     rcx, 0B60h                 ; +2912 = 第 14 项
1400A5664  call    name_hash                   ; -> name_hash("0076531d.DAT")
1400A5669  mov     edx, cs:dword_14117C094
1400A5672  mov     rcx, cs:qword_14117C098
1400A5679  shl     edx, 0Ch
1400A567C  call    buffer_xor_decrypt
```

`key = name_hash("0076531d.DAT") = name_hash("0076531d") = 0xC4CECBE0`。

`sub_1408C57D0` @ `0x1408C57D0` 建立名为 `"codec thread"` 的线程
（`0x140D7D9B8`），是 CODEC 子系统的入口。

### 1.1 磁盘上是**逐扇区（4096 字节）分别加密**——实测

`_probe_bri47.py` 的穷举判决（判据：16 字节栅格上的记录头魔数命中数 /
512 字节窗口 UTF-8 严格可解码数 / 可打印字节比）：

| 模型 | 魔数命中 | UTF-8 窗口 | 可打印比 |
|---|---:|---:|---:|
| **per-4096（每个扇区独立 seed）** | **2761** | **1519** | **0.549** |
| 连续（全文件一条密钥流） | 6 | 2 | 0.382 |
| 每 16384 一组（16384 对齐） | 664 | 579 | 0.439 |
| 每 8192 一组（8192 对齐） | 1384 | 1088 | 0.487 |

另见 `_probe_bri8.py`（A/B 判决）、`_probe_bri17.py`（块内 keystream 偏移
k=1..3 全文件 0 魔数，证否"块内偏移"模型）。

**块与扇区不对齐**：第 2 块起点是 `file+0x944b0`（非 4096 的整数倍），
记录可（且确实会）横跨扇区。早期代码里 `r.end = min(下一条记录, 扇区末)`
的扇区截断是个 bug——它把大记录的脚本字节码砍掉，使可解出 `0x6d` 的记录
只有 6 条；去掉后是 843 条。

### 1.2 `buffer_xor_decrypt` 与"逐扇区"的矛盾 —— **已定位，未完全闭合**

`buffer_xor_decrypt` @ `0x14010F4C0` 实证（decompile）：

```c
mt_seed(mt, key);  mt_advance(mt, 20);
for (i = 0; i < len >> 2; i++) buf[i] ^= mt_next(mt) ^ 0xB9D3018F;
/* 尾数 len & 3 字节用再一个 mt_next 的低字节依次 XOR */
```

只 seed 一次，密钥流**连续覆盖整个长度** —— 它本身不可能产生逐扇区效果。

`briefing_dat_request_pages` @ `0x140804220` 的汇编（逐行核对）：

```asm
14080422a  mov edi, [rcx+78h]     ; edi = req
14080424f  shr esi, 18h           ; esi = req >> 24 = 页数-1
140804256  lea edx, [rsi+1]
140804259  shl edx, 0Eh           ; 缓冲 = 页数 * 16384
14080426d  lea r8d, [rsi+1]
140804271  sar edi, 8
140804274  shl r8d, 0Eh
14080427b  shr r8d, 0Ch           ; a3 = 4 * 页数   -> dword_14117C094
14080427f  movzx edx, di          ; a2 = (req >> 8) & 0xFFFF  = 扇区号
140804282  call briefing_dat_request
```

即 `buffer_xor_decrypt(buf, 4*页数*4096, key)`，**长度恒 >= 16384**。
（旧文档写的 `dword_14117C094 = (HIBYTE(req)+1) << 2` 取值来源混淆，
`HIBYTE` 在这里实际是 `req >> 24`，已按汇编更正。）

提交路径（本次定位到的，正是原计划要找的 op=7 通路）：

```
briefing_dat_load            0x1400A5570
  -> sub_14008B240           0x14008B240   （薄封装）
  -> briefing_io_submit_request  0x1401208C0
        sub_14045DF30(req, 7, buf, 扇区, 扇区数, ...)
        stub_noop_io_hook(buf + (扇区 << 12), 扇区数 << 12)
        sub_14045D120(handle, req)          提交
```

**`0x14001F870` 是 `xor eax, eax; retn` —— 一个空桩**（已更名
`stub_noop_io_hook`）。所以 `briefing_io_submit_request` 只负责构造并提交
op=7 请求，没有在这里做任何解密。

归档层确实也解密：`archive_read_entry_simple` @ `0x140122730` 在
`entry.flags & 0x10` 时对每个读取单元调用
`buffer_xor_decrypt(chunk, n, *(u32*)(entry + 228))`，且进度累加 `n << 12`
（即读取单元 = 4096 字节扇区）。同族还有 `archive_read_entry_stream`
`0x140122B80`、`archive_read_entry_chunked` `0x140123060`。

**仍未闭合**：`briefing_dat_load` 那条连续 XOR 与归档层那条逐扇区 XOR
若都作用于本文件，两次 XOR 的叠加不可能等于实测的"逐扇区
key=name_hash"（前者周期 4096、后者周期 >= 16384，代数上不相容）。
因此要么本条目的归档层 `flags & 0x10` 未置位，要么 `dword_14117C094`
在提交路径里被改写为 1。**磁盘格式以实测为准（逐扇区 4096）**，工具按实测实现。

---

## 2. 记录头（28 字节，起点 16 字节对齐）

直接来源是 `briefing_record_parse` @ `0x1400A3230`：

| 偏移 | 类型 | 含义 |
|---|---|---|
| `+0x00` | u24 | 记录头魔数 `0x62456F`；与 `+0x03` 合成 `6f 45 62 4e`（**全部记录相同**） |
| `+0x03` | u8 | 魔数第 4 字节 `0x4E` |
| `+0x04` | u32 | `0xFFFFFFFF` —— u32 数组终止符；本文件所有记录该数组为空 |
| `+0x08` | u32 | 运行时计数槽 |
| `+0x0C` | u32 | `off0` → 脚本区 |
| `+0x10` | u32 | `off1` → u32 偏移表 |
| `+0x14` | u32 | `off2` → UTF-8 文本池 |
| `+0x18` | u32 | `off3`（4 字节，多为 0，语义未验证） |

### 2.1 剔除魔数碰撞的假阳性

决定性判据：**脚本区入口必须是合法字节码**（opcode `0x8d`/`0x8e`）。
`_probe_bri18.py` 交叉表：

| | 台词全可解码 | 台词含乱码 |
|---|---|---|
| 入口 opcode 合法 | **2049** | 0 |
| 入口 opcode 非法 | 13 | **601** |

---

## 3. 语言归属 —— **已解决**

### 3.1 结构：2 组 x 6 个连续语言块

| 组 | 语言 | 记录数 | 扇区 | 台词行数 |
|---|---|---:|---|---:|
| 1 | ja | 248 | 0–127 | 2,532 |
| 1 | en | 270 | 148–287 | 4,011 |
| 1 | fr | 258 | 288–439 | 3,579 |
| 1 | de | 254 | 440–590 | 3,617 |
| 1 | it | 251 | 591–735 | 3,421 |
| 1 | es | 258 | 736–876 | 3,611 |
| 2 | ja | 87 | 877–901 | 415 |
| 2 | en | 88 | 901–922 | 828 |
| 2 | fr | 80 | 924–945 | 516 |
| 2 | de | 84 | 945–968 | 577 |
| 2 | it | 84 | 968–990 | 620 |
| 2 | es | 87 | 990–1011 | 711 |

（合计 2,049 条记录 / 24,438 行）

### 3.2 决定性证据（`_probe_bri40.py`）

同一语音 ID `v_bri_amd0010_000_0` 在 6 个位置各出现一次，分别是**同一段
台词的 6 种语言**：

```
sec  47 (ja)  建国以来、<R=祖国,ニカラグア>が自分達の意志で行く先を決められたことは…
sec 192 (en)  Since it was founded, my country has not once been able to choose…
sec 335 (fr)  Depuis qu’il existe, mon pays n’a jamais pu choisir librement son…
sec 488 (de)  Seit es gegründet wurde, konnte mein Land seinen Weg nicht ein Mal…
sec 636 (it)  Fin dalla sua nascita, il mio paese non ha mai potuto scegliere la…
sec 780 (es)  Desde su fundación, mi país nunca ha podido tomar sus propias…
```

早先"按语音 ID 做跨段对齐"被误判为证伪，是因为用了错误的分块边界
（当时按等分扇区段切，而块边界既不按扇区也不等长）。

### 3.3 判定方法与交叉验证

1. **权威判据 = 位置**（`LANG_BLOCKS`，见 `pwsf_briefing.py`）。
   记录头内确实没有语言字段——各块记录头逐字节同构，语言是位置属性。
2. **交叉校验 = 停用词词频**（`judge_lang()`）。块内逐记录一致率
   96~100%（`_probe_bri44.py`）；两种判据冲突 52/2049 = 2%，多为无实词的
   短记录（如 `Snake...`、`Chico.`）。
3. `lang_get_language_id()` @ `0x140027B40` 的 0=en 1=fr 2=de 3=it
   4=es,pt 6=ja 与块序一致（ja 在最前）。

### 3.4 已证伪、勿再尝试

* **按语音 ID 做跨段对齐**：不是假说错，是边界错。见 §3.2。
* **`dword_141495DE0` 是语言索引**：错。`sub_1405E06E0`（已更名
  `briefing_menu_state_machine`）@ `0x1405E07CB` 读它是
  **TOPIC → 请求字**表：

  ```c
  swprintf(Buffer, 15, "TOPIC_%03d", topic->no);
  sub_1408045E0(Buffer, dword_141495DE0[topic->briefing_idx]);
  ```

  该表运行时由 `briefing_topic_req_table_load` @ `0x14025A6C0` 从脚本
  token 流填充：循环取 `briefing_script_next_keyword()`，当关键字 ==
  `3918807`（`0x3BCB57`）时把下一个 token 的 u24 值顺序写入。静态内容为
  全 `0xFFFFFFFF`。**与语言无关。**
* **`<R=>` 与 olang 的 `<I=>` 有对照关系**：无关。olang 的 `<I=...>`
  是**手柄按键图标**（`ATK` / `CAMERA` / `MOVE` / `△` / `AIM`…，101 种 /
  2,892 次），与振假名不是一类东西。

---

## 4. 台词区与富文本

```
off1 -> 偏移表（u32，严格递增，首项为 0）
off2 -> 文本池（NUL 结尾的 UTF-8 串连续存放）
串数 n = (off2 - off1) / 4        第 i 串从 off2 + table[i] 开始
```

### 富文本标记 `<R=表示,よみ>`（振假名 ruby）

实测 **188 种取值 / 330 次**，分布在 270 条记录。全部含逗号，无单参形式。

```
<R=ZEKE,ジーク>×18   <R=FSLN,サンディニスタ>×12   <R=人工知能,AI>×11
<R=研究施設,ラボ>×9  <R=列車車庫,ターミナル>×8    <R=機械,マシン>×8
<R=幽霊,ファンタズマ>×7                          <R=相互確証破壊,MAD>
<R=海洋温度差発電,OTEC>                          <R=米州機構,OAS>
```

> 渲染函数**尚未定位**：二进制里没有 `<R=` 字面量（`0x140AB037D` 处那个
> `<R>` 落在浮点常量数组里，是误命中），推测是逐字符比较 `'<'` `'R'` `'='`。

---

## 5. 脚本区与字节码

```
v11   = v10 + off0
pool  = v11 + 4                    (A->pool)
entry = v11 + u32@(v11) + 8        (A->entry)  <- 解释器从这里起步
tbl   = a1 + 4                     (A->tbl)
```

### 5.1 两套解码器（不可混用）

| 函数 | 用途 | 覆盖 |
|---|---|---|
| `briefing_insn_operand` `0x1400A4770` | 解释器主循环的**长度**解码 | `op & 0xF` 为 0..12 即长度，13/14/15 → 后随 u8/u16/u24 |
| `briefing_insn_decode` `0x1400A4B40` | **完整**指令解码（表达式、实参区） | 上表 + `op & 0xC0 == 0xC0` 是 1 字节 + `op & 0xF0 == 0` 的低操作码表，其中 **`0x07` = 后随 u8 长度的字符串字面量** |

遍历整段字节码**必须**用后者。用前者遇到 `0x07` 会失步——实测改用完整
规则后，能解出 `0x6d` 的记录从 8 条涨到 843 条。

### 5.2 解释器 `briefing_script_run` @ `0x1400A35C0`

按 `op & 0xF0` 分派：

* **`0x30`**：`acc = sub_14013CD90(payload)`。**`sub_14013CD90`（已更名
  `briefing_expr_eval_rpn`）不是文本取值器，而是 RPN 表达式求值器（栈机）**：
  压入操作数，遇到 `op & 0xE0 == 0xA0` 的字节就按 `op & 0x1F` 取运算符
  （1=`-`单目 2=`!` 3=`~` 4=`+` 5=`-` 6=`*` 7=`/` 8=`%` 9=`<<` 10=`>>`
  11=`==` 12=`!=` 13=`<` 14=`<=` 15=`>` 16=`>=` 17=`|` 18=`&` 19=`^`
  20=`||` 21=`&&` 22=赋值 23=`,`）作用于栈顶两项，结果存
  `qword_1410A23D8`。（这更正了旧文档"0x30 = 文本"的假设。）
* **`0x60`**：外部调用。`payload[0..2]` = u24 处理器 id，在
  `qword_141103DF0` 链表里查处理函数，实参由
  `briefing_call_args_build` `0x1400A53D0(payload+3, &n)` 构造后调用。
* **`0x70`**：按 id 调子程序（`sub_1400A3980` 查表 → 递归解释器）。

### 5.3 顶层结构（`0x6d` 在第 5 层）

记录 0 实例：

```
0x60c  8e len=382    d0   包裹
0x60f   6e len=378   d1   id=0x57C8D1  实参 RPN
0x61f    8e len=361  d2   包裹
0x622     6e len=357 d3   id=0x9930CC  80 9a 07 14 "v_bri_kaz0010_000_0\0"
0x640       8e len=326 d4 包裹
0x643        6d len=23 d5 id=0x3B91EB  ...   <- 行 0
0x65c        6d len=23 d5 id=0x3B91EB  ...   <- 行 1
...
```

### 5.4 `0x6d`（逐行演出信息）—— **已解出**

`0x6d` = op `0x60` + u8 长度，处理器 id = `0x3B91EB`，总长 25 字节。
载荷 = `[u24 id][args 20 字节]`，args 布局：

| 字节 | 含义 | 证据 |
|---|---|---|
| `args[0..1]` | `07 06` 常量前缀 | 众数占比 96% |
| `args[2..5]` | **说话人 ID**（u32，高字节恒 `0x0e`） | 同一说话人的多行取值相同，对话中随说话人交替 |
| `args[6]` | **行号（0 起）** | `_probe_bri49.py`：命中率 **100%** |
| `args[7]` | `0` | 96% |
| `args[8..11]` | `5a 69 26 b2` 全文件常量 | 90% |
| `args[12..13]` | `01 01` | 86% / 96% |
| `args[14..15]` | **开始时刻** u16 LE | 与上一行的"止"严格相等 |
| `args[16]` | `1` | 85% |
| `args[17..18]` | **结束时刻** u16 LE | 与下一行的"起"严格相等 |
| `args[19]` | `0` | 86% |

时间轴首尾相接的实证（记录 205）：

```
行0  spk=0x0e…e6  t=445..1825   そう言えば、ヒューイからもらったIDカードでは…
行1  spk=0x0e…42  t=1825..2758  ああ、奴のカードは無効にしたからな。
行2  spk=0x0e…e6  t=2758..3037  どうして。
行3  spk=0x0e…42  t=3037..4249  あんな奴を、私の研究所に入れさせるものか。
```

覆盖率：**843 / 2,049 条记录、10,667 / 24,438 行**（其中 708 条记录的
`0x6d` 条数恰好等于台词条数）。

### 5.5 语音资源 ID

格式 `v_<集>_<说话人><编号>_<行号>_<变体>`，414 种：

| 集 | 例 | 扇区段 |
|---|---|---|
| `v_bri` | `v_bri_kaz0010_000_0`、`v_bri_amd0020_010_0` | 组 1（主体 CODEC 通话） |
| `v_fop` | `v_fop_kaz_1660_000_0` | 组 2 |
| `v_myo` | `v_myo_rad_0010_000_0` | 组 2 |
| `v_paz` / `v_ccl` / `v_dsl` / `v_eva` / `v_kaz` | `v_paz_dry_0010_000_0` | 散布 |

说话人标识：`kaz`(Miller) `amd`(Amanda) `paz` `cst` `dry` `rad` `eva`。

> **语音 ID 不是严格的跨语言对齐键**：`_probe_bri46.py` 统计组 1 的 353 个
> ID，只有 97 个覆盖全部 6 种语言（分布 1:22 2:30 3:50 4:64 5:90 6:97）。
> 各语言块的记录数不等（ja 248 / en 270 / fr 258 / de 254 / it 251 /
> es 258），`en vs ja` 独有 84 个、缺失 62 个。跨语言对齐请优先用
> **块内序号 + 行号**，语音 ID 仅作辅助。

---

## 6. 扇区块语义（组 2）—— **已解决**

组 2（扇区 877–1011）不是"同一套内容的另一形态"，而是**另一套内容的
6 语言全量副本**：

* 语音 ID 集与组 1 几乎不相交（组 2 是 `v_fop` / `v_myo`，组 1 是 `v_bri`）；
* 内部同样按 ja→en→fr→de→it→es 顺序排列（`_probe_bri43/44.py` 游程压缩，
  块内一致率 96~100%）；
* 每组 ~80–88 条记录，远少于组 1 的 ~250 条。

---

## 7. 复现

```powershell
cd d:\PWSF
python -m pwsf.briefing                                       # 摘要
python -m pwsf.briefing -o research\ANALYSIS\_briefing_lines.tsv
```

```python
import pwsf_briefing as B
br = B.load(".../MLG/disc0_rel/0076531d.DAT")
for r in br.records[:5]:
    print(r.group, r.lang, r.sector, r.n_lines,
          r.voice_ids(br.data)[:2], r.cues(br.data)[:3], r.ruby()[:2])
```

输出 TSV 列：`group  lang  sector  off  idx  line  t_start  t_end
speaker  voice_ids  text`

## 8. 取证脚本

| 脚本 | 结论 |
|---|---|
| `_probe_bri8.py` | 逐扇区 vs 连续的 A/B 判决 |
| `_probe_bri17.py` | 证否块内 keystream 偏移 k=1..3 |
| `_probe_bri18.py` | 脚本入口合法性 → 剔除 601 条假阳性 |
| **`_probe_bri40.py`** | **语言归属的决定性证据（同语音 ID 六语对照）** |
| `_probe_bri41/42/43.py` | 方法迭代（锚点对齐 / 停用词 / 游程压缩），结论已被 44 取代 |
| **`_probe_bri44.py`** | **平滑 → 合并 → 12 块 → 交叉验证** |
| `_probe_bri45.py` | LCS 序列对齐 + 增补记录定位 |
| `_probe_bri46.py` | 证否"语音 ID 是严格跨语言键" |
| **`_probe_bri47.py`** | **解密粒度穷举判决（per-4096 胜出）** |
| `_probe_bri48.py` | 走弯路：未递归下钻，`0x6d` 只找到 28 条（记录其失败） |
| **`_probe_bri49.py`** | **递归解码 → `0x6d` 参数画像 → 行号/说话人/时间轴** |
