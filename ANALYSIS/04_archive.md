# 04 · 归档容器（PDT / DAT / KEY）

状态：**格式已打通并全量验证**。工具 `TOOLS/pwsf_archive.py`（解析）
+ `TOOLS/pwsf_names.py`（条目名哈希）+ `TOOLS/pwsf_archive_index.py`（全盘索引）。

```
138 个容器   134 个通过自洽校验   113,348 个条目   2,042 个 payload CRC-32 全通过
报告：ANALYSIS/_archive_index.tsv
```

---

## 1. 总体加密链

三类资源（olang / 影片 / 归档）共用一套 MT19937 流加密（见 `00_overview.md`），
归档在此基础上多了**两层**：

```
key = name_hash(容器 basename)                        0x14010F450

第 1 层  MT 流（跨头/索引/名字表连续，不重新播种）
        mt_xor_seed 0x14010F8B0   -> mt_seed(key) + mt_advance(20)
        mt_xor_stream 0x14010F5C0 -> 逐 dword 异或 (mt_next() ^ 0xB9D3018F)

第 2 层  二次解扰（unmask），两种模式
        mode 0x100  unmask_xor_byte    0x140123DD0   每字节 xor (lo & 0xFF)
        mode 0x40   unmask_lcg_dwords  0x140123CC0   逐 dword 的 LCG 流
                    unmask_lcg_derive_key 0x140123DB0
```

---

## 2. 容器布局

`archive_index_load` @ `0x1401238C0` 是唯一的解析入口。底层读取是
**裸 `ReadFile` 顺序读**（`io_read_raw` @ `0x140044950`），**无扇区对齐**：

```
文件偏移
  +0x00              40 字节  头
  +0x28              12n      索引表
  +0x28 + 12n        24n      名字表（BST）
  align_up(…, 0x800)          payload 区
```

证据：

* `v18 = r13 + 4*(n + (n+5)*2) = base + 40 + 12n`，即名字表紧接索引表。
* 头的 `+0x20` 字段 == 名字表偏移，在**全部 134 个有效容器**上都等于 `40 + 12n`。
* 首个条目偏移 == `align_up(40 + 36n, 0x800)`，逐条目
  `offset[i+1] = align_up(offset[i] + size[i], 0x800)`，收尾对齐文件大小。

### 2.1 头（40 字节，MT 解密后）

| 偏移 | 类型 | 含义 |
|---|---|---|
| `+0x00` | u32 | `lo`；**为 0 则完全不做二次解扰** |
| `+0x04` | u32 | `hi`；0 → mode 0x100，非 0 → mode 0x40 |
| `+0x08` | u32 | `m`，mode 0x40 的 LCG 增量乘数 |
| `+0x0C` | 28 B | 暂存区，原地解扰；`+0x0C` 随后被游戏清零 |
| `+0x10` | u32 | 常量 `0x007A7E9C`（魔数） |
| `+0x14` | u32 | 常量 `0x00010000`（版本） |
| `+0x18` | **i16** | 条目数 n（**有符号**，`movsx rsi, word ptr [...]` @ `0x140123AC9`） |
| `+0x1A` | u16 | 常量 2 |
| `+0x1C` | u32 | 0（DLC 容器为运行时地址，见 §6 疑点） |
| `+0x20` | u32 | 名字表偏移 == `40 + 12n` |
| `+0x24` | u32 | 0（DLC 容器为运行时地址） |

> 过往结论错在两点：一是**漏了二次解扰**就去读 `+0x18`（读出 56327 / 1873 /
> 13373 等噪声），二是把 n 当成 u16。两者都已在本次修正。

### 2.2 二次解扰（第 2 层）

```
if (lo != 0) {
    if (hi != 0) {                       // mode 0x40
        s    = hi ^ lo
        k    = s | ((s ^ 0x6576) << 16)          // unmask_lcg_derive_key
        inc  = m * s
        unmask_lcg_dwords(dst, len, &k, &inc)    // k 在调用间连续递推
    } else {                             // mode 0x100
        unmask_xor_byte(dst, len, lo & 0xFF)     // 无状态
    }
}
```

对**同一条 LCG 流**连续作用三次：暂存区(28) → 索引表(12n) → 名字表(24n)。

`unmask_lcg_dwords`：`*d ^= k; k = inc + 48828125 * k`（`48828125` @ `0x140123CEE`）。

### 2.3 索引表项（12 字节）

```
+0x00  u32  size
+0x04  u32  crc32        == zlib.crc32(payload[:size & ~3])
+0x08  u32  offset
```

`archive_index_load` 把它们分别写入 `pkg+0xE0`、`pkg+0xD8`、`pkg+0xDC`。

### 2.4 名字表项（24 字节）—— 是二叉搜索树，不是数组

`entry_index_bsearch` @ `0x140123D60` 名字有误导性，它实际是 **BST 遍历**：

```
+0x00  u32  key      == entry_name_hash(条目名)
+0x04  u32  slot     查到后返回，作为索引表下标
+0x08  u64  gt       needle >  key 时走
+0x10  u64  le       needle <= key 时走
```

`gt`/`le` 是**相对名字表首址**的偏移，游戏在遍历前统一重定位
（`*(qword*)(e+8) += base`、`*(qword*)(e+16) += base`），0 表示空。
根是节点 0。

注意 `if (a2) a3 ^= ~((16*a2) ^ ((a2 ^ 0x10EA0) >> 4));` 只作用于 **needle**，
**树里存的 key 是原始 `entry_name_hash`**，所以可以直接用字符串反查。

---

## 3. 条目名 → key

`entry_name_hash` @ `0x14011F820`：

```python
h = 0
for c in name:                       # 遇到 '.' 或 NUL 停
    h = (c + ((32*h) | (h >> 19))) & 0xFFFFFF
if h == 0: h = 1
if name[i] == '.':
    ext = name[i+1:]
    if ext in g_ext_id_table: h |= ext_id << 24
return h
```

`(32*h) | (h >> 19)` 恰好是 24 位循环左移 5 位（`32*h` 占位 5..28，`h>>19` 占位
0..4，互不重叠），故 `h = (ROTL24(h,5) + c) & 0xFFFFFF`，**可逆**：
`h_prev = ROTR24((h - c) & 0xFFFFFF, 5)`。

`g_ext_id_table` @ `0x140F4C7D0`：`(const char *ext, u32 id)` 对，16 字节/项，
**67 项**，已完整导出到 `TOOLS/pwsf_names.py` 的 `EXT_IDS`。
（部分 id 不唯一：`mdp`/`mdc`/`mdl`/`mdb` 都是 `0x13`。）

**条目名不存于容器**，只存哈希；名字必须回到二进制里找。方法：
`ANALYSIS/_strings.tsv`（IDB 全部 49,869 条字符串）逐个算 `entry_name_hash`
建反查表（43,368 个不同哈希）。

已实证命中（无扩展名的纯名字）：

| 容器 | 条目 |
|---|---|
| `ms0\EU\DLCBGM\*.PDT` | `DBMINFO` `MUSIC` `ZAPPIN` |
| `ms0\EU\DLCTEX\*.PDT` | `TEXT` |
| `MLG\disc0_rel\ADEMO\0058cafb.pdt` | `0018ef0c` / `0058cafb`（高字节 `0x14`=`txp`） |

> disc0 主归档（`0001112d` 等）的条目名**不在** IDB 字符串表里，尚未反查。
> 但它们的高 8 位仍能给出类型（`bgp` `la3` `mtsq` `txp` …），见报告。

---

## 4. 条目 payload 解密

管线来自 `archive_read_entry_simple` @ `0x140122730`：

```
1. buffer_xor_decrypt(buf, len, pkg+0xE4)    0x14010F4C0
      key = pkg+0xE4 = name_hash(容器 basename)，从头开始的新 MT 状态
2. entry_payload_transform(pkg, buf, len)    0x140123E90
      mode 0x100 -> 每字节 xor (lo & 0xFF)        【已验证】
      mode 0x40  -> dword LCG，种子在 pkg+0xC4/0xC8【未验证】
3. payload_crc32_accum(pkg+0xC0, buf, len)   0x140124000   校验
```

### CRC 就是标准 CRC-32

`payload_crc32_accum` 的表在 `g_crc32_table` @ `0x1409BEE20`。实测
`g_crc32_table[i] ^ 0x3FC47CDA` **正好等于**标准反射 CRC-32 表（poly
`0xEDB88320`），而循环里的两个 `^ 0x3FC47CDA` 相互抵消。于是：

```python
entry.crc == zlib.crc32(payload[:len & ~3])
```

（`a3 & 0xFFFFFFFC` → 最后一个不完整 dword 不参与校验。）

**验证结果：2,042 / 2,042 通过**，抽样明细（全量，非抽样）：

```
ms0\EU\DLCBGM\e41b91fb.PDT      4/4
ms0\EU\DLCTEX\ad1af1fb.PDT      3/3
ms0\EU\DLCVOICE\181ae463.PDT   40/40
MLG\disc0_rel\0001112d.PDT     86/86
MLG\disc0_rel\ADEMO\0058cafb    2/2
```

解密后的明文档例：

```
DLCTEX TEXT :
  "Variation of Jungle Fatigues camouflage. Raises camo index in
   environments of a similar color."
DLCBGM DBMINFO:
  "KOI NO YOKUSHI-RYOKU" / "Akihiro Honda" / "\"MGS-PW\" Sound Team"
DLCBGM slot0  :
  "DLCB_MP\0" + "1wm101_koinoyokushiryoku.pdt"
0001112d 条目0:
  "SP$\0\0 … 251922 PW_EN"          （内层又是 SP 容器）
```

---

## 5. 逻辑包名 → 真实文件

`path_resolve_install` @ `0x140043DA0`：

```
disc0:/PSP_GAME/USRDIR<rest>
    -> /JPN/disc0_rel<rest>      (lang_get_language_id()==6)
    -> /EXLANG/disc0_rel<rest>   (启动器语言=="pt" 且非 /ADEMO /ADEMOHQ /CAMO)
    -> /MLG/disc0_rel<rest>      (其余)
ms0:<rest> -> /ms0<rest>，随后按语言槽替换最后一段，最后 '/' 全改成 '\'
```

语言槽替换表（`xmmword_141884920` / `xmmword_141884930` 决定槽号）：

| 逻辑名 | 槽 0 | 槽 1 | 槽 2 | 槽 3 |
|---|---|---|---|---|
| `/BKD00000.PDT` | 8b1ae9c3 | 8b1ae97b | 8b1ae97c | 8b1ae97d |
| `/AVD00000.PDT` | 181ae4ab | 181ae463 | 181ae464 | — |
| `/AVD00001.PDT` | 191ae4ad | 191ae465 | 191ae466 | — |
| `/AVD00002.PDT` | 1a1ae4af | 1a1ae467 | 1a1ae468 | — |
| `/AVD00003.PDT` | 171ae4a9 | 171ae461 | 171ae462 | — |

Steam 版只发布**槽 1**：`ms0\EU\DLCVOICE\{181ae463, 191ae465, 1a1ae467,
171ae461}.PDT`；`BKD00000`（8b1ae97*）**未随包发布**。

`subtitle_load_resources` @ `0x14026BE10` 遍历 17×5 = 85 个槽，
每个槽取包名（最多 5 个，运行时填入 ctx+0，16 字节/个；索引表 85 字节在
ctx+100，`subtitle_slot_name` @ `0x1401B9DF0`），然后
`archive_open_entry(h, "SUBTITLE", 1, 0)`。

---

## 6. 疑点 / 未验证（**不得当作结论使用**）

1. **`009645fa.PDT` 的扩展名 id `0xf3`–`0xfe`**
   该容器（唯一有效的 mode 0x40 容器，511 MB，557 条目）的节点 key 高字节
   出现 `0xf0`–`0xff` 全段。但 `g_ext_id_table` 只有 67 项，其中 `0xf0`=dar、
   `0xf1`=qar、`0xf2`=cnf、`0xff`=psq，**`0xf3`–`0xfe` 不在表内**。
   容器本身通过了全部自洽校验，所以解析应当没问题，但高字节来源不明。

2. **mode 0x40 的 payload 解扰未验证**
   需要 `pkg+0xC4`（状态）与 `pkg+0xC8`（增量）的初值，二者不在
   `archive_index_load` 中赋值。当前 `decrypt_payload()` 对该模式抛
   `NotImplementedError`。受影响的只有 `009645fa.PDT`（其余 133 个有效容器
   都是 mode 0x100 或 lo==0）。报告里该容器 `crc_ok` 列为 `-`。

3. **`002aba34.DAT`（544 MB）与 `0076531d.DAT`（4 MB）不是本格式**
   两者都走 `buffer_xor_decrypt` 一次性路径（后者是 BRIEFING 数据，见
   `03_codec.md`）。它们能被"解析"出 count（20437 / 32020），但
   `verify()` 全部失败（`hdr+0x20` 不符、BST 子指针越界）——**这是预期的拒绝**。
   `002aba34.DAT` 的 544 MB 主归档格式待反（线索：`bigdat_load_and_verify`
   @ `0x1400A6290`）。

4. **`archive_index_load` 里的 `if (n > 96) goto fail`**
   134 个有效容器中有 5 个 n 超过 96（219 / 557 / 608 / 2304）。说明这些
   大容器走的是**另一条加载路径**，不走 `archive_index_load`。格式本身一致，
   提取不受影响，但"96"这条边界的归属函数尚未定位。

5. **disc0 主归档的条目名未反查**
   `0001112d` / `00b2b2a8` / `00b2b475` / `00b2b4b6` / `009645fa` 的节点 key
   在 IDB 字符串表里无命中。下一步可用 §3 的可逆性，配合已知命名约定
   （8 位十六进制等）做定向爆破。

6. **DLC 容器头 `+0x1C` / `+0x24` 存的是运行时地址**
   `ms0\EU\DLCTEX\*` / `DLCBGM\*` 这两字段形如 `0x00C081E0` / `0x00C08260`，
   disc0 容器则为 0。用途未知，解析时忽略。

---

## 7. 用法

```bash
python TOOLS/pwsf_archive_index.py          # 全盘索引 -> ANALYSIS/_archive_index.tsv
python TOOLS/pwsf_archive_index.py -v       # 带耗时日志
python TOOLS/pwsf_archive_index.py --full   # 不做 CRC 字节预算，全量校验（慢）
```

```python
import pwsf_archive as A, pwsf_names as N
arc = A.load(".../00b2b475.PDT")            # 或 A.parse(data, stem, path)
A.verify(arc, filesize)                     # [] 表示自洽
slot = A.bst_walk(arc, N.entry_name_hash("SUBTITLE"))
blob = A.read_entry(arc, slot)              # 已解密
assert A.entry_crc(blob) == arc.entries[slot].b
```

取证脚本（保留为证据）：`TOOLS/_probe_pdt3.py`（二次解扰）、
`_probe_pdt4.py`（大容器自洽）、`_probe_pdt5.py`（stem.ext 假说，已否决）、
`_probe_pdt6.py`（字符串反查）、`_probe_scan.py`（首轮全盘扫描）、
`_probe_payload.py`（payload 解密链爆破）。
