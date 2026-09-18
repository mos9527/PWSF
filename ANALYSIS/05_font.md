# 05 · 字体（FONT/*.xpr）与 UI 贴图包（Text/*.txp）

结论先行：**字体可扩，且不需要 hook 渲染器。** 字形查找按 Unicode BMP 码点
走一张 `cMaxGlyph = 0xFF5E` 的转换表，表本身已经按全 BMP 尺寸随包发布；
主字体图集 4096×4096 只用到第 612 行，**剩约 51 行空白，够塞 ~3,100 个全角汉字**。

---

## 1. 两个字体包，按语言选择

`font_init_load_all` @ `0x140043410`：

```c
v0 = "0007ccd8.xpr"; v1 = "000ebbe8.xpr";
if (lang_get_language_id() == 6) {          // 日语
    v0 = "00c7c9f9.xpr"; v1 = "001cbbd1.xpr";
}
font_load_xpr(&g_font_large, v0, 4096);
font_load_xpr(&g_font_small, v1, 2048);
```

| 逻辑 | 文件 | 磁盘 | 字体对象 |
|---|---|---|---|
| 默认（欧美） | `FONT\0007ccd8.xpr` | ✅ 16,918,556 B | `g_font_large` @ `0x141061A18` |
| 默认（欧美） | `FONT\000ebbe8.xpr` | ✅ 2,236,444 B | `g_font_small` @ `0x141061AB0` |
| 日语 | `FONT\00c7c9f9.xpr` | ❌ 未随包发布 | — |
| 日语 | `FONT\001cbbd1.xpr` | ❌ 未随包发布 | — |

两个字体对象间距 152 字节，`dword_141061A0C` 选当前字体。

> 日语字体不在 Steam 版里，和 `path_resolve_install` 把 `lang_id == 6` 指向
> `/JPN/disc0_rel`（该目录同样不存在）是一致的——**Steam 版根本走不到日语分支**。
> olang 里的 ja 文本是随包带着的死数据。

## 2. XPR2 容器

`xpr_package_load` @ `0x140042630`，全大端：

```
+0   'XPR2'          汇编里比较的是 1481658930 = 0x58505232
+4   u32 header_size
+8   u32 data_size
+12  header 块（header_size 字节）
     +0  u32 资源数
     +4  目录，24 字节/项：
           +0  u32 类型标签 'TX2D' / 'USER'
           +4  u32 偏移（指向 header 块内，**不是** data 块）
           +8  u32 大小
           +16 u32 名字偏移（加载时低 dword 字节序翻转后加上 header 基址）
     data 块（data_size 字节）
```

`12 + header_size + data_size == 文件大小`，两个文件都精确吻合。

加密与 olang 同一套：`name_hash(路径)` 播种，**头 12 字节、header 块、data 块
共用一条连续 MT 密钥流**（`sub_14010F8B0` 播种后连续三次
`sub_14010F5C0`），所以用一次性的 `buffer_xor_decrypt` 整文件解即可。

实测两个包都是 2 个资源：

| 文件 | header | data | 资源 |
|---|---|---|---|
| `0007ccd8.xpr` | `0x22810` | `0x1000000` | `FontTexture`(TX2D, off `0x50`, 52 B) / `FontData`(USER, off `0x84`, `0x22708` B) |
| `000ebbe8.xpr` | `0x22010` | `0x200000` | 同名，`FontData` `0x21B88` B |

## 3. FontData = Xbox 360 ATG 风格字体表

`font_load_xpr` @ `0x140042C60` 按名字取 `FontTexture` / `FontData` 两个资源，
然后就地把 `FontData` 全部字段做字节序翻转：

```
+0   u32  version        必须 == 5，否则整个加载失败
+4   u32 × 4  度量        → font+96..+108；实测 0x42860000 = float 67.0（字高）
+20  u16  cMaxGlyph      → font+128
+22  u16 × (cMaxGlyph+1) 转换表：Unicode 码点 → 字形索引 → font+136
p = FontData + 2*(cMaxGlyph+1)
p+22 u32  num_glyphs     → font+112
p+26 GLYPH_ATTR × num_glyphs → font+120，16 字节/项：
     u16 tu1, tv1, tu2, tv2   图集内**像素**坐标（非归一化）
     u16 off, width, advance, mask
```

`font_glyph_rect_for_char` @ `0x140043B10` 证实查找方式：

```c
__int64 font_glyph_rect_for_char(ctx, unsigned __int16 a2)   // a2 = u16 码点
{
    idx  = (a2 > cMaxGlyph) ? 0 : translator[a2];
    attr = &glyphs[idx];                       // 元素步长 16 字节
    rc   = SetRect(attr[0], attr[1], attr[2]-attr[0], attr[3]-attr[1]);
}
```

参数类型是 `unsigned __int16`，越界回退到字形 0，**所以索引键就是 Unicode BMP
码点**。旁证：转换表里 `U+00C4`、`U+2013`、`U+2019` 这些位置都有字形，
与 Unicode 码位一一对应（不是 Shift-JIS，也不是字节索引）。

## 4. 实测覆盖与余量

```
0007ccd8.xpr (large)  cMaxGlyph=0xFF5E  num_glyphs=643  已映射码点 642
    汉字 U+4E00..U+9FFF : 323
    假名 U+3040..U+30FF : 130
    图集触及 tu2_max=4069  tv2_max=612   最高字形 67px  mask 全为 0

000ebbe8.xpr (small)  cMaxGlyph=0xFF5E  num_glyphs=459  已映射码点 458
    汉字 : 155    假名 : 104
    图集触及 tu2_max=2026  tv2_max=748
```

图集尺寸由 TX2D 头的 X360 纹理取值常量给出（低 13 位 = 宽-1，次 13 位 = 高-1）：

| 文件 | dword[9] | 宽 × 高 | data_size | 推出 |
|---|---|---|---|---|
| `0007ccd8.xpr` | `0x01FFEFFF` | 4096 × 4096 | `0x1000000` = 16,777,216 | 正好 1 字节/像素（8 位单通道） |
| `000ebbe8.xpr` | `0x007FE7FF` | 2048 × 1024 | `0x200000` = 2,097,152 | 同上 |

**余量**：主字体 4096 行里只用到 612 行，按 68px 行高算，
剩 `(4096-612)/68 ≈ 51` 行；每行按全角 67px 可放 `4096/67 ≈ 61` 个，
合计 **≈ 3,100 个汉字位**，且完全不用改图集尺寸。
小字体只剩 `(1024-748)/68 ≈ 4` 行（约 120 个），**是真正的瓶颈**。

## 5. `Text/*.txp` 不是字形贴图（纠正此前记录）

`ui_texture_request_by_ctrltype` @ `0x14003B520` 构造路径 `Text/$$PF$$.txp`，
把 `$$PF$$` 占位符替换成由 `launcher_get_ctrltype()` 选出的 id：

| ctrltype | 文件 | 大小 |
|---|---|---|
| 0 | `005318e4.txp` | 15,228,928 |
| 1 | `005318e5.txp` | 15,228,928 |
| 2 | `0082988a.txp` | 15,228,928 |
| 3 / 4 | `008299c5.txp` | 15,228,928 |

随后无条件再请求 `Text/005302d4.txp`（36,847,616 B）。
四个同尺寸文件是**手柄按键图标集**，不是语言变体，也不是字形贴图。
这与 olang 文本里的 `<I=AIM>` `<I=DEC>` 内联图标引用对得上（见 01 号文档 §4）。

`.txp` 自身的头（解密后）也带 id：

```
+0  u32 type      0024e502=4, 005302d4/005318e*/0082988a/008299c5=1, 0083be4a=0
+4  u32 id        自身 id，或所属根包 id
+8  u32 count     0x23=35 / 0xFF=255 / 0x54=84 / 0x0A=10
+12 u32 count     同上
+24 u32 0x30      疑似头长度
```

`0024e502.txp` 的 `+4` 是自己的 id 且 type=4，其余 15 MB / 36 MB 文件的 `+4`
全部是 `0x0024E502` —— 它是根索引，其余是它的数据分包。**格式未细反**，
目前汉化不需要动它。

## 6. 实证：引擎按 Unicode 码点查字形（UTF-8 解码链已确认存在）

`font_glyph_rect_for_char` 收的是 `unsigned __int16`，但"UTF-8 文本在哪一步
转成码点"没有直接找到解码函数（按 `0xFFFD` 搜到的两处都是位掩码假阳性）。
改用**数据侧实证 + 反证**，结论同样是硬的。

### 6.1 正面：现役文本的码点，字体 100% 覆盖

把 `_dump_olang.tsv` / `subtitle_ingame.tsv` / `_briefing_lines.tsv` 的全部文本
按 UTF-8 解码取码点，与两个字体转换表的并集（740 个码点）求差：

| 语言 | 全量文本去重码点 | 其中汉字 | **字体缺失** |
|---|---:|---:|---:|
| de | 127 | 3 | **0** |
| en | 118 | 3 | **0** |
| es | 232 | 49 | **0** |
| fr | 165 | 26 | **0** |
| it | 181 | 47 | **0** |
| pt | 62 | 0 | **0** |
| ja | 1,849 | 1,560 | 1,217 |

五个欧洲语言 + 葡语**一个码点都不缺**。日语缺 1,217 个，与 §1 的
"日语字体未随包发布、日语分支走不到"完全自洽。

### 6.2 反证：按原始 UTF-8 字节索引是不可能的

若引擎拿字节去查转换表，则每个多字节字符都需要其**续字节**（`0x80..0xBF`）
位置上有字形。实测：

```
欧语文本在该模型下需要的续字节值：62 个（0x80,0x81,0x82,...）
两个字体在 U+0080..U+00BF 区间里的字形：10 个
  （0xA0 0xA1 0xA9 0xAA 0xAB 0xAE 0xB0 0xBA 0xBB 0xBF —— 都是 Latin-1 标点）
```

62 个里只有 10 个有字形。若真按字节索引，西班牙语的 `ñ`（`C3 B1`）要用
`U+00B1`，而 `U+00B1` 没有字形 —— 西/法/德/意文本会满屏缺字。事实不是这样。

> **结论：引擎在字形查找前把 UTF-8 解成了 Unicode 码点。**
> 这条此前被列为"做字库之前唯一的致命风险"，现已排除。

### 6.3 汉化需要多少字形

日文全量文本用到 **1,560 个汉字**（1,849 个去重码点）。同内容的简体中文
译本用字量应在同一量级（通常 1,500–2,500），而主字体图集有
**约 3,100 个空位**（§4）——**装得下，且不用扩图集**。

## 6.4 汉字走哪个字体：恒定走 `g_font_large`（瓶颈不存在）

`sub_14008AB50` 里那处 `*v2 <= 0xFF ? 句柄A : 句柄B` 曾被列为最高优先待办，
现已查清：**那个句柄是死参数**。

`ui_get_font_handles` @ `0x1400C1560` 只是把两个全局拷给出参
（`qword_141183750` 给 `<=0xFF`，`qword_141183758` 给 `>0xFF`），
但下游三个消费者**全都不读这个句柄**：

```
sub_14003BFE0        lea rax, g_font_globals ; retn      ← 2 条指令，忽略 rcx
sub_14003C0A0        直接把 &g_font_globals 传给 font_glyph_metrics
font_glyph_rect_for_char  movsxd r9, cs:g_font_index      ← rcx 全程未被读取
```

字体真正由 `g_font_index` @ `0x141061A0C` 选择（`imul r8, r9, 98h`，
步长 152 = 两个字体对象的间距）。而它在整个映像里**只有一处写入**：

```c
font_static_init @ 0x140001370        // CRT 静态构造
    'eh vector constructor iterator'(&g_font_large, 0x98, 2, ctor, dtor);
    ...
    g_font_index = 0;                 // 0x14000141D，此后再无写入
```

交叉引用确认 `0x141061A0C` 只有两条：`0x14000141D` 写 0、`0x140043B14` 读。
另一条取度量的路径 `font_glyph_metrics` @ `0x1400438B0` 用的是同一个
`*(int*)(a1+92)`，即同一个索引。

> **结论：`g_font_index` 是编译期常量 0，所有字形查找都落在 `g_font_large`
> （4096×4096，约 3,100 个空位）。`g_font_small` 被加载也被释放，但没有任何
> 字形路径索引它。§7.2 记的小字体瓶颈不成立。**

顺带两条实现细节（`font_glyph_metrics`）：宽度等于行高（67，`lang_id == 6`
时 66）的字形按空白处理；码点 `0x7490` 被特判成 1.15 倍宽的格子。

## 7. 对本土化的影响

1. **不需要 hook 渲染器**。加汉字 = 填转换表 + 追加 `GLYPH_ATTR` + 往图集
   空白行里贴 8 位灰度位图 + 重算 `num_glyphs` + 重新加密。全部离线可做。
2. **只有一个字体在用，而且够用**：`g_font_index` 恒为 0，全部字形走
   `g_font_large`（§6.4）；需要 ~1,560 字，有 ~3,100 空位。
   小字体 `g_font_small` 不参与字形查找，其容量不构成约束。
3. `version` 必须保持 5，否则 `font_load_xpr` 直接判失败返回 0。
4. 所有多字节字段是**大端**，写回时别忘了翻转。
5. 图集是 8 位单通道，塞字形时直接贴灰度位图即可，无需管通道 mask
   （实测 643 个字形的 `mask` 字段全为 0）。

## 8. 待办

- [x] ~~确认文本渲染侧的 UTF-8 → u16 解码~~ —— 见 §6.1/§6.2，实证 + 反证闭合
- [x] ~~确认汉字走哪个字体对象~~ —— 见 §6.4，`g_font_index` 恒 0，走大字体
- [ ] 写回工具链（见 [计划 05](../PLANS/05_font.md) C 项）：`pwsf_xpr.py` 解包/重打包
      + `pwsf_font.py` 转换表与 `GLYPH_ATTR` 读写 + 图集装箱
- [ ] TX2D 头 52 字节逐字段反（`sub_140088870` 消费它）——
      **仅在决定扩大图集时才需要**，当前余量够用，已降级
- [ ] `Text/*.txp` 容器格式（仅在需要替换按键图标时才做）
- [ ] 码点 `0x7490` 的特判是做什么用的（`font_glyph_metrics` 里 1.15 倍宽格子）

## 9. 复现

```powershell
cd d:\PWSF\TOOLS
python _probe_font1.py    # 确认 .xpr/.txp 用 name_hash 加密
python _probe_font2.py    # XPR2 目录 + FontData + 覆盖率 + 图集余量
python _probe_font3.py    # 字体覆盖 vs 全量文本码点；反证按字节索引不成立
```
