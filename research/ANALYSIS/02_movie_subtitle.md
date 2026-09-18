# 02 · 影片 / 字幕子系统

---

## 1. 媒体文件：统一用 `name_hash` 加密

`.xmx`（视频）与 `.xsx`（音频）与 olang **共用同一套解密**
（见 01 号文档 §3：`name_hash(basename)` → `mt_seed` → `mt_advance(20)` → `XOR 0xB9D3018F`）。

实测（解密后前 48 字节）：

| 文件 | key | 明文魔数 | 实际格式 |
|---|---|---|---|
| `MLG/data/Mov/00568c22.xmx` | `0x6F853C0C` | `00 00 00 20 66 74 79 70 69 73 6f 6d ... 6d 64 61 74` | **MP4**（`ftypisom` / `iso2avc1mp41` / `mdat`） |
| `MLG/data/Mov/00348273.xmx` | `0x2947F603` | 同上 | MP4 |
| `EXLANG/data/Mov/0019f5e1.xmx` | `0xB8BBF35F` | 同上 | MP4 |
| `MLG/data/Mov/00348273.xsx` | `0x2947F603` | `4f 67 67 53 ... 01 76 6f 72 62 69 73` | **Ogg Vorbis**（`OggS` + `vorbis`） |
| `MLG/data/Mov/004bc514.xsx` | `0x603CF4DF` | 同上 | Ogg Vorbis |
| `EXLANG/data/Mov/0019f5e1.xsx` | `0xB8BBF35F` | 同上 | Ogg Vorbis |
| `MLG/data/hqMov/008f5eec.xsx` | `0xED86ACEC` | 同上 | Ogg Vorbis |

> **结论：`.xsx` 不是字幕文件，是音轨。**
> 影片 = `.xmx`(视频) + `.xsx`(音频)。字幕文字在别处（见 §2）。

### 1.1 影片目录解析 `movie_dir_resolve` @ `0x140050370`

```
若影片名（a3 所指串）尾部包含 "00362e0c" / "0019f5e1" / "001a05e1" 之一：
    路径 = g_launcher_config[6]  + "/EXLANG/data"
         + (g_launcher_config[25] == "1" ? "/hqMov" : "/Mov") + "/"
否则：
    路径 = *(char*)(a1 + 5972)          // 默认目录
```
与磁盘一致：`EXLANG/data/{Mov,hqMov}/` 下恰好只有 `0019f5e1` / `001a05e1` /
`00362e0c` 三部片——即**葡萄牙语版**专有影片。

---

## 2. 字幕正文的两个来源

### 2.1 归档包内名为 `SUBTITLE` 的条目（影片字幕）

`subtitle_load_resources` @ `0x14026BDE0`：
```c
v3 = sub_140124130(4);                       // 取归档句柄
for (v4 = 0; v4 < 17; ++v4)                  // 17 个包
  for (v6 = 0; v6 < 5; ++v6) {               // 每包 5 个槽
      name = subtitle_slot_name(v4, v6);
      if (!name) continue;
      archive_set_package(v3, name);
      h = archive_open_entry(v3, "SUBTITLE", 1);      // ← 条目名 "SUBTITLE" @ 0x140D234E8
      if (h > 0) {
          // 读入栈缓冲，NUL 结尾
          // sub_140099780 分配 strlen+1 并 memcpy
          // 存入 *(char**)(a1 + 768 + 8*idx)，并 ++*(u32*)(a1 + 120)
      }
  }
*(u32*)(a1 + 112) = 2;                       // 状态 = 已加载
```
即：每个 `SUBTITLE` 条目被当成**一整段 NUL 结尾文本**读入，共 17×5 = 85 个指针槽
（偏移 `+768`，8 字节/项），计数在 `+120`。

### 2.2 olang 表（游戏内字幕 = AI 兵器战斗语音字幕）

`subtitle_state_machine` @ `0x14026BC00`，汇编逐条核对（见 §6.2）：
```c
v3 = &xmmword_141884900;             // sub_140052190 就是 lea rax, g / retn
switch (a1[29]) {                    // 字幕显示模式
  case 1: v4 = (v3[13]==1) ? 12339829 : 4622435;   a1[31] = 74; break;  // 0xBC4A75 / 0x468863
  case 2: v4 = (v3[11]==1) ? 14894709 :  2725226;  a1[31] = 38; break;  // 0xE34675 / 0x29956A
  case 3: v4 = (v3[12]==1) ? 15322101 : 13855740;  a1[31] = 28; break;  // 0xE9CBF5 / 0xD36BFC
  case 4: v4 = (v3[10]==1) ?  9449591 :  4395006;  a1[31] = 32; break;  // 0x903077 / 0x430FFE
}
for (v6 = 0; v6 < a1[31]; ++v6) {
    lang = get_olang_lang_id(-1);
    text_get(v4 /*group*/, v6 /*entry*/, lang, &str);
    // 拷入 a1[32 + v6]
}
```

> 十六进制以 `mov ebp, imm32` 的字节为准：`0xBC4A75` `0x468863` `0xE34675`
> `0x29956A` `0xE9CBF5` `0xD36BFC` `0x903077` `0x430FFE`。
> 本文档 2026-09-01 版的 8 个十六进制值全部抄错（十进制一直是对的），
> §6.2 早先的"零命中"结论就是被这组错值带偏的，现已推翻，见 §6.2。

`v4` 确为 olang group 键：`text_get` @ `0x1400E6990` 只是 `text_lookup`
@ `0x1400E6EB0` 的薄封装，而 `text_lookup` 就是 olang 的三级查表
（group 键 → entry 键 → key id）。对应关系：

| `text_get` 实参 | olang 层级 |
|---|---|
| `v4` | group 键 |
| `v6`（0 .. `a1[31]`-1） | entry 键 |
| `get_olang_lang_id(-1)` | key id（语言） |

`v3[10..13]` 这四个标志同时也是 `path_resolve_install` @ `0x140043DA0`
里的 DLC 安装槽选择器，因此每组字幕都绑定到一个语音包：

| 模式 `a1[29]` | 标志地址 | DLC 包 | 槽 1 group | 槽 2 group | 行数 `a1[31]` |
|---|---|---|---|---|---|
| 1 | `0x141884934` | `AVD00003.PDT` | `0x00BC4A75` | `0x00468863` | 74 |
| 2 | `0x14188492C` | `AVD00000.PDT` | `0x00E34675` | `0x0029956A` | 38 |
| 3 | `0x141884930` | `AVD00001.PDT` | `0x00E9CBF5` | `0x00D36BFC` | 28 |
| 4 | `0x141884928` | `AVD00002.PDT` | `0x00903077` | `0x00430FFE` | 32 |

标志为 0 时 `switch` 落到 `loc_14026BDB5`（直接置状态 2 返回），不取字幕。
四个标志由 `sub_140035400` @ `0x140035400` 在 Steam 上下文初始化时清零。

→ **游戏内字幕就是 olang 表**，01 号文档的工具可直接提取；
已由 `pwsf.subtitle` 导出，见 §6.2。

### 2.3 字幕上下文结构

`get_subtitle_ctx` @ `0x1402F6030` 返回的上下文：

| 偏移 | 内容 |
|---|---|
| `+0` | 5 个名字槽，16 字节/个（包名，NUL 结尾） |
| `+80` | 5 × u32：`str_hash24(包名)` |
| `+100` | 17 × 5 = 85 字节映射表：`(包 idx, 槽) → 名字槽下标` |

依据 `subtitle_slot_name` @ `0x1401B9DF0`：
```c
if (pkg > 0x10 || slot > 4) return 0;
v5 = *(u8*)(ctx + 100 + 5*pkg + slot);
if (v5 > 4) return 0;
return ctx + 16 * v5;          // 空串返回 0
```

`subtitle_ctx_register_from_filelist` @ `0x1401D4020` 填充它：
```c
for (pkg = 0; pkg < 17; ++pkg) {
    if (((pkg - 6) & 0xFFFFFFFA) != 0 || pkg == 7) {      // 跳过部分包
        for (i = 0; i < 5; ++i) {
            rec = list[i];                                 // 数组在 a1+15264，步长 304 字节
            name = package_name(rec[33], rec[0]);          // rec[33] = u32 @ +132
            h    = str_hash24((char*)(rec + 1));           // 名字在 rec +4
            if (name) subtitle_ctx_update(pkg, name, h);
        }
        list += 38;                                        // +304 字节
    }
}
```
`subtitle_ctx_update` @ `0x1401B9F60`。
`subtitle_slot_table_init` @ `0x1401B8B00` 随后用 `str_hash24` 校验 5 个槽，
失效的槽清 0（未通过校验 → 该包字幕不加载）。

---

## 3. 归档（PDT/DAT）格式 —— **进行中，尚未验证**

`disc0_rel\*.PDT` / `*.DAT` / `*.KEY` 在磁盘上均为密文（首字节随机）。

### 3.1 解密（已确认）

`archive_index_load` @ `0x1401238C0`：
```c
v6 = sub_140044950(handle, hdr40, 40);          // 读 40 字节头 → 0x1412A8050
path_resolve_install(Destination, pkg_path);
key = name_hash(Destination);                   // == name_hash(basename)
sub_14010F8B0(key, mt);                        // = mt_seed(mt, key); mt_advance(mt, 20)
sub_14010F5C0(hdr40, v6, mt);                  // XOR 解密（不重新播种）
...
sub_14010F5C0(index, 12*n, mt);                // 继续用同一 MT 状态
sub_14010F5C0(names, 24*n, mt);
```

`sub_14010F8B0` / `sub_14010F5C0` 与 `buffer_xor_decrypt` **算法完全相同**，
只是把“播种”和“异或”拆开，以便同一 MT 状态连续处理头/索引/名字三段。

### 3.2 头部（推测，未验证）

40 字节头（全局缓冲 `0x1412A8050`）：

| 偏移 | 符号 | 说明 |
|---|---|---|
| `+0` | `qword_1412A8050` | 低 32 位 = A，高 32 位 = B |
| `+8` | `dword_1412A8058` | C |
| `+12` | `dword_1412A805C` | 28 字节暂存区（`sub_140123CC0/DD0` 的目标） |
| `+24` | `word_1412A8068` | **n = 条目数** |
| `+40` | `dword_1412A8078` | 索引缓冲（`12 * n`） |

加载流程：
```
if (A) { if (B) { 变换1 } else { 变换2 } }        // 变换细节未反
*(pkg+204) = qword[0];  *(pkg+212) = C;
读 12*n 字节索引 → 解密
读 24*n 字节名字表 → 解密
// 名字表重定位（每项 24 字节，v22 = base+16，步长 3 个 qword = 24 字节）：
//   *(qword*)(e+8)  = base + *(qword*)(e+8)
//   *(qword*)(e+16) = base + *(qword*)(e+16)
entry_index_bsearch(names, 0, n)
```

### 3.3 实测（未通过自洽校验 —— 记录现状，不作结论）

按 `key = name_hash(stem)`、`mt_advance(20)`、头 40 字节 → 索引 `12n` → 名字表 `24n`
顺序解密：

| 文件 | 大小 | key | A | B | C | n@+24 | 结果 |
|---|---|---|---|---|---|---|---|
| `00b2b475.PDT` | 0x2B2000 | 0xF972B770 | 0x5363DC | 0 | 0 | 56327 | 索引/名字表呈噪声，**未通过** |
| `0001112d.PDT` | 0x6498800 | 0xB479795F | 0x2AD707 | 0 | 0 | 1873 | 噪声，**未通过** |
| `00b2b4b6.PDT` | 0x4EDF800 | 0xCF6434CE | 0x53693D | 0 | 0 | 13373 | 噪声，**未通过** |
| `0076531d.DAT` | 0x3F3560 | 0xC4CECBE0 | 0x4E62456F | 0xFFFFFFFF | 0xFFFFFFFF | 1524 | 头 `[12]=0x5F8==n`、`[16]=0x14`、`[20]=0x48`；索引前 11 个 u32 单调递增（188/305/434/630/796/910/1021/1077/1196/1276/1417），**部分自洽** |

疑点（待排查）：
- `if (n > 96) goto fail` 与 n=13373/56327 矛盾 → **偏移 +24 大概率不是条目数**，
  或 `word_1412A8068` 在 IDA 中的类型/偏移识别有误。需回读 `0x1412A8068` 的实际类型。
- 索引/名字表的**文件偏移**假设（紧接头之后）未证实。
- `sub_140044950` / `sub_140121570` 的读偏移与扇区对齐未反。

---

## 4. 已确认事实 vs 待办

**已确认**
- [x] `.xmx` = MP4(H.264)、`.xsx` = Ogg Vorbis，均 `name_hash` 解密
- [x] 影片目录选择规则（`movie_dir_resolve`）
- [x] 字幕上下文结构（5 名字槽 / 5 哈希 / 85 字节映射表）
- [x] 影片字幕正文 = 归档包内 `SUBTITLE` 条目（NUL 结尾文本）——**格式结论，
      但 Steam 版无此资源，见 §6.1**
- [x] 游戏内字幕 = olang group `0xBC4A75` `0x468863` `0xE34675` `0x29956A`
      `0xE9CBF5` `0xD36BFC` `0x903077` `0x430FFE`，**已全量导出，见 §6.2**
- [x] 归档解密算法与 olang 同一套（`sub_14010F8B0` + `sub_14010F5C0`）
- [x] 归档格式（索引 / 名字表偏移、12 字节索引项、payload 解扰）——
      已在 [04 号文档](04_archive.md) 打通，本节原有的 5 条待办随之作废

**待办**
- [ ] 定位 17 个字幕包名里除 `MMV00000.PDT` / `AVD0000*.PDT` / `BKD00000.PDT`
      之外的其余项（串在 `0x140D234D8` 紧邻 `SUBTITLE`）——
      仅影响完整性，不影响提取

---

## 5. 复现

```powershell
cd d:\PWSF\research\TOOLS
python _probe_xsx.py     # .xsx → Ogg Vorbis
python _probe_pdt.py     # PDT 归档头
python _probe_pdt2.py    # 头 + 索引 + 名字表自洽性检查

cd d:\PWSF
python -m pwsf.subtitle  # 游戏内字幕 → research\ANALYSIS\subtitle_ingame.tsv
```

---

## 6. 补充证据（两条，均推翻/收窄此前结论）

### 6.1 全盘无 `SUBTITLE` 条目 —— 影片字幕资源未随 Steam 版发布

判据：`pwsf.archive_index` 的 `KNOWN` 集合**已包含 `"SUBTITLE"`**，
对 134 个有效容器（113,348 条目）逐个 BST 节点做哈希反查，结果：

```
rows 138 | ok 134 | 有已解析条目名的容器 50 | SUBTITLE 命中 0
```

索引脚本读 `HEAD_CAP = 8 MiB` 的头，而名字表最大仅 `24 × 2304 ≈ 55 KiB`，
索引表 `12 × 2304 ≈ 27 KiB`，**覆盖完整，不存在截断漏检**。

旁证（同一报告）：

| 容器 | 条目数 | CRC | 已解析条目名 |
|---|---:|---|---|
| `ms0\EU\DLCVOICE\171ae461.PDT` | 76 | 76/76 | *（空）* |
| `ms0\EU\DLCVOICE\181ae463.PDT` | 40 | 40/40 | *（空）* |
| `ms0\EU\DLCVOICE\191ae465.PDT` | 30 | 30/30 | *（空）* |
| `ms0\EU\DLCVOICE\1a1ae467.PDT` | 34 | 34/34 | *（空）* |

即 §5 表中 `AVD0000*` 的四个真实文件**全部条目名未在 IDB 字符串表中命中**，
且无一是文本类条目（对比 `DLCBGM` 的 `DBMINFO`/`MUSIC`/`ZAPPIN`、
`DLCTEX` 的 `TEXT` 均可解析）。唯一可能承载字幕的 `BKD00000.PDT`
（`8b1ae97*`）按 `path_resolve_install` 表**未随包发布**。

> 结论：**影片字幕在 Steam 版不可提取，因为数据不存在**。
> 这不是格式没打通，是发行内容缺失——02 号目标的 B 线就此定性收尾，
> 不必再投入逆向。若要字幕，只能自行制作并对齐 `.xmx` 时间轴。

### 6.2 `v4` = olang group 键（已闭合）；先前的"零命中"是抄错常量所致

**先前结论作废。** 2026-09-01 记录的"8 个 group 键在 137,358 行 olang dump
中零命中"，根因是 §2.2 的十六进制值抄错，筛选用的是一组不存在的键。

汇编取证（`0x14026BC00`，127 条指令全量核对）：

```
14026bce6  mov ebp, 0BC4A75h      ; 不是 0xBC5075
14026bcdf  mov ebp, 468863h       ; 不是 0x468563
14026bcc0  mov ebp, 0E34675h      ; 不是 0xE33255
14026bcb2  mov ebp, 29956Ah       ; 不是 0x298E82
14026bc93  mov ebp, 0E9CBF5h      ; 不是 0xE9C6FC
14026bc85  mov ebp, 0D36BFCh      ; 不是 0xD37BFC
14026bc66  mov ebp, 903077h       ; 不是 0x903F77
14026bc55  mov ebp, 430FFEh       ; 不是 0x43895A
14026bd27  mov ecx, ebp           ; ebp 原封不动进 text_get 的第 1 参
14026bd29  call text_get
```

`ebp` 从赋值到 `call` 之间没有任何修改，所以 `v4` 就是 `text_get` 的 group 参数；
而 `text_get` → `text_lookup` @ `0x1400E6EB0` 正是 olang 三级查表。

用汇编原值重新筛 `_dump_olang.tsv`，**8 组全部命中，且行数与 `a1[31]` 精确吻合**
（命中行数 = `a1[31]` × 6 语言 × 2 文件）：

| group | `a1[31]` | dump 命中行 | entry 键 | 承载文件 |
|---|---:|---:|---|---|
| `0xBC4A75` | 74 | 888 | 0..73 连续 | `MLG/Text/009c9ea4.olang` + `EXLANG/Text/00c7f1dd.olang` |
| `0x468863` | 74 | 888 | 0..73 连续 | 同上 |
| `0xE34675` | 38 | 456 | 0..37 连续 | 同上 |
| `0x29956A` | 38 | 456 | 0..37 连续 | 同上 |
| `0xE9CBF5` | 28 | 336 | 0..27 连续 | 同上 |
| `0xD36BFC` | 28 | 336 | 0..27 连续 | 同上 |
| `0x903077` | 32 | 384 | 0..31 连续 | 同上 |
| `0x430FFE` | 32 | 384 | 0..31 连续 | 同上 |

所以这批表**就在 `MLG\Text\` 下**，不需要动 `g_olang_slots` @ `0x14121C020`
的运行时注册链（那仍是 01 号的缺口，但与本模块无关）。

内容即 AI 兵器的战斗语音字幕，例如 `0xBC4A75` 的前几条英文：
`Lock disengaged.` / `Reinitializing platform.` / `Self-defense system online.`

**槽 1 与槽 2 的分工（实测）**：槽 1 的四组六语言俱全（另有 EXLANG 的
葡语副本，写在 es 槽），槽 2 的四组**只有日文非空**——与"槽 2 = 日语语音
DLC"一致。Steam 版发布的是槽 1 的四个包（`171ae461` / `181ae463` /
`191ae465` / `1a1ae467`，见 §5），所以实机生效的是槽 1 这四组。

| 模式 | 包 | 槽 | group | 行数 | 非空（按语言） |
|---|---|---:|---|---:|---|
| 1 | AVD00003 | 1 | `0xBC4A75` | 74 | de/en/es/fr/it/ja/pt 各 68 |
| 1 | AVD00003 | 2 | `0x468863` | 74 | ja 62 |
| 2 | AVD00000 | 1 | `0xE34675` | 38 | ja 20，其余六语各 22 |
| 2 | AVD00000 | 2 | `0x29956A` | 38 | ja 14 |
| 3 | AVD00001 | 1 | `0xE9CBF5` | 28 | 七语各 18 |
| 3 | AVD00001 | 2 | `0xD36BFC` | 28 | ja 14 |
| 4 | AVD00002 | 1 | `0x903077` | 32 | 七语各 16 |
| 4 | AVD00002 | 2 | `0x430FFE` | 32 | ja 14 |

导出：`pwsf.subtitle` → `ANALYSIS/subtitle_ingame.tsv`，
**4,128 行**（含空行，便于回写时保持行号对齐），列为
`mode / pack / slot / group / line / lang / src / text`。
脚本内置断言：每组 entry 键必须构成 `0 .. a1[31]-1` 的连续区间，否则报错退出。

### 6.4 §6.1 的范围收窄（2026-09-18，**旧结论保留**）

§6.1 说「影片字幕在 Steam 版不可提取，因为数据不存在」。
**它证明的东西比这句话窄**：证到的是"归档里没有 `SUBTITLE` 条目、
`MMV00000.PDT` / `BKD00000.PDT` 未随包发布"，这部分仍然成立。

推翻依据：2026-09-18 的实机截图里，漫画过场底部**确实显示着字幕**
（`They're willing to give us an offshore plant`），气泡里还有一整句
英文台词。所以「过场字幕数据不存在」是错的——数据在，只是不走
`subtitle_load_resources` @ `0x14026BDE0` 的 `SUBTITLE` 通路。

这句话既不在 olang（137,358 行）也不在 BRIEFING.DAT（24,438 行）里。
逐容器排除后唯一剩下的去处是 `002aba34.DAT`（= `SLOT.DAT`），
详见 [08_cutscene_text.md](08_cutscene_text.md)。

### 6.3 本轮 IDA 符号更进（IDB 已保存）

| 地址 | 旧名 | 新名 |
|---|---|---|
| `0x140052190` | `sub_140052190` | `get_install_state` |
| `0x14026C1F0` | `sub_14026C1F0` | `subtitle_task_create` |
| `0x140035400` | `sub_140035400` | `steam_ctx_init_clear_install_slots` |
| `0x141884900` | `xmmword_141884900` | `g_install_state` |
| `0x141884920` | `xmmword_141884920` | `g_install_slots_lo` |
| `0x141884930` | `xmmword_141884930` | `g_install_slots_hi` |

另在 `0x14026BC00` / `0x14026BD29` / `0x140052190` / `0x141884920` /
`0x141884930` 写入注释，记录 group 键与安装槽的对应关系。
