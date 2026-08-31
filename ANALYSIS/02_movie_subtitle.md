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

### 2.2 olang 表（游戏内字幕 / 提示字幕）

`subtitle_state_machine` @ `0x14026BC00`：
```c
switch (a1[29]) {                    // 字幕显示模式
  case 1: v4 = (v3[13]==1) ? 12339829 : 4622435;   a1[31] = 74; break;  // 0xBC5075 / 0x468563
  case 2: v4 = (v3[11]==1) ? 14894709 :  2725226;  a1[31] = 38; break;  // 0xE33255 / 0x298E82
  case 3: v4 = (v3[12]==1) ? 15322101 : 13855740;  a1[31] = 28; break;  // 0xE9C6FC / 0xD37BFC
  case 4: v4 = (v3[10]==1) ?  9449591 :  4395006;  a1[31] = 32; break;  // 0x903F77 / 0x43895A
}
for (v6 = 0; v6 < a1[31]; ++v6) {
    lang = get_olang_lang_id(-1);
    text_get(v4 /*group*/, v6 /*entry*/, lang, &str);
    // 拷入 a1[32 + v6]
}
```
→ **游戏内字幕就是 olang 表**，group 键为上面 8 个常量之一，entry 为行号。
这部分 **01 号文档的工具已可直接提取**。

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
- [x] 影片字幕正文 = 归档包内 `SUBTITLE` 条目（NUL 结尾文本）
- [x] 字幕上下文结构（5 名字槽 / 5 哈希 / 85 字节映射表）
- [x] 游戏内字幕 = olang group `0xBC5075` `0x468563` `0xE33255` `0x298E82`
      `0x903F77` `0x43895A` `0xE9C6FC` `0xD37BFC`
- [x] 归档解密算法与 olang 同一套（`sub_14010F8B0` + `sub_14010F5C0`）

**待办**
- [ ] 确认 `0x1412A8068` 的真实类型/偏移，解出正确的条目数 n
- [ ] 反 `sub_140044950` / `sub_140121570`，确定索引与名字表的文件偏移
- [ ] 反 `entry_index_bsearch` @ `0x140123D60`，确定 12 字节索引项布局
- [ ] 反 `entry_payload_transform` @ `0x140123E90` / `entry_payload_unmask` @ `0x140124000`
- [ ] 定位 17 个字幕包名（`MMV00000.PDT` `AVD0000*.PDT` `BKD00000.PDT` 等，
      串在 `0x140D234D8` 紧邻 `SUBTITLE`）
- [ ] 打通后：解出 `SUBTITLE` 条目内容并导出

---

## 5. 复现

```powershell
cd d:\PWSF\TOOLS
python _probe_xsx.py     # .xsx → Ogg Vorbis
python _probe_pdt.py     # PDT 归档头
python _probe_pdt2.py    # 头 + 索引 + 名字表自洽性检查
```
