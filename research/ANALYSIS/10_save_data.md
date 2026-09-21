# 10 · 存档（`mgspw_savedata_win`）

起因：实机截图里存档列表还显示英文任务名
`Opening / Investigate the Supply Facility`，而 `src/slot/slot_12.po` 里这句
已经译好。要判断「是没覆盖到的语料」还是「文字根本存在存档里」，就得把存档
打开看。

**结论：存档里没有任务名 → 那是运行时查表来的 → 查的是 STAGEDAT 那份
`lang_mission_info`（见 §4）。**

---

## 1 存档在哪

```
C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw_savedata_win\
    <steam_id64>\launcher\launcher_sv       436 B   JSON（上次语言/窗口模式）
    <steam_id64>\steam_autocloud.vdf         53 B
    <steam_id64>\usersv                    4096 B
    <steam_id64>\ww\EU_SYSTEM.DAT           144 B   系统档（JP 版叫 JP_SYSTEM.DAT）
    <steam_id64>\ww\STW000000ac1d01     325,968 B   游戏存档
```

`325,968 B = 325.9 KB`，与截图显示的「325.9KB」一致，mtime `2026-09-21 12:35`
与截图时间一致 —— **截图里的就是这个文件**。目录由

```
sub_14010EBF0:  sub_14001F910(buf, "%s")            -> "../mgspw_savedata_win"
                mkdir
                sub_14001F910(buf, "%s/%lld")       -> + steam id
                sub_14001F910(buf, "%s/%lld/%s")    -> + "ww"
```

拼出（`../mgspw_savedata_win` @ `0x1409BD8F0`）。文件名前缀由
`sub_1400416E0` 给出：`lang_get_language_id() == 6 ? "STJ000000" : "STW000000"`
（@ `0x140D8FFE0` / `0x140D8FFF0`）。列表界面就是 `sub_140036550` 用
`FindFirstFileA` 扫这个目录、按前缀过滤，最多 99 项。

## 2 加密：又是那个 LCG

`systemdat_state_machine` @ `0x1401BBC80` case 4 →
`systemdat_decrypt_and_build` @ `0x1401BE8F0`：

```c
v40 = LCG(g_rand_state);                    // 1566083941 * s + 1
v1[i] = g_rand_state;                       // 12 个 u32 写进头
idx   = (v49 >> 8) % 5;
*v1        = idx ^ (v1[1] | 0xAD47DE8F);
v1[idx+2]  = s0 ^ 0x1327DE73;
v1[idx+3]  = s1 ^ 0x2D71D26C;
v1[idx+7]  = s2 ^ 0xBC4DEFA2;
sub_14010DE00(s0, s1, s2);                  // 播种
sub_14010DDC0(v1 + 16, len);                // 加扰，数据从偏移 64 开始
```

`sub_14010DE00` @ `0x14010DE00` / `sub_14010DDC0` @ `0x14010DDC0`：

```c
v3    = s1 ^ s0;
state = v3 | ((v3 ^ 0x6576) << 16);
inc   = s2 * v3;
for (dword) { *p++ ^= state; state = inc + 48828125 * state; }
```

与归档层 `entry_payload_transform` @ `0x140123E90` 的 mode 0x40 分支**同一个
LCG**（`04_archive.md` §6.2 / 09 §2）。种子自存在 64 字节头里，所以离线可解。

## 3 实测：解开 `STW000000ac1d01`

`_probe_savedata3.py`：

```
header u32: efefdebb cba8deb8 71cdc699 7a9c6d5e 0d693017 4a847614
            13e955b7 2dca1141 f3d19f83 6f580fb0 12c2c071 bc2a8b10
            001723cc 00000000 1529027b 61d35637
recovered idx = 4            (合法范围 0..4)
seeds s0=0x00ce8bc4 s1=0x00bbc32d s2=0x006764b2
  -> state=0x2dff48e9 inc=0x77c6b602
```

解出来 `0x186c0..0x18c80` 是一串**明文台词**（玩家喊话槽位）：

```
GO! GO! GO! | Hold it! | We're pulling out! | It's the enemy! |
I don't think so. | I'm good to go. | CO-OP In! | Give me a hand. |
Snake In! | Take cover!! | Impressive. | Good luck. |
I'm counting on you! | I knew you had it in you... | That's good stuff!!
```

**没有任务名**（ASCII 与 UTF-16LE/BE 都搜过，`Investigate` / `Opening` /
`Supply` 全部 -1）。其余 99% 是二进制游戏状态。

## 4 那存档列表上的任务名从哪来

排除法：

| 候选 | 证据 |
|---|---|
| 磁盘 17 张 `.olang` | `_dump_olang.tsv`（137k 行）里 `Investigate the Supply` **-1** |
| 存档文件 | §3，解密后无此字符串 |
| SLOT.DAT 的 `0x00514128`（= `lang_mission_info`） | `_probe_slot_installed.py` 直读**已安装的** `research/BUILD/002aba34.DAT`：该槽位已是 `开场／调查补给设施`（两条副本 `0xa7f464` / `0xd19ef2` 都是）。装进游戏后界面仍显示英文 ⇒ 不是它 |
| **STAGEDAT 的 `lang_mission_info_en.olang`**（entry 15/174/180） | 剩下唯一一份 ⇒ **就是它** |

即：**这批任务名/任务说明走的是 stage，stage 现在只读（`po_import` 跳过、
`po_lint` 报 `stage-readonly`），所以它还是英文。** 直接证明要等 stage 写回
（或从 IDA 反查列表界面的取文本函数），目前是排除法结论。

## 5 复现

```powershell
python research\TOOLS\_probe_savedata.py          # 存档目录列清单 + needle
python research\TOOLS\_probe_savedata2.py         # 字节特征（魔数/周期/zlib）
python research\TOOLS\_probe_savedata3.py --dump research\BUILD\save_plain.bin
python research\TOOLS\_probe_slot_installed.py    # 直读已安装的 SLOT.DAT 产物
python research\TOOLS\_probe_briefing_exlang.py   # EXLANG 那份 BRIEFING
```

## 6 未闭合

1. 除喊话槽位外，存档其余二进制结构未反（任务进度、Mother Base 状态等）。
2. `EU_SYSTEM.DAT`（144 B）与 `usersv`（4096 B）用了同一套 LCG 但分区不同
   （`systemdat_decrypt_and_build` 里有两个长度：231,408 与 61,664），未逐一验证。
3. §4 是排除法，缺一条「列表界面取文本函数」的正面证据。
