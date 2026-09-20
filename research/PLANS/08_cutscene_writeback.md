# 08 · 过场文字写回（`pwsf.slotdat_build`）

状态：**方案已定，未实现**。依据都在 `ANALYSIS/08_cutscene_text.md` §7（语料）
和 §8（下一步），数据来自 `_probe_slot27/28/29.py`。

## 1. 目标

把 `src/slot/*.po` 里的译文写回 `MLG/disc0_rel/002aba34.DAT`（544 MB），
覆盖 en 槽（与 `po_import --lang en` 的默认行为一致），产出可安装的
`BUILD/002aba34.DAT` + `BUILD/002aba34.KEY`。

## 2. 为什么不能就地写

记录里的资源条目**只有 (id, off)，没有长度**：一个池的长度 = 下一个条目的
off − 本条目的 off。所以池长度是排布决定的，不是字段。

实测（`_probe_slot27.py`，43 张过场表的 en 池）：

* 池已经装到 **99.3%**（最坏 `0x003b090d`）
* 空转重建（不翻译，只 `OlangBuilder.serialize()`）总共只省 1,263 B —— 内嵌
  池没有磁盘上那 17 个 `.olang` 的 dead slack
* 把译文写成原文的 0.8 / 1.0 / 1.2 倍大小：能放进原槽的分别是
  **42 / 42 / 2** 张

中文会不会更省？用**现成的日文副本**代跑（同 CJK，UTF-8 都是 3 字节/字）：

```
ja/en 字节比   1,575 条串   mean 1.687  median 1.125  p90 3.231
日文写进 en 槽后能放进原槽：14 / 43
   最坏 0x003b054d  15,334 > 13,872  (+1,462 B)
```

**结论：就地写回放弃。**

## 3. 可行方案：重排 + 重压 + 重建容器

解压后的槽是我们自己重建的，不是固定映像 —— 条目 off 是 u32，可以改。
所以：

1. 解压记录 → 得到 `[res 表][data area]`
2. 改目标池（`OlangBuilder.set_text` + `serialize()`）
3. **重排** data area：所有池紧凑排列（去掉原 padding），回写每条目的 off；
   哨兵条目（id `0` / `0x7f000000`）的 off 设为 data area 末尾
4. `zlib -9` 重新压缩
5. 重算 `A = ceil(inflated / 4096)`、`B = ceil((comp + 16) / 4096)`
6. **extra block 原样保留**：`end - start - B` 那个扇区区间是第二个独立的
   zlib 流（`slotdat_load_and_verify` 里 `v20 = v5 + B*4096`）。密文直接搬，
   只重算它在新记录里的位置；它自己单独走一次从偏移 0 起的 XOR
7. 按新 `B` 重排所有记录 → 新的 `start` / `end` → 重写 `SLOT.KEY`
8. 两层 XOR（每个记录都从偏移 0 起用同一条合成密钥流）→ 写 `SLOT.DAT`

实测代价（`_probe_slot29.py`，日文写进 en 槽模拟中文）：

```
触碰 34 个记录，其中 9 个 B 变化
多数 B 反而 −1 扇区（紧凑重排 + zlib -9 省回来的比译文涨的多）
总账：A +4 扇区，B −9 扇区 → SLOT.DAT 小 36,864 字节
```

**文件大小不会失控**，这是方案能落地的决定性数据。

## 4. 落地步骤

1. `pwsf/slotdat_build.py`
   * `repack_record(rec, ks, patch) -> (comp, inflated)` —— 上面第 1–4 步
     （`_probe_slot29.py` 里已有草稿，删掉那个空的 `for e in entries: pass`）
   * `rebuild(translations, lang, outdir)` —— 遍历 2,137 条记录，只重排
     受影响的记录，其余**密文原样搬**（省时间），重写 KEY
2. 验证器：重建后逐条读回，确认
   * 每个记录 `inflate` 成功且 `raw == len(inflated)`
   * 译文落在正确的 `(table_id, group, entry, lang)`
   * 未翻译的池逐字节不变
3. 接进 `pwsf/po_import`：`slots.SlotRef` 已经能解析，`slot_sources()` 也就绪，
   补上 `build` 分支即可（现在 `po_import` 会因为 kind 不是 olang/codec 跳过）
4. 装进 `install.py`（备份 `.orig` + `--restore`，见 AGENTS.md）

## 5. 风险点

| 风险 | 说明 |
|---|---|
| 12 位 `A` 溢出 | `A` 只有 12 位（§4 已经踩过一次：记录 1764/1847 就是被截断的）。重建后若有记录需要 `A > 4095`，得改位域方案——目前最大 1798，余量充足 |
| 压缩率 | 全部 2,137 条都重排时（不只是过场那 34 条）总账未必还是负的，实现时先全量测一遍 |
| 运行时间 | 全量解压 1.2 GB + 重压 ≈ 几分钟；只重排受影响记录会快得多 |
| extra block | 别丢。它不在 `pwsf.slotdat.pools()` 里（那个只解析 data area） |
| 扇区 0 | 记录从 sector 1 开始（start[0]=1），sector 0 的内容未查明，重建时原样保留 |

## 6. 复现

```powershell
python research\TOOLS\_probe_slot27.py   # 就地写回的余量（不可行）
python research\TOOLS\_probe_slot28.py   # ja/en 字节比 + 14/43
python research\TOOLS\_probe_slot29.py   # 重排 + 重压的代价（可行）
```
