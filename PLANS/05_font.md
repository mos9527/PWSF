# 计划 05 · 字体扩字形

状态：**✅ 主线完成，实机已验证**。完整取证见
[../ANALYSIS/05_font.md](../ANALYSIS/05_font.md)。

```
FONT\0007ccd8.xpr  XPR2 / ATG font  4096x4096 A8  643 字形  用到第 612 行  ← 全部字形走它
FONT\000ebbe8.xpr  XPR2 / ATG font  2048x1024 A8  459 字形  用到第 748 行  ← 加载但不参与查找
转换表 cMaxGlyph = 0xFF5E（全 BMP），字形查找按 u16 Unicode 码点
```

## 已完成

- [x] `.xpr` = XPR2（Xbox 360 资源包，大端），加密与 olang 同一套
- [x] XPR2 目录布局（24 B/项，类型标签 + header 块内偏移 + 名字偏移）
- [x] `FontData` 布局：version / 度量 / `cMaxGlyph` / 转换表 / `GLYPH_ATTR[]`
- [x] `font_glyph_rect_for_char` 实证索引键 = u16 Unicode 码点（非 Shift-JIS）
- [x] 图集尺寸从 TX2D 取值常量解出，与 `data_size` 精确对账
- [x] 余量实测：主字体约 51 空行 ≈ 3,100 个全角字位
- [x] 纠正"`Text\*.txp` 是字形贴图"的旧记录——实为按手柄类型选的按键图标包
- [x] **UTF-8 解码链已闭合**：六语言全量文本码点字体 100% 覆盖，
      且"按原始字节索引"被反证（需要 62 个续字节字形，实有 10 个）
- [x] 汉化用字量估算：日文全量用 1,560 汉字，主字体空位 ~3,100 → 装得下
- [x] **汉字走 `g_font_large`，小字体瓶颈不成立**：`g_font_index`
      @ `0x141061A0C` 全映像只有一处写入（`font_static_init` 里赋 0），
      `ui_get_font_handles` 发出的句柄下游三个消费者全都不读
- [x] **图集线性存储**（非 X360 tiled），字形按 `tv1 = 1 + 68k` 行网格排布
- [x] **写回工具链完成**：`pwsf_xpr.py` + `pwsf_font.py`，
      容器 / FontData / 重加密三层往返均**字节一致**
- [x] **中文字形 PoC 跑通**：53 个字形写进第 9 行，字形 643 → 696，
      原有字形与图集区域逐字节未变；已备份 `.orig` 后装入游戏
- [x] **实机确认通过**：玩家名界面的 `up to 15` 渲染成 `up to 一五`
      （证据图 `ANALYSIS/_font_poc_ingame.jpg`）。顺带证明替换字体文件
      不触发任何完整性校验，且 `g_font_index` 恒 0 的结论正确
- [x] IDA 更进 12 处符号并保存 IDB

> **计划 05 主线完成。** 字体侧不再阻塞本土化，
> 后续工作转入 [计划 06](06_localization_pipeline.md)。

## 未完成（可选 / 已降级）

- [ ] TX2D 头 52 字节逐字段反（`sub_140088870` 消费）——仅在要扩大图集时需要
- [ ] 码点 `0x7490` 的特判用途（`font_glyph_metrics` 里的 1.15 倍宽格子）
- [ ] `Text/*.txp` 容器格式（仅在要替换按键图标时需要）

## 复现

```powershell
cd d:\PWSF\TOOLS
python _probe_font1.py    # .xpr/.txp 用 name_hash 加密
python _probe_font2.py    # XPR2 目录 + FontData + 覆盖率 + 图集余量
python _probe_font3.py    # 字体覆盖 vs 全量文本码点；反证按字节索引不成立
python _probe_font4.py    # 图集导出 PNG，确认线性存储
python _probe_font5.py    # 往返字节一致性（容器 / FontData / 重加密）
python _probe_font6.py    # 现役汉字的墨迹度量基准
python _poc_font_cn.py             # 中文字形 PoC：构建 + 校验
python _poc_font_cn.py --install   # 备份 .orig 后装入游戏
python _poc_font_cn.py --restore   # 还原
```
