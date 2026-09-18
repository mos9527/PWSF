# 计划 05 · 字体扩字形

状态：**格式已打通，可扩性已实证**。完整取证见
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
- [x] IDA 更进 12 处符号并保存 IDB

> **字库工作没有前置阻塞了，可以直接开工。**
> 需要 ~1,560 字位，主字体有 ~3,100 个，不用扩图集。

## 未完成

### A. 写回工具（唯一剩余工作）

- [ ] `pwsf_xpr.py`：XPR2 解包 / 重打包（保持大端与目录偏移自洽）
- [ ] `pwsf_font.py`：转换表与 `GLYPH_ATTR` 的读写；从 TTF 渲染 8 位灰度
      字形并装箱进图集空白行；`version` 保持 5
- [ ] 校验：重打包后重新解析应逐字段等价，且 `12+header+data == 文件大小`

### B. 可选 / 已降级

- [ ] TX2D 头 52 字节逐字段反（`sub_140088870` 消费）——仅在要扩大图集时需要
- [ ] 码点 `0x7490` 的特判用途（`font_glyph_metrics` 里的 1.15 倍宽格子）
- [ ] `Text/*.txp` 容器格式（仅在要替换按键图标时需要）

## 复现

```powershell
cd d:\PWSF\TOOLS
python _probe_font1.py
python _probe_font2.py
python _probe_font3.py
```
