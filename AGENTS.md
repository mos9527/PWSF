PWSF - PEACE WALKER SANS FRONTIERS
---
METAL GEAR SOLID PEACE WALKER (STEAM) 本土化工作

# Goal
- [x] UI 文字【提取】 → `research/ANALYSIS/_dump_olang.tsv`（137,358 行）
- [x] 字幕文字【提取】 → `research/ANALYSIS/subtitle_ingame.tsv`（4,128 行）
      影片字幕在 Steam 版无数据，见 `research/ANALYSIS/02_movie_subtitle.md` §6.1
- [x] CODEC【提取】 → `research/ANALYSIS/_briefing_lines.tsv`（24,438 行）
- [x] 写回链路实机验证：olang 文本 + 字体扩字形
- [x] 汉化管线闭环：`pwsf.po_lint` / `po_import` / `install`，见 `research/PLANS/06` §9
- [ ] 可分发补丁 `pwsf.patch`，指示见 `README.md` §下一步 → `research/PLANS/07`
- [ ] CODEC 回写：卡在 `briefing_insn_decode` 的 `case 0x10/0x20` 长度规则
- [x] 过场（漫画）文字【提取】：`SLOT.DAT` 两层 XOR（MT + LCG）已破，2,137
 条记录全量解压；内嵌 144 张 `.olang` 表（其中 43 张是过场，英文 1,928 行）
 → `_cutscene_lines.tsv` / `_slot_olang_lines.tsv`，见
 `research/ANALYSIS/08_cutscene_text.md` §5.5 / §7
- [ ] 过场文字【写回】：语料已进 .po（默认开），`pwsf.slotdat_build` 未实现；
 方案 = 重排池 + 重压 + 重建容器（实测文件反而小 36 KB），
 见 `research/PLANS/08_cutscene_writeback.md`

# Layout
```
pwsf/        工具包。成熟实现放这里，模块名不带前缀（pwsf.crypto 等）
src/         翻译工作区（.po）
research/
  ANALYSIS/  逆向文档（编号 01..07）+ 提取产物 + 证据图
  PLANS/     工作拆分，00_overview.md 是索引
  TOOLS/     _probe_* 取证脚本、_poc_* 端到端验证、pwsf_* 兼容垫片
  BUILD/     重打包产物（gitignore）
```

# Rules
- 使用 IDA MCP 获取+更新证据
- 积极更进 IDA 符号名
- 一切实现【务必】收集【完整】证据链
- 【绝不】guess，【一定】从二进制发现实现逻辑
- 发现【一定】撰写各自模块文档，放在 `research/ANALYSIS` 目录下
- 长上下文工作需要breakup成多个计划文件，放在 `research/PLANS` 目录下

# Conventions
- 路径一律走 `pwsf.config`，【不要】再硬编码游戏目录
- `research/TOOLS/_probe_*.py` 是**证据**，保留不删；文档里的每个数字都要能由
  对应探针复现，新结论先写探针再写文档
- 成熟能复用的实现【移入】`pwsf/` 包；`research/TOOLS/pwsf_*.py` 是垫片，别在
  那里写逻辑
- 模块 docstring 里写清结论来自哪个 IDA 地址
- 改动二进制前先备份 `.orig`，并提供 `--restore`
- 推翻旧结论时【保留】错误记录与推翻依据（例：`02_movie_subtitle.md` §6.2）
