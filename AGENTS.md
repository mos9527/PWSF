PWSF - PEACE WALEKR SANS FRONTIERS
---
METAL GEAR SOLID PEACE WALKER (STEAM) 本土化工作

# Goal
当前目标
- [x] 实现 UI 文字的【提取】 → `ANALYSIS/_dump_olang.tsv`（137,358 行）
- [x] 实现字幕文字的【提取】 → `ANALYSIS/subtitle_ingame.tsv`（4,128 行）
      影片字幕在 Steam 版无数据，见 `ANALYSIS/02_movie_subtitle.md` §6.1
- [x] 实现 CODEC 的【提取】 → `ANALYSIS/_briefing_lines.tsv`（24,438 行）

下一步：回写（rebuild）工具链，见 `PLANS/01_ui_text.md` 待办 3

# Rules
- 使用 IDA MCP 获取+更新证据
- 积极更进 IDA 符号名
- 一切实现【务必】收集【完整】证据链
- 【绝不】guess，【一定】从二进制发现实现逻辑
- 发现【一定】撰写各自模块文档，放在 `ANALYSIS` 目录下
- 长上下文工作需要breakup成多个计划文件，放在 `PLANS` 目录下
