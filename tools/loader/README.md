# tools/loader

打包时随补丁一起分发的 **ASI loader**（`winmm.dll`），用来加载 `pwsf.asi`。

## 为什么需要

字体注入 DLL 只能以 `.asi` 形态工作。伪装成 `winmm.dll` 会在**导入解析阶段**
就被加载 —— 那时 exe 还在 Steam/壳的解密之前，整模块里扫不到 `font_load_xpr`
的 prologue（2026-09-22 实测 `sigscan = 0`，hook 装不上）。由 ASI loader 晚加载
才能命中。

## 安装策略

**只在游戏目录还没有 `winmm.dll` 时才放。** 已经有的话原样保留 —— 那可能是玩家
或其它 mod 自己的 loader，覆盖它会弄坏别人的东西。还原时也只删 `pwsf.asi`，
loader 不动。

## 这份文件

- 来源：Ultimate ASI Loader，x64 Release 的 `winmm.dll`
  （zip 里 `winmm-x64.SHA512` 记录的原始路径 `bin\x64\Release\winmm.dll`）
- 大小：3,615,928 字节
- SHA512：`840C97B7B3ED40DE3D4E6372D9BD43B022796F4EA57C71969B5DED978B344ED5A70579318337877B9AAD8C6F0E74CE19B32F1AC5D4C5E5679D5F4682819937FA`

`winmm-x64.SHA512` 一并留着，便于日后核对文件没被动过。上游许可见
https://github.com/ThirteenAG/Ultimate-ASI-Loader —— 分发时按其许可署名。
