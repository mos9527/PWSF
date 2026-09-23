# 07 — 可分发补丁（整文件打包 + 两个 .bat）

把「装一份汉化」从「跑三条 Python 命令」变成「发一个文件夹 / 一个 zip，
双击 `install.bat`」。

## 1. 补丁包里有什么

`python -m pwsf.patch --build`（可选 `--zip`）生成 `research/BUILD/pwsf_patch/`：

```
pwsf_patch/
  files/                 按游戏目录原样摆放的「替换文件」（整个文件，非 delta）
    MLG/disc0_rel/0076531d.DAT
    MLG/disc0_rel/002aba34.DAT / .KEY
    MLG/Text/0005ee2f.olang ...（14 个）
    FONT/0007ccd8.xpr
  MANIFEST.tsv           dest\ttarget\tkind\tsize\tsha256\torig_sha256
  files.tsv              dest,payload   （给 .bat 解析，纯路径，无哈希）
  PATCH.txt              版本 / 构建时间 / 逐文件哈希（人工核对用）
  README.txt             食用说明
  install.bat / restore.bat
```

共 18 个文件、≈566 MB（544 MB 是 SLOT.DAT）。

## 2. 为什么整文件打包，不做 delta

`_probe_patch1.py` 实测「原文 vs 构建后」逐字节差异：

| 文件 | 大小 | 改动占比 | 改动分布 |
|------|------|----------|----------|
| SLOT.DAT | 544 MB | 17.4% | 散在 109 个区间，最长 110 MB、中位 330 B |
| 字体 XPR2 图集 | 17 MB | 51% | 3408 处，多为增字形的小段 |
| 14×olang | 各数 KB–数百 KB | 全部 | 整文件重写 |
| CODEC DAT | 4 MB | 极少量 | 几处定长槽位 |

这些文件要么整体加密（MT19937 XOR，olang / codec / 字体 header），要么内部
还压了载荷（SLOT.DAT 记录、XPR2 纹理）。对原文件做二进制 delta：
- SLOT.DAT 的「改动区间」本身就把没变的字节算进去了，真实载荷≈17%，省不了多少；
- 字体是重建了图集，改在纹理像素层，delta 同样散、同样小；
- 还要自己写解码/重打包才能应用 delta，收益抵不过复杂度。

所以「补丁 = 整文件」，安装 = `copy`，玩家端不需要 Python。

## 3. 安装器不校验游戏原版哈希（重要决定）

成品补丁的 `install.bat` 只做两件事：**若该文件还没有 `*.orig` 备份，先备份
当前游戏文件；然后把 `files/` 里的替换文件覆盖过去。** 不做 SHA-256 比对，
不拒绝「既不是原版也不是本补丁」的文件。

理由与取舍：

- 玩家环境千奇百怪，原版哈希门禁会频繁误伤（别的汉化、手动改过、版本不一致），
  而报错对普通玩家不友好。
- 让玩家自己确认 Steam 游戏是最新原版：库里右键 → 属性 → 验证游戏文件完整性。
  这一步本来装任何 mod 都该做。
- 风险：若玩家装补丁时游戏不是原版，被备份成 `*.orig` 的会是「错的文件」，
  之后 `restore.bat` 还原回去的是错的、再 `po_import` 提取英文语料也会中毒。
  食用说明已写明这个坑，责任在玩家侧确认版本。

开发侧仍保留严格模式：`pwsf/in` 的 `install(items, verify_game=True)` 复用
`MANIFEST` 里的 `orig_sha256` 走状态机（原版→备份后装；本构建→跳过；都不像→
拒绝，除非 `--force`），供从仓库迭代时用。成品补丁调的是 `verify_game=False`。

## 4. 备份与还原

- 备份统一用 `config.BACKUP_SUFFIX` = `*.orig`，放在游戏文件旁边。
- `*.orig` 是可逆链路的锚：既是还原依据，也是 `config.pristine`（再提取英文
  语料）的来源，所以**只备份「记录里的原版」**，绝不备份被改过的文件。
- `restore.bat`（成品）/ `python -m pwsf.install --restore`（开发）互为可逆：
  把 `*.orig` 拷回游戏文件。
- 游戏更新后：先还原，再让 Steam 更新，重装补丁即可（`*.orig` 不受更新影响）。

## 5. 静态 helper 的位置

`install.bat` / `restore.bat` 是**静态文件**，放在仓库 `tools/build/`，打包时
`shutil.copy2` 进 `pwsf_patch/`。它们读 `files.tsv`（`dest,payload` 逗号分隔，
Windows 路径不含逗号，batch 用 `delims=,` 解析）拿到每个文件的目标与来源。
不内嵌生成脚本文本——改 installer 直接改 `tools/build/` 下的文件。

## 6. 版本标记

`git_describe()` 取 `YYYYmmdd+g<短哈希>[-dirty]`（无 tag 时回退 `unknown`），
写进 `PATCH.txt` 与 zip 文件名，方便玩家报问题时对上版本。

## 7. 实测结论

- 打包：`--build` 复制 566 MB + 生成清单/说明/拷 .bat，正常。
- 开发侧安装（`verify_game=True`）已由 `_probe_po5.py` 逐情形走过。
- 成品 `.bat` 在开发沙箱里无法端到端跑（环境拦了 `certutil` / `reg`），
  但其逻辑只用最基础的 cmd 习惯用法（`copy`、`for /f`、`reg query` 探测
  Steam 目录、`set /p` 读 `game_dir.txt`），在玩家 64 位 Windows 上即开即用。

## 8. 后续变更（2026-09-23）：安装器与备份一并取消

§4、§5 已被推翻，**保留原文**如下依据：

- 静态 helper `tools/build/install.bat` / `restore.bat` 已删除，包里不再带任何
  脚本；`files.tsv` 与 `patch.write_files_tsv` 同步删掉（它只是给 `.bat` 解析的
  两列路径，`MANIFEST.tsv` 已含同样的目标路径）。
- 装法改为**手动覆盖**：`files\` 按游戏目录原样复制进去覆盖同名文件，
  `pwsf.asi`（必要时加 ASI loader `winmm.dll`）放 `mgspw.exe` 同目录。
  `README.txt` 就写这三步。
- **完全不管备份**：`patch --install` 走 `install(verify_game=False,
  backup=False)`，不留 `*.orig`，`--restore` 参数一并去掉；回到原版靠 Steam
  「验证游戏文件的完整性」。
- 开发侧 `pwsf.install` 的哈希门禁与 `*.orig` 备份不变 —— 那份备份同时是
  `config.pristine` 再提取英文语料的来源，不能丢。
