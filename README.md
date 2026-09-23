# Peace Walker Sans Frontiers

> [!WARNING]
> 字库，提取，等逆向工作几乎完全由大模型完成
>
> AI 大模型使用: Claude Opus 5, Tencent Hunyuan 4-dev, Tencent Hunyuan 3

> [!TIP]
> 翻译工作初版同样使用大模型生成（见 `tools/`），有意人工校对，润色者欢迎 PR/提交 Issue 参与工作。

METAL GEAR SOLID PEACE WALKER（Steam 版）翻译工作

## 安装依赖

Python 3.13，除字体构建用到的 Pillow 外无第三方依赖

```powershell
pip install pillow
```

## 使用

从 Release 获取：[传送门](https://github.com/mos9527/PWSF/releases)

从源码装（开发用）

> [!NOTE]
> 需要 **Visual Studio Build Tools**（MSVC `cl` + Windows SDK）和 `cmake`：
> 注入 DLL（`hooklib64/`）由 `po_import --install` 自动调 cmake 编，启动器
> shim（`pwsf/shim/`）靠 `cl` 编。纯 Python 的汉化链路本身不依赖它。

在根目录执行。

```powershell
python -m pwsf.config --init
python -m pwsf.po_import --install
```

- 注入 DLL 只有一种形态：编出的 `pwsf.dll` 装成 **`pwsf.asi`**（`--hook asi`，
  默认；`--hook none` 不装）。伪装成 `winmm.dll` 会在 exe 解密之前加载，扫不到代码
- 自带的 ASI loader（`winmm.dll`）**只在游戏目录没有时才补一个**；已有则原样保留，
  不抢别的 mod 的 loader
- `--debug-hook` 按 `-DPWSF_DEBUG=ON` 重编：弹控制台并打印 hook 每一步

还原：`python -m pwsf.install --restore`   # 删掉装进去的 pwsf.asi（loader 保留）

可选，启动器直接启动游戏：

```powershell
python -m pwsf.launch --install-shim
```
## 补丁构建

`python -m pwsf.patch --build` 生成补丁包（`research/BUILD/pwsf_patch/` 与 `PWSF-<ver>.zip`）。

没有安装器，也不做备份 —— 装就是手动覆盖：

1. Steam 库里右键 MGS PW → 属性 →「已安装的文件」→ 验证游戏文件的完整性，确认是最新原版
2. 把包里 `files\` 的内容按目录结构复制进游戏目录（含 `FONT`、`MLG` 的 `mgspw`），同名一律覆盖
3. 把 `pwsf.asi` 放进 `mgspw.exe` 所在目录；那里还没有 `winmm.dll` 的话再放一个包里的 `winmm.dll`（ASI loader）

想卸掉就再「验证游戏文件的完整性」让 Steam 把文件拉回来，然后手动删掉 `pwsf.asi`。

开发侧 `python -m pwsf.install` 仍会留 `*.orig` 备份（它同时是英文语料的来源）；补丁包刻意不管备份。

其余见 [`AGENTS.md`](AGENTS.md)

## Credit
- 简中字库来自 [lxgw/975 圆体](https://github.com/lxgw/975Yuan)
- https://github.com/mos9527/hooklib64
