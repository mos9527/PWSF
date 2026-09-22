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
> 注入 DLL（`hooklib64/`）和启动器 shim（`pwsf/shim/`）都靠 MSVC 编，
> 纯 Python 的 `po_import` 汉化链路本身不依赖它。

在根目录执行。

- 前置 DLL 构建 -> `pwsf.dll`（名字固定，装成 winmm.dll 还是 pwsf.asi 由安装侧选）
```powershell
cmake -S hooklib64 -B hooklib64/build -A x64
cmake --build hooklib64/build --config Release
```

- 根目录下安装
- `pwsf.dll` 默认装成 `winmm.dll`
- `--hook asi` 装成 `pwsf.asi`（需要已有 Ultimate ASI Loader），`--hook none `不装
```powershell
python -m pwsf.config --init
python -m pwsf.po_import --install
```

还原：`python -m pwsf.install --restore`   # 也会把装进去的注入 DLL 删掉

## 补丁构建

`python -m pwsf.patch --build` 可生成补丁包。

```text
install.bat "游戏目录\mgspw"     # 装之前先确认 Steam 游戏是最新原版
                                  # 会问注入 DLL 装成 winmm.dll（默认）还是 pwsf.asi
restore.bat "游戏目录\mgspw"     # 还原 *.orig 备份，并删掉注入 DLL
```

其余见 [`AGENTS.md`](AGENTS.md)

## Credit
- 简中字库来自 [lxgw/975 圆体](https://github.com/lxgw/975Yuan)
- https://github.com/mos9527/hooklib64
