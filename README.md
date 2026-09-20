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

从源码装（开发用）：

```powershell
python -m pwsf.config --init
python -m pwsf.po_import --install
```

还原：`python -m pwsf.install --restore`

## 补丁构建

`python -m pwsf.patch --build` 可生成补丁包。

```text
install.bat "游戏目录\mgspw"     # 装之前先确认 Steam 游戏是最新原版
restore.bat "游戏目录\mgspw"     # 还原 *.orig 备份
```

其余见 [`AGENTS.md`](AGENTS.md)

## Credit
- 简中字库来自 [lxgw/975 圆体](https://github.com/lxgw/975Yuan)

