# Peace Walker Sans Frontiers

> [!WARNING]
> 字库，提取，等逆向工作几乎完全由大模型完成
> AI 大模型使用: Claude Opus 5, Tencent Hunyuan 4-dev, Tencent Hunyuan 3

> [!TIP]
> 翻译工作起步初期，有意者欢迎 PR 参与工作。

METAL GEAR SOLID PEACE WALKER（Steam 版）本土化工具链

## 安装依赖

Python 3.13，除字体构建用到的 Pillow 外无第三方依赖

```powershell
pip install pillow
```

## 使用

```powershell
python -m pwsf.config --init
python -m pwsf.po_import --install
```

还原：`python -m pwsf.install --restore`

其余见 [`AGENTS.md`](AGENTS.md)

## Credit
- 简中字库来自 [lxgw/975 圆体](https://github.com/lxgw/975Yuan)

