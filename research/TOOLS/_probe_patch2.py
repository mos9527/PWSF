"""Probe: 补丁包该不该压缩 —— 载荷熵值实测（PLANS/07、`pwsf.patch`）

打包默认 store（`--zip-level 0`）的依据：加密 + 压缩过的游戏容器，deflate
压不动。本脚本对补丁包里四类载荷各取一段（SLOT.DAT 取 64 MB，其余 16 MB /
整文件）分别走 ZIP_STORED 与 deflate -9，报出体量比与耗时差。

Usage:  python research/TOOLS/_probe_patch2.py          # 需要先 --build
"""
import io
import time
import zipfile
from pathlib import Path

BASE = Path("research/BUILD/pwsf_patch/files")
# (相对路径, 取样字节数；None = 整文件)
SAMPLES = [
    ("MLG/disc0_rel/002aba34.DAT", 64 << 20),
    ("FONT/0007ccd8.xpr", 16 << 20),
    ("MLG/disc0_rel/009645fa.PDT", 16 << 20),
    ("MLG/disc0_rel/0076531d.DAT", None),
]


def zipped(data: bytes, level: int) -> tuple:
    """-> (zip 体量, 耗时秒)"""
    buf = io.BytesIO()
    t = time.time()
    kw = {} if level <= 0 else {"compresslevel": level}
    method = zipfile.ZIP_STORED if level <= 0 else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", method, **kw) as z:
        z.writestr("x", data)
    return len(buf.getvalue()), time.time() - t


def main() -> None:
    if not BASE.is_dir():
        raise SystemExit(f"{BASE} 不存在，先跑 python -m pwsf.patch --build")
    print(f"{'payload':34s} {'raw':>12s} {'store':>12s} "
          f"{'deflate9':>12s} {'%':>7s} {'extra s':>8s}")
    for rel, n in SAMPLES:
        p = BASE / rel
        if not p.is_file():
            print(f"{rel:34s} (missing)")
            continue
        with p.open("rb") as f:
            data = f.read() if n is None else f.read(n)
        s, ts = zipped(data, 0)
        d9, td = zipped(data, 9)
        print(f"{rel:34s} {len(data):12,d} {s:12,d} {d9:12,d} "
              f"{100.0 * d9 / len(data):6.2f}% {td - ts:8.1f}")


if __name__ == "__main__":
    main()
