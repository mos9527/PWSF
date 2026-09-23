"""证据：STAGEDAT（009645fa.PDT）内嵌归档的【文件清单】普查。

`pwsf.stage` 只把 `.olang` 成员当语料（`lang_of()` 靠 `_en/_fr/...` 后缀判
语言，非 olang 一律跳过）。本脚本把内嵌归档里**所有**成员列出来，按扩展名
统计，并给每个非 olang 成员记下前 32 字节 —— 用来判断有没有漏掉的文本文
件（.txt / .xml / .msd / 无名文件等）。

用法（仓库根）：
    python research\\TOOLS\\_probe_stage_files.py
    python research\\TOOLS\\_probe_stage_files.py --limit 20
    python research\\TOOLS\\_probe_stage_files.py --grep infiltr
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pwsf import stage as ST                      # noqa: E402
from pwsf.archive import parse as arc_parse, verify as arc_verify  # noqa: E402


def printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--grep", default=None,
                    help="只在成员数据里搜这个子串（大小写不敏感）")
    args = ap.parse_args()

    container = ST.container_path()
    with container.open("rb") as f:
        arc = arc_parse(f.read(min(container.stat().st_size, ST.HEAD_CAP)),
                        container.stem, str(container), max_entries=200000)
    problems = arc_verify(arc, container.stat().st_size)
    if problems:
        raise SystemExit(f"container self-check failed: {problems}")
    state0, inc = ST.seeding(arc)
    print(f"{container}: {arc.count} entries, mode {arc.mode:#x}")

    n_files = 0
    ext_of = Counter()
    non_olang = []
    hits = []
    needle = args.grep.encode() if args.grep else None
    nlow = needle.lower() if needle else None

    with container.open("rb") as f:
        total = arc.count if not args.limit else min(args.limit, arc.count)
        for i in range(total):
            e = arc.entries[i]
            f.seek(e.c)
            plain = ST.payload(arc, f.read(e.a), state0, inc)
            body, note = ST.inflate(plain)
            if body is None:
                continue
            files, err = ST.inner_files(body)
            if err:
                print(f"  entry {i}: inner archive parse failed ({err})")
                continue
            for name, size, data in files:
                n_files += 1
                ext = name.rsplit(".", 1)[-1] if "." in name else "<none>"
                ext_of[ext] += 1
                if ext != "olang":
                    non_olang.append((i, name, size, data[:32]))
                if nlow and nlow in data.lower():
                    hits.append((i, name, data.lower().find(nlow)))
    print(f"{n_files} inner files")
    for ext, n in ext_of.most_common():
        print(f"  {ext:10s} {n}")
    print(f"\n{len(non_olang)} non-.olang members:")
    for i, name, size, head in non_olang[:200]:
        print(f"  entry {i:4d} {size:9d} B  {name}  {head.hex()} "
              f"|{printable(head)}|")
    if needle:
        print(f"\ngrep {args.grep!r}: {len(hits)} hit(s)")
        for i, name, off in hits[:50]:
            print(f"  entry {i:4d} {name} @ {off:#x}")


if __name__ == "__main__":
    main()
