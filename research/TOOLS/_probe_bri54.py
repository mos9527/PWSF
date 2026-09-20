"""_probe_bri54.py —— CODEC 回写端到端 PoC（pwsf.briefing_build）

_answer_: 译文能不能真的回到 ``0076531d.DAT`` 里、且除了文本池之外
一个字节都没动？

[A] 单元级：``briefing_build.rebuild`` + ``verify``
    —— 取若干 en 记录整条替换，产物与原文**等长**，verify 无问题
[B] 读回：用 ``pwsf.briefing.load``（游戏那套解析）读产物，台词变中文；
    没被点的记录、没被点的行仍是英文
[C] 超预算：译文比原文长 -> 报出，该记录保持英文，绝不搬家
[D] 管线级：临时 .po -> ``python -m pwsf.po_import`` -> MANIFEST.tsv 里
    出现 ``0076531d.DAT``（kind=codec）
"""
import subprocess
import sys
import tempfile
from pathlib import Path

from pwsf_briefing import load
from pwsf import config
from pwsf import briefing as B
from pwsf import briefing_build as BB

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "research" / "BUILD" / "_poc_bri54"


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def fake(text: str) -> str:
    """一条"中文"译文：按 1/4 字节折算成汉字，必定短于原文。"""
    return "\n".join("漢" * max(1, len(seg.encode()) // 4)
                     for seg in text.split("\n"))


def en_records(limit=5):
    """从导出产物里挑几条干净的 en 记录：无 <I= / <R= / % 标记。"""
    rows = config.BRIEFING_TSV.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    by_rec = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        g = int(c[col["group"]])
        off = int(c[col["off"]], 0)
        t = c[col["text"]].replace("\\n", "\n")
        by_rec.setdefault((g, off), {})[int(c[col["line"]])] = t
    out = []
    for (g, off), lines in sorted(by_rec.items()):
        if len(lines) < 2:
            continue
        if any(("<" in t or "%" in t or '"' in t) for t in lines.values()):
            continue
        out.append(((g, off), lines))
        if len(out) >= limit:
            break
    return out


def refs_of(recs):
    """{(g, off): {line: text}} -> translations keyed by reference string."""
    out = {}
    for (g, off), lines in recs:
        for line, text in lines.items():
            out[f"codec/{g}/{off >> 12}/{off:#x}/{line}"] = fake(text)
    return out


def main():
    config.require_game()
    OUT.mkdir(parents=True, exist_ok=True)
    src = BB.source_path()
    raw = src.read_bytes()
    picks = en_records()
    print(f"挑了 {len(picks)} 条 en 记录：")
    for (g, off), lines in picks:
        print(f"  codec/{g}/{off >> 12}/{off:#x}  {len(lines)} 行  "
              f"{lines[0][:44]!r}")

    # ---------------------------------------------------------------- [A]
    trans = refs_of(picks)
    n_lines = len(trans)
    print(f"\n[A] rebuild: {n_lines} 行 / {len(picks)} 条记录")
    path, st = BB.rebuild(trans, config.LANG_EN, OUT)
    problems = BB.verify(path, trans, config.LANG_EN)
    built = path.read_bytes()
    print(f"    产物 {len(built)} 字节，原文件 {len(raw)} 字节，"
          f"等长={len(built) == len(raw)}，有改动={built != raw}")
    print(f"    verify: {len(problems)} 个问题" +
          ("" if not problems else "  " + "; ".join(problems[:3])))
    print(f"    {st}")

    # ---------------------------------------------------------------- [B]
    print("\n[B] 用游戏那套解析读回产物")
    br = load(path)
    idx = {r.off: r for r in br.records}
    ok = bad = 0
    for ref, want in trans.items():
        g, _sec, off, line = (int(x, 0) for x in ref.split("/")[1:])
        got = idx[off].lines[line]
        if got == want:
            ok += 1
        else:
            bad += 1
            if bad <= 3:
                print(f"    {ref}: {got!r} != {want!r}")
    print(f"    译文到位 {ok}/{len(trans)}，错位 {bad}")
    # 未被点的行必须一字不改
    picked = {(g, off) for g, off in [(g, off) for (g, off), _ in picks]}
    touched = set()
    for ref in trans:
        g, _s, off, line = (int(x, 0) for x in ref.split("/")[1:])
        touched.add((g, off, line))
    old = {r.off: r for r in B.iter_records(bytes(BB.crypt(raw)))}
    diff = 0
    for (g, off) in picked:
        for i, (a, b) in enumerate(zip(old[off].lines, idx[off].lines)):
            if (g, off, i) not in touched and a != b:
                diff += 1
    print(f"    未点名的行有改动: {diff}")
    other = sum(1 for off, r in old.items()
                if off not in {o for _g, o in picked}
                and r.lines != idx[off].lines)
    print(f"    未点名的记录有改动: {other}")

    # ---------------------------------------------------------------- [C]
    print("\n[C] 超预算路径")
    (g, off), lines = picks[0]
    huge = dict(trans)
    huge.update({f"codec/{g}/{off >> 12}/{off:#x}/{k}": "漢" * 400
                 for k in lines})
    path2, st2 = BB.rebuild(huge, config.LANG_EN, OUT)
    print(f"    overflow {len(st2.overflow)} 条: {st2.overflow[:2]}")
    idx2 = {r.off: r for r in B.iter_records(bytes(BB.crypt(path2.read_bytes())))}
    kept = all(idx2[off].lines[i] == lines[i] for i in lines)
    print(f"    该记录保持英文: {kept}")
    print(f"    其余记录照写: {st2.rewritten}/{st2.targeted}")

    # ---------------------------------------------------------------- [D]
    print("\n[D] 管线级：临时 .po -> po_import")
    with tempfile.TemporaryDirectory() as tmp:
        po_dir = Path(tmp) / "po"
        po_dir.mkdir()
        build = Path(tmp) / "build"
        body = []
        for ref, t in trans.items():
            parts = ref.split("/")
            off, line = int(parts[3], 0), int(parts[4])
            body.append(f'#: {ref}\nmsgid "{esc(old[off].lines[line])}"\n'
                        f'msgstr "{esc(t)}"\n')
        (po_dir / "codec_poc.po").write_text(
            'msgid ""\nmsgstr ""\n"Language: zh_CN\\n"\n\n'
            + "\n".join(body), encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "pwsf.po_import",
                            "--po-dir", str(po_dir), "--outdir", str(build),
                            "--skip-font"],
                           cwd=REPO, capture_output=True, text=True)
        print("    " + "\n    ".join(r.stdout.strip().splitlines()[-14:]))
        if r.returncode != 0:
            print("    STDERR:", r.stderr[-800:])
            return 1
        mf = (build / "MANIFEST.tsv").read_text(encoding="utf-8").splitlines()
        print("    MANIFEST:")
        for line in mf[1:]:
            print("      " + line[:110])

    # ---------------------------------------------------------------- [E]
    # 超预算必须被 po_lint 拦在编译之前
    print("\n[E] po_lint 对超预算译文的反应")
    with tempfile.TemporaryDirectory() as tmp:
        po_dir = Path(tmp) / "po"
        po_dir.mkdir()
        build = Path(tmp) / "build"
        (g, off), lines = picks[0]
        body = []
        for line, text in lines.items():
            body.append(f'#: codec/{g}/{off >> 12}/{off:#x}/{line}\n'
                        f'msgid "{esc(old[off].lines[line])}"\n'
                        f'msgstr "{esc("漢" * 400)}"\n')
        (po_dir / "codec_over.po").write_text(
            'msgid ""\nmsgstr ""\n"Language: zh_CN\\n"\n\n'
            + "\n".join(body), encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "pwsf.po_lint",
                            "--po-dir", str(po_dir), "--no-font"],
                           cwd=REPO, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "error" in line or "codec-budget" in line:
                print("    " + line.strip())
        print(f"    po_lint 退出码 {r.returncode}（非 0 = 已拦截）")
        r = subprocess.run([sys.executable, "-m", "pwsf.po_import",
                            "--po-dir", str(po_dir), "--outdir", str(build),
                            "--skip-font"],
                           cwd=REPO, capture_output=True, text=True)
        print(f"    po_import 退出码 {r.returncode}（非 0 = 拒绝构建）")

    print(f"\n产物留在 {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
