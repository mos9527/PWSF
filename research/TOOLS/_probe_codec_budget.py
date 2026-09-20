"""_probe_codec_budget.py —— CODEC 池超预算：行级账目与定向压缩

`po_lint` 只报「记录 0x97400 需要 264 字节、池只有 236」，却不说该动哪一行：
一条记录里常有十几行，其中只有一部分是译文。本探针把账算到行 ——

    need   = sum(len(utf8(line)) + 1)   未译的行按英文原文计入
    budget = off3 - off2                记录自带的池容量，改不了（ANALYSIS/03 §9.2）

再按 (译文字节 - 原文字节) 排序，指出哪些译文最该瘦身。

`--fix` 把最该瘦身的行交给模型压一轮，要求这一批合计省出 ≥ gap 字节，
校验通过才写回 .po：换行数 / `<I=>` / 格式符必须与原文一致，压完重算 need
必须 ≤ budget（校验用 `briefing_build.overflows`，与 lint 同一个判据）。

用法：
    python research\\TOOLS\\_probe_codec_budget.py             # 只报告
    python research\\TOOLS\\_probe_codec_budget.py --fix        # 压缩并写回
"""
import argparse
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import poio                                    # noqa: E402
import requests                                # noqa: E402
from pwsf import briefing as B                 # noqa: E402
from pwsf import briefing_build as BB          # noqa: E402
from pwsf import slots                         # noqa: E402

PO_DIR = ROOT / "src" / "codec"
API_URL = "https://openrouter.ai/api/v1/chat/completions"


def blen(s: str) -> int:
    return len(s.encode("utf-8"))


def load_po():
    """{(group, off, line): (path, entry)} —— 已填译文的 CODEC 条目。"""
    out = {}
    for path in sorted(PO_DIR.glob("*.po")):
        entries, _ = poio.parse(path)
        for e in entries:
            if not e.msgstr:
                continue
            for r in e.refs:
                if not r.startswith("codec/"):
                    continue
                ref = slots.parse_ref(r)
                out[(ref.group, ref.off, ref.line)] = (path, e)
    return out


def translations(by_ref):
    """{#: reference: msgstr} —— `briefing_build` / `po_lint` 吃的形状。"""
    out = {}
    for (g, off, line), (_path, e) in by_ref.items():
        for r in e.refs:
            if r.startswith("codec/"):
                out[r] = e.msgstr
    return out


def account(by_ref, recs, over, show=8):
    """[(gap, off, need, budget, rows)] —— rows 按可省字节降序。"""
    out = []
    for g, off, need, budget in over:
        rec = recs.get(off)
        if rec is None:
            continue
        rows = []
        for i, src in enumerate(rec.lines):
            hit = by_ref.get((g, off, i))
            if hit is None:
                continue
            path, e = hit
            rows.append({"line": i, "src": src, "dst": e.msgstr,
                         "src_bytes": blen(src), "dst_bytes": blen(e.msgstr),
                         "path": path, "entry": e})
        rows.sort(key=lambda r: -(r["dst_bytes"] - r["src_bytes"]))
        out.append((g, off, need, budget, rows))
    return out


SHRINK_SYSTEM = """你是本地化审校。下面几条《合金装备：和平行者》的中文译文放进游戏
文本池后超出容量，必须缩短。

要求：
1. 这一批合计至少要省出 {gap} 个 UTF-8 字节（一个汉字 3 字节）。
   优先压"当前字节"最大的那几条，压到够了就可以只压一部分。
2. 不改变意思、不丢换行数、不动 `<I=XX>` 与 `%d` 这类占位符。
3. 手法：去掉"的/了/吧"等虚字、"——"改逗号、书面语改口语、删掉解释性补充。
4. 只输出 JSON：{{"编号": "缩短后的译文"}}。没压的条目不要出现在 JSON 里。"""


def call(items, system, model, key, session, timeout=120):
    payload = {
        "model": model,
        "temperature": 0.3,
        "max_tokens": 4000,
        "reasoning": {"effort": "none"},
        "enable_thinking": False,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": json.dumps(items, ensure_ascii=False)}],
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    for attempt in range(3):
        try:
            r = session.post(API_URL, headers=headers,
                             data=json.dumps(payload, ensure_ascii=False),
                             timeout=timeout)
            if r.status_code < 400:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass
    return None


def parse_reply(text):
    t = text.strip()
    t = t.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j < 0:
        return None
    try:
        return json.loads(t[i:j + 1])
    except json.JSONDecodeError:
        return None


def fix_one(g, off, need, budget, rows, by_ref, args, session):
    """压一条记录；返回写入的 {path: {lineno: text}}。"""
    gap = need - budget
    cand = rows[:args.max_lines]
    items = {str(i): {"en": r["src"], "zh": r["dst"],
                      "bytes_now": r["dst_bytes"],
                      "max_bytes": r["src_bytes"]}
             for i, r in enumerate(cand, 1)}
    raw = call(items, SHRINK_SYSTEM.format(gap=max(gap, 3)), args.model,
               args.key, session)
    if raw is None:
        return {}
    reply = parse_reply(raw) or {}

    writes = {}
    for i, r in enumerate(cand, 1):
        val = reply.get(str(i))
        if not isinstance(val, str) or not val.strip():
            continue
        val = val.strip()
        # 模型常吞掉 CODEC 每条结尾的换行，只补尾部
        while r["src"].endswith("\n") and not val.endswith("\n") \
                and r["src"].count("\n") > val.count("\n"):
            val += "\n"
        if r["src"].count("\n") != val.count("\n"):
            continue
        if val.count("<I=") != r["src"].count("<I="):
            continue
        if blen(val) >= r["dst_bytes"]:      # 没压短就不动
            continue
        writes.setdefault(r["path"], {})[r["entry"].msgstr_line] = val
    return writes


def shrink_long(by_ref, args, session):
    """把译文「不比英文短」的 CODEC 行全部压到英文以内。

    判据（ANALYSIS/03 §9.2）：记录的池容量是烧进去的，而它原本装的就是英文。
    只要每行译文都比对应英文短，need <= 英文用量 <= budget 恒成立，任何记录
    都不会超。这比按记录打补丁彻底：超预算只是超长行的下游症状。
    """
    todo = [(k, v) for k, v in sorted(by_ref.items())
            if blen(v[1].msgstr) >= blen(v[1].msgid)]
    print(f"\n待压缩：{len(todo)} 行（译文不比英文短）")
    batches = [todo[i:i + args.batch] for i in range(0, len(todo), args.batch)]
    done = 0

    def work(batch):
        items = {str(i): {"en": e.msgid, "zh": e.msgstr,
                          "max_bytes": blen(e.msgid)}
                 for i, (_k, (_p, e)) in enumerate(batch, 1)}
        raw = call(items, SHRINK_ALL_SYSTEM, args.model, args.key, session)
        reply = parse_reply(raw) if raw else None
        if not reply:
            return {}
        writes = {}
        for i, (_k, (path, e)) in enumerate(batch, 1):
            val = reply.get(str(i))
            if not isinstance(val, str) or not val.strip():
                continue
            val = val.strip()
            src = e.msgid
            while src.endswith("\n") and not val.endswith("\n") \
                    and src.count("\n") > val.count("\n"):
                val += "\n"
            if src.count("\n") != val.count("\n"):
                continue
            if val.count("<I=") != src.count("<I="):
                continue
            if blen(val) >= blen(src):          # 没压到英文以内就不要
                continue
            writes.setdefault(path, {})[e.msgstr_line] = val
        return writes

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for writes in pool.map(work, batches):
            for path, mapping in writes.items():
                with _lock_for(path):
                    poio.commit(path, mapping, poio.eol_of(path))
            done += sum(len(m) for m in writes.values())
    return done


SHRINK_ALL_SYSTEM = """你是本地化审校。下列《合金装备：和平行者》的中文译文，
UTF-8 字节数没有比英文原文短。游戏给每条台词预留的空间就是英文的长度，超了
会直接写不进去。

要求：
1. 每条压到 UTF-8 字节数严格小于 `max_bytes`（中文一字 3 字节，省两三个字
   通常就够；英文原文里的换行也算字节）。
2. 不改变意思、换行数不变、`<I=XX>` 与 `%d` 这类占位符原样保留。
3. 手法：删"的/了/吧"等虚字、"——"改逗号、书面语改口语、删解释性补充。
4. 只输出 JSON：{"编号": "缩短后的译文"}。实在压不动的保持原样即可。"""


_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(path):
    with _LOCKS_GUARD:
        lk = _LOCKS.get(path)
        if lk is None:
            lk = _LOCKS[path] = threading.Lock()
        return lk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fix", action="store_true", help="调模型压缩并写回 .po")
    ap.add_argument("--shrink-all", action="store_true",
                    help="把译文不比英文短的 CODEC 行全部压到英文以内")
    ap.add_argument("--batch", type=int, default=20)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--max-lines", type=int, default=6,
                    help="每条记录最多送几行给模型（默认 6）")
    ap.add_argument("--model", default="deepseek/deepseek-v4.1-flash")
    ap.add_argument("--key", default=os.environ.get("OPENROUTER_API_KEY"))
    args = ap.parse_args()

    by_ref = load_po()
    if not by_ref:
        sys.exit("src/codec 里没有译文")
    data = BB.crypt(BB.source_path().read_bytes())
    recs = {r.off: r for r in B.iter_records(bytes(data))}
    over = BB.overflows(translations(by_ref))
    if not over:
        print("没有超预算记录")
        return

    acc = account(by_ref, recs, over)
    print(f"{len(over)} 条记录超预算，合计超 "
          f"{sum(n - b for _g, _o, n, b in over)} 字节")
    for g, off, need, budget, rows in acc:
        print(f"\ncodec/{g}/{off:#x}  need {need} / budget {budget}  "
              f"超 {need - budget} 字节，{len(rows)} 行已译")
        for r in rows[:8]:
            print(f"  line {r['line']:2d}  {r['src_bytes']:4d}B -> "
                  f"{r['dst_bytes']:4d}B ({r['dst_bytes'] - r['src_bytes']:+d})  "
                  f"{r['path'].name}:{r['entry'].msgstr_line}  {r['dst'][:32]!r}")

    if not (args.fix or args.shrink_all):
        return
    if not args.key:
        sys.exit("缺 API key：设置 OPENROUTER_API_KEY")

    session = requests.Session()
    if args.shrink_all:
        print(f"\n压短 {shrink_long(by_ref, args, session)} 行")
        by_ref = load_po()
        over = BB.overflows(translations(by_ref))
        if not over:
            print("\n复验：全部装得下")
            return
        acc = account(by_ref, recs, over)

    for g, off, need, budget, rows in acc:
        writes = fix_one(g, off, need, budget, rows, by_ref, args, session)
        for path, mapping in writes.items():
            poio.commit(path, mapping, poio.eol_of(path))
        print(f"  {off:#x}: 压了 {sum(len(m) for m in writes.values())} 行")

    print("\n复验：")
    by_ref = load_po()
    over = BB.overflows(translations(by_ref))
    if over:
        for g, off, need, budget in over:
            print(f"  仍超 codec/{g}/{off:#x}: {need} / {budget} "
                  f"(超 {need - budget})")
    else:
        print("  全部装得下")


if __name__ == "__main__":
    main()
