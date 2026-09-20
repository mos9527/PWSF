"""扫描 src/ 的全部 msgid，抽出候选专有名词与不可译条目。

给术语表定稿提供证据：哪些词是真正的专有名词（句中也大写），哪些只是
句首大小写，哪些条目根本不是英文句子（资源名 / 内部 ID，不该翻）。

用法：
    python tools/scan_terms.py                 # 打印 top 摘要
    python tools/scan_terms.py --all           # 全量候选写 tools/terms_candidates.tsv
    python tools/scan_terms.py --src ../src
"""

import argparse
import collections
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poio

# 序列里允许出现的连接词（本身不大写，但不打断专有名词）
LINK = {"of", "the", "and", "for", "in", "de", "la", "van", "von", "del", "da"}
TOKEN = re.compile(r"[A-Za-z0-9_'’\-]+")
# 句首判定：前一个非空字符是这些，说明这个大写词只是句子开头
SENT_END = set('.!?"”’')


def is_cap(tok):
    return tok[:1].isupper() and tok[:1].isalpha()


def is_word(tok):
    return any(c.isalpha() for c in tok)


def scan(src):
    seq_mid = collections.Counter()   # 句中出现（真专有名词信号）
    seq_all = collections.Counter()   # 全部出现
    caps_all = collections.Counter()  # 全大写词
    n_entry = 0
    n_skip = 0
    n_icon = 0
    n_fmt = 0
    skip_samples = []
    where = collections.defaultdict(set)  # 术语 -> 出现在哪些分区

    for path in sorted(Path(src).rglob("*.po")):
        grp = path.parent.name
        entries, _ = poio.parse(path)
        for e in entries:
            n_entry += 1
            text = e.msgid
            if "<I=" in text:
                n_icon += 1
            if re.search(r"%[dsfduoxc]|%\d+\$", text):
                n_fmt += 1
            if looks_untranslatable(text):
                n_skip += 1
                if len(skip_samples) < 40:
                    skip_samples.append(text)
            for tok in TOKEN.findall(text):
                if tok.isupper() and len(tok) >= 2 and is_word(tok):
                    caps_all[tok] += 1
            for seq, mid in sequences(text):
                seq_all[seq] += 1
                if mid:
                    seq_mid[seq] += 1
                    where[seq].add(grp)
    return dict(seq_all=seq_all, seq_mid=seq_mid, caps_all=caps_all,
                n_entry=n_entry, n_skip=n_skip, n_icon=n_icon, n_fmt=n_fmt,
                skip_samples=skip_samples, where=where)


def sequences(text):
    """抽出连续的大写开头词序列。yield (序列, 是否句中出现)。"""
    spans = [(m.group(0), m.start()) for m in TOKEN.finditer(text)]
    i = 0
    while i < len(spans):
        tok, pos = spans[i]
        if not is_cap(tok):
            i += 1
            continue
        # 往前看第一个非空字符，判断是不是句首
        j = pos - 1
        while j >= 0 and text[j].isspace():
            j -= 1
        at_start = j < 0 or text[j] in SENT_END
        seq = [tok]
        k = i + 1
        while k < len(spans):
            ntok, npos = spans[k]
            gap = text[spans[k - 1][1] + len(spans[k - 1][0]):npos]
            if gap.strip():          # 中间有标点就断
                break
            if is_cap(ntok) or ntok.lower() in LINK:
                seq.append(ntok)
                k += 1
            else:
                break
        yield " ".join(seq), not at_start
        i = k


INTERNAL_RE = re.compile(r"^(?:[A-Za-z]{2,6}_[A-Za-z0-9_]+)+$")   # MO_DEV_IT_xxx
RESOURCE_RE = re.compile(r"^[A-Za-z]+(?:-[A-Za-z0-9]+)*-?\d+[A-Za-z]{0,3}$")  # Sns-Cocoon-087Au


def looks_untranslatable(text):
    """不该送进翻译器的内容：内部字符串、资源名、型号代号。

    判定刻意保守——宁可多翻一条，也不能把台词误杀掉。像 `OK.`、`I...`、
    `August 24.` 这种只有一两个词的台词片段必须保留给译者。
    """
    t = text.strip()
    if not t:
        return True
    if not any(c.isalpha() for c in t):          # 纯数字 / 符号
        return True
    if INTERNAL_RE.match(t):                     # MO_MODEL_VIEWER_ 之类
        return True
    if RESOURCE_RE.match(t):                     # Sns-Cocoon-087Au
        return True
    words = t.split()
    if len(words) == 1 and re.search(r"\d", t):  # 单 token 且含数字：型号/代号
        return True
    return False


# 常见英文短词，用来把 "OK" "Yes" 这类真单词从代号里救回来
PLAIN_EN = {
    "ok", "yes", "no", "on", "off", "exit", "back", "next", "start", "stop",
    "retry", "cancel", "apply", "close", "open", "save", "load", "delete",
    "options", "option", "settings", "help", "menu", "title", "main", "new",
    "continue", "return", "select", "confirm", "skip", "done", "ready",
    "weapon", "item", "items", "soldier", "staff", "mission", "missions",
    "level", "rank", "score", "time", "name", "type", "list", "detail",
    "details", "info", "data", "system", "sound", "display", "screen",
    "control", "controls", "keyboard", "camera", "map", "briefing",
}


def load_terms(path):
    """术语表 tsv: en zh cat note [ci=1] -> [(en, zh, ci)]

    第 5 列写 `ci=1` 表示该条忽略大小写匹配。默认大小写敏感——这是刻意的：
    `Snake` 与真蛇 `snake`、`Boss` 与 `you're the boss` 必须区分开。
    """
    out = []
    with open(path, encoding="utf-8") as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0] and parts[1]:
                ci = len(parts) >= 5 and parts[4].strip() == "ci=1"
                out.append((parts[0], parts[1], ci))
    return out


def term_pattern(en, ci=False):
    """术语在语料里的匹配方式。

    默认匹配「原形 或 全大写」+ 词边界：UI 文本大量全大写（`MOTHER BASE`、
    `PEACE WALKER`、`TARGET`），而小写往往是另一个意思——`snake`（真蛇）、
    `the end`（结束）、`us`（我们）、`staff`（工作人员）都不该被替换。
    `ci=1` 才退化为完全忽略大小写。
    """
    if ci:
        return re.compile(r"(?<![A-Za-z])" + re.escape(en) + r"(?![A-Za-z])", re.I)
    alts = list(dict.fromkeys([en, en.upper()]))
    return re.compile(r"(?<![A-Za-z])(?:" +
                      "|".join(re.escape(a) for a in alts) + r")(?![A-Za-z])")


def term_counts(src, terms):
    """术语表每条在语料中的命中次数（长串优先，命中即占位避免重复计）。"""
    texts = []
    for path in sorted(Path(src).rglob("*.po")):
        entries, _ = poio.parse(path)
        texts += [e.msgid for e in entries]
    hits = collections.Counter()
    for t in texts:
        rest = t
        for en, _zh, ci in sorted(terms, key=lambda kv: -len(kv[0])):
            pat = term_pattern(en, ci)
            if pat.search(rest):
                hits[en] += 1
                rest = pat.sub(" ", rest)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=None, help="src 目录，默认 ../src")
    ap.add_argument("--top", type=int, default=120)
    ap.add_argument("--all", action="store_true", help="全量候选写 tsv")
    ap.add_argument("--terms", default=None,
                    help="对照术语表：打印每条命中次数，并列出未收录的高频候选")
    args = ap.parse_args()

    src = args.src or str(Path(__file__).resolve().parent.parent / "src")
    r = scan(src)

    print(f"src            = {src}")
    print(f"entries        = {r['n_entry']}")
    print(f"untranslatable = {r['n_skip']} ({r['n_skip'] * 100 // max(r['n_entry'], 1)}%)")
    print(f"with <I=..>    = {r['n_icon']}")
    print(f"with %s/%d..   = {r['n_fmt']}")
    print()
    print("--- 疑似不可译样本 ---")
    for s in r["skip_samples"][:25]:
        print("   ", s[:90])

    print()
    print(f"--- 专有名词候选（句中出现次数 >= 2）top {args.top} ---")
    mid = [(k, v) for k, v in r["seq_mid"].items() if v >= 2]
    mid.sort(key=lambda kv: (-kv[1], kv[0]))
    for k, v in mid[:args.top]:
        w = ",".join(sorted(r["where"][k]))
        print(f"{v:5d}  {k[:44]:46s} {w}")

    print()
    print("--- 全大写词 top 40 ---")
    for k, v in r["caps_all"].most_common(40):
        print(f"{v:5d}  {k}")

    if args.terms:
        terms = load_terms(args.terms)
        hits = term_counts(src, terms)
        print()
        print(f"--- 术语表 {len(terms)} 条，"
              f"未命中 {sum(1 for t in terms if hits[t[0]] == 0)} 条 ---")
        for en, zh, _ci in terms:
            if hits[en] == 0:
                print(f"     0  {en} -> {zh}")
        covered = {t[0] for t in terms}
        mid = [(k, v) for k, v in r["seq_mid"].items() if v >= 5]
        gaps = [(k, v) for k, v in mid
                if k not in covered and not any(k.startswith(c) or c in k for c in covered)]
        gaps.sort(key=lambda kv: -kv[1])
        print()
        print("--- 高频但未收录（top 60）---")
        for k, v in gaps[:60]:
            print(f"{v:5d}  {k}")

    if args.all:
        out = Path(__file__).resolve().parent / "terms_candidates.tsv"
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write("count_mid\tcount_all\tterm\tgroups\n")
            for k, v in sorted(r["seq_mid"].items(), key=lambda kv: (-kv[1], kv[0])):
                f.write(f"{v}\t{r['seq_all'][k]}\t{k}\t{','.join(sorted(r['where'][k]))}\n")
        print(f"\n全量候选 -> {out}")


if __name__ == "__main__":
    main()
