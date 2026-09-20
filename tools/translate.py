"""批量机翻 src/*.po —— 调 OpenRouter / OpenAI 兼容的 chat completions API。

设计前提：脱离上下文逐批翻译，一致性靠 `terms.tsv` 术语表硬约束，
正确性靠本地校验（图标引用 / 格式符 / 换行数）+ `pwsf.po_lint` 兜底。

密钥从环境变量读，不要写进仓库：
    $env:OPENROUTER_API_KEY = "sk-or-v1-..."

用法：
    python tools/translate.py --dry-run                       # 看一条 prompt
    python tools/translate.py --group olang --limit 40        # 小步试跑
    python tools/translate.py --group codec --workers 8       # 正式批量
    python tools/translate.py --file src/olang/olang_01.po    # 指定文件
    python tools/translate.py --all --batch 25 --retries 3

产物：直接原地写回 .po 的 msgstr；失败与告警记 tools/translate.log。
已填 msgstr 的条目默认跳过，随时中断随时续跑。
"""

import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poio
from scan_terms import looks_untranslatable, load_terms, term_pattern

try:
    import requests
except ImportError:
    sys.exit("需要 requests：pip install requests")

API_URL = "https://openrouter.ai/api/v1/chat/completions"
ICON = re.compile(r"<I=[^>]*>")
FMT = re.compile(r"%(?:\d+\$)?[dsfuoxXcepg%]")

GROUP_HINT = {
    "olang": "这是 UI 文案与游戏内字幕。用词要短、要像主机游戏的中文界面，"
             "不要书面语，不要补解释。",
    "codec": "这是 CODEC 通话 / 简报台词，每条可能带说话人信息。"
             "口语化，贴合说话人性格。硬约束：译文的 UTF-8 字节数必须"
             "小于英文原文，中文天然更短，但禁止扩写、禁止加注释、禁止加引号。",
    "slot": "这是内嵌文本，包含过场漫画台词与 UI 说明。台词口语化，"
            "说明文简洁。",
}

SYSTEM = """你是《合金装备：和平行者》(Metal Gear Solid: Peace Walker) 的英译中本地化译者。

硬性规则（违反即作废）：
1. 只输出 JSON 对象，键为条目编号（字符串），值为中文译文。不要输出解释、代码块围栏或多余文字。
2. `<I=XXX>` 是手柄按键/图标引用，必须原样保留，一个字符都不许改。
3. `%d` `%s` 这类格式符原样保留，数量与顺序不变。
4. 换行数必须与原文一致：原文没有换行，译文就不能有；原文有 N 个换行，译文也要有 N 个。
   特别注意：CODEC 台词每条都以换行结尾，那个**结尾换行必须保留**。
5. 游戏不会自动折行，超长会被裁掉。译文宁短勿长，不要扩写、不要加注、不要加书名号引号。
6. 内部字符串、资源名、型号代号（如 Sns-Cocoon-087Au、M16A1）原样保留。
7. 专有名词严格按下表翻译；表中没有的人名地名用简体中文通行译名。
8. 多义词必须结合整批内容判断，别望文生义。本作里 plant 通常指"工厂/发电站"
   （OTEC 海洋热能转换厂），不是"植物"；magazine 是基地里的"杂志"，不是"弹匣"。

{group}

本次批次适用的术语（英文 -> 中文）：
{terms}"""


# ---------------------------------------------------------------- 校验

def fix_newlines(src, dst):
    """补回模型弄丢的首尾换行。

    两种是确定性的，本地补即可，不必麻烦模型：
    * 结尾换行被吞（CODEC 每条都以 \\n 结尾，最常见）；
    * 前导空行被删（排版用的 \\n\\n\\n... 开头，模型当成空白丢掉）。
    中间的分行丢了没法本地定位，只能靠 repair。
    """
    while src.endswith("\n") and not dst.endswith("\n") \
            and src.count("\n") > dst.count("\n"):
        dst += "\n"
    lead_src = len(src) - len(src.lstrip("\n"))
    lead_dst = len(dst) - len(dst.lstrip("\n"))
    if lead_src > lead_dst and src.count("\n") > dst.count("\n"):
        dst = "\n" * (lead_src - lead_dst) + dst
    # PSP/Xbox 时代的 UI 文本用 \r\n 分行，模型一律只给 \n。行数对上了就把
    # \r 补回去，否则游戏里那一行会连在一起。
    if "\r\n" in src and "\r\n" not in dst \
            and src.count("\n") == dst.count("\n"):
        dst = dst.replace("\n", "\r\n")
    return dst


def check(src, dst):
    """返回 None 表示通过，否则返回失败原因。"""
    if not dst or not dst.strip():
        return "empty"
    if src.count("\n") != dst.count("\n"):
        return f"newline {src.count(chr(10))}->{dst.count(chr(10))}"
    if sorted(ICON.findall(src)) != sorted(ICON.findall(dst)):
        return "icon"
    if FMT.findall(src) != FMT.findall(dst):
        return "format"
    if ICON.search(dst.replace("<I=", "<I=")) and dst.count("<I=") != src.count("<I="):
        return "icon-count"
    return None


def byte_len(s):
    return len(s.encode("utf-8"))


# ---------------------------------------------------------------- 术语

def pick_terms(terms, texts):
    """只保留这批文本里真正出现的术语，长串优先、命中即占位避免重复。"""
    blob = "\n".join(texts)
    picked = []
    for en, zh, ci in sorted(terms, key=lambda kv: -len(kv[0])):
        pat = term_pattern(en, ci)
        if pat.search(blob):
            picked.append((en, zh))
            blob = pat.sub(" ", blob)
    return picked


# ---------------------------------------------------------------- API

def call_api(payload, args, session):
    headers = {
        "Authorization": f"Bearer {args.key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/pwsf",
        "X-OpenRouter-Title": "PWSF localization",
    }
    last = None
    for attempt in range(args.retries + 1):
        try:
            r = session.post(args.url, headers=headers,
                             data=json.dumps(payload, ensure_ascii=False),
                             timeout=args.timeout)
            if r.status_code >= 400:
                last = f"HTTP {r.status_code}: {r.text[:300]}"
                time.sleep(2 * (attempt + 1))
                continue
            return r.json()["choices"][0]["message"]["content"], None
        except Exception as e:  # 网络/解析问题一律重试
            last = repr(e)
            time.sleep(2 * (attempt + 1))
    return None, last


def sanitize_json(t: str) -> str:
    """把 JSON 字符串值里的裸控制字符转义掉。

    模型经常不转义译文里的换行，直接输出物理换行 —— JSON 不允许字符串值
    里出现裸控制字符，整批译文就都判成不可解析（`unparsable`）白白丢掉。
    这里按引号状态机只动字符串**内部**的控制字符，结构位置的空白照旧。
    """
    out, in_str, esc = [], False, False
    for ch in t:
        if in_str:
            if esc:
                out.append(ch)
                esc = False
            elif ch == "\\":
                out.append(ch)
                esc = True
            elif ch == '"':
                in_str = False
                out.append(ch)
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\r":
                out.append("\\r")
            elif ch == "\t":
                out.append("\\t")
            else:
                out.append(ch)
            continue
        if ch == '"':
            in_str = True
        out.append(ch)
    return "".join(out)


def parse_reply(text):
    """模型偶发会加 ```json 围栏或前后寒暄，这里都剥掉。"""
    t = sanitize_json(text.strip())
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j < 0:
        return None
    try:
        return json.loads(t[i:j + 1])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------- 主流程

def collect(args):
    """收集待译条目：[(path, entry, group)]"""
    src = Path(args.src)
    if args.file:
        files = [Path(f) if os.path.isabs(f) else src / f for f in args.file]
    else:
        files = sorted(src.rglob("*.po"))
        if args.group:
            want = set(args.group.split(","))
            files = [f for f in files if f.parent.name in want]

    out = []
    for path in files:
        if not path.exists():
            sys.exit(f"找不到文件：{path}")
        entries, lines = poio.parse(path)
        CACHE[str(path)] = lines
        EOL[str(path)] = poio.eol_of(path)
        for e in entries:
            if e.msgstr and not args.force:
                continue
            if not args.include_all and looks_untranslatable(e.msgid):
                continue
            out.append((str(path), e, path.parent.name))
        if args.limit and len(out) >= args.limit:
            out = out[:args.limit]
            break
    return out


CACHE = {}
EOL = {}
LOCK = threading.Lock()
FILE_LOCKS = {}
STATS = {"ok": 0, "fail": 0, "skip": 0, "long": 0, "shrunk": 0, "repaired": 0}


def commit_batch(path, mapping):
    """把一个批次的译文落盘。

    两个约束：
    1. 基底必须是磁盘最新内容（`poio.commit` 内部重读）。`CACHE` 里那一份是
       启动时快照，拿它重写会让同文件其它批次的译文被覆盖。
    2. 同一文件串行提交：读-改-写不是原子操作，两个线程同时来会丢一半。
    """
    if not mapping:
        return
    with LOCK:
        fl = FILE_LOCKS.get(path)
        if fl is None:
            fl = FILE_LOCKS[path] = threading.Lock()
    with fl:
        _, lines = poio.commit(path, mapping, EOL[path])
        CACHE[path] = lines


def log_error(path, msgid, reason):
    with LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"file": path, "msgid": msgid[:200],
                                "reason": reason}, ensure_ascii=False) + "\n")


LOG_PATH = None


def run_batch(batch, args, terms, session):
    """翻译一批；返回 {entry: 译文} 与失败清单。"""
    items = {}
    for idx, (_, e, _) in enumerate(batch, 1):
        obj = {"en": e.msgid}
        if "\n" in e.msgid:
            obj["nl"] = e.msgid.count("\n")  # 显式告知换行数，模型常漏
        if args.context and e.comments:
            obj["ctx"] = " | ".join(e.comments)
        items[str(idx)] = obj

    group = batch[0][2]
    picked = pick_terms(terms, [e.msgid for _, e, _ in batch])
    term_txt = "\n".join(f"{en} -> {zh}" for en, zh in picked) or "（本批无）"
    system = SYSTEM.format(group=GROUP_HINT.get(group, ""), terms=term_txt)
    user = json.dumps(items, ensure_ascii=False, indent=None)

    payload = {
        "model": args.model,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    }
    # 关思考：OpenRouter 统一参数 + DeepSeek 自家开关，双管齐下
    if args.reasoning != "omit":
        payload["reasoning"] = {"effort": args.reasoning}
    if not args.thinking:
        payload["enable_thinking"] = False
    if args.dry_run:
        print("=== SYSTEM ===\n" + system)
        print("\n=== USER ===\n" + user[:4000])
        return {}, [(b, "dry-run") for b in batch]

    raw, err = call_api(payload, args, session)
    if raw is None:
        return {}, [(b, f"api: {err}") for b in batch]
    reply = parse_reply(raw)
    if reply is None:
        return {}, [(b, f"unparsable: {raw[:600]}") for b in batch]

    ok, bad = {}, []
    for idx, (path, e, _) in enumerate(batch, 1):
        val = reply.get(str(idx))
        if isinstance(val, dict):
            val = val.get("zh") or val.get("translation") or val.get("msgstr")
        if isinstance(val, list):
            val = "\n".join(str(x) for x in val)   # 行数组自带结构，别 strip
        elif isinstance(val, str):
            val = val.strip()
        if not isinstance(val, str):
            bad.append(((path, e, group), "missing"))
            continue
        val = fix_newlines(e.msgid, val)
        reason = check(e.msgid, val)
        if reason:
            bad.append(((path, e, group), reason))
            continue
        ok[e] = val
    if args.shrink and ok:
        ok = shrink(ok, args, session)
    if args.repair and bad and not args.dry_run:
        fixed, bad = repair(bad, args, session)
        ok.update(fixed)
        if bad:
            fixed, bad = repair_by_line(bad, args, session)
            ok.update(fixed)

    for path, e, _ in batch:
        val = ok.get(e)
        if val and byte_len(val) > byte_len(e.msgid):
            STATS["long"] += 1
            log_error(path, e.msgid,
                      f"longer {byte_len(e.msgid)}->{byte_len(val)}")
    return ok, bad


REPAIR_SYSTEM = """你是本地化审校。下列译文被判不合格，游戏里会显示错乱。

逐条按要求重译：
- `lines` 是原文按换行切开的每一行。带 `lines` 的条目，输出值必须是**行数
  相同的 JSON 数组**，一行一个元素，不要用带 \\n 的字符串 —— 数组长度对了，
  换行位置就一定对（含结尾那个空行，它对应一个空字符串元素）。
- 没有 `lines` 的条目（单行）照常输出字符串。
- `<I=XX>` 与 `%d` 之类占位符原样保留。
- 只输出 JSON：{"编号": [...] 或 "重译后的译文"}。"""


def repair(bad, args, session):
    """把校验不过的条目单独重发一轮；还不过就留在 bad 里交给人工。"""
    items, order = {}, []
    for i, ((_path, e, _g), reason) in enumerate(bad, 1):
        items[str(i)] = {"en": e.msgid, "nl": e.msgid.count("\n"),
                         "lines": e.msgid.split("\n"), "bad": reason}
        order.append((str(i), e, reason))
    payload = {
        "model": args.model,
        "temperature": 0.3,
        "max_tokens": args.max_tokens,
        "messages": [{"role": "system", "content": REPAIR_SYSTEM},
                     {"role": "user", "content": json.dumps(items, ensure_ascii=False)}],
    }
    if args.reasoning != "omit":
        payload["reasoning"] = {"effort": args.reasoning}
    if not args.thinking:
        payload["enable_thinking"] = False

    raw, err = call_api(payload, args, session)
    if raw is None:
        return {}, bad
    reply = parse_reply(raw)
    if not reply:
        return {}, bad

    ok, still = {}, []
    for k, e, reason in order:
        val = reply.get(k)
        if isinstance(val, dict):
            val = val.get("zh")
        if isinstance(val, list):
            val = "\n".join(str(x) for x in val)   # 行数组 = 换行位置对齐
        elif isinstance(val, str):
            val = val.strip()
        if not isinstance(val, str):
            still.append(((_path_of(e, bad), e, ""), reason))
            continue
        val = fix_newlines(e.msgid, val)
        if check(e.msgid, val):
            still.append(((_path_of(e, bad), e, ""), f"repair-failed {reason}"))
            continue
        ok[e] = val
        STATS["repaired"] += 1
    return ok, still


SPLIT_SYSTEM = """你是本地化审校。下面按行给出《合金装备：和平行者》的游戏文本，
一行一条编号。

逐条译成中文：每行独立成句，不要合并相邻行，不要自己加换行或引号。
`<I=XX>` 与 `%d` 之类占位符原样保留。空白行就原样返回空白。
只输出 JSON：{"编号": "该行的中文"}，编号与输入一一对应，一条都不能漏。"""


def repair_by_line(bad, args, session):
    """最后一级修复：按行拆开逐行重译，拼回去行数必然对齐。

    模型顽固地把两行台词并成一行（`newline 2->1`），连"输出行数组"都拦不住。
    逐行翻译就不存在吞换行这回事：N 行进去 N 行出来，\n 一 join 就对上了。
    """
    items, per = {}, {}
    n = 0
    for i, ((_path, e, _g), _reason) in enumerate(bad, 1):
        for line in e.msgid.split("\n"):
            n += 1
            items[str(n)] = line
            per.setdefault(i, []).append(str(n))

    payload = {
        "model": args.model,
        "temperature": 0.3,
        "max_tokens": args.max_tokens,
        "messages": [{"role": "system", "content": SPLIT_SYSTEM},
                     {"role": "user", "content": json.dumps(items, ensure_ascii=False)}],
    }
    if args.reasoning != "omit":
        payload["reasoning"] = {"effort": args.reasoning}
    if not args.thinking:
        payload["enable_thinking"] = False

    raw, err = call_api(payload, args, session)
    if raw is None:
        return {}, bad
    reply = parse_reply(raw)
    if not reply:
        return {}, bad

    ok, still = {}, []
    for i, ((path, e, group), reason) in enumerate(bad, 1):
        keys = per.get(i, [])
        vals = []
        for k, line in zip(keys, e.msgid.split("\n")):
            v = reply.get(k)
            if isinstance(v, list):
                v = " ".join(str(x) for x in v)
            if isinstance(v, str) and v.strip():
                vals.append(v.strip())
            elif not line.strip():
                vals.append(line)          # 空行原样保留
            else:
                vals = None
                break
        if not vals:
            still.append(((path, e, group), f"split-failed {reason}"))
            continue
        joined = fix_newlines(e.msgid, "\n".join(vals))
        if check(e.msgid, joined):
            still.append(((path, e, group), f"split-failed {reason}"))
            continue
        ok[e] = joined
        STATS["repaired"] += 1
    return ok, still


def _path_of(entry, bad):
    for (path, e, _g), _r in bad:
        if e is entry:
            return path
    return ""


SHRINK_SYSTEM = """你是本地化审校。下列中文译文的 UTF-8 字节数超过了英文原文，游戏文本池装不下。

要求：
1. 不改变意思、不丢失换行数、不动 `<I=XX>` 与 `%d` 这类占位符。
2. 压缩到 UTF-8 字节数小于英文原文（中文一个字 3 字节，省两三个字通常就够）。
3. 优先删冗余：把"——"换成逗号或空格、"的"字能省就省、书面语改口语。
4. 只输出 JSON：{"编号": "缩短后的译文"}。"""


def shrink(ok, args, session):
    """把超长译文再压一轮；压不动就保留并记录。"""
    longs = {str(i): (e, v) for i, (e, v) in enumerate(ok.items(), 1)
             if byte_len(v) > byte_len(e.msgid)}
    if not longs:
        return ok
    items = {k: {"en": e.msgid, "zh": v,
                 "bytes_now": byte_len(v), "bytes_max": byte_len(e.msgid)}
             for k, (e, v) in longs.items()}
    payload = {
        "model": args.model,
        "temperature": 0.3,
        "max_tokens": args.max_tokens,
        "messages": [{"role": "system", "content": SHRINK_SYSTEM},
                     {"role": "user", "content": json.dumps(items, ensure_ascii=False)}],
    }
    if args.reasoning != "omit":
        payload["reasoning"] = {"effort": args.reasoning}
    if not args.thinking:
        payload["enable_thinking"] = False

    raw, err = call_api(payload, args, session)
    if raw is None:
        return ok
    reply = parse_reply(raw)
    if not reply:
        return ok
    for k, (e, _old) in longs.items():
        val = reply.get(k)
        if isinstance(val, dict):
            val = val.get("zh")
        if not isinstance(val, str):
            continue
        val = fix_newlines(e.msgid, val.strip())
        if check(e.msgid, val):
            continue
        if byte_len(val) < byte_len(e.msgid):
            ok[e] = val
            STATS["shrunk"] += 1
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=None, help="src 目录，默认 ../src")
    ap.add_argument("--file", action="append", help="指定 .po（可多次）")
    ap.add_argument("--group", help="olang / codec / slot，逗号分隔")
    ap.add_argument("--limit", type=int, help="最多处理多少条")
    ap.add_argument("--batch", type=int, default=25, help="每请求多少条")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--model", default="deepseek/deepseek-v4.1-flash")
    ap.add_argument("--reasoning", default="none",
                    help="none / low / medium / high；none=关闭思考，省钱")
    ap.add_argument("--thinking", action="store_true",
                    help="显式打开模型侧 thinking（默认关）")
    ap.add_argument("--no-shrink", dest="shrink", action="store_false",
                    help="不做超长二次压缩（默认会压）")
    ap.add_argument("--no-repair", dest="repair", action="store_false",
                    help="校验不过不重试（默认会单独重译一轮）")
    ap.add_argument("--url", default=API_URL)
    ap.add_argument("--key", default=os.environ.get("OPENROUTER_API_KEY") or
                    os.environ.get("OPENAI_API_KEY"))
    ap.add_argument("--terms", default=None, help="术语表，默认同目录 terms.tsv")
    ap.add_argument("--no-terms", action="store_true")
    ap.add_argument("--context", action="store_true", help="带上 #. 注释（说话人等）")
    ap.add_argument("--include-all", action="store_true", help="连代号/数字也送翻")
    ap.add_argument("--force", action="store_true", help="已译的也重翻")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--temperature", type=float, default=0.3)
    ap.add_argument("--max-tokens", type=int, default=8000,
                    help="回复上限；整批被截断会整批判为不可解析")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    args.src = args.src or str(Path(__file__).resolve().parent.parent / "src")
    args.terms = args.terms or str(Path(__file__).resolve().parent / "terms.tsv")
    global LOG_PATH
    LOG_PATH = str(Path(__file__).resolve().parent / "translate.log")

    terms = [] if args.no_terms else load_terms(args.terms)
    targets = collect(args)
    if not targets:
        print("没有待译条目（都已翻译？）")
        return

    print(f"待译 {len(targets)} 条 / 术语表 {len(terms)} 条 / "
          f"batch={args.batch} workers={args.workers} model={args.model}")
    if args.dry_run:
        targets = targets[:min(args.batch, len(targets))]

    # 按文件分批，保证一批只写一个文件，写完立即落盘
    by_file = {}
    for t in targets:
        by_file.setdefault(t[0], []).append(t)
    batches = []
    for path, items in by_file.items():
        for i in range(0, len(items), args.batch):
            batches.append(items[i:i + args.batch])

    if args.dry_run:
        batches = batches[:1]
        run_batch(batches[0], args, terms, None)
        return

    if not args.key:
        sys.exit("缺 API key：设置环境变量 OPENROUTER_API_KEY，或 --key 传入")

    session = requests.Session()
    t0 = time.time()

    def work(batch):
        return batch, run_batch(batch, args, terms, session)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for batch, (ok, bad) in pool.map(work, batches):
            mapping = {}
            for e, val in ok.items():
                mapping[e.msgstr_line] = val
            commit_batch(batch[0][0], mapping)
            STATS["ok"] += len(ok)
            for (path, e, _), reason in bad:
                STATS["fail"] += 1
                log_error(path, e.msgid, reason)
            print(f"\r  ok={STATS['ok']} fail={STATS['fail']} "
                  f"long={STATS['long']} {int(time.time() - t0)}s", end="", flush=True)

    print()
    print(f"完成：ok={STATS['ok']} fail={STATS['fail']} "
          f"重译修复={STATS['repaired']} 压缩={STATS['shrunk']} "
          f"仍超长={STATS['long']} 用时 {int(time.time() - t0)}s")
    print(f"失败明细 -> {LOG_PATH}")


if __name__ == "__main__":
    main()
