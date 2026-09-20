"""极简 gettext .po 读写，独立于 pwsf 包。

只支持本项目导出的子集：注释行（#: / #. / #,）、msgid / msgstr 及其
多行续写形式。复数与 msgctxt 不处理——导出器靠 `#:` 定位槽位，不用 msgctxt。

写回时保持文件其余内容逐字节不变，只替换 `msgstr` 那一行（原文是单行
`msgstr ""`，译文也按单行写入，续行合并进这一行）。
"""

ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}
UNESCAPE = {"\n": "\\n", "\t": "\\t", "\r": "\\r", '"': '\\"', "\\": "\\\\", "\0": "\\0"}


def unescape(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(ESCAPES.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def escape(s):
    return "".join(UNESCAPE.get(c, c) for c in s)


class Entry:
    __slots__ = ("msgid", "msgstr", "refs", "comments", "flags", "msgid_line", "msgstr_line")

    def __init__(self):
        self.msgid = ""
        self.msgstr = ""
        self.refs = []
        self.comments = []
        self.flags = []
        self.msgid_line = -1
        self.msgstr_line = -1


def _literal(line, path, lineno):
    line = line.strip()
    if len(line) < 2 or not line.startswith('"') or not line.endswith('"'):
        raise ValueError(f"{path}:{lineno}: malformed .po string: {line!r}")
    return unescape(line[1:-1])


def parse(path):
    """返回 (entries, lines)。entries 不含头块（msgid 为空的那条）。"""
    path = str(path)
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    entries, cur, field = [], Entry(), None

    def flush():
        nonlocal cur, field
        if field is not None and cur.msgid:
            entries.append(cur)
        cur, field = Entry(), None

    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("#"):
            if field is not None:
                flush()
            tag = line[1:2]
            body = line[2:].strip() if len(line) > 2 else ""
            if tag == ":":
                cur.refs += body.split()
            elif tag == ",":
                cur.flags += [x.strip() for x in body.split(",") if x.strip()]
            elif tag == ".":
                cur.comments.append(body)
            continue
        if line.startswith("msgid "):
            if field == "msgstr":
                flush()
            cur.msgid = _literal(line[6:], path, i + 1)
            cur.msgid_line = i
            field = "msgid"
        elif line.startswith("msgstr "):
            cur.msgstr = _literal(line[7:], path, i + 1)
            cur.msgstr_line = i
            field = "msgstr"
        elif line.startswith('"'):
            if field is None:
                raise ValueError(f"{path}:{i + 1}: continuation without a field")
            setattr(cur, field, getattr(cur, field) + _literal(line, path, i + 1))
        else:
            raise ValueError(f"{path}:{i + 1}: unexpected line {line!r}")
    flush()
    return entries, lines


def eol_of(path):
    """探测原文件的换行风格，写回时保持一致，避免整文件被 git 标成改动。"""
    with open(path, "rb") as f:
        head = f.read(65536)
    return "\r\n" if b"\r\n" in head else "\n"


def write(path, lines, mapping, eol="\n"):
    """把 {行号: 译文} 写回 msgstr 行，其余内容逐字节不变。返回改动条数。"""
    out = list(lines)
    for lineno, text in mapping.items():
        out[lineno] = f'msgstr "{escape(text)}"'
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(eol.join(out) + eol)
    return len(mapping)
