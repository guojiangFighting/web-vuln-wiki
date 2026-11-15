# -*- coding: utf-8 -*-
"""统一学习门户构建脚本：把两个 wiki 的全部条目渲染成 HTML，生成 portal/content.js
用法（在 web-vuln-wiki 目录）:
  python _tools/build_portal.py
依赖: pip install markdown；要求 ../web-pentest-playbook 与本库同级。
"""
import json, re, sys, io, os
from pathlib import Path
from datetime import date

import markdown

HERE = Path(__file__).resolve().parent.parent          # web-vuln-wiki/
PARENT = HERE.parent                                    # 两库的父目录
PLAYBOOK = PARENT / "web-pentest-playbook"
OUT_DIR = HERE / "portal"
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

MD = markdown.Markdown(extensions=["tables", "fenced_code"])

FM_RE = re.compile(r"^---\n.*?\n---\n", re.S)
A_RE = re.compile(r'(<a\s+href=")([^"]+)(")')


def build_path_map(wiki_root_name, manifest):
    """路径 -> entry id 映射（含跨库）。键形如 'web-vuln-wiki/10-injection/xss.md'"""
    m = {}
    for e in manifest["entries"] if "entries" in manifest else manifest["topics"]:
        key = f"{wiki_root_name}/{e['path']}"
        m[key] = e["id"]
    return m


def rewrite_links(html, entry_full_rel):
    """把条目内相对 .md 链接改写为 SPA 路由 #/<wiki>/<id>；其余保留。"""
    def repl(m):
        href = m.group(2)
        if href.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        base = os.path.dirname(entry_full_rel)
        resolved = os.path.normpath(os.path.join(base, href)).replace("\\", "/")
        if resolved in PATH_MAP:
            wiki_name, entry_id = PATH_MAP[resolved]
            return f'{m.group(1)}#/{wiki_name}/{entry_id}{m.group(3)}'
        # 非条目链接（如 viewer.html）保持相对——由 portal 目录修正到 ../cards/
        if "cards/viewer.html" in resolved:
            return f'{m.group(1)}../cards/viewer.html{m.group(3)}'
        return m.group(0)
    return A_RE.sub(repl, html)


def render_entry(wiki_name, full_rel, abs_path, meta):
    raw = abs_path.read_text(encoding="utf-8")
    body = FM_RE.sub("", raw, count=1)
    body = re.sub(r"^#\s+.+\n+", "", body, count=1)   # 标题已由 entry-head 渲染，去掉正文重复 H1
    MD.reset()
    html = MD.convert(body)
    html = rewrite_links(html, full_rel)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return {
        "id": meta["id"], "title": meta["title"], "category": meta["category"],
        "path": meta["path"], "html": html, "text": text[:4000],
        "summary": meta.get("summary", ""),
        "symptoms": meta.get("symptoms", []),
        "mapsTo": meta.get("maps_to", "") or meta.get("maps-to", ""),
        "severity": meta.get("severity", ""), "owasp": meta.get("owasp", ""),
    }


def load_manifest(p):
    return json.loads(p.read_text(encoding="utf-8"))


PATH_MAP = {}
wikis_out = []

wiki_manifest = load_manifest(HERE / "manifest.json")
PATH_MAP.update(build_path_map("wiki", wiki_manifest))
entries = []
for t in wiki_manifest["topics"]:
    full_rel = f"web-vuln-wiki/{t['path']}"
    entries.append(render_entry("wiki", full_rel, HERE / t["path"], {
        "id": t["id"], "title": t["title"], "category": t["category"],
        "path": t["path"], "summary": t.get("summary", ""),
        "severity": t.get("severity", ""), "owasp": t.get("owasp", ""),
    }))
wikis_out.append({"id": "wiki", "name": "Web 漏洞教科书", "desc": "32 个漏洞条目：是什么、为什么、怎么修",
                  "entries": entries})

if PLAYBOOK.exists():
    pb_manifest = load_manifest(PLAYBOOK / "manifest.json")
    PATH_MAP.update(build_path_map("playbook", pb_manifest))
    entries = []
    for e in pb_manifest["entries"]:
        full_rel = f"web-pentest-playbook/{e['path']}"
        entries.append(render_entry("playbook", full_rel, PLAYBOOK / e["path"], e))
    wikis_out.append({"id": "playbook", "name": "实战手册",
                      "desc": "30 个实战条目：怎么打、打不动怎么办（含工具实践）",
                      "entries": entries})

card_count = 0
cards_path = HERE / "cards" / "cards.json"
if cards_path.exists():
    card_count = load_manifest(cards_path).get("count", 0)

OUT_DIR.mkdir(exist_ok=True)
data = {"generated": str(date.today()), "cardCount": card_count, "wikis": wikis_out}
(OUT_DIR / "content.js").write_text(
    "const PORTAL_DATA = " + json.dumps(data, ensure_ascii=False) + ";\n",
    encoding="utf-8")
total = sum(len(w["entries"]) for w in wikis_out)
print(f"门户构建完成: {len(wikis_out)} 库 / {total} 条目 / {card_count} 卡 -> portal/content.js")
