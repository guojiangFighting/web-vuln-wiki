# -*- coding: utf-8 -*-
"""统一学习门户构建脚本：把学习体系中全部 wiki 的条目渲染成 HTML，生成 portal/content.js
用法（在 web-vuln-wiki 目录）:
  python _tools/build_portal.py
依赖: pip install markdown；要求三个 wiki 目录同级。
"""
import json, re, sys, io, os
from pathlib import Path
from datetime import date

import markdown

HERE = Path(__file__).resolve().parent.parent          # web-vuln-wiki/
PARENT = HERE.parent
OUT_DIR = HERE / "portal"
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

MD = markdown.Markdown(extensions=["tables", "fenced_code"])
FM_RE = re.compile(r"^---\n.*?\n---\n", re.S)
A_RE = re.compile(r'(<a\s+href=")([^"]+)(")')

# 学习体系注册表：wiki 目录名 -> (路由 id, 展示名, 描述)
WIKIS = [
    ("web-vuln-wiki", "wiki", "Web 漏洞教科书", "32 个漏洞条目：是什么、为什么、怎么修", "topics"),
    ("web-pentest-playbook", "playbook", "实战手册", "30 个实战条目：怎么打、打不动怎么办（含工具实践）", "entries"),
    ("android-re-wiki", "android", "Android 逆向", "21 个条目：APK 逆向、常见移动漏洞与防护绕过", "entries"),
]


def load_manifest(p):
    return json.loads(p.read_text(encoding="utf-8"))


def build_path_map(wiki_root_name, manifest, list_key, wid):
    m = {}
    for e in manifest[list_key]:
        m[f"{wiki_root_name}/{e['path']}"] = (wid, e["id"])
    return m


PATH_MAP = {}
for root, wid, _, _, list_key in WIKIS:
    PATH_MAP.update(build_path_map(root, load_manifest(PARENT / root / "manifest.json"), list_key, wid))


def rewrite_links(html, entry_full_rel):
    def repl(m):
        href = m.group(2)
        if href.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        resolved = os.path.normpath(os.path.join(os.path.dirname(entry_full_rel), href)).replace("\\", "/")
        if resolved in PATH_MAP:
            wiki_name, entry_id = PATH_MAP[resolved]
            return f'{m.group(1)}#/{wiki_name}/{entry_id}{m.group(3)}'
        if "cards/viewer.html" in resolved:
            return f'{m.group(1)}../cards/viewer.html{m.group(3)}'
        return m.group(0)
    return A_RE.sub(repl, html)


def render_entry(full_rel, abs_path, meta):
    raw = abs_path.read_text(encoding="utf-8")
    body = FM_RE.sub("", raw, count=1)
    body = re.sub(r"^#\s+.+\n+", "", body, count=1, flags=re.M)   # 去掉正文首个 H1（标题已由 entry-head 渲染）
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


wikis_out = []
card_count = 0
for root, wid, name, desc, list_key in WIKIS:
    root_path = PARENT / root
    if not root_path.exists():
        print(f"[跳过] {root} 不存在")
        continue
    manifest = load_manifest(root_path / "manifest.json")
    entries = []
    for e in manifest[list_key]:
        entries.append(render_entry(f"{root}/{e['path']}", root_path / e["path"], e))
    wikis_out.append({"id": wid, "name": name, "desc": desc, "entries": entries})

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
