# -*- coding: utf-8 -*-
"""web-vuln-wiki 构建与校验脚本
用法:
  python _tools/build.py check   # 校验条目结构、卡片 schema、内部链接
  python _tools/build.py build   # 校验通过后合并卡片、生成 manifest / anki / cards.js
"""
import json, re, sys, io
from pathlib import Path
from datetime import date

ROOT = Path(__file__).resolve().parent.parent
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

TOPICS = [
    # (rel_path, id, category, is_basic)
    ("00-basics/http-basics.md", "http-basics", "基础", True),
    ("00-basics/encoding-bypass.md", "encoding-bypass", "基础", True),
    ("00-basics/owasp-top10.md", "owasp-top10", "基础", True),
    ("10-injection/sql-injection.md", "sqli", "注入类", False),
    ("10-injection/nosql-injection.md", "nosql-injection", "注入类", False),
    ("10-injection/command-injection.md", "command-injection", "注入类", False),
    ("10-injection/ssti.md", "ssti", "注入类", False),
    ("10-injection/xxe.md", "xxe", "注入类", False),
    ("10-injection/ldap-injection.md", "ldap-injection", "注入类", False),
    ("20-frontend/xss.md", "xss", "前端与跨站类", False),
    ("20-frontend/csrf.md", "csrf", "前端与跨站类", False),
    ("20-frontend/cors.md", "cors", "前端与跨站类", False),
    ("20-frontend/clickjacking.md", "clickjacking", "前端与跨站类", False),
    ("20-frontend/open-redirect.md", "open-redirect", "前端与跨站类", False),
    ("20-frontend/prototype-pollution.md", "prototype-pollution", "前端与跨站类", False),
    ("30-authn-authz/idor.md", "idor", "访问控制与认证类", False),
    ("30-authn-authz/access-control.md", "access-control", "访问控制与认证类", False),
    ("30-authn-authz/jwt-attacks.md", "jwt-attacks", "访问控制与认证类", False),
    ("30-authn-authz/session-management.md", "session-management", "访问控制与认证类", False),
    ("40-files-requests/ssrf.md", "ssrf", "文件与请求类", False),
    ("40-files-requests/path-traversal.md", "path-traversal", "文件与请求类", False),
    ("40-files-requests/file-upload.md", "file-upload", "文件与请求类", False),
    ("40-files-requests/request-smuggling.md", "request-smuggling", "文件与请求类", False),
    ("50-logic-concurrency/business-logic.md", "business-logic", "逻辑与并发类", False),
    ("50-logic-concurrency/race-condition.md", "race-condition", "逻辑与并发类", False),
    ("50-logic-concurrency/cache-attacks.md", "cache-attacks", "逻辑与并发类", False),
    ("60-info-config/info-disclosure.md", "info-disclosure", "信息泄露与配置类", False),
    ("60-info-config/misconfiguration.md", "misconfiguration", "信息泄露与配置类", False),
]

SEVERITIES = {"critical", "high", "medium", "low", "-"}
DIFFS = {"basic", "advanced", "trap"}
TYPES = {"概念", "场景", "辨析", "排查"}

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+\.md)\)")

def check():
    errors, warns = [], []
    seen_ids = set()
    all_card_ids = set()
    stats = {}
    for rel, tid, cat, basic in TOPICS:
        p = ROOT / rel
        if not p.exists():
            errors.append(f"[缺失] {rel}")
            continue
        text = p.read_text(encoding="utf-8")
        lines = text.count("\n") + 1
        # frontmatter
        if not text.startswith("---\n"):
            errors.append(f"{rel}: 缺少 frontmatter")
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        if m:
            fm = m.group(1)
            fm_id = re.search(r"^id:\s*(\S+)", fm, re.M)
            if not fm_id or fm_id.group(1) != tid:
                errors.append(f"{rel}: frontmatter id 应为 {tid}，实际 {fm_id.group(1) if fm_id else '无'}")
            else:
                if tid in seen_ids:
                    errors.append(f"{rel}: id 重复")
                seen_ids.add(tid)
            sev = re.search(r"^severity:\s*(\S+)", fm, re.M)
            if not sev or sev.group(1) not in SEVERITIES:
                errors.append(f"{rel}: severity 非法: {sev.group(1) if sev else '无'}")
            for field in ("title:", "category:", "owasp:", "cwe:", "tags:"):
                if field not in fm:
                    errors.append(f"{rel}: frontmatter 缺 {field}")
            if cat not in fm.replace("category:", "", 1):
                if f"category: {cat}" not in fm:
                    errors.append(f"{rel}: category 应为 {cat}")
        else:
            continue
        # 必需章节
        required = ["## 一句话", "## 常见误区", "## 关联"]
        if basic:
            alts = [s for s in ("## 安全要点", "## 与漏洞的关系", "## 怎么修") if s in text]
            if not alts:
                errors.append(f"{rel}: 基础条目需至少含 安全要点/与漏洞的关系/怎么修 之一")
        else:
            required += ["## 它是怎么发生的", "## 攻击场景", "## 怎么发现它", "## 常见绕过与进阶", "## 怎么修"]
        for sec in required:
            if sec not in text:
                errors.append(f"{rel}: 缺少章节 {sec}")
        # 授权声明
        if "仅用于授权安全测试与防御学习" not in text:
            errors.append(f"{rel}: 缺少授权声明")
        # 链接有效性
        for target in LINK_RE.findall(text):
            if target.startswith("http"):
                continue
            resolved = (p.parent / target).resolve()
            if not resolved.exists():
                errors.append(f"{rel}: 死链 {target}")
        # 行数
        if lines < 60:
            warns.append(f"{rel}: 仅 {lines} 行（建议 90+）")
        # 卡片
        cj = ROOT / "cards/src" / f"{tid}.json"
        if not cj.exists():
            errors.append(f"[缺失] cards/src/{tid}.json")
            continue
        try:
            data = json.loads(cj.read_text(encoding="utf-8"))
        except Exception as e:
            errors.append(f"cards/src/{tid}.json: JSON 解析失败 {e}")
            continue
        if data.get("topic") != tid:
            errors.append(f"cards/src/{tid}.json: topic 应为 {tid}")
        cards = data.get("cards", [])
        if not (4 <= len(cards) <= 6):
            errors.append(f"cards/src/{tid}.json: 卡片数 {len(cards)} 不在 4~6")
        diffs = set()
        for c in cards:
            cid = c.get("id", "")
            if not cid.startswith(tid + "-c"):
                errors.append(f"{cj.name}: 卡 id 非法 {cid}")
            if cid in all_card_ids:
                errors.append(f"{cj.name}: 卡 id 重复 {cid}")
            all_card_ids.add(cid)
            if c.get("difficulty") not in DIFFS:
                errors.append(f"{cid}: difficulty 非法 {c.get('difficulty')}")
            diffs.add(c.get("difficulty"))
            if c.get("type") not in TYPES:
                errors.append(f"{cid}: type 非法 {c.get('type')}")
            if not c.get("q") or not c.get("a"):
                errors.append(f"{cid}: q/a 为空")
        if "basic" not in diffs:
            warns.append(f"cards/src/{tid}.json: 无 basic 卡")
        if "advanced" not in diffs:
            warns.append(f"cards/src/{tid}.json: 无 advanced 卡")
        stats[rel] = (lines, len(cards))

    print(f"条目数: {len(TOPICS)}  检查完成")
    for rel, (l, c) in stats.items():
        print(f"  {rel}: {l} 行, {c} 卡")
    if warns:
        print(f"\n警告 {len(warns)} 条:")
        for w in warns:
            print("  !", w)
    if errors:
        print(f"\n错误 {len(errors)} 条:")
        for e in errors:
            print("  X", e)
        return False
    print("\n校验全部通过 ✓")
    return True

def build():
    if not check():
        print("校验未通过，终止构建。")
        sys.exit(1)
    topics_meta, merged_cards = [], []
    for rel, tid, cat, basic in TOPICS:
        p = ROOT / rel
        text = p.read_text(encoding="utf-8")
        fm = re.match(r"^---\n(.*?)\n---\n", text, re.S).group(1)
        def fget(k):
            m = re.search(rf"^{k}:\s*(.+)$", fm, re.M)
            return m.group(1).strip() if m else ""
        title = fget("title")
        sev = fget("severity")
        owasp = fget("owasp")
        cwe = fget("cwe")
        tags = re.findall(r"[\w-]+", fget("tags"))
        # 一句话
        one = ""
        m1 = re.search(r"## 一句话\s*\n+>\s*(.+)", text)
        if m1:
            one = m1.group(1).strip()
        cj = ROOT / "cards/src" / f"{tid}.json"
        cdata = json.loads(cj.read_text(encoding="utf-8"))
        cards = cdata["cards"]
        for c in cards:
            merged_cards.append({
                "id": c["id"], "topic": tid, "topicTitle": title, "category": cat,
                "difficulty": c["difficulty"], "type": c["type"],
                "q": c["q"], "a": c["a"],
                "hint": c.get("hint"), "pitfall": c.get("pitfall"),
            })
        topics_meta.append({
            "id": tid, "path": rel, "title": title, "category": cat,
            "severity": sev, "owasp": owasp, "cwe": cwe, "tags": tags,
            "summary": one, "cards": len(cards),
        })
    # cards.json
    out_cards = ROOT / "cards/cards.json"
    out_cards.write_text(json.dumps({"version": 1, "generated": str(date.today()),
                                     "count": len(merged_cards), "cards": merged_cards},
                                    ensure_ascii=False, indent=1), encoding="utf-8")
    # cards.js（供 viewer.html file:// 直接引用）
    out_js = ROOT / "cards/cards.js"
    out_js.write_text("const CARDS = " + json.dumps(merged_cards, ensure_ascii=False) + ";\n", encoding="utf-8")
    # anki-import.tsv
    def esc(s):
        return s.replace("\t", " ").replace("\n", "<br>").replace("\r", "")
    tsv = ROOT / "cards/anki-import.tsv"
    rows = []
    for c in merged_cards:
        front = esc(c["q"]) + (f"<br><br><small>提示: {esc(c['hint'])}</small>" if c.get("hint") else "")
        back = esc(c["a"]) + (f"<br><br><b>易错点:</b> {esc(c['pitfall'])}" if c.get("pitfall") else "")
        tags = f"web-vuln-wiki {c['topic']} {c['difficulty']} {c['type']}"
        rows.append(f"{front}\t{back}\t{tags}")
    tsv.write_text("\n".join(rows) + "\n", encoding="utf-8")
    # manifest.json
    manifest = {
        "name": "web-vuln-wiki",
        "description": "Web 漏洞学习知识库：LLM 与人类双端优化。条目结构统一（原理/检测/修复/误区），知识卡 4~6 张/条目。",
        "generated": str(date.today()),
        "entryPoints": {"llm": "llms.txt", "human": "README.md", "machineIndex": "manifest.json"},
        "disclaimer": "仅用于授权安全测试与防御学习。",
        "stats": {"topics": len(topics_meta), "cards": len(merged_cards),
                  "categories": sorted({t['category'] for t in topics_meta})},
        "topics": topics_meta,
        "cardsFile": "cards/cards.json",
        "ankiImport": "cards/anki-import.tsv",
        "viewer": "cards/viewer.html",
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"构建完成: {len(topics_meta)} 条目 / {len(merged_cards)} 张卡")
    print(f"  cards/cards.json  cards/cards.js  cards/anki-import.tsv  manifest.json")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"
    if cmd == "check":
        ok = check()
        sys.exit(0 if ok else 1)
    elif cmd == "build":
        build()
    else:
        print("用法: python _tools/build.py [check|build]")
        sys.exit(2)
