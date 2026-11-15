# Web 漏洞学习 Wiki

一个 **LLM 与人类双端优化** 的 Web 漏洞知识库：33 个条目 × 统一结构 × 168 张知识卡。

> **使用边界**：本库仅用于授权安全测试与防御学习。所有条目默认你在合法授权范围内实践。

## 目录结构

```
web-vuln-wiki/
├── README.md               ← 你在这里（人类入口）
├── llms.txt                ← LLM 入口（llms.txt 标准）
├── manifest.json           ← 机器可读索引（主题/分类/统计）
├── 00-basics/              ← 基础：HTTP、编码与绕过、OWASP Top 10
├── 10-injection/           ← 注入类：SQLi / NoSQL / 命令 / SSTI / XXE / LDAP / 反序列化 / CRLF
├── 20-frontend/            ← 前端与跨站类：XSS / CSRF / CORS / WebSocket / 点击劫持 / 开放重定向 / 原型污染
├── 30-authn-authz/         ← 访问控制与认证类：IDOR / 越权总类 / JWT / 会话管理 / GraphQL / 加密失败
├── 40-files-requests/      ← 文件与请求类：SSRF / 路径穿越 / 文件上传 / 请求走私
├── 50-logic-concurrency/   ← 逻辑与并发类：业务逻辑 / 竞态条件 / 缓存攻击
├── 60-info-config/         ← 信息泄露与配置类：信息泄露 / 安全配置错误
├── cards/
│   ├── viewer.html         ← 交互式学习卡片（浏览器直接打开）
│   ├── anki-import.tsv     ← Anki 导入文件（168 张）
│   ├── cards.json          ← 合并后的卡片数据（LLM 亦可读）
│   └── src/<topic>.json    ← 每个条目的卡片源文件
├── _templates/             ← 条目模板与卡片 schema（新增条目从这里开始）
└── _tools/build.py         ← 校验与构建脚本
```

## 人类学习路径

**第一周 · 打地基**：[HTTP 基础](00-basics/http-basics.md) → [编码与绕过](00-basics/encoding-bypass.md) → [OWASP Top 10 总览](00-basics/owasp-top10.md)。这三篇是后面所有条目的前置语言。

**第二、三周 · 注入家族**（同一根因，七种形态）：[SQL 注入](10-injection/sql-injection.md) 精读 → [NoSQL](10-injection/nosql-injection.md) / [命令注入](10-injection/command-injection.md) / [SSTI](10-injection/ssti.md) / [XXE](10-injection/xxe.md) / [LDAP](10-injection/ldap-injection.md) / [反序列化](10-injection/insecure-deserialization.md) / [CRLF](10-injection/crlf-injection.md) 对照读。读完问自己：为什么「参数化」能治本？

**第四周 · 前端与信任边界**：[XSS](20-frontend/xss.md) → [CSRF](20-frontend/csrf.md) → [CORS](20-frontend/cors.md) → [点击劫持](20-frontend/clickjacking.md) → [开放重定向](20-frontend/open-redirect.md) → [原型污染](20-frontend/prototype-pollution.md)。主线：同源策略管什么、不管什么。

**第五周 · 访问控制**：[越权总类](30-authn-authz/access-control.md) → [IDOR](30-authn-authz/idor.md) → [JWT 攻击](30-authn-authz/jwt-attacks.md) → [会话管理](30-authn-authz/session-management.md) → [GraphQL 安全](30-authn-authz/graphql-security.md) → [加密失败](30-authn-authz/crypto-failures.md)。掌握**双账号法**与**角色矩阵法**两个方法论。

**第六周 · 服务端边界**：[SSRF](40-files-requests/ssrf.md) → [路径穿越](40-files-requests/path-traversal.md) → [文件上传](40-files-requests/file-upload.md) → [请求走私](40-files-requests/request-smuggling.md)。

**第七周 · 扫不出的问题**：[业务逻辑](50-logic-concurrency/business-logic.md) → [竞态条件](50-logic-concurrency/race-condition.md) → [缓存攻击](50-logic-concurrency/cache-attacks.md) → [信息泄露](60-info-config/info-disclosure.md) → [配置错误](60-info-config/misconfiguration.md)。

**每天 10 分钟**：打开 [交互卡片](cards/viewer.html) 过 20 张卡（自测模式），或把 [anki-import.tsv](cards/anki-import.tsv) 导入 Anki 用间隔重复。

### 每个条目的读法
所有条目结构完全一致：**一句话 → 它是怎么发生的（根因）→ 攻击场景（学）→ 怎么发现它（测）→ 常见绕过 → 怎么修（防）→ 常见误区 → 关联**。建议按「误区 → 修复 → 场景」的顺序回读第二遍——误区最能校准认知。

## LLM 使用方式

1. **入口**：先读 [llms.txt](llms.txt)（标准格式，含全部条目的一句话摘要与路径）。
2. **检索**：`manifest.json` 提供机器可读索引（id / 路径 / 分类 / 严重度 / OWASP 映射 / 摘要 / 卡片数），按 `id` 定位条目文件。
3. **条目自包含**：每个条目都有完整 frontmatter 与统一章节，可单独加载成上下文；交叉引用为相对链接，可沿链接做图谱遍历。
4. **知识卡**：`cards/cards.json` 是结构化的问答对（id / 难度 / 题型 / q / a / hint / pitfall），可直接用于出题、测验生成或作为 few-shot 素材。
5. **维护**：新增条目时复制 `_templates/vuln-template.md` 与 `_templates/card-schema.json`，写完运行 `python _tools/build.py build`——校验结构并重新生成全部索引。

## 校验与构建

```bash
python _tools/build.py check   # 校验条目结构 / 卡片 schema / 链接有效性
python _tools/build.py build   # 校验 + 重新生成 cards.json / anki / manifest / cards.js
```
