Web 漏洞学习知识库 (web-vuln-wiki) - 纯文本说明
====================================================

这是什么
--------
面向 LLM 与人类双端优化的 Web 漏洞知识库：33 个漏洞条目，统一结构
（一句话/原理/攻击场景/检测/绕过/修复/常见误区/关联），每个条目配
4~6 张知识卡（共 168 张）。

仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

怎么读（人类）
--------------
1. 推荐入口：portal/index.html（统一学习门户，含搜索与阅读进度）
2. 推荐顺序：00-basics（HTTP/编码/OWASP）-> 10-injection -> 20-frontend
   -> 30-authn-authz -> 40-files-requests -> 50-logic -> 60-info-config
3. 知识卡自测：cards/viewer.html 或 cards/anki-import.tsv 导入 Anki

怎么用（LLM）
-------------
1. 入口：llms.txt（条目摘要与路径）
2. 索引：manifest.json（id/路径/分类/严重度/OWASP 映射）
3. 知识卡数据：cards/cards.json

目录
----
00-basics/          基础（HTTP/编码与绕过/OWASP Top 10）
10-injection/       注入类（SQLi/NoSQL/命令/SSTI/XXE/LDAP/反序列化/CRLF）
20-frontend/        前端与跨站类（XSS/CSRF/CORS/WebSocket/点击劫持/开放重定向/原型污染）
30-authn-authz/     访问控制与认证类（IDOR/越权/JWT/会话/GraphQL/加密失败）
40-files-requests/  文件与请求类（SSRF/路径穿越/文件上传/请求走私）
50-logic-concurrency/ 逻辑与并发类（业务逻辑/竞态/缓存攻击）
60-info-config/     信息泄露与配置类
cards/              知识卡（viewer/anki/json）
_tools/build.py     校验与构建

维护
----
新增条目：复制 _templates/ 模板，写完运行 python _tools/build.py build
姊妹库：web-pentest-playbook（实战手册）/ android-re-wiki / binary-re-wiki
统一门户：portal/index.html（含全部姊妹库条目）
主页：https://github.com/guojiangFighting/web-vuln-wiki
