---
id: http-basics
title: HTTP 基础（HTTP Essentials）
category: 基础
severity: -
owasp: -
cwe: -
tags: [http, basics, headers, session, sop]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# HTTP 基础（HTTP Essentials）

## 一句话
> HTTP 是 Web 攻防的共同语言：绝大多数 Web 漏洞，本质都是「对 HTTP 请求里的某个部分做了不该做的信任」——所以学漏洞，先把请求每一行的含义和信任边界吃透。

## 请求与响应的结构

```http
GET /search?q=hello HTTP/1.1          ← 请求行：方法 + 路径 + 版本
Host: example.com                     ← 头部：元信息，每行 key: value
Cookie: session=abc123
Content-Length: 0

                                      ← 空行
（POST 时这里跟 body）
```

```http
HTTP/1.1 200 OK                       ← 状态行：版本 + 状态码 + 短语
Content-Type: text/html; charset=utf-8
Set-Cookie: session=abc123; HttpOnly

<!doctype html>...                    ← body
```

安全视角的两个关键：**路径 + query 是用户可控输入的主要来源**；**头部（Cookie、Referer、自定义头）同样可控**，而且经常被开发者忘记当作输入。

## 方法（Method）

| 方法 | 语义 | 安全性 | 幂等 | 漏洞视角 |
|------|------|--------|------|----------|
| GET | 取资源 | 安全 | 幂等 | 参数进日志/Referer，敏感数据别放 GET |
| POST | 提交数据 | 不安全 | 不幂等 | CSRF 最常打的对象 |
| PUT/DELETE | 增删 | 不安全 | 幂等 | 未授权开放的 PUT/DELETE 是高危配置错误 |
| HEAD | 取头部 | 安全 | 幂等 | 盲注探测常用其响应差异 |
| OPTIONS | 问能力 | 安全 | 幂等 | 响应里 `Allow` 头暴露攻击面 |

「幂等」= 同一请求发多次效果与发一次相同。写操作不幂等，所以才有重放与竞态问题。

## 状态码
- **2xx 成功**：200 正常；201 已创建；204 无内容。
- **3xx 重定向**：301/302 跳转——[开放重定向](../20-frontend/open-redirect.md)的舞台，看 `Location` 头是否被用户输入影响。
- **4xx 客户端错误**：403 拒绝（越权测试的关键信号）；404 不存在；429 限流。
- **5xx 服务端错误**：500 经常伴随详细堆栈——[信息泄露](../60-info-config/info-disclosure.md)的入口。

## 安全上必须认识的 Header

| Header | 作用 | 漏洞关联 |
|--------|------|----------|
| Cookie / Set-Cookie | 会话凭证 | 窃取目标是 [XSS](../20-frontend/xss.md)；属性缺失是 [会话管理](../30-authn-authz/session-management.md)弱点 |
| Referer / Origin | 请求来源 | [CSRF](../20-frontend/csrf.md) 校验依据、[CORS](../20-frontend/cors.md) 判定输入、UUID 泄露途径 |
| X-Forwarded-For | 代理透传的客户端 IP | 可伪造，别当鉴权依据 |
| Location | 重定向目标 | [开放重定向](../20-frontend/open-redirect.md) |
| Content-Length / Transfer-Encoding | 消息边界 | [请求走私](../40-files-requests/request-smuggling.md)的根源 |
| Content-Security-Policy | 限制脚本来源 | XSS 的纵深防御 |
| X-Frame-Options / frame-ancestors | 防嵌 iframe | [点击劫持](../20-frontend/clickjacking.md) |
| Strict-Transport-Security | 强制 HTTPS | 降级与剥离攻击 |

## 会话机制对比：Cookie vs Session vs JWT

| | Cookie（纯） | Session | JWT |
|--|--|--|--|
| 状态存哪 | 浏览器 | 服务端存储，浏览器只拿 id | 浏览器 |
| 服务端可主动失效 | 难 | 容易（删存储） | 难（要额外黑名单） |
| 篡改风险 | 高（明文） | 低 | 依赖签名校验是否正确 |
| 典型弱点 | 无签名可伪造 | id 可预测、固定 | [算法与校验缺陷](../30-authn-authz/jwt-attacks.md) |

三者都靠浏览器**自动附带 Cookie** 这一行为工作——这正是 [CSRF](../20-frontend/csrf.md) 存在的根本原因。

## 同源策略（Same-Origin Policy, SOP）
定义：协议 + 域名 + 端口三者完全一致才算同源；浏览器禁止脚本**读取**跨源响应。

- **SOP 管的是「读」**：跨域发请求（图片、表单提交、script 加载）通常是被允许的，只是响应不让读。所以 CSRF 不被 SOP 阻止。
- **不受 SOP 限制的常见操作**：`<script src>`、`<img src>`、CSS 加载、表单提交、iframe 嵌套（但拿不到内容）。
- **CORS** 是 SOP 的官方豁免机制——配置错了就等于把「读」的口子开给了任意网站（见 [CORS 配置错误](../20-frontend/cors.md)）。

## HTTP/1.1 与 HTTP/2 一句话
HTTP/1.1 用文本分隔消息，靠 `Content-Length` / `Transfer-Encoding` 标定 body 边界；HTTP/2 用二进制帧天然标定长度。当 HTTP/2 前端把请求「降级翻译」给 HTTP/1.1 后端时，翻译不一致就会产生[请求走私](../40-files-requests/request-smuggling.md)。

## 与漏洞的关系
本条目每个知识点都对应 wiki 中的一类漏洞，学习时按此地图串联：

| 知识点 | 直接关联的漏洞条目 |
|--------|-------------------|
| 方法与幂等 | [业务逻辑](../50-logic-concurrency/business-logic.md)（重放）、[竞态条件](../50-logic-concurrency/race-condition.md) |
| Cookie 自动携带 | [CSRF](../20-frontend/csrf.md)、[会话管理](../30-authn-authz/session-management.md) |
| 同源策略与 CORS | [XSS](../20-frontend/xss.md)、[CORS 配置错误](../20-frontend/cors.md) |
| CL / TE 边界 | [请求走私](../40-files-requests/request-smuggling.md) |
| 30x 与 Location | [开放重定向](../20-frontend/open-redirect.md) |
| Header 可伪造 | [SSRF](../40-files-requests/ssrf.md)、[XSS](../20-frontend/xss.md) 的 source |
| 5xx 与报错回显 | [信息泄露](../60-info-config/info-disclosure.md)、[SQL 注入](../10-injection/sql-injection.md)（报错注入） |

## 安全要点
1. 会话 Cookie 全套属性：`HttpOnly; Secure; SameSite=Lax`。
2. 安全头按需齐备：CSP、HSTS、X-Frame-Options。
3. 服务端把「一切输入」都当不可信：query、body、Cookie、Header、路径。
4. 重定向目标、Origin 校验、文件名……凡是「白名单能解决的地方不要用黑名单」。

## 常见误区
- **「GET 请求无害」**：GET 参数同样能注入（SQLi 常见于搜索参数），还会进访问日志与 Referer。
- **「Cookie 和 Session 是二选一」**：Session 也要靠 Cookie 存 id，两者不是同一层面的概念。
- **「同源策略能防 CSRF」**：SOP 禁止读跨域响应，但不禁跨域发送请求，CSRF 正好活在「发了但读不到」的缝隙里。
- **「HTTPS = 安全」**：TLS 只保护传输层，应用层漏洞（注入、越权）原样存在。

## 关联
- 后续：[编码与绕过](encoding-bypass.md) · [OWASP Top 10 总览](owasp-top10.md)
- 参考：[MDN HTTP Overview](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Overview) · [MDN Same-Origin Policy](https://developer.mozilla.org/zh-CN/docs/Web/Security/Same-origin_policy)
