---
id: crlf-injection
title: CRLF 注入（CRLF Injection / Header Injection）
category: 注入类
severity: medium
owasp: A03:2021-Injection
cwe: CWE-93
tags: [crlf, header-injection, response-splitting, log-injection]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# CRLF 注入（CRLF Injection）

## 一句话
> 用户输入里的回车换行符（`\r\n`，即 CRLF）被拼进 HTTP 响应头或日志文本，改变了「行」的结构——在响应头里能注入新头乃至拆分出第二个响应，在日志里能伪造任意记录。

## 它是怎么发生的
**根因**：HTTP 报文的头部区以 CRLF 分隔每一行，日志文件以换行分隔每条记录。当用户输入未经 CR/LF 过滤就被拼进 `Location`、`Set-Cookie`、自定义头或日志字符串，「一行」的边界被攻击者改写。

典型危险写法（重定向场景示意）：

```python
resp["Location"] = "/next?page=" + request.args["page"]
```

`page` 传入 `%0d%0aSet-Cookie:%20session=attacker_value`（URL 解码后即 CRLF）时，响应变为：

```http
HTTP/1.1 302 Found
Location: /next?page=
Set-Cookie: session=attacker_value   ← 注入的新头
```

**两个后果方向**：
1. **响应头注入（Header Injection）**：注入任意响应头——`Set-Cookie` 会话固定、注入 `Access-Control-Allow-Origin` 破坏 [CORS](../20-frontend/cors.md)、注入 `Location` 强化[开放重定向](../20-frontend/open-redirect.md)；
2. **响应拆分（Response Splitting，历史形态）**：注入完整的 `\r\n\r\n` + 第二个响应体——在共享[缓存](../50-logic-concurrency/cache-attacks.md)时代可毒化其他用户，现代 HTTP 栈多数已封死，但仍可出现在自研代理与老组件中。

**第三个常被忽视的方向**：**日志注入（CWE-117）**——输入进入应用/审计日志，CRLF 伪造日志行，破坏审计完整性，或为[路径穿越](../40-files-requests/path-traversal.md)的日志投毒链铺路。

## 攻击场景

### 场景一：重定向点注入 Set-Cookie（会话固定）
**目标**：登录后跳转参数被拼进 `Location`。**思路**：注入 `Set-Cookie` 头把已知会话 id 种给受害者。
**payload**：`?next=%0d%0aSet-Cookie:%20sid=attacker_known_id`
**结果**：受害者携带攻击者已知的 sid → 接[会话固定](../30-authn-authz/session-management.md)完成接管。

### 场景二：下载文件名注入
**目标**：`Content-Disposition` 里的文件名参数。**思路**：文件名拼进响应头，换行符注入新头。
**payload**：`filename=a.pdf%0d%0aX-Injected:%201`
**结果**：响应头出现 `X-Injected` 即确认；进一步注入安全头覆盖（如清除 CSP）放大其它漏洞。

### 场景三：日志注入破坏审计
**目标**：任何「输入进日志」的点（User-Agent、用户名、搜索词）。**思路**：换行符伪造日志行。
**payload**：用户名 `admin%0d%0aWARN: audit bypassed`
**结果**：审计日志出现假记录——单独是完整性问题，组合价值在于让[信息泄露](../60-info-config/info-disclosure.md)的日志面变成攻击面。

## 怎么发现它
- **手工测试**：枚举「用户输入会出现在响应头或日志」的点——重定向参数、下载文件名、Set-Cookie 值、自定义头回显（`X-` 类）；发 `%0d%0aX-Probe: 1`（双重编码 `%250d%250a` 赌解码层次），看响应头是否出现探针头。
- **真假判断**：探针头出现 = 确认；只返回 400/500 可能是框架已拒绝（好信号）；区分「头被注入」与「值被 URL 编码后原样显示」——注入的标志是**新头独立成行**。

## 常见绕过与进阶
- **过滤 `%0d%0a`**：试 `%0a`（部分服务器只认 LF）、Unicode 行分隔符、双重编码；
- **校验在解码前**：归一化后再校验的缺口同[编码与绕过](../00-basics/encoding-bypass.md)原理；
- **组合放大**：与[开放重定向](../20-frontend/open-redirect.md)、[会话固定](../30-authn-authz/session-management.md)、缓存层（历史形态的投毒）组合成链，报告按链定级。

## 怎么修
1. **用框架的头 API（治本）**：现代框架的 header 设置函数内置 CR/LF 拒绝——避免手拼 `Location`/`Set-Cookie` 原始串。
2. **输入进头前过滤 CR/LF**：白名单字符集（重定向目标、文件名按各自规则校验）。
3. **日志侧**：结构化日志（JSON 行）天然免疫行注入；文本日志对输入做换行转义。
4. **升级老组件**：自研代理、老版本应用服务器的头解析是响应拆分的残余温床。

## 常见误区
- **「现代框架都防了，不用测」**：框架入口安全 ≠ 全链路安全——自研网关、手拼 header 的导出/下载功能、老中间件仍是高频残余点。
- **「CRLF 只能拆响应」**：响应拆分已近绝迹，但**头注入**（会话固定/安全头覆盖）与**日志注入**（审计破坏、投毒链）是当下的真实危害面。
- **「日志注入是低危杂项」**：它是 LFI→RCE 链的铺路石，也是合规审计完整性的直接破坏。

## 关联
- 相关：[开放重定向](../20-frontend/open-redirect.md)（Location 拼接是高频注入点） · [会话管理](../30-authn-authz/session-management.md)（注入 Set-Cookie 的去向） · [路径穿越](../40-files-requests/path-traversal.md)（日志投毒链）
- 实战：[web-pentest-playbook 越权链](../../web-pentest-playbook/30-business/idor-chains.md)（组合定级思路）
- 参考：[OWASP: HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) · [CWE-117（日志注入）](https://cwe.mitre.org/data/definitions/117.html)
