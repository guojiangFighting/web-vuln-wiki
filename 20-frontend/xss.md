---
id: xss
title: 跨站脚本（XSS: Cross-Site Scripting）
category: 前端与跨站类
severity: high
owasp: A03:2021-Injection
cwe: CWE-79
tags: [xss, frontend, injection, owasp-top10]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 跨站脚本（XSS: Cross-Site Scripting）

## 一句话
> 攻击者的输入被原样写进受害者的页面，浏览器把它当 HTML/JS 执行——于是攻击者的代码获得了在受害者身份下操作页面的全部能力（读 DOM、发请求、拿 Cookie）。

## 它是怎么发生的
**根因**：把「不可信数据」直接拼进「会被浏览器解析为代码的上下文」，没有按语境编码。浏览器区分不了「页面的代码」和「数据里的代码」——HTML 是数据与标记混排的格式，这个混排就是 XSS 的生存空间。

典型危险写法（前端示意）：

```js
document.getElementById("out").innerHTML = "搜索结果: " + location.hash.slice(1);
```

URL 带 `#<img src=x onerror=alert(1)>` 时，事件处理器就在受害者浏览器里执行了。

**三种类型对比**：

| 类型 | payload 存在哪 | 谁触发 | 典型位置 |
|------|---------------|--------|----------|
| 反射型（Reflected） | 请求参数 | 当次请求即触发 | 搜索回显、错误页 |
| 存储型（Stored） | 服务端存储（DB） | 任何访问该内容的用户 | 评论、昵称、个人简介——危害最大 |
| DOM 型（DOM-based） | 前端逻辑内 | 前端 sink 处理 source 时 | `location.hash`/`postMessage` → `innerHTML` |

source（输入来源）：URL 参数、hash、`postMessage`、`localStorage`、referrer。sink（危险出口）：`innerHTML`、`document.write`、`eval`、`location.href=javascript:`、jQuery `$(html)`。

## 攻击场景

### 场景一：反射型验证（HTML 正文语境）
**目标**：证明输入未经编码进入页面。**思路**：先放无害探针观察回显位置，再按语境构造。
**payload**：`"><svg/onload=alert(1)>`（引号先闭合属性，再进正文语境）
**结果**：弹窗即证明。授权测试中用 `console.log` 或自控域回连替代 `alert`。

### 场景二：属性语境逃逸
**目标**：输入被塞进 `<input value="...">`。**思路**：先闭合引号与标签，再开新语境。
**payload**：`"><script>alert(1)</script>` 或 `"><img src=x onerror=alert(1)>`
**结果**：脱离属性语境进入标签语境。

### 场景三：存储型打管理员
**目标**：评论/工单/日志类功能。**思路**：payload 存进数据库，等待管理员查看。
**结果**：管理员触发 → 其会话与权限被滥用（如静默发请求到管理接口）。存储型之所以高危，正因为受害者是「看内容的人」而攻击者只需写入。

### 场景四：DOM XSS（纯前端）
**目标**：无服务端参与的注入。**思路**：source（hash/postMessage）直接流向前端 sink。
**payload**：`#<img src=x onerror=alert(1)>`（hash 不进服务端日志，常规扫描易漏）
**结果**：需要纯前端审计（source→sink 数据流追踪）才能系统性发现。

危害面：读取 DOM 与同源数据、以受害者身份发请求（叠加 CSRF 效果）、键盘记录、伪造页面——本质是「页面级完全控制」。`HttpOnly` 能挡住 Cookie 窃取，但挡不住「以受害者身份发请求」。

## 怎么发现它
- **手工测试**：每个回显点先判断**输出语境**（正文/属性/JS 字符串/URL），再选探针；四种语境的正确性比 payload 花样更重要。
- **工具**：Burp Scanner / XSS hunter 类平台做覆盖度补充；浏览器 DevTools 断点追 DOM 型的 source→sink。
- **真假判断**：弹窗是金标准；只有 `<script>` 原样出现在源码里不算（可能已被实体化）；区分「被编码后无害显示」与「被解码后执行」要看最终 DOM（DevTools 的 Elements 面板），不是 HTTP 响应原文。

## 常见绕过与进阶
- **标签被滤**：事件属性（`onerror`/`onfocus`）、伪协议（`javascript:`）、标签变体（`<svg>`/`<details>`）。
- **引号被滤**：反引号（部分语境）、无引号属性、`/` 替代空格。
- **编码错配**：输出编码用了 HTML 实体但 sink 是 `innerHTML`（实体被二次解析）、JSON 响应进入 `eval`。
- **CSP 对抗**：nonce 泄露、白名单域上的开放上传、`unsafe-inline` 遗留。
- 思路主线：**先确认「过滤器/编码发生在哪个语境」，再找该语境的语法死角**——与[编码与绕过](../00-basics/encoding-bypass.md)的原理完全一致。

## 怎么修
1. **按上下文输出编码（治本）**：HTML 正文用 HTML 实体编码；属性值加引号并编码引号；JS 字符串用 JSON 序列化；URL 做 URL 编码。四套编码不能混用——这是修复正确性的核心。
2. **不信任的 HTML 必须净化**：富文本用 DOMPurify 类库做白名单净化，而非字符串过滤。
3. **前端 sink 治理**：`innerHTML` 换 `textContent`；`eval`/`Function` 从代码里移除；`postMessage` 校验 origin。
4. **纵深**：CSP（nonce/hash 模式，禁 `unsafe-inline`）、Cookie `HttpOnly`、关键操作二次确认。
5. **框架默认防护别关**：React/Vue 的插值默认转义，`dangerouslySetInnerHTML`/`v-html` 是需要审计的出口。

## 常见误区
- **「过滤了 `<script>` 就安全」**：事件属性、SVG、编码变体都能执行；黑名单思路注定不完备。
- **「HttpOnly 了 XSS 就无害」**：Cookie 只是 XSS 收益之一，「以受害者身份发请求」不受 HttpOnly 影响。
- **「转义 = 替换 `<` 和 `>`」**：属性语境要转义引号，JS 语境要防 `\` 与换行，单一字符集覆盖不了四个语境。
- **「XSS 是低危的弹窗」**：危害评估看「谁会触发、能做什么动作」，存储型 + 管理员触发可达接管账号级别。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（同源策略） · [编码与绕过](../00-basics/encoding-bypass.md)
- 相关：[CSRF](csrf.md)（XSS 可打穿 CSRF Token） · [CORS](cors.md) · [原型污染](prototype-pollution.md)（污染后常以 XSS 落地）
- 参考：[OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [PortSwigger: XSS](https://portswigger.net/web-security/cross-site-scripting)
