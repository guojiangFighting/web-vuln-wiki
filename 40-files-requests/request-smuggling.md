---
id: request-smuggling
title: HTTP 请求走私（HTTP Request Smuggling）
category: 文件与请求类
severity: high
owasp: A05:2021-Security Misconfiguration
cwe: CWE-444
tags: [smuggling, proxy, http, misconfiguration]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。探测仅在授权环境进行并严格控制请求量。

# HTTP 请求走私（HTTP Request Smuggling）

## 一句话
> 前端与后端对「一条请求在哪里结束」理解不一致——`Content-Length` 与 `Transfer-Encoding` 的取舍分歧让攻击者构造的请求被「重新切分」，多余的部分被拼进下一个人的请求里。这是代理链的架构级配置病。

## 它是怎么发生的
**根因**：HTTP/1.1 用两种头标定 body 边界：`Content-Length: N`（按字节数）与 `Transfer-Encoding: chunked`（按分块）。当请求链路上有两个解析器（前端代理 → 后端服务）而它们对「同时出现时信谁」的取舍不同，同一段字节就被切成了两条不同的请求：

```
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
...
```

- **前端按 CL**：body 是 `0\r\n\r\nGET...` 共 6 字节，整条请求原样转给后端；
- **后端按 TE**：`0` 分块表示消息结束，剩下的 `GET /admin...` 被解析成**下一条独立请求**。

于是攻击者的前缀「走私」成了下一个用户的请求开头——后端以为那是受害者的请求的一部分。三种经典形态按「谁先信 CL / TE」命名：

| 形态 | 前端解析 | 后端解析 |
|------|----------|----------|
| CL.TE | 信 Content-Length | 信 Transfer-Encoding |
| TE.CL | 信 Transfer-Encoding | 信 Content-Length |
| TE.TE | 两者都信 TE，但混淆写法（如 `Transfer-Encoding: xchunked`、大小写/空格变体）让某一方退回 CL | — |

**触发条件**：代理链存在 + 组件对边界的解析不一致 + 攻击者能控制 body 内容。

## 攻击场景

### 场景一：请求前缀劫持
**目标**：把受害者的下一个请求拼到攻击者构造的请求之后。**思路**：走私一个「请求头到此为止」的残缺请求，后端把受害者请求的开头当作残缺请求的 body 收下；等攻击者再发一个请求，后端把受害者的内容当作它的响应吐回。
**结果**：攻击者读到受害者的请求头——含其 Cookie 与 CSRF Token。这是走私危害的顶点形态。

### 场景二：绕过前端访问控制
**目标**：前端代理按路径做 ACL（`/admin` 只许内网）。**思路**：走私的「第二条请求」由后端直接解析，根本不经过前端的 ACL。
**payload**：走私体里放 `GET /admin HTTP/1.1`
**结果**：前端看到的是无害请求，后端执行了被禁路径——「访问控制做在链路某一层」的架构在这个攻击面前失效。

### 场景三：缓存投毒联动
**目标**：共享缓存的公开页面。**思路**：走私体里放「请求 / 且带恶意响应头」的内容，受害者请求同一 URL 时缓存返回被污染的响应。
**结果**：与[缓存攻击](../50-logic-concurrency/cache-attacks.md)联动，影响所有命中该键的用户。

## 怎么发现它
- **手工测试（差异法，概念级）**：利用「时间差」与「响应错位」两种信号——CL.TE 探测：给 CL 一个小于实际 body 的值，后端按 TE 等待更多分块，若响应**延迟/超时**说明后端信 TE；TE.CL 探测反之。再确认「第二条走私请求被后端当真」。
- **工具**：Burp 的 HTTP Request Smuggler 扩展自动化探测。
- **真假判断**：延迟也可能来自网络抖动——成对探测（对照组）、重复三次；**绝不对生产环境做高强度探测**，走私探测本身可能污染其他用户的请求。

## 常见绕过与进阶
- **TE 变体**：`Transfer-Encoding: chunked` 的空格、大小写、`x:` 前缀变体——T-E 与 TE 头重复时各组件取舍不同（TE.TE 的核心）。
- **CL 与 TE 双头**：两个 `Content-Length` 头，前后端取第一个/最后一个不同。
- **HTTP/2 降级**：HTTP/2 前端把二进制请求翻译成 HTTP/1.1 发给后端时，`content-length` 与真实 body 长度不一致（H2.CL 走私）——现代走私的主战场。
- 思路主线：**走私 = 「两个解析器 + 一个歧义」，只要链路上存在任何解析分歧点，就存在走私**——所以修复是架构性的。

## 怎么修
1. **端到端规范化（治本）**：整条链路统一策略——要么全部禁 TE 只信 CL，要么全部禁 CL 只信 TE；「歧义请求直接 400 拒绝」是最干净的产品化实现（现代代理均有此选项）。
2. **HTTP/2 到 HTTP/1.1 转换纯净**：降级时校验 content-length 与实际 body 一致，冲突即拒绝。
3. **组件对齐**：链路上的代理/网关/应用服务器版本统一升级，避免老组件的解析行为混入。
4. **架构简化**：链路越短、解析器越少，走私面越小——每加一层代理都要重新核对边界策略。

## 常见误区
- **「走私是应用代码漏洞」**：应用代码往往无错——漏洞在中间件链路的配置与版本组合上，所以它归 A05 配置错误。
- **「HTTPS 或 H2 就免疫」**：H2→H1.1 降级恰好是现代走私的主要来源；加密不影响「边界解析」这一层。
- **「探测走私 = 高强度攻击」**：差异探测只需极少量请求，但生产环境的重探测确实可能干扰他人——这也是它只适合授权测试的原因。
- **「只有 CL.TE/TE.CL 两种」**：TE.TE 混淆与 H2 降级走私已让分类远超教科书二分；理解「解析分歧」这个根模型即可涵盖全部变体。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（CL/TE 与消息边界）
- 相关：[缓存攻击](../50-logic-concurrency/cache-attacks.md)（投毒联动） · [访问控制总类](../30-authn-authz/access-control.md)（绕过前端 ACL）
- 参考：[PortSwigger: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) · [RFC 7230 消息解析要求](https://datatracker.ietf.org/doc/html/rfc7230)
