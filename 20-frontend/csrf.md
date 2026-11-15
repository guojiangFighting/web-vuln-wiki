---
id: csrf
title: 跨站请求伪造（CSRF: Cross-Site Request Forgery）
category: 前端与跨站类
severity: high
owasp: A01:2021-Broken Access Control
cwe: CWE-352
tags: [csrf, frontend, session, owasp-top10]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 跨站请求伪造（CSRF）

## 一句话
> 受害者浏览器会自动携带 Cookie 发请求，攻击者诱导它在自己的网站上发出指向目标的请求——服务端看到的是「带合法会话的请求」，无法区分是受害者本人点的还是恶意页面代发的。

## 它是怎么发生的
**根因**：HTTP 的会话认证靠 Cookie，而 Cookie 由浏览器**自动附加**到所有指向该域的请求（无论请求从哪个页面发起）。同源策略只禁止读取跨域响应，不禁跨域发送请求——CSRF 恰好活在「能发、不能读」的缝隙里。

攻击成立的三个条件（缺一不可）：
1. **有价值的动作**：改邮箱、转账、授权——GET 无副作用的站点没有 CSRF 攻击面；
2. **凭据自动携带**：Cookie 类认证（Session/JWT-in-Cookie）都受影响；纯 Header Token（`Authorization: Bearer`）天然免疫，因为跨站脚本拿不到也带不上；
3. **请求可预测**：全部参数可枚举或可猜测（无一次性 Token）。

攻击示意：恶意页面 `<img src="https://bank.com/transfer?to=attacker&amount=1000">` 或自动提交的表单 POST——受害者访问恶意页，浏览器带着 bank.com 的 Cookie 发出请求。

## 攻击场景

### 场景一：GET 型（历史形态，现多已绝迹）
**目标**：副作用挂在 GET 上的老系统。**思路**：`<img>`/链接直接触发。
**结果**：现代规范已要求副作用操作禁用 GET，此场景主要作为认知起点。

### 场景二：POST 表单自动提交
**目标**：无 Token 的 POST 接口。**思路**：攻击页面内嵌同目标表单并 `form.submit()`，无需读响应。
**payload**：一个自动提交的 `<form method=POST action="https://target.com/email">`
**结果**：受害者邮箱被改为攻击者控制的地址——随后「忘记密码」即可接管账号。

### 场景三：JSON 接口的变通
**目标**：只收 JSON 的接口。**思路**：JSON 也能用 HTML 表单以 text/plain 或无 enctype 方式发出，若服务端不校验 Content-Type 或容忍格式偏差仍可命中。
**结果**：证明「接口收 JSON」本身不是 CSRF 免疫证明，Token/SameSite 才是。

### 场景四：登录 CSRF
**目标**：登录接口。**思路**：诱导受害者用攻击者的凭据登录。
**结果**：受害者在「自己的电脑」上用了攻击者的账号，之后输入的隐私数据反而流入攻击者账号——冷门但真实。

## 怎么发现它
- **手工测试**：逐个列出**有副作用的接口**，构造 CSRF PoC 页面（本地打开，不含任何目标外行为），移除 Token / 改变 SameSite 环境后提交，看动作是否成功。关键是「服务端到底校验了什么」：删 Token 重放、改 Token 任意值、换 Referer 三种试探。
- **真假判断**：删除 Token 后请求仍成功 = 无校验；Token 校验存在但与 Session 无绑定（全局静态 Token）= 可复用；仅校验 Referer 但可用子域/开放重定向伪造来源 = 防御可绕。需要受害条件（SameSite=Lax 下跨站 POST）时明确写出利用条件。

## 常见绕过与进阶
- **仅校验 Referer**：子域 XSS / 子域接管 / [开放重定向](open-redirect.md)可伪造 Referer 起点 noreferrer。
- **Token 与会话未绑定**：拿到任意一个合法 Token 即可全局复用。
- **SameSite=Lax 的边界**：顶层导航的 GET 仍带 Cookie——GET 型副作用在 Lax 下仍可 CSRF。
- **主域污染**：同主域子域的 XSS 能设置/覆盖 Cookie，从而喂给目标接口。
- 思路主线：**CSRF 防御的有效性 = 校验物是否「攻击者域拿不到、受害者域也伪造不了」**。

## 怎么修
1. **CSRF Token（同步器模式，治本）**：服务端下发与会话绑定的随机 Token，写操作必须携带并校验；放在隐藏表单字段或自定义 Header（Header 形态天然要求 JS 读 Token，跨站页读不到）。
2. **SameSite Cookie**：`Set-Cookie: ...; SameSite=Lax`（现代浏览器默认）；敏感会话可用 `Strict`。这是低成本的体系性缓解，但单独使用不充分（见绕过）。
3. **Origin/Referer 校验**：作为第二层，校验 Origin 头是否为白名单域。
4. **要求二次交互**：改邮箱/支付等高危操作要求输入密码或验证码——把「请求」升级为「确认过的意图」。
5. **认证方式选型**：纯 Header Bearer Token（非 Cookie 存储）的 API 天然免疫 CSRF——前端架构选型时就把 CSRF 一起考虑。

## 常见误区
- **「上了 HTTPS / 有 CORS 就没 CSRF」**：CORS 管「读」，CSRF 打「写」；两者是完全独立的两层。
- **「Token 放 Cookie 里就完事」**：放 Cookie 的 Token 会被浏览器自动带上，除非配合「前端读 Cookie 写进 Header」的双提交模式，否则形同虚设。
- **「接口只收 JSON 就免疫」**：Content-Type 校验不严格时表单照样投递；免疫的是「Header Token」，不是「JSON 格式」。
- **「XSS 与 CSRF 是并列的两类事」**：XSS 能在同源环境读 Token、发任意请求，等于直接终结 CSRF 防御——所以「存在 XSS 的站点谈 CSRF 有效性」没有意义，两者要一起评估。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（SOP 与 Cookie 机制）
- 相关：[XSS](xss.md)（CSRF 防御的天敌） · [CORS](cors.md)（管「读」的那一半） · [会话管理](../30-authn-authz/session-management.md)
- 参考：[OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) · [MDN SameSite](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
