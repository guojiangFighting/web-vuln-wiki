---
id: open-redirect
title: 开放重定向（Open Redirect）
category: 前端与跨站类
severity: low
owasp: A01:2021-Broken Access Control
cwe: CWE-601
tags: [redirect, phishing, oauth, frontend]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 开放重定向（Open Redirect）

## 一句话
> 跳转目标取自用户输入且未校验，攻击者能让你的域名把受害者送到恶意网站——单独是低危的钓鱼辅助，但它能让 OAuth 的授权码「合法地」流进攻击者手里，那时就是高危。

## 它是怎么发生的
**根因**：服务端把用户可控参数（`next`、`redirect`、`url`、`returnUrl`）直接写进 `Location` 响应头或前端 `window.location`，没有白名单校验「目的地是不是自家的」。

典型危险写法：

```python
return redirect(request.args.get("next", "/"))
```

`?next=https://evil.com` → 302 的 `Location` 指向攻击者站点。

**为什么值得在意的真实理由**：地址栏先显示你的可信域名、再跳到恶意站——钓鱼成功率高；更关键的是 OAuth/OIDC 流程中 `redirect_uri` 若可被影响，**授权码（code）会被送到攻击者域**，等于绕过整个授权模型的出口校验。

## 攻击场景

### 场景一：参数型跳转（基础形态）
**目标**：登录后的回跳地址。**思路**：把 `next` 换成外域。
**payload**：`https://target.com/login?next=https://evil.com/phish`
**结果**：登录成功后 302 到恶意站，页面可仿制登录框二次骗密码。

### 场景二：变体绕过白名单
**目标**：已有「必须以 `/` 开头」等弱校验。**思路**：利用浏览器对 `Location` 的解析宽容度。

| 输入 | 浏览器解析为 | 利用点 |
|------|-------------|--------|
| `//evil.com` | 协议相对地址 → evil.com | 以 `/` 开头但跳外域 |
| `/\evil.com` | 多数浏览器视为 `//evil.com` | 反斜杠变体 |
| `https://target.com@evil.com` | userinfo 语法 → host 是 evil.com | 看起来含 target.com |
| `https://target.com.evil.com` | 子串匹配命中 | 白名单用「包含」判断时 |

**结果**：每一行都是一种「弱校验的具体死法」——修复必须逐条对照。

### 场景三：OAuth redirect_uri 污染
**目标**：授权码/Token 流出。**思路**：开放重定向点位于 OAuth 域内，`redirect_uri=https://sso.target.com/callback?next=//evil.com`。
**结果**：授权码先到合法 callback，再被跳转到攻击者域——「合法注册的 redirect_uri + 内部开放重定向」是绕过 OAuth 白名单的经典组合，危害从钓鱼跃升为账号接管。

### 场景四：Headers 注入叠加
**目标**：`Location` 由拼接构成。**思路**：若参数含 `\r\n`（CRLF 未过滤）可注入任意响应头乃至拆分响应。
**结果**：与 CRLF 注入（向响应头注入回车换行）同族，属开放重定向点的升级形态；现代框架多已封死。

## 怎么发现它
- **手工测试**：枚举一切跳转参数（next/redirect/url/return/to/target/continue/dest），外域 payload 全家桶（`https://evil.com`、`//evil.com`、`/\evil.com`、`https:evil.com`）逐一观察 30x 的 `Location`；也测前端 `window.location = getParam(...)` 的 DOM 型跳转。
- **真假判断**：跳转发生在**服务端响应**或**客户端脚本**且目标可完全控制外域才成立；仅锚点跳转、同域路径参数、需用户再点一次链接的不算。危害评估务必检查该点是否在 OAuth/SSO 域内。

## 常见绕过与进阶
- **白名单子串匹配**：`target.com in url` → `https://target.com.evil.com`。
- **「必须 https 开头」**：`https:evil.com`（无斜杠，部分解析器视为相对）、`https://@evil.com`。
- **多级跳转**：白名单内的另一个参数型跳转点（A 域 → B 域 → 外域）。
- **编码层**：`%2F%2Fevil.com`，赌应用解码发生在校验之后（见[编码与绕过](../00-basics/encoding-bypass.md)）。
- 思路主线：**每一种绕过都对应一种「解析器差异」，测试时逐一列出即可，无需背 payload 清单**。

## 怎么修
1. **白名单精确匹配（治本）**：合法目的地维护在服务端（`return_to_id=3` 这种**索引制**最彻底——用户输入永远只是一个 id，不是 URL）。
2. **相对路径强校验**：必须以单 `/` 开头、且不以 `//` 或 `/\` 开头；或规范化后强制 `new URL(url, "https://target.com").origin === "https://target.com"`。
3. **OAuth 场景零容忍**：redirect_uri 精确匹配注册值；内部跳转参数与授权流程严格隔离。
4. **中间页提示**：确需跳外域（隐私政策等）时插入「即将离开本站」确认页。

## 常见误区
- **「开放重定向 = 只能钓鱼 = 不用修」**：OAuth/SSO 域内的开放重定向直接升级为授权码泄露 → 账号接管；同一个漏洞在不同位置的评级差三档。
- **「校验了 `http://` 就行」**：协议相对 `//`、反斜杠、@userinfo 都是等价外域写法。
- **「只防服务端跳转」**：`window.location`、`<a href>` 拼接的前端跳转同样要审。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（30x 与 Location） · [编码与绕过](../00-basics/encoding-bypass.md)
- 相关：[CSRF](csrf.md)（Referer 伪造的跳板） · [SSRF](../40-files-requests/ssrf.md)（重定向跟随是 SSRF 绕过手法之一）
- 参考：[OWASP Unvalidated Redirects](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet) · [PortSwigger: OAuth](https://portswigger.net/web-security/oauth)
