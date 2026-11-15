---
id: session-management
title: 会话管理缺陷（Session Management Flaws）
category: 访问控制与认证类
severity: high
owasp: A07:2021-Identification and Authentication Failures
cwe: CWE-384
tags: [session, cookie, auth, lifecycle]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 会话管理缺陷（Session Management Flaws）

## 一句话
> 会话是从「登录成功」到「登出失效」的整条生命周期——生成可预测、传输可截获、失效不彻底，任何一环的缺陷都让攻击者无需密码就能持有你的身份。

## 它是怎么发生的
**根因**：HTTP 无状态，会话机制用「一个凭证」代表整段登录状态。安全完全取决于这个凭证的四个环节：

| 环节 | 应满足 | 典型缺陷 |
|------|--------|----------|
| 生成 | 高熵、不可预测 | 时间戳/递增 id/弱随机（Math.random） |
| 传输 | 仅 HTTPS | 明文 HTTP 泄露、Referer 泄露 |
| 存储 | HttpOnly + Secure + SameSite | 无 HttpOnly → [XSS](../20-frontend/xss.md) 直取 |
| 失效 | 登出/改密后立即作废 | 登出只删浏览器 Cookie，服务端会话仍活 |

**根本难点**：前三个环节是「一次性配置」，第四个环节（失效）是「每个变更动作都要联动」的设计问题——改密码、踢人、封号都要让旧会话死亡，漏一个联动就是洞。

## 攻击场景

### 场景一：登出后旧会话仍有效
**目标**：确认失效机制是否真正执行。**思路**：登出后用抓下来的旧 Cookie 重放请求。
**payload**：登出 → 原样重放 `Cookie: session=abc123` 的 `GET /api/profile`
**结果**：返回 200 与个人数据 = 失效不彻底。这是最高频的会话缺陷：很多实现只在前端删了 Cookie。

### 场景二：改密不踢旧会话
**目标**：怀疑账号被盗的场景（改密码本应是止损手段）。**思路**：改密后用旧会话继续访问。
**结果**：仍有效 = 攻击者截获的会话永久存活，改密形同虚设。

### 场景三：会话固定（Session Fixation）
**目标**：登录前后 session id 不更换的系统。**思路**：攻击者先拿到一个 id 并塞给受害者（链接携带、子域 Cookie 注入），受害者用它登录后，该 id 升级为合法会话——攻击者用同一个 id 直接进入。
**payload**：`https://target.com/login?sid=attacker_known_id`
**结果**：登录成功后 id 未换 = 会话固定成立。修复铁律：**登录成功必须换新 id**。

### 场景四：可预测的会话 id
**目标**：自研会话生成。**思路**：多拿几个 id 看规律（递增、时间戳+用户名、md5(用户名)）。
**结果**：能推断下一个 id = 攻击者可直接「预订」他人会话。现成框架的默认生成器都合格，风险集中在自研实现。

## 怎么发现它
- **手工测试（生命周期核对表）**：按四环节逐项检查——
  1. 生成：收集多个会话 id 比对结构；评估熵（是否有时间戳、用户名成分）。
  2. 传输：`Set-Cookie` 是否带 `Secure`；全站是否强制 HTTPS。
  3. 存储：是否带 `HttpOnly`、`SameSite`；id 是否出现在 URL（会出现在日志/Referer）。
  4. 失效：登出重放、改密重放、超时时间是否合理、并发登录策略。
- **工具**：Burp 抓包比对 Cookie 属性；脚本批量采集会话 id 做熵分析。
- **真假判断**：重放旧会话 200 才算失效缺陷（缓存导致的 200 要看 `Cache-Control` 与内容新鲜度）；「前端登出」与「服务端登出」必须区分——后端接口返回 200 不代表会话已从存储删除。

## 常见绕过与进阶
- **「记住我」独立令牌**：长效 remember-me token 与会话失效逻辑脱节，登出不清理。
- **会话 id 在 URL**：`?sid=` 形态随 Referer/日志扩散，任何「URL 含凭证」都是高危形态。
- **并行会话无上限**：无设备管理/踢出机制，令牌泄露后无法止损。
- 思路主线：**会话安全的全部问题 = 「凭证的信任边界」与「状态变更的联动完整性」**——后者要逐个动作（登出/改密/封号/降权）验证。

## 怎么修
1. **用成熟框架的会话实现**：生成、失效、轮换都是已解问题；自研只在有明确理由时做，并审计熵与随机源（CSPRNG）。
2. **登录与提权重置会话**：登录成功、修改密码、权限变更时销毁旧会话、签发新 id（同时终结[会话固定](#场景三会话固定session-fixation)）。
3. **服务端真失效**：登出删除服务端会话记录（或 JWT 场景配黑名单/版本号）；踢出、封号联动全部活跃会话。
4. **Cookie 属性全套**：`HttpOnly; Secure; SameSite=Lax; Path=/`，合理 TTL；绝不在 URL 传会话 id。
5. **设备与并发管理**：列出活跃会话、支持远端登出——把「凭证泄露后的止损」做成产品能力。

## 常见误区
- **「登出 = 点了退出按钮」**：用户视角的登出与服务端视角的登出是两回事；测试以「重放旧凭证」的结果为准。
- **「JWT 就没有会话管理问题」**：[JWT 的无状态](jwt-attacks.md)意味着失效更难——它只是把问题从「服务端存储」挪到了「撤销机制」。
- **「会话 id 只要够长就行」**：长而不随机（时间戳+哈希）照样可预测；熵与随机源质量才是核心。
- **「超时短就安全」**：超时只限制时间窗，不解决「失效不联动」；两个维度独立评估。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（Cookie/Session/JWT 对比）
- 相关：[JWT 攻击](jwt-attacks.md) · [XSS](../20-frontend/xss.md)（会话凭证的直接窃取者） · [CSRF](../20-frontend/csrf.md)（会话的自动携带是 CSRF 的前提）
- 参考：[OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) · [PortSwigger: Session flaws](https://portswigger.net/web-security/session-security)
