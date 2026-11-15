---
id: clickjacking
title: 点击劫持（Clickjacking / UI Redressing）
category: 前端与跨站类
severity: low
owasp: A05:2021-Security Misconfiguration
cwe: CWE-1021
tags: [clickjacking, frontend, iframe]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 点击劫持（Clickjacking / UI Redressing）

## 一句话
> 攻击者把目标网站套进一个透明 iframe 叠在自己的页面上，受害者以为在点「领取奖品」，实际点的是底下那个看不见的「删除账号」按钮——利用的是「视觉欺骗」，不是代码漏洞。

## 它是怎么发生的
**根因**：浏览器允许任意页面把其他站点嵌入 `<iframe>`（默认无限制），且 iframe 内容可以设为透明并精确对位。受害者的**点击落点**与**看到的界面**不一致——操作是受害者亲自做的（带 Cookie、带 Token、有人类交互），所以 CSRF Token、SameSite 等防伪造机制全部失效；唯一缺的是「让用户看见自己点了什么」。

攻击结构：

```html
<style>iframe { opacity: 0; position: absolute; }</style>
<button>点击领取奖品</button>
<iframe src="https://target.com/settings/delete-account"
        style="top:-50px; left:-120px; width:800px; height:600px"></iframe>
```

iframe 被挪动对位，让目标页的「确认删除」按钮恰好压在诱饵按钮上。

**触发条件**：目标页面未设置 `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`，且存在**单次点击即可完成的敏感操作**。

## 攻击场景

### 场景一：单点击劫持
**目标**：一键操作（关注、点赞、授权、删除）。**思路**：透明 iframe 对位。
**结果**：受害者一次点击完成目标操作，全程不知情。

### 场景二：多步点击（组合 UI）
**目标**：需要两次点击的操作（先「设置」再「确认」）。**思路**：诱饵页面做成多步引导（第一步「点击开始」、第二步「点击确认领取」），每步对应 iframe 内的一个按钮，鼠标跟随提示框引导位置。
**结果**：多步流程同样可被「搬运」——复杂度上升，可行性不受根本影响。

### 场景三：拖放劫持（Drag & Drop）
**目标**：需要拖拽或文本输入的场景。**思路**：让受害者拖动的是「看似文本的敏感内容」（如自动填充的 token），投放到 iframe 内的目标控件。
**结果**：可构造数据投递，绕过纯点击的局限。

### 场景四：与 XSS/CSRF 的边界对照
**说明**：clickjacking 不需要任何代码注入，服务端收到的请求与正常用户操作完全一致——这就是它绕过 CSRF 防御的原因，也是它只能「借用用户权限」而不能「读取数据」（跨域 iframe 内容不可读）的原因。

## 怎么发现它
- **手工测试**：对敏感页面发请求，检查响应头是否有 `X-Frame-Options: DENY/SAMEORIGIN` 或 CSP `frame-ancestors 'none'/'self'`；没有即存在嵌入面，再用本地 PoC 页面（透明 iframe 对位）验证一次关键按钮的可达性。
- **真假判断**：有防护头 = 不可嵌（除非头配置为允许特定域且该域可被滥用）；无防护头但页面无敏感操作 = 报告为低危加固项。「可嵌入」本身不是漏洞，**可嵌入 + 敏感单步操作**才是。

## 常见绕过与进阶
- **仅防护敏感页**：攻击可借「不敏感页面的跳转/状态变化」组合完成（iframe 内先导航再操作）。
- **`SAMEORIGIN` 的子域例外**：同主域子域可嵌（若目标允许任意子域），子域风险仍在。
- **JS 框架（frame-busting）作为唯一防护**：纯客户端 `top != self` 跳转可被 `sandbox` 属性（禁脚本）或 `loading` 行为绕过——**必须用响应头**，JS 方案不是修复。

## 怎么修
1. **响应头防护（标准做法）**：`Content-Security-Policy: frame-ancestors 'none'`（或 `'self'`）；兼容旧浏览器叠加 `X-Frame-Options: DENY`。两者都加，CSP 版本是现代标准。
2. **按需放行**：确需被嵌入的场景（如小部件）用 `frame-ancestors https://trusted.com` 精确白名单。
3. **敏感操作二次确认**：危险动作增加确认弹窗/输入验证——即便被劫持，二次交互也难以伪装。
4. **UI 层加固**：关键按钮点击后短暂遮罩、基于 `top` 检测的 JS 作为补充（不可替代响应头）。

## 常见误区
- **「clickjacking 是 XSS 的一种」**：无任何代码执行，纯视觉与交互欺骗；防护维度也完全不同（响应头 vs 输出编码）。
- **「CSRF Token 能防 clickjacking」**：Token 防「伪造请求」，clickjacking 的请求是真实用户亲手发起的，Token 自然存在且合法。
- **「页面加了 frame-busting JS 就安全」**：JS 方案在 `sandbox` iframe（脚本被禁）中失效；必须依赖响应头。
- **「低危就不用修」**：单独低危，但结合社交工程对「资金/授权/删除」类操作可达高危——修复成本（一行响应头）与收益严重不对称。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（响应头）
- 相关：[CSRF](csrf.md)（同为「借用用户身份」类，一个伪造请求、一个劫持交互） · [CORS](cors.md)
- 参考：[OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking) · [MDN X-Frame-Options](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Frame-Options)
