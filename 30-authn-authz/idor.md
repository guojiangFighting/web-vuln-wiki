---
id: idor
title: 不安全的直接对象引用（IDOR: Insecure Direct Object Reference）
category: 访问控制与认证类
severity: high
owasp: A01:2021-Broken Access Control
cwe: CWE-639
tags: [idor, access-control, api, owasp-top10]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 不安全的直接对象引用（IDOR）

## 一句话
> 接口用 id/uuid/订单号这类「对象引用」定位资源，却只校验了「登录没登录」，没校验「这个对象是不是你的」——把 id 换成别人的，别人的数据就到手了。这是水平越权的最典型形态。

## 它是怎么发生的
**根因**：把「认证（authentication，你是谁）」与「授权（authorization，你能动谁的东西）」混为一谈。代码里有会话校验（`if not user: 401`），但没有对象属主校验（`WHERE id = ? AND owner = user.id`）。

典型危险写法：

```python
@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    order = db.get(Order, order_id)      # 直接按 id 取
    return jsonify(order)                 # 没检查 order.user_id == current_user.id
```

把 URL 里的 `1001` 改成 `1002`，就拿到了别人的订单。

**为什么它常年是 Top 10 第一类的常客**：不是技术难度问题，而是「每个接口、每个对象」都要写一遍属主校验，漏一处就是洞——它是覆盖率问题，不是单点修复问题。

## 攻击场景

### 场景一：换 id 读他人数据（基础形态）
**目标**：API 返回对象详情。**思路**：双账号法——账号 A 遍历 id，观察是否拿到账号 B 的资源。
**payload**：`GET /api/orders/1002`（A 的会话）
**结果**：返回 B 的订单详情 = IDOR 实锤。

### 场景二：写操作越权（比读更严重）
**目标**：修改/删除接口。**思路**：同一对象引用换 id 后提交修改。
**payload**：`POST /api/orders/1002/cancel`（A 的会话，操作 B 的订单）
**结果**：能改能删——评估上高于纯读。**测试必须覆盖写**，只测读会低估一档。

### 场景三：非 id 引用的对象
**目标**：文件、消息等。**思路**：引用不一定长 id 的样——下载链接里的文件名、邮件的 message-id、PDF 的页码参数。
**payload**：`GET /download?file=invoice_2023_1002.pdf`
**结果**：URL 结构可猜测的对象引用都是同一类问题。

### 场景四：UUID 就安全了吗
**说明**：UUID 不可枚举但**可以泄露**——Referer 头、分享链接、日志、其他接口的列表响应、相邻资源路径。拿到一个 UUID 后换到无权接口仍能命中。「不可猜」是混淆纵深（提高门槛），不是「属主校验」这一本治；把 UUID 当修复是 IDOR 最流行的错误认知（见误区）。

## 怎么发现它
- **手工测试（双账号法，标准方法论）**：注册 A、B 两个账号；用 A 的会话，对每个「对象级接口」把 A 的资源 id 换成 B 的（或递增/递减邻近 id），对比响应；读、改、删、子资源（列表内嵌 id）逐类过。**双账号法是 IDOR 测试的黄金标准，因为它天然规避了「数据存在与否」的干扰**——响应内容与 B 的真实数据一致，证据确凿。
- **工具**：Burp 的 Authorize / Authz 插件自动做「同一请求 × 两个会话」的交叉比对。
- **真假判断**：404/403 响应要区分「对象不存在」与「被拒绝」（响应体、时间差）；列表接口返回的 id 与详情接口不一致时要分别测；GraphQL 的 `node(id:)` 与 REST 的 path id 是两个独立测试面。

## 常见绕过与进阶
- **前端传 id 换成传 index**：列表接口 `?index=3` 定位他人条目——参数换形态，本质同源。
- **批量接口**：详情接口校验了，`?ids=1,2,3` 批量接口漏了——**每个端点独立测试**。
- **子对象路径**：`/api/user/A/folder/7` 校验了 A，但 folder 7 属于 B——嵌套资源每层都要验属主。
- **HTTP 方法差**：GET 校验了，PATCH/DELETE 忘了——方法 × 对象是完整测试矩阵。
- 思路主线：**把「认证层」与「授权层」在脑中拆开，对每个端点问一句「这里的对象属于谁，谁说了算」**。

## 怎么修
1. **统一对象级鉴权层（治本）**：数据访问层强制带属主条件（`owner = current_user`），或中间件在路由层统一校验——不依赖每个开发者「记得写」。
2. **deny by default**：默认拒绝，显式放行公开资源。
3. **不可枚举 id 只作纵深**：UUID 降低批量枚举效率，配合上两条使用；不依赖它做唯一防线。
4. **完整测试矩阵进 CI**：角色 × 端点 × 方法的授权回归测试，把「漏一处」变成机器能抓的问题。
5. **审计日志**：对象级操作记录操作者与对象属主，事后可发现异常访问模式。

## 常见误区
- **「接口返回 403 了，没漏洞」**：要看所有方法与参数形态——GET 403 不代表 PATCH 也 403；id 在 body 里走另一条校验路径的也不少见。
- **「用了 UUID 不会被打」**：UUID 只防批量枚举，防不了单点泄露；泄露途径（Referer/日志/分享）是常态。
- **「前端不展示入口就测不到」**：前端隐藏 ≠ 服务端鉴权，直接构造请求即可触达——这正是 access-control 的通用铁律。
- **「IDOR 只影响『查看』」**：改、删、执行（如代他人下单、越权审批）的代价通常远高于读取。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（API 形态）
- 相关：[访问控制总类](access-control.md)（IDOR 是其中水平越权的特例） · [会话管理](session-management.md)（会话身份是鉴权的前提）
- 参考：[OWASP Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing) · [PortSwigger: Access control](https://portswigger.net/web-security/access-control)
