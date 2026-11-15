---
id: graphql-security
title: GraphQL 安全（GraphQL Security）
category: 访问控制与认证类
severity: high
owasp: A01:2021-Broken Access Control
cwe: CWE-285
tags: [graphql, api, access-control, introspection]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# GraphQL 安全（GraphQL Security）

## 一句话
> GraphQL 把所有接口折叠进一个端点、由客户端自由拼装查询——传统「按 URL 做鉴权/限流/缓存」的整套体系全部失效，**每个字段（resolver）都必须独立做对象级校验**，漏一个就是越权。

## 它是怎么发生的
**根因**：REST 的安全模型建立在「一个 URL = 一个功能」上，网关/中间件按路径配规则。GraphQL 的「一个 URL = 所有功能」打破了这个前提：

1. **鉴权粒度错位**：网关只验「能不能访问 /graphql」（通常只验登录），字段级的对象归属校验落在每个 resolver——开发者漏写一个，越权即成；
2. **自描述性反噬**：introspection 让端点主动交出全部 schema——类型、字段、关系一次枚举完毕，攻击面测绘自动化；
3. **无限拼装**：客户端可在一个请求里组合任意查询——限流按「请求数」计数时，一个请求能塞进成百上千次逻辑查询。

## 攻击场景

### 场景一：introspection 全图枚举
**目标**：摸清全部字段与关系。**思路**：查询 `__schema`，拿到完整类型图（配合工具可视化）。
**payload**：`{ __schema { types { name fields { name } } } }`
**结果**：未禁 introspection 的生产端点直接交出「接口清单」——后续越权测试的靶图（[信息泄露](../60-info-config/info-disclosure.md)的组合价值）。

### 场景二：字段级越权（resolver 漏鉴权）
**目标**：对象归属数据（他人订单/邮箱）。**思路**：REST 详情接口鉴权修好了，但同一数据的 GraphQL 字段是**另一条代码路径**。
**payload**：`{ user(id: "1002") { email orders { id total } } }`（用 A 会话查 B 的 id）
**结果**：返回 B 的数据 = 对象级鉴权缺失（[IDOR](idor.md) 在 GraphQL 的形态）。

### 场景三：batching / 别名轰炸绕限流
**目标**：有验证码/限流的接口（登录、OTP）。**思路**：用别名（alias）在单个请求里重复同一 mutation 多次——请求数 = 1，逻辑执行 = N。
**payload**：`mutation { a: login(...) b: login(...) c: login(...) ... }`
**结果**：[限流](../../web-pentest-playbook/20-bypass/ratelimit-bypass.md)按请求计数时被整建制绕过。

### 场景四：错误提示猜字段（suggestions）
**目标**：introspection 被禁时继续枚举。**思路**：查询不存在的字段，GraphQL 的报错常带「你是不是想查 xxx」建议——按字典枚举字段名。
**结果**：schema 仍可被逐步还原。

### 场景五：复杂度攻击（DoS）
**目标**：深层嵌套/循环关系（user→friends→friends→…）。**思路**：一次请求让服务端做指数级解析。
**结果**：资源耗尽——按业务影响评估是否可报 DoS 风险。

## 怎么发现它
- **端点发现**：`/graphql`、`/api/graphql`、`/graphiql`（调试界面）、`/v1/graphql`；GET `?query={__typename}` 探测；前端 JS 里搜 `graphql`/query 模板。
- **手工测试**：introspection 开 → 全图导出后按 [REST 越权矩阵](access-control.md)逐字段测（重点：对象 id 参数、跨关系访问）；introspection 关 → suggestions 枚举。
- **真假判断**：返回他人数据要[双账号交叉](idor.md)确认；别名轰炸要确认「逻辑真的执行了 N 次」（业务侧终态证据），仅 200 响应不算。

## 常见绕过与进阶
- **introspection 禁用绕过**：部分实现只禁了顶层 `__schema`，字段级 `__type(name:)` 仍可达；或用换行/大小写变体绕简单过滤。
- **GET 通道**：部分端点接受 GET query——mutation 走 GET 时 CSRF 面重新打开（[CSRF](../20-frontend/csrf.md) 的 GraphQL 形态）。
- **子图/网关分叉**：多服务的 federated 架构中，各子图的鉴权策略不一致——同一字段在 A 子图受保护、B 子图裸奔。

## 怎么修
1. **字段级授权（治本）**：鉴权写在 resolver 层（每字段/每对象），不允许「端点级一遍过」；用统一的授权 directive 强制兜底。
2. **生产禁 introspection**、禁 GraphiQL；错误信息去 suggestion。
3. **限复杂度**：查询深度限制、复杂度评分、分页强制（max first/limit）。
4. **禁 batching 或限批**：防别名轰炸；按「逻辑操作数」限流而非请求数。
5. **GET 只读且禁 mutation**、缓存按完整 query 哈希（防[缓存键歧义](../50-logic-concurrency/cache-attacks.md)）。

## 常见误区
- **「网关验了 JWT 就安全」**：验签只回答「登录了吗」，回答不了「这个字段是这个人能看的吗」——GraphQL 的全部安全问题是**粒度**问题。
- **「加了 depth limit 就没有 DoS」**：深度只是复杂度的一个维度，别名计数与分页参数同样能放大。
- **「GraphQL 是新栈所以没有老洞」**：它只是换了洞的位置——IDOR、CSRF、信息泄露全部原样存在，只是移到了 resolver 层。

## 关联
- 相关：[IDOR](idor.md) · [访问控制总类](access-control.md) · [信息泄露](../60-info-config/info-disclosure.md)（introspection 的归类）
- 实战：[web-pentest-playbook：越权实战变体](../../web-pentest-playbook/30-business/idor-chains.md) · [限流与验证码对抗](../../web-pentest-playbook/20-bypass/ratelimit-bypass.md)
- 参考：[OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) · [PortSwigger: GraphQL](https://portswigger.net/web-security/graphql)
