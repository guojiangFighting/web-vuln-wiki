---
id: nosql-injection
title: NoSQL 注入（NoSQL Injection）
category: 注入类
severity: high
owasp: A03:2021-Injection
cwe: CWE-943
tags: [injection, nosql, mongodb, json]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# NoSQL 注入（NoSQL Injection）

## 一句话
> 用户输入被拼进 NoSQL 查询（常见 MongoDB），输入里塞进 `$ne`、`$gt` 这类查询操作符就能改写查询条件——和 SQL 注入同根：数据被当成了查询语言。

## 它是怎么发生的
**根因**：与 [SQL 注入](sql-injection.md)完全同构——「数据」与「查询语法」没有分离。区别只在查询语言从 SQL 换成了 MongoDB 的 JSON 语法，而 JSON 语法里**值本身可以是对象**，于是操作符可以随值一起进来。

典型危险写法（Node.js 示意）：

```js
db.users.findOne({ user: req.body.user, pass: req.body.pass });
```

当 body 不是字符串而是对象时：

```json
{ "user": "admin", "pass": { "$ne": "x" } }
```

查询变成「pass 不等于 x 的 admin」，恒真，登录被绕过。

**触发三要素**：
1. 用户输入（尤其 JSON body）直接作为查询条件对象的一部分；
2. 服务端没有把值强制收窄为 string/number（「类型校验缺失」是 NoSQL 注入的独门入口）；
3. 响应差异可观察（登录成功与否、返回条数、报错）。

## 攻击场景

### 场景一：操作符绕过登录
**目标**：不知道密码登入。**思路**：把值升级为操作符对象构造恒真条件。
**payload**：`{"pass": {"$ne": "x"}}` 或 `{"pass": {"$regex": "^.*$"}}`。
**结果**：返回第一条匹配记录，通常即管理员。

### 场景二：正则逐字符猜密码
**目标**：在返回信息不区分「用户不存在/密码错」时拿密码。**思路**：`$regex` 锚定前缀，靠响应真假逐字符推进。
**payload**：`{"pass": {"$regex": "^a"}}` → `^ab` → `^abc` …
**结果**：与布尔盲注同节奏，把密码「问」出来。

### 场景三：聚合管道注入
**目标**：拼接进 `$where` / 聚合表达式。**思路**：`$where` 接受 JS 字符串，注入即接近服务端 JS 执行。
**payload**：概念上等同把表达式改成恒真并带出数据。
**结果**：影响升级为信息泄露乃至 RCE（取决于引擎与配置）。

### 场景四：URL 参数的字符串形式
**目标**：非 JSON 的 query 参数。**思路**：框架的扩展语法 `?pass[$ne]=x` 同样能构造成对象（Express/Qs 类解析器）。
**结果**：与场景一等价，但更常被开发者忽略。

## 怎么发现它
- **手工测试**：所有「登录/搜索/筛选」接口，在 JSON 值位置尝试把字符串升级为对象 `{"$ne": ""}`；URL 参数用 `[$ne]` 语法。观察：响应是否从「密码错误」变为「成功」、返回条数是否变化。
- **工具**：Burp Intruder 对操作符字典（`$ne`/`$gt`/`$regex`/`$where`）批量试探。
- **真假判断**：`$ne` 命中后要交叉验证——换 `$gt: ""` 与 `$regex: "^."` 得到相同结果，才是「操作符生效」的强证据；仅 500 报错可能是类型异常而非注入。

## 常见绕过与进阶
- **类型收窄只做一层**：校验了 body 顶层却漏了嵌套对象里的键（`{"a": {"b": {"$ne": 1}}}`）。
- **换注入位置**：Cookie、Header 同样能进查询条件，开发者常只盯 body。
- **`$where` 与 `$function`**：一旦能进这两个 sink，性质从「改查询」升级为「服务端 JS 执行」。
- 思路主线：**JSON 的值可以是对象——任何「把 body 当查询条件用」的代码都要重新审一遍**。

## 怎么修
1. **输入类型强制收窄（治本第一层）**：`typeof req.body.pass === 'string'`，或用 schema 校验（Joi/Zod/JSON Schema）把每个字段钉死为标量；对象一律拒绝。
2. **不把原始 body 直接喂查询**：显式挑选字段、显式构造查询条件对象。
3. **ODM/参数化**：Mongoose 的 Schema 类型约束会自动把非预期类型降级/拒绝；禁用 `$where`。
4. **最小权限**：数据库账号限定库与集合，禁服务端执行类配置。
5. **报错收敛**：MongoDB 报错常回显查询结构，统一错误响应。

## 常见误区
- **「NoSQL 没有注入」**：查询语法换成 JSON 不等于语法不存在；操作符注入、`$where` 注入都是成熟攻击面。
- **「上了 Mongoose 就安全」**：默认 Schema 约束有帮助，但 `strictQuery` 配置、`findOne` 收原始对象、聚合管道仍可能绕过。
- **「只校验 Content-Type 是 JSON」**：注入靠的是值的内容不是请求格式；query 参数的 `[$ne]` 语法照样构造对象。

## 关联
- 前置：[SQL 注入](sql-injection.md)（同构问题在关系库中的形态） · [HTTP 基础](../00-basics/http-basics.md)
- 相关：[命令注入](command-injection.md) · [SSRF](../40-files-requests/ssrf.md)（`$where` 升级后常与出网确认结合）
- 参考：[OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6.4-Testing_for_NoSQL_Injection) · [PortSwigger: NoSQL injection](https://portswigger.net/web-security/nosql-injection)
