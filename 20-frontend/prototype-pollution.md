---
id: prototype-pollution
title: 原型污染（Prototype Pollution）
category: 前端与跨站类
severity: high
owasp: A03:2021-Injection
cwe: CWE-1321
tags: [prototype-pollution, javascript, frontend, node]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 原型污染（Prototype Pollution）

## 一句话
> JavaScript 里所有对象共享同一个原型（`Object.prototype`），攻击者通过 `__proto__` 键把任意属性写进这个「公共祖先」，从而影响整个应用的对象行为——JS 世界里的「全局变量注入」。

## 它是怎么发生的
**根因**：JS 的属性查找沿原型链向上走：`obj.a` 找不到时会查 `Object.prototype.a`。而常见的「合并对象 / 解析查询串」代码用递归循环把用户输入的键值对赋进目标对象，**没有过滤 `__proto__` 这类保留键**：

```js
function merge(target, src) {
  for (const key in src) {
    if (typeof src[key] === "object") merge(target[key] = target[key] || {}, src[key]);
    else target[key] = src[key];        // key 可以是 __proto__
  }
}
merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
```

`target["__proto__"]["isAdmin"] = true` 实际改写的是 `Object.prototype.isAdmin`——此后**全应用**任何未显式赋值的 `obj.isAdmin` 都变成 `true`。

**触发三要素**：
1. **可控键**：输入的键名未过滤（`__proto__`、`constructor.prototype`）；
2. **递归写入口（sink）**：deep-merge、`Object.assign` 链、query 解析器（`?__proto__[x]=y` 的 `[k]=v` 语法天然构造嵌套）、`JSON.parse` 后直接 merge；
3. **可观察的 gadget**：某个业务逻辑读取被污染的属性并做出有意义的行为（权限判断翻转、模板/路径拼接 → XSS/RCE）。

**前端 vs 服务端**：浏览器里污染 `Object.prototype` 影响当前页面 JS；Node 服务端影响整个进程——后者危害更高。

## 攻击场景

### 场景一：确认污染存在
**目标**：证明写入生效。**思路**：造一个「本不存在的全局属性」再检测。
**payload**：`?__proto__[polluted]=yes`（或 JSON body），随后在控制台执行 `({}).polluted`。
**结果**：返回 `"yes"` 而非 `undefined`，污染确凿——这是所有后续利用的前提。

### 场景二：权限判断翻转
**目标**：依赖默认值的鉴权逻辑。**思路**：找代码里 `if (user.isAdmin)`、`options.internal` 这类「未初始化就使用」的属性。
**payload**：`{"__proto__": {"isAdmin": true}}`
**结果**：所有「未显式赋值」的判断对象继承污染值——具体可达性取决于业务代码，测试需审计 gadget。

### 场景三：服务端 gadget → RCE（概念）
**目标**：证明服务端可升级危害。**思路**：污染「被用于拼路径/命令/模板」的公共配置对象（如 Node 常见的 `child_process` spawn 参数 `shell`、模板根目录、`Object.prototype.outputEncoding`）。
**结果**：属 gadget 链研究，依赖具体库版本；测试中通常报告「污染点 + 候选 gadget 列表」即可，把利用链证实留给受控复现。

### 场景四：客户端 gadget → DOM XSS
**目标**：前端库按配置对象渲染 DOM。**思路**：污染影响 `innerHTML` 类 sink 的配置项。
**结果**：污染落地为 [XSS](xss.md)，这是客户端原型污染最常见的实际危害形态。

## 怎么发现它
- **手工测试**：在一切「合并/解析」行为点（deep-merge 接口、`qs` 类 query 解析、GraphQL 输入、文件配置上传）注入 `__proto__[polluted]=yes`；客户端则在控制台查 `({}).polluted`，服务端看后续响应行为差异或报错变化。
- **真假判断**：`(Object.prototype.polluted === undefined)` 且确有递归合并代码 ≠ 无风险（可能键被过滤）；「payload 被吞」要区分「过滤了保留键」与「合并逻辑根本不递归」。确认 gadget 才能定级，否则按「技术性存在」降级报告。

## 常见绕过与进阶
- **过滤 `__proto__` 键**：换 `constructor[prototype][x]` 等价路径。
- **JSON 键为字符串**：`JSON.parse('{"__proto__":...}')` 与字面量 `{__proto__:` 行为不同（后者是 setter 语义）——两种通道要分别测。
- **非递归防护**：只挡一层 `__proto__` 的浅检查，嵌套两层的 `a[__proto__][b]` 仍可达。
- 思路主线：**「键过滤」要覆盖一切通向 `Object.prototype` 的路径，而不是那个字面键名**。

## 怎么修
1. **升级依赖（最高性价比）**：qs、lodash、deep-extend 等历史上出过此漏洞的库的新版本已内置防护——先用工具清点版本。
2. **合并逻辑防御**：递归 merge 时过滤保留键（`__proto__`、`constructor`、`prototype`）；或用 `Object.create(null)` 作为解析目标，或 `Object.freeze(Object.prototype)`（全局冻结是激进方案，需回归测试）。
3. **解析器配置**：query 解析器关闭「方括号构造嵌套对象」的能力（如 qs 的 `plainObjects`/`allowPrototypes` 正确配置）。
4. **schema 校验**：进入业务前的输入用严格 schema（白名单键），保留键天然被拒。

## 常见误区
- **「污染成功 = 高危漏洞」**：定级看 gadget——没有可利用 gadget 的污染是「技术性弱点」，报告里要如实分级。
- **「只存在于前端」**：Node 服务端一旦中招影响整个进程，危害更高；两端都要测。
- **「`JSON.parse` 安全」**：`JSON.parse` 本身不触发 setter，但它的产物若再进递归 merge，照样污染——危险在合并逻辑，不在解析器。
- **「与 XSS 无关」**：客户端原型污染最常见的落地就是 DOM XSS gadget——它是 XSS 的上游根因之一。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)（query 与 JSON body）
- 相关：[XSS](xss.md)（客户端 gadget 的落地形态） · [NoSQL 注入](../10-injection/nosql-injection.md)（同为「键/值结构被注入」）
- 参考：[PortSwigger: Prototype pollution](https://portswigger.net/web-security/prototype-pollution) · [OWASP Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
