---
id: ssti
title: 服务端模板注入（SSTI: Server-Side Template Injection）
category: 注入类
severity: critical
owasp: A03:2021-Injection
cwe: CWE-1336
tags: [injection, ssti, rce, template]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 服务端模板注入（SSTI）

## 一句话
> 用户输入被拼进**模板源代码**再渲染，模板引擎把输入里的 `{{ }}`、`${ }` 当作模板语法求值——从信息泄露到远程代码执行，取决于引擎与沙箱。

## 它是怎么发生的
**根因**：模板引擎的定位是「让静态模板 + 动态数据生成页面」。安全用法是**数据通过变量传入**；危险用法是把用户输入**拼进模板字符串本身**再交给引擎编译——输入中的模板语法会被当表达式执行。

典型危险写法（Python/Jinja2 示意）：

```python
render_template_string("Hello " + request.args["name"])
```

`name` 传入 `{{7*7}}`，页面输出 `Hello 49`——表达式被求值了。而安全写法 `render_template_string("Hello {{name}}", name=...)` 中同样的输入只会原样显示。

**与 XSS 的分界**：[XSS](../20-frontend/xss.md) 是注入的内容在**浏览器**执行；SSTI 是在**服务端模板引擎**里执行。同一个输入点，`<script>` 无效而 `{{7*7}}` 有效，说明你在和模板引擎说话。

**触发条件**：用户输入 → 字符串拼接 → `render_template_string` / `Template(text)` / Freemarker `new Template()` 等「以字符串为模板源」的 API。

## 攻击场景

### 场景一：探测与引擎指纹
**目标**：确认存在 SSTI 并识别引擎。**思路**：不同引擎语法不同，用决策树逐个试探。

| 输入 | Jinja2 | Twig | Freemarker | ERB |
|------|--------|------|------------|-----|
| `{{7*7}}` | 49 | 49 | 原样 | 原样 |
| `${7*7}` | 原样 | 原样 | 49 | 原样 |
| `<%= 7*7 %>` | 原样 | 原样 | 原样 | 49 |

**结果**：哪个语法返回 49，就确定了引擎家族，后续利用路径随之确定。

### 场景二：信息泄露
**目标**：读取配置。**思路**：利用模板暴露的全局对象。
**payload**（Jinja2）：`{{ config.items() }}`
**结果**：页面回显应用配置，常含 SECRET_KEY、数据库地址。

### 场景三：从表达式到 RCE
**目标**：证明可执行系统命令（仅在授权环境）。**思路**：沿对象继承链找标准库（如 Jinja2 中经 `__class__ → __subclasses__` 定位到 subprocess/os 模块），构造调用。
**说明**：具体 payload 链较长且依赖版本，掌握**方法论**即可——SSTI 的利用是「在模板语法允许的对象图里走一条路，走到能执行命令的对象为止」。沙箱引擎（如 Jinja2 Sandbox）会砍断这条路的部分环节，逃逸属于研究前沿，不是「背 payload」能解决的问题。

### 场景四：前端模板的注入面
**目标**：客户端模板引擎（如老版本 AngularJS）。**思路**：与 SSTI 同构但发生在浏览器沙箱里，通常降级为 XSS。
**结果**：危害取决于客户端引擎能否触达服务端（一般不能），仍值得单独报告。

## 怎么发现它
- **手工测试**：所有「内容会回显、且看起来像渲染出来的」输入点（邮件模板、消息通知、个性化问候、PDF/报表生成），先发 `{{7*7}}`，再看 `${7*7}`、`<%= 7*7 %>`；出现 49 即确认。
- **工具**：tplmap 类工具可在授权测试中自动识别与验证（理解其原理比会用更重要）。
- **真假判断**：页面原样显示 `{{7*7}}` 有两种可能——不存在 SSTI，或框架做了 HTML 转义。区分方法：换 `{{7*'7'}}`（字符串乘法，Jinja2 出 `7777777`，转义不影响数字运算）。`49` 也可能来自业务巧合，用两个不同表达式交叉验证。

## 常见绕过与进阶
- **关键字被滤**：模板语法的等价写法很多（`{% raw %}` 冲突、属性访问用 `|attr()`、字符串拼接构造属性名）。
- **沙箱绕过**：属于深度研究，思路是「找沙箱未覆盖的对象/属性访问路径」；测试中遇到沙箱，报告「存在 SSTI 且表达式可控」本身已足够高危。
- **引擎差异**：Freemarker 的 `new` 内置方法、Velocity 的反射可达性——同一思路在不同引擎的对象图里走不同路径。
- 思路主线：**先指纹、再对象图、最后执行面**；不要跳过前两步直接背 payload。

## 怎么修
1. **架构级根治：输入永不进模板源**。模板是代码，数据是数据——用 `render(template, data)` 的参数通道传值，禁止 `render(user_input)`。
2. **确需动态模板（如用户自定义邮件样式）**：用无逻辑模板引擎（如 Mustache 类）或专用占位符替换，而非图灵完备引擎。
3. **沙箱作为缓解而非修复**：开启引擎沙箱、限制可用过滤器与全局对象。
4. **报错收敛**：模板编译错误常回显源码与路径，统一错误响应。
5. **代码审计关键词**：`render_template_string`、`Template(`、`new Template`、`velocity`、`freeMarkerConfigurer`——所有以字符串为源的渲染调用都过一遍。

## 常见误区
- **「页面没回显表达式结果就不是 SSTI」**：盲 SSTI 同样存在（报错/时间/带外确认），和 SQL 盲注一样。
- **「把 `{{ }}` 替换掉就安全了」**：引擎语法不止一种定界符，且过滤符号不改变「输入进模板源」的根因。
- **「SSTI = XSS 的一种」**：执行位置完全不同（服务端 vs 浏览器），危害等级和修复方式都不同，报告必须区分。

## 关联
- 前置：[编码与绕过](../00-basics/encoding-bypass.md)
- 相关：[命令注入](command-injection.md)（SSTI 的常见终点） · [XSS](../20-frontend/xss.md)（同输入点的另一种语境） · [SQL 注入](sql-injection.md)
- 参考：[PortSwigger: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection) · [OWASP SSTI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.10-Testing_for_Server-Side_Template_Injection)
