---
id: insecure-deserialization
title: 不安全的反序列化（Insecure Deserialization）
category: 注入类
severity: critical
owasp: A08:2021-Software and Data Integrity Failures
cwe: CWE-502
tags: [deserialization, rce, gadget, owasp-top10]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 不安全的反序列化（Insecure Deserialization）

## 一句话
> 应用把不可信数据「还原」成语言对象时，构造的序列化字节流会在还原过程中自动执行对象的方法——攻击者借此从篡改属性（逻辑绕过）一路走到远程代码执行（gadget 链）。

## 它是怎么发生的
**根因**：序列化保存的不只是数据，还有**对象的类型与结构**。反序列化库为了「忠实还原」，会在还原时自动调用魔术方法（PHP `__wakeup`/`__destruct`、Java `readObject`、Python `__reduce__`/`__setstate__`）——这些方法里若触发了其它对象的方法调用，攻击者只要控制字节流，就控制了「还原什么对象、调用什么方法」。

典型危险模式（概念）：

```text
用户输入（Cookie / 参数 / 消息队列 / 缓存）→ base64 解码 → 反序列化 API（unserialize/readObject/pickle.loads）
```

**与其它注入的分界**：SQL 注入把数据拼进查询语言；反序列化把数据直接「变成对象」——它绕过了「数据永远只是数据」的全部常规防线，因此危害上限通常更高（直达 RCE）。

**语言形态对照**：

| 语言 | 特征指纹 | 魔术入口 |
|------|----------|----------|
| Java | `rO0AB`（base64）/ `AC ED 00 05`（hex） | `readObject` |
| PHP | `O:8:"` / `a:2:{` | `__wakeup` `__destruct` `__toString` |
| Python | `\x80\x04` / `gASV`（base64） | `__reduce__` |
| .NET | `AAEAAAD/////` | `OnDeserialized` |

## 攻击场景

### 场景一：属性篡改（逻辑绕过，入门形态）
**目标**：序列化数据里的鉴权属性。**思路**：不改结构只改值——序列化串是「明文结构化」的（PHP/Python 尤甚），直接改 `is_admin` 类字段后重放。
**payload**：把 cookie 里的 `O:4:"User":2:{s:5:"admin";b:0;...}` 中 `b:0` 改 `b:1`，并修正长度标记。
**结果**：以管理员身份通过校验——前提是反序列化数据未签名或签名可绕。

### 场景二：gadget 链（RCE，进阶形态）
**目标**：证明可达代码执行。**思路**：gadget = 「应用或其依赖里『反序列化时会触发危险操作』的方法序列」。攻击者不创建新代码，而是**把已有类的方法串成链**（如常见的命令执行 gadget 起点）。
**说明**：具体 gadget 链依赖目标 classpath 与组件版本（ysoserial 类工具即为此设计，授权环境使用），本条目止步于方法论——**测试中确认「反序列化入口可控」本身已足以定高危**，链的利用留给受控复现。

### 场景三：无输出确认（盲形态）
**目标**：不回显时确认入口生效。**思路**：与[盲注入](../../web-pentest-playbook/20-bypass/sqli-limited.md)同思路——时间差（gadget 内 sleep 类调用）或带外回连（DNS 查询特征）。
**结果**：延迟/回连即证明反序列化被触发。

## 怎么发现它
- **特征扫描**：Cookie/参数/请求体里的 base64 解码后查语言指纹（上表）；`Content-Type` 与消息头里的序列化标记（Java `application/x-java-serialized-object`）。带外形态的确认参考 [SSRF](../40-files-requests/ssrf.md) 的回连手法。
- **入口枚举**：一切「对象状态跨请求传递」的位置——session 存储、记住我 cookie、视图状态（.NET ViewState）、消息队列、缓存值、导入文件。
- **真假判断**：指纹存在 ≠ 可利用——改属性后要**观察行为差异**（权限变化/响应变化）才算命中；.NET ViewState 需确认 MAC 校验密钥状态（密钥泄露或未校验才成立）。

## 常见绕过与进阶
- **有签名**：HMAC 保护下直接篡改失败——找密钥泄露（[信息泄露](../60-info-config/info-disclosure.md)）、密钥弱可爆破、或**重放旧版本签名数据**（签名不绑定版本时的降级攻击）。
- **白名单过滤**：部分库支持类白名单——枚举白名单内是否恰好有 gadget 起点。
- **入口转移**：不接受「数据」形态时，找接受「结构」的（如某些缓存/队列配置文件）。

## 怎么修
1. **不反序列化不可信数据（唯一治本）**：跨边界传状态用 JSON 等纯数据格式——JSON 只还原「数据」，不执行「行为」。
2. **历史接口必须保留时**：类白名单（反序列化前校验类型）+ 完整性校验（HMAC，密钥轮换）+ 最小暴露面。
3. **组件治理**：知名 gadget 链多经第三方库——依赖清单（SBOM）+ CVE 订阅（同[配置错误](../60-info-config/misconfiguration.md)的组件治理）。
4. **架构面**：序列化对象不出进程边界；必须跨边界时显式拆解为数据传输对象。

## 常见误区
- **「加了签名/加密就安全」**：签名只保证「没被改」，不阻止「还原行为」——且签名数据可整体重放；治本仍是「不还原不可信数据」。
- **「只有 Java 才有这个问题」**：PHP（`unserialize`）、Python（`pickle`——文档明确警告不可用于不可信数据）、.NET（ViewState）全是成熟攻击面。
- **「看不到序列化数据就没有」**：内部通信（消息队列、缓存、RPC）同样承载序列化对象——拿到内网立足点后（如经 [SSRF](../40-files-requests/ssrf.md)）这些是纵深目标。

## 关联
- 前置：[编码与绕过](../00-basics/encoding-bypass.md)（base64 形态识别）
- 相关：[命令注入](command-injection.md)（gadget 的常见终点） · [JWT 攻击](../30-authn-authz/jwt-attacks.md)（同属「完整性 ≠ 可信」） · [SSRF](../40-files-requests/ssrf.md)
- 参考：[OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [PortSwigger: Insecure deserialization](https://portswigger.net/web-security/deserialization)
