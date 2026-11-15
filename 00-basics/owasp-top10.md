---
id: owasp-top10
title: OWASP Top 10 总览（OWASP Top 10:2021）
category: 基础
severity: -
owasp: -
cwe: -
tags: [owasp, basics, checklist]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# OWASP Top 10 总览（OWASP Top 10:2021）

## 一句话
> OWASP Top 10 不是「十大漏洞」，而是行业从海量真实事件里统计出的「十大风险类别」——用它建立测试 checklist 的心智地图，用本 wiki 的具体条目落地每个类别。

## 2021 十条速览

| 编号 | 名称 | 一句话含义 | 典型 CWE | 本 wiki 主对应 |
|------|------|-----------|----------|----------------|
| A01 | Broken Access Control（失效的访问控制） | 没有在服务端逐对象校验「这个身份能不能动这个资源」 | CWE-200/285 | [越权总类](../30-authn-authz/access-control.md) |
| A02 | Cryptographic Failures（加密失败） | 该加密/哈希的没做或做错 | CWE-259/327 | [加密失败](../30-authn-authz/crypto-failures.md)、部分涉及 [JWT 攻击](../30-authn-authz/jwt-attacks.md) |
| A03 | Injection（注入） | 数据被当成代码解析 | CWE-79/89 | [SQL 注入](../10-injection/sql-injection.md)、[XSS](../20-frontend/xss.md) 等全部注入类 |
| A04 | Insecure Design（不安全设计） | 代码写得再对，设计本身就缺防御 | CWE-209/256 | [业务逻辑](../50-logic-concurrency/business-logic.md)、[竞态条件](../50-logic-concurrency/race-condition.md) |
| A05 | Security Misconfiguration（安全配置错误） | 默认配置、多余功能、暴露的调试面 | CWE-16/611 | [配置错误](../60-info-config/misconfiguration.md) |
| A06 | Vulnerable & Outdated Components（易受攻击的过时组件） | 依赖与中间件带着已知漏洞上场 | CWE-1104 | 归入[配置错误](../60-info-config/misconfiguration.md) |
| A07 | Identification & Authentication Failures（身份识别与认证失败） | 认证与会话管理的设计缺陷 | CWE-798/384 | [会话管理](../30-authn-authz/session-management.md) |
| A08 | Software & Data Integrity Failures（软件与数据完整性失败） | 不验证更新、反序列化、CI/CD 的信任链 | CWE-502 | [不安全的反序列化](../10-injection/insecure-deserialization.md) |
| A09 | Security Logging & Monitoring Failures（日志与监控失败） | 出了事没人知道 | CWE-778 | 与[信息泄露](../60-info-config/info-disclosure.md)互为反面 |
| A10 | Server-Side Request Forgery（SSRF） | 服务端替攻击者发请求 | CWE-918 | [SSRF](../40-files-requests/ssrf.md) |

## 本 wiki 全部条目 × Top 10 映射表

测试某个目标时，可以按下表把全部 32 个条目组织成 checklist（链接均为 wiki 内相对路径）。

### A01 失效的访问控制
| 条目 | 一句话检查点 |
|------|--------------|
| [CSRF](../20-frontend/csrf.md) | 写操作有没有 Token / SameSite 保护 |
| [开放重定向](../20-frontend/open-redirect.md) | 跳转参数是否可指向外域 |
| [GraphQL 安全](../30-authn-authz/graphql-security.md) | resolver 是否逐字段做对象级授权 |
| [IDOR](../30-authn-authz/idor.md) | 换对象 id 能否读改他人资源 |
| [越权总类](../30-authn-authz/access-control.md) | 普通角色能否触达管理端点 |
| [路径穿越](../40-files-requests/path-traversal.md) | 文件参数能否跳出基准目录 |
| [文件上传](../40-files-requests/file-upload.md) | 上传文件能否被当脚本执行 |

### A03 注入
| 条目 | 一句话检查点 |
|------|--------------|
| [SQL 注入](../10-injection/sql-injection.md) | 拼接查询点 `'` 与运算探测 |
| [NoSQL 注入](../10-injection/nosql-injection.md) | JSON 值里能否塞 `$ne` 等操作符 |
| [命令注入](../10-injection/command-injection.md) | 参数是否直达 shell 命令 |
| [SSTI](../10-injection/ssti.md) | `{{7*7}}` 是否被求值成 49 |
| [XXE](../10-injection/xxe.md) | XML 解析是否允许外部实体 |
| [LDAP 注入](../10-injection/ldap-injection.md) | 过滤器参数是否可拼接 |
| [XSS](../20-frontend/xss.md) | 输入是否在未编码情况下回显 |
| [原型污染](../20-frontend/prototype-pollution.md) | `__proto__` 键是否被合并进对象 |
| [CRLF 注入](../10-injection/crlf-injection.md) | 拼进响应头/日志的输入是否过滤换行 |

### A02 加密失败
| 条目 | 一句话检查点 |
|------|--------------|
| [加密失败](../30-authn-authz/crypto-failures.md) | 密码存储算法、密钥管理、随机数来源逐项核对 |

### A04 不安全设计
| 条目 | 一句话检查点 |
|------|--------------|
| [业务逻辑](../50-logic-concurrency/business-logic.md) | 流程能否跳步、重放、传负数 |
| [竞态条件](../50-logic-concurrency/race-condition.md) | 同一请求并发多发是否多次生效 |

### A05 安全配置错误
| 条目 | 一句话检查点 |
|------|--------------|
| [CORS 配置错误](../20-frontend/cors.md) | Origin 是否被反射且允许凭据 |
| [点击劫持](../20-frontend/clickjacking.md) | 响应是否缺 frame-ancestors/XFO |
| [请求走私](../40-files-requests/request-smuggling.md) | CL 与 TE 是否同时出现且链路不一致 |
| [缓存攻击](../50-logic-concurrency/cache-attacks.md) | 缓存键是否漏掉影响响应的输入 |
| [信息泄露](../60-info-config/info-disclosure.md) | 报错/备份/.git 是否可直接获取 |
| [配置错误](../60-info-config/misconfiguration.md) | 默认凭据、调试端点、过时组件 |

### A07 认证与会话失败
| 条目 | 一句话检查点 |
|------|--------------|
| [JWT 攻击](../30-authn-authz/jwt-attacks.md) | alg 是否可控、签名是否必校验 |
| [会话管理](../30-authn-authz/session-management.md) | 登出后旧会话是否失效 |

### A08 软件与数据完整性失败
| 条目 | 一句话检查点 |
|------|--------------|
| [不安全的反序列化](../10-injection/insecure-deserialization.md) | 序列化特征串是否出现在不可信边界 |

### A10 SSRF
| 条目 | 一句话检查点 |
|------|--------------|
| [SSRF](../40-files-requests/ssrf.md) | URL 参数是否让服务端发起请求 |

### 基础条目（不直接对应 Top 10）
| 条目 | 用途 |
|------|------|
| [HTTP 基础](http-basics.md) | 读懂一切测试手法的地基 |
| [编码与绕过](encoding-bypass.md) | 理解所有「绕过」背后的唯一原理 |
| 本条目 | 测试 checklist 的组织框架 |

## 如何把 Top 10 用作测试 checklist
1. **按类别分配时间**：统计上 A01 与 A03 占真实事件大头，优先覆盖。
2. **每个类别落到具体条目**：类别是抽象的，检查点是具体的（看上表右列）。
3. **记录证据而非感觉**：每项检查留「请求/响应 + 判断依据」，可复现才成立。
4. **区分「未发现」与「不存在」**：黑盒没测出 ≠ 没有；报告里写清覆盖范围。

## 安全要点
1. **授权是前提**：Top 10 方法论建立在「对目标有书面授权」之上——先确认范围与规则，再谈测试。
2. **证据优于结论**：每项检查留存请求/响应与判断依据，可复现的才写进报告。
3. **区分「未发现」与「不存在」**：黑盒覆盖有限，报告写清测试范围与盲区。
4. **不留脏数据**：逻辑与并发类验证用测试账号，验证到可复现一次即止。

## 常见误区
- **「Top 10 是漏洞排行榜」**：它是风险类别的统计视角，一个 XSS 事件可以同时归入 A03 与 A05。
- **「按 Top 10 测完就安全」**：Top 10 覆盖不了业务逻辑与访问控制的全部形态，A04 的核心恰恰是「设计层面因站而异」。
- **「A04 不安全设计没法测」**：可以测——把业务状态机画出来，枚举异常转换（见[业务逻辑](../50-logic-concurrency/business-logic.md)）。

## 关联
- 前置：[HTTP 基础](http-basics.md)
- 参考：[OWASP Top 10:2021 官方页面](https://owasp.org/Top10/) · [OWASP WSTG 测试指南](https://owasp.org/www-project-web-security-testing-guide/)
