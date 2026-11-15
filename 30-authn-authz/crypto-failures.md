---
id: crypto-failures
title: 加密失败（Cryptographic Failures）
category: 访问控制与认证类
severity: high
owasp: A02:2021-Cryptographic Failures
cwe: CWE-327
tags: [crypto, password, hash, key-management, owasp-top10]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 加密失败（Cryptographic Failures）

## 一句话
> 该保护的数据没保护到位：密码用快哈希裸存、密钥写死在代码里、随机数可预测、敏感字段明文入库——传输层（HTTPS）和访问控制都对，数据本身仍然是裸奔的。

## 它是怎么发生的
**根因**：加密失败不是「某一行代码写错」，而是三个系统性的错位：

| 类别 | 典型问题 | 为什么危险 |
|------|----------|-----------|
| **弱算法/弱用法** | MD5/SHA1 存密码、无盐、DES/ECB 模式、自研加密 | 快哈希可暴力+彩虹表；ECB 有块特征；自研算法必然有结构缺陷 |
| **密钥管理失败** | 密钥硬编码（JS/APP/配置）、密钥入日志/Git、弱密钥 | 拿到密钥 = 整套加密变「透明胶带」 |
| **该加密的没加密** | 敏感字段明文入库、token/验证码用 `Math.random` 生成、日志带敏感数据 | 访问控制一旦漏一次（SQLi/信息泄露），数据直接裸奔 |

**共同根源**：把「加密」当成一个可选项而不是「数据分级后的强制要求」——没做过「哪些数据是敏感的、每一项用什么保护」的映射表。

## 攻击场景

### 场景一：密码弱哈希（拿到库之后的最后一道门）
**目标**：验证密码存储强度（在授权获取的测试数据上）。**思路**：识别哈希形态（长度/格式），快哈希用字典/彩虹表验证。
**payload**：32 位 hex = MD5、40 位 = SHA1；对测试账号的已知密码验证「是否加盐」。
**结果**：能反查出弱口令用户 = 存储可被暴力破解；确认算法后修复方向明确（argon2/bcrypt）。

### 场景二：硬编码密钥（前端/客户端交付物）
**目标**：JS bundle、移动端包、配置文件。**思路**：搜密钥特征（`AKIA`、`api_key`、`secret`、JWK 内容）与加密逻辑。
**结果**：前端加密的密钥人人可得 → 「加密」退化为混淆；接 [JWT 攻击](jwt-attacks.md)（弱 HMAC 密钥爆破后伪造令牌）。

### 场景三：可预测随机数（token/验证码）
**目标**：重置 token、验证码、会话 id。**思路**：`Math.random()`/时间戳种子生成的值可预测——采集样本建立预测模型。
**结果**：预测下一个 token → 接[账号接管](../../web-pentest-playbook/30-business/account-takeover.md)链路。检验口诀：**安全用途必须 CSPRNG**（[会话管理](session-management.md)的生成环节）。

### 场景四：ECB 模式的块特征
**目标**：自研加密接口的密文。**思路**：ECB 加密相同明文块输出相同密文块——构造特定输入（如长重复值）观察密文重复模式。
**结果**：密文出现周期性重复 = ECB 确认，可做块级重排/删除攻击。

## 怎么发现它
- **形态识别**：密文长度/字符集/重复模式判断算法族；哈希彩虹表核对常见弱口令的哈希值（如 MD5("123456")=e10adc... 是公开常识性数据）。
- **客户端审计**：[JS 攻击面](../../web-pentest-playbook/10-recon/js-endpoints.md)同源方法——bundle 里搜密钥特征与加密调用。
- **熵评估**：token/验证码采集多样本看结构（时间戳成分、可预测序列）。
- **真假判断**：识别出「疑似弱哈希」需要已知明文对照（测试账号已知密码）才算确认；密文重复 ≠ 一定 ECB（分组长度巧合需排除）。

## 常见绕过与进阶
- **前端加密**：密钥在前端 = 给攻击者的说明书——重点测「前端加密 + 后端直接信」的接口（重放/篡改密文字段）。
- **降级攻击**：同时支持强弱算法的接口，强制协商到弱算法。
- **存储侧联动**：弱哈希/明文数据的价值在「其它漏洞拖库后」兑现——评估时与 [SQL 注入](../10-injection/sql-injection.md)、[信息泄露](../60-info-config/info-disclosure.md)组成危害链。

## 怎么修
1. **数据分级映射表（治本的组织措施）**：列出每类敏感数据（密码/令牌/PII/密钥）× 要求的保护方式，落地为编码规范。
2. **密码存储**：argon2id / bcrypt / scrypt（自适应慢哈希 + 盐）；禁 MD5/SHA 家族。
3. **密钥管理**：密钥进 KMS/密管服务，不入代码与镜像；定期轮换；泄露即视为失效（同 [信息泄露](../60-info-config/info-disclosure.md) 的轮换铁律）。
4. **随机数**：安全用途一律 CSPRNG（`secrets`/`crypto.getRandomValues`）。
5. **算法现代化**：TLS 1.2+、AES-GCM 等认证加密模式；不自研算法。

## 常见误区
- **「上了 HTTPS 数据就安全了」**：TLS 只保护传输中——静态存储（DB/备份/日志）与使用中（内存/日志打印）是另外两个阶段，各有各的加密要求。
- **「MD5 加盐就够了」**：盐防彩虹表，不防暴力——MD5 每秒可算数十亿次，慢哈希才是密码存储的正解。
- **「加密了就能放前端」**：前端的一切（含密钥）对用户可见；前端加密只是混淆，真正的机密性边界必须服务端。
- **「加密失败是密码学专家的事」**：绝大多数问题（快哈希、硬编码、弱随机）是工程习惯，不是密码学难题。

## 关联
- 相关：[JWT 攻击](jwt-attacks.md)（弱密钥即本类问题） · [会话管理](session-management.md)（生成环节的熵） · [信息泄露](../60-info-config/info-disclosure.md)（密钥泄露面）
- 实战：[web-pentest-playbook：账号接管](../../web-pentest-playbook/30-business/account-takeover.md)（可预测 token 的下游链）
- 参考：[OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) · [OWASP Top 10 A02](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
