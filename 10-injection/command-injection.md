---
id: command-injection
title: 命令注入（Command Injection）
category: 注入类
severity: critical
owasp: A03:2021-Injection
cwe: CWE-78
tags: [injection, rce, shell, owasp-top10]
---

> 本条目仅用于授权安全测试与防御学习。请勿对未授权目标使用文中技术。

# 命令注入（Command Injection）

## 一句话
> 用户输入被拼进一条交给操作系统 Shell 执行的命令，输入里的 Shell 元字符（`;`、`|`、`` ` ``、`$()`）让攻击者追加自己的命令——通常直接等于远程代码执行（RCE）。

## 它是怎么发生的
**根因**：与 [SQL 注入](sql-injection.md)同构，只是解析器从数据库换成了 Shell——数据与命令未分离，而 Shell 的语法里**元字符天然用于拼接多条命令**。

典型危险写法（Python 示意）：

```python
os.popen("ping -c 1 " + request.args["host"])
```

`host` 传入 `127.0.0.1; cat /etc/passwd` 时实际执行：

```bash
ping -c 1 127.0.0.1; cat /etc/passwd
```

两条命令依次执行，第二条是攻击者的。

**触发三要素**：
1. 输入进入「调用外部命令」的 sink（`os.system`/`popen`、`subprocess` 带 `shell=True`、Node `child_process.exec`、PHP `system`/`exec`、Java `Runtime.exec` 复杂形态）；
2. 拼接而非参数化；
3. 结果可观察（回显、时间差或带外信号）。

**注意**：命令注入 ≠ 代码注入。命令注入跑的是**系统命令**；代码注入（eval 类）跑的是**应用语言代码**。前者危害同样常达 RCE。

## 攻击场景

### 场景一：分号追加（有回显）
**目标**：让输出里多出想要的数据。**思路**：用元字符把第二条命令接上去。
**payload**：`127.0.0.1; id`
**结果**：页面在 ping 结果后附带当前用户身份。

### 场景二：管道 / 后台执行
**目标**：把前一条命令的输出转走，或让恶意命令后台跑。**思路**：`|` 接管输出流，`&` 让命令脱离等待。
**payload**：`127.0.0.1 | cat /etc/passwd`、`127.0.0.1 & sleep 10`
**结果**：响应中出现目标文件内容；`&` 适合构造时间差。

### 场景三：盲命令注入（无回显）
**目标**：页面不显示命令输出时确认注入。**思路**：把命令结果转换为时间差或带外信号。
**payload**：`; sleep 5`（响应延迟 5 秒）；`; ping -c 1 xxx.dnslog.cn`（带外回连，需自建 DNS 记录）。
**结果**：延迟/回连即证据。时间法要多次取样排除网络抖动。

### 场景四：换行符与编码变体
**目标**：`;` 被过滤时。**思路**：Shell 认多个元字符等价物——换行符 `%0a`、反引号 `` `cmd` ``、`$( )`。
**payload**：`127.0.0.1%0aid`
**结果**：与新命令逐条执行等价。

## 怎么发现它
- **手工测试**：找一切「参数会触发外部行为」的功能——ping/探测、文件转换、图片处理（ImageMagick）、导出、备份。每个点先用**时间法**（`; sleep 5`）做无痕探测，再看回显。
- **工具**：Burp Collaborator / 自建 dnslog 做带外确认最可靠。
- **真假判断**：`sleep 5` 也可能是业务本身慢——用「成对探测」：`; sleep 5` 与 `; sleep 0` 对比响应时间，重复三次以上再下结论。反引号在某些框架会被先解释，注意区分「应用层解释」与「Shell 层解释」。

## 常见绕过与进阶
- **空格被滤**：`$IFS`、`{cmd,arg}` 花括号展开、`<` 重定向替代。
- **黑名单关键字**：拼接 `c'a't`、变量拼接 `a=c;b=at;$a$b`、Base64 解码执行。
- **长度受限**：分多条命令分批写文件再执行（进阶思路，授权测试中用于验证可利用性）。
- **无 shell 的 Java**：`Runtime.exec` 不走 shell，单字符串会被整体当程序名——这类点要找「重载为双参数数组仍可控」的场景，思路不同但同根。
- 思路主线：**黑名单永远列不全 Shell 的等价语法；白名单 + 不经 Shell 才是出路**。

## 怎么修
1. **根本不调用 Shell（治本）**：`ping` 用语言的网络库、文件操作用文件 API、压缩用库函数——把「需要外部命令」的场景消灭掉。
2. **必须调用时用参数化 API**：Python `subprocess.run([...], shell=False)`（参数数组）、Node `execFile`、PHP `escapeshellarg` 全包参数。数组形式的 API 让每个参数只作为**一个字符串**传给目标程序，元字符失去语法意义。
3. **白名单校验输入**：域名/IP/文件名按严格格式校验，超过字符集直接拒绝。
4. **降权运行**：应用进程用低权限账号，限制出网，让「即使注入也难横向」。
5. **日志与告警**：对子进程创建记录审计日志。

## 常见误区
- **「过滤了分号就安全」**：Shell 等价元字符成打（`|` `&` 换行 反引号 `$()`），黑名单是打地鼠。
- **「用了 escapeshellcmd 就行」**：它转义的是「命令整体」层面的字符，参数仍应逐个 `escapeshellarg`；混用会漏。
- **「参数数组绝对安全」**：数组防止的是「元字符变语法」，但参数本身仍可能被目标程序二次解释（如 `find -exec`、`tar --checkpoint`），深挖 sink 行为仍然必要。

## 关联
- 前置：[编码与绕过](../00-basics/encoding-bypass.md) · [HTTP 基础](../00-basics/http-basics.md)
- 相关：[SQL 注入](sql-injection.md)（同根：数据与代码未分离） · [SSTI](ssti.md) · [SSRF](../40-files-requests/ssrf.md)（带外确认共用出网通道）
- 参考：[OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection) · [PortSwigger: OS command injection](https://portswigger.net/web-security/os-command-injection)
