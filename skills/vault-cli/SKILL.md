---
name: vault-cli
description: "本地凭据抽屉：DPAPI 零交互加密存账号密码与 TOTP 种子，提供 set/get/list/gen/totp/export/import 命令，供脚本与自动化调用。当需要保存登录凭据、给自动化脚本取密码、生成强密码、计算两步验证码、或在多台机器间迁移凭据时使用。"
---

# vault-cli

一个**零依赖**的本地凭据管理器，给脚本和自动化用。

它的定位很明确：**机器人的凭据抽屉**，不是给人用的密码管理器界面。
所以它默认零交互（Windows DPAPI），方便 cron / 定时任务直接取密码。

## 什么时候用

- 自动化脚本需要登录凭据（签到、抓取、调 API），不想把密码写进代码或 `.env`
- 需要保存 TOTP 种子，并在脚本里算验证码
- 需要生成强密码
- 需要把整套凭据搬到另一台机器

**不适合**：需要多设备实时同步、图形界面、浏览器插件、共享给团队 —— 那些请用 KeePassXC / 1Password / Bitwarden。

## 快速开始

```bash
# 新增（缺密码时交互输入，不回显）
node scripts/cli.mjs set github --user alice --totp JBSWY3DPEHPK3PXP

# 给脚本取用（JSON 便于 jq / node 解析）
node scripts/cli.mjs get github --json
node scripts/cli.mjs get github --field password

# 盘点：只显示字段有无，不显示值
node scripts/cli.mjs list
```

## 命令

| 命令 | 作用 |
|---|---|
| `set <name> [--user --password --totp --url --note]` | 新增或更新 |
| `get <name> [--json] [--field password]` | 取用（写审计） |
| `list [--json]` | 盘点，只显示字段有无 |
| `rm <name>` | 删除 |
| `gen <name> [--length 24] [--user] [--url]` | 生成强密码并保存，**密码打印到 stdout** |
| `totp <name> [--json]` | 输出当前 6 位验证码与剩余秒数（写审计） |
| `search <keyword>` | 按名字/用户名/URL/备注匹配 |
| `rename <old> <new>` | 改名（目标已存在则拒绝） |
| `export -o <file>` | 用主密码导出可迁移密文 |
| `import <file> [--replace]` | 导入（默认合并；`--replace` 整库替换） |
| `audit [--tail N]` | 查看审计尾部 |
| `doctor` | 自检：后端、路径、是否误落在 git 仓库、能否解密 |

## 数据在哪

```
~/.vault-cli/vault.enc        ← 密文（Windows: DPAPI；其他平台: 主密码）
~/.vault-cli/vault.audit.log  ← 审计（时间/操作/名字/调用方，不含值）
```

可用 `VAULT_DIR` 覆盖目录（测试时很常用）。

**代码在仓库里，数据永远在仓库外**，并且 `doctor` 会检查数据目录有没有误落在 git 工作区里。

## 两种后端

| 后端 | 触发条件 | 日常要输密码吗 |
|---|---|---|
| `dpapi` | Windows 默认 | 否（绑定当前 Windows 用户） |
| `passphrase` | 其他平台默认，或 `VAULT_BACKEND=passphrase` | 是（`--master-password` 或 `VAULT_MASTER_PASSWORD`） |

## 换机器怎么搬

DPAPI 密文**不能跨用户、跨机器解密**。迁移必须走导出：

```bash
# 旧机器
node scripts/cli.mjs export -o vault.export.enc      # 输入一次主密码
# 传到新机器（U 盘 / 私有网盘均可）
node scripts/cli.mjs import vault.export.enc         # 输入同一个主密码
```

导入后会**用新机器的本地后端重新加密**，之后照常零交互。

> 主密码忘了 = 导出文件永远打不开，没有后门。
> 两台机器同时写会互相覆盖：请约定「一主多只读」，或每次迁移前用 `list --json` 对比 `updatedAt`。

## 三条硬约束

1. **明文只在内存**：密文落盘，导出用 scrypt+AES-256-GCM，明文从不写临时文件。
2. **明文不进命令行**：DPAPI 调用走 stdin，`ps` / 任务管理器看不到密码。
3. **写操作立即收紧权限**：Windows 用 `icacls` 去掉继承只授当前用户；其他平台 `chmod 600`。

## 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| `DPAPI 失败 ... The parameter is incorrect` | 换了 Windows 用户或机器 | 用 `export`/`import` 迁移，别直接拷 `vault.enc` |
| `缺少参数且当前不是交互终端` | 非 TTY 下没给 `--password` | 脚本里显式传参，或改用 `--json` 读取 |
| `需要主密码：请用 --master-password` | passphrase 后端 | 设 `VAULT_MASTER_PASSWORD` |
| `解密失败：主密码不对` | 密码错或文件被改 | 确认密码；导出文件没有恢复手段 |
| `doctor` 报「位于 git 仓库内」 | `VAULT_DIR` 指到了仓库里 | 换到家目录，别把密文提交 |

## 进一步阅读

- [设计说明](references/design.md)：威胁模型、为什么 DPAPI、导出文件格式
- [排障手册](references/troubleshooting.md)：错误码与逐条处理

## 自检

```bash
node scripts/test.mjs
```

覆盖 TOTP 的 RFC 6238 官方向量、Base32 解码、密码生成形态、加密往返、错密码失败、篡改检测。
