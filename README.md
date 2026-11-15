# Vault Cli

[![skills.sh](https://skills.sh/b/tutula/vault-cli)](https://skills.sh/tutula/vault-cli)

本地凭据抽屉：DPAPI 零交互加密存账号密码与 TOTP 种子，提供 set/get/list/gen/totp/export/import 命令，供脚本与自动化调用。当需要保存登录凭据、给自动化脚本取密码、生成强密码、计算两步验证码、或在多台机器间迁移凭据时使用。

## 安装

```bash
npx skills add tutula/vault-cli --skill vault-cli
```

或全局安装：

```bash
npx skills add tutula/vault-cli --skill vault-cli -g
```

## 它做什么

本地凭据抽屉：DPAPI 零交互加密存账号密码与 TOTP 种子，提供 set/get/list/gen/totp/export/import 命令，供脚本与自动化调用。当需要保存登录凭据、给自动化脚本取密码、生成强密码、计算两步验证码、或在多台机器间迁移凭据时使用。

## 什么时候用

| 你会说 | 它做什么 |
|---|---|
| （示例说法） | （对应动作） |

## 结构

```
skills/vault-cli/
├── SKILL.md
├── references/
├── scripts/
└── assets/
```

## 安全

- 不包含密钥、个人路径、账号信息
- 脚本只做本地处理 / 只读公开页面
- 安装后仍应审阅 `SKILL.md` 与 `scripts/`

## License

MIT
