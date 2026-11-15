# 设计说明

## 威胁模型

**防的是**：密文文件或备份被单独拷走后被读出内容（比如误传到网盘、误提交到 Git、电脑丢失但未解锁）。

**不防**：以当前 Windows 用户身份运行的恶意进程。它可以直接调用 DPAPI 解密。

这个取舍是刻意的：目标场景是「cron / 自动化脚本零交互取密码」，任何要求每次输主密码的设计都会让自动化失效。
如果你的威胁模型包含「本机已被入侵」，请不要用本工具，改用硬件密钥或 KeePassXC + 手动解锁。

## 为什么默认 DPAPI

- 无需管理主密码，定时任务可直接解密
- 密文与「当前用户 + 当前机器」绑定，拷走文件本身没有意义
- 系统级实现，不用自己发明密钥管理

代价：**不可跨机、不可跨用户**。这由 `export`/`import` 补偿。

## 两种后端

| 后端 | 密钥来源 | 文件结构 |
|---|---|---|
| `dpapi` | Windows DPAPI(CurrentUser) 保护的随机密钥 | `{ version, backend: "dpapi", blob: <base64> }` |
| `passphrase` | `scrypt(主密码, salt)` | `{ version, backend: "passphrase", blob: <base64 的导出信封> }` |

选择逻辑：`VAULT_BACKEND` 显式指定 > Windows 用 dpapi > 其他平台用 passphrase。

## 导出文件格式

```json
{
  "format": "vault-cli-export",
  "version": 1,
  "kdf": { "name": "scrypt", "salt": "<base64>", "N": 32768, "r": 8, "p": 1 },
  "cipher": "aes-256-gcm",
  "iv": "<base64 12字节>",
  "tag": "<base64 16字节>",
  "data": "<base64 密文>"
}
```

参数选择：

- **scrypt N=32768, r=8, p=1** → 约 33.5 MB 内存，需要显式设置 `maxmem`（Node 默认上限 32 MB，这里踩过坑）
- **AES-256-GCM** → 同时提供机密性与完整性，篡改会在 `final()` 抛错
- 每次导出生成**新的 salt 与 IV**，同一主密码导两次密文也不同

## 为什么明文走 stdin

DPAPI 由 PowerShell 调用。如果把 base64 明文作为命令行参数传：

```
powershell -Command "...Protect([Convert]::FromBase64String('c2VjcmV0'))..."
```

那么 `ps`、任务管理器、Windows 事件日志都可能留下明文痕迹。
所以脚本是**常量字符串**（无拼接、无注入面），明文通过 `stdin` 传入。

## 审计设计

`vault.audit.log` 每行一个 JSON：

```json
{"ts":"2026-11-15T09:15:18.920Z","op":"get","name":"github","caller":"cli"}
```

- `op`：`set/get/list/rm/gen/totp/export/import/rename`
- `caller`：`VAULT_CALLER` 环境变量或 `cli`，便于区分是哪个脚本读的
- **绝不记录凭据值**

## 权限收紧

| 平台 | 做法 |
|---|---|
| Windows | `icacls <file> /inheritance:r /grant:r "<USER>:F"`，去掉继承、只授当前用户 |
| 其他 | `chmod 600` |

失败不阻断主流程（某些文件系统不支持 ACL），只静默跳过。

## 已知限制

1. 单文件全量读写：几千条以内没问题，不适合十万级
2. 无并发控制：两个进程同时写会后写覆盖
3. 无版本历史：删了就是删了
4. 审计只追加不轮转，长期使用需自行清理
