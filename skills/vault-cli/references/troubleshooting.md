# 排障手册

## 解密类

### `DPAPI 失败（exit 1）：… 使用"3"个参数调用"Unprotect"时发生异常`

**原因**：密文与当前 Windows 用户/机器不匹配。

按顺序排查：

1. 是不是换了 Windows 账号？DPAPI 的 CurrentUser 作用域认账号，不认文件。
2. 是不是换了机器？密文不能跨机。
3. 是不是把 `vault.enc` 从别处拷过来的？

**正确做法**：在原机器 `export`，在新机器 `import`，不要直接拷 `vault.enc`。

### `解密失败：主密码不对，或文件被改动过`

导出/导入时主密码错误，**或**文件在传输中被改过。

GCM 无法区分这两种情况（都会认证失败），所以提示合并了。三种可能：

- 主密码记错（最常见）
- 复制文件时被截断（用 `certutil -hashfile` 或 `sha256sum` 校验）
- 文件被别的程序改写过

**没有恢复手段**。这是设计使然：有后门就等于没有加密。

### `vault.enc 格式不认识（缺少 alg/blob）`

文件被外部程序改写过（比如被人手工编辑，或用旧版本覆盖）。
从备份恢复；没有备份就重新 `set`。

## 使用类

### `缺少参数且当前不是交互终端：请输入 xxx 的密码`

脚本里调用了 `set` 却没给 `--password`，而 stdin 不是 TTY（cron、CI、Node 子进程都属于这种情况）。

```bash
# 脚本里显式传参
node scripts/cli.mjs set site --user me --password "$PASSWORD"

# 或者让脚本从别处取（不落 shell 历史）
PASSWORD=$(其他来源) node scripts/cli.mjs set site --user me --password "$PASSWORD"
```

`get` 不受影响：它是读操作，不需要 TTY。

### `需要主密码：请用 --master-password 或 VAULT_MASTER_PASSWORD`

当前是非 Windows 平台（或强制 `VAULT_BACKEND=passphrase`），而环境里没有主密码。

```bash
VAULT_MASTER_PASSWORD=... node scripts/cli.mjs list
```

生产环境建议由 systemd `EnvironmentFile=` 或任务计划的环境变量注入，不要写在命令里。

### `[vault] 没有 xxx`

名字打错，或该条被删。用 `list` 或 `search` 确认：

```bash
node scripts/cli.mjs search keyword
```

### `[vault] xxx 没有 totp 种子`

该条只存了密码。补种子的两种方式：

```bash
# 整体覆盖（不传 password 时会重新提示输入）
node scripts/cli.mjs set xxx --totp JBSWY3DPEHPK3PXP

# 注意：set 是整体替换，password 会走交互输入
```

### TOTP 验证码一直被拒

按生成的服务端时间对照排查：

1. 系统时间偏差 > 30 秒 → 校准时间（`w32tm /resync` 或 `timedatectl`）
2. 种子复制错了 → 重新复制，注意去掉空格与短横（工具会自动处理）
3. 服务端用的是 8 位或 60 秒周期 → 本工具默认 6 位 / 30 秒，不支持自定义（改 `store.mjs` 的 `totp()` 入参）

## 数据安全类

### `doctor` 报「位于 git 仓库内」

```bash
node scripts/cli.mjs doctor
# 仓库检查:  失败 — 数据目录 /path/to/repo/.vault 位于 git 仓库 /path/to/repo 内
```

说明 `VAULT_DIR` 指到了仓库目录下，密文有被 `git add` 的风险。

**处理**：把 `VAULT_DIR` 换到家目录（默认就是 `~/.vault-cli`），并确认 `.gitignore` 里有 `*.enc`。

### 误提交了 `vault.enc`

1. **先假设已泄漏**：立刻把所有涉及平台的密码改掉
2. 用 `git filter-repo` 或 BFG 从历史里清除
3. 注意：如果那台机器的 DPAPI 密钥还在，别人拿到仓库也只能看到 base64 —— 但仍然按泄漏处理更稳

## 迁移类

### 导入后条目变少了

`import` 默认是**合并**：

- 同名条目会**被导出文件覆盖**（不看时间戳）
- 想整库替换要显式 `--replace`
- 想保留新机器上较新的条目，先 `list --json` 对比两边 `updatedAt`

### 两台机器同时写

没有冲突解决机制，后写覆盖先写。约定：

- 一主多只读：只有一台机器写入，其他机器定期 `import` 覆盖
- 或每次改动前后手动 `export` 留档
