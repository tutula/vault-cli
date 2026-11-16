// @ts-check
/**
 * vault-cli 的加密与存储层。
 *
 * 设计要点：
 * - **零依赖**：DPAPI 通过 PowerShell 调用，scrypt/AES-GCM 用 Node 内置 `crypto`；
 * - **数据不在代码仓库里**：默认目录 `~/.vault-cli/`，并可用 `VAULT_DIR` 覆盖；
 * - **明文从不落盘**：明文只在本进程内存，DB 与导出文件都是密文；
 * - **两种后端**：Windows 用 DPAPI（零交互）；其他平台用主密码（scrypt + AES-256-GCM）。
 *
 * 威胁模型：防的是「密文/备份被拷走后被读」，不是「本机被入侵」。
 * 所以 DPAPI 后端对以当前用户身份运行的进程没有防御力，这是有意的取舍。
 */

import { spawn } from "node:child_process";
import { createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync } from "node:crypto";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

/** 默认数据目录（刻意放在家目录下，不在任何仓库里） */
export const DATA_DIR = process.env.VAULT_DIR ? resolve(process.env.VAULT_DIR) : join(homedir(), ".vault-cli");
/** 密文文件 */
export const VAULT_FILE = join(DATA_DIR, "vault.enc");
/** 审计日志 */
export const AUDIT_FILE = join(DATA_DIR, "vault.audit.log");

/** 导出文件格式标识 */
const EXPORT_FORMAT = "vault-cli-export";
const EXPORT_VERSION = 1;

/**
 * @typedef {Object} Credential
 * @property {string} [user]     用户名 / 手机号 / 邮箱
 * @property {string} [password] 密码
 * @property {string} [totp]     TOTP 种子（base32，可含空格与短横）
 * @property {string} [url]      关联站点
 * @property {string} [note]     备注
 * @property {string} updatedAt  最后更新时间（ISO）
 */

/** @typedef {Record<string, Credential>} Vault */

/**
 * 建目录（含父目录），已存在不算错。
 * @param {string} dir
 * @returns {Promise<void>}
 */
export async function ensureDir(dir) {
  await mkdir(dir, { recursive: true });
}

/**
 * 当前使用的加密后端：Windows 默认 DPAPI，其它平台默认主密码。
 * 可用 `VAULT_BACKEND=dpapi|passphrase` 强制指定。
 * @returns {"dpapi"|"passphrase"}
 */
export function backend() {
  const forced = (process.env.VAULT_BACKEND ?? "").toLowerCase();
  if (forced === "dpapi" || forced === "passphrase") return forced;
  return process.platform === "win32" ? "dpapi" : "passphrase";
}

/**
 * 用 DPAPI(CurrentUser) 加密。
 * 明文经 **stdin** 传入，不出现在进程命令行里（`ps`/任务管理器看不到）。
 * @param {Buffer} plain
 * @returns {Promise<Buffer>}
 */
export async function dpapiProtect(plain) {
  const out = await runPowerShell(
    [
      "$ErrorActionPreference='Stop'",
      "[Console]::OutputEncoding=[Text.Encoding]::UTF8",
      "Add-Type -AssemblyName System.Security",
      "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())",
      "$p=[Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser')",
      "[Console]::Out.Write([Convert]::ToBase64String($p))",
    ].join("; "),
    plain.toString("base64"),
  );
  return Buffer.from(out.trim(), "base64");
}

/**
 * 用 DPAPI(CurrentUser) 解密。换用户/换机器必然失败。
 * @param {Buffer} cipher
 * @returns {Promise<Buffer>}
 */
export async function dpapiUnprotect(cipher) {
  const out = await runPowerShell(
    [
      "$ErrorActionPreference='Stop'",
      "[Console]::OutputEncoding=[Text.Encoding]::UTF8",
      "Add-Type -AssemblyName System.Security",
      "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())",
      "$p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser')",
      "[Console]::Out.Write([Convert]::ToBase64String($p))",
    ].join("; "),
    cipher.toString("base64"),
  );
  return Buffer.from(out.trim(), "base64");
}

/**
 * 执行固定 PowerShell 脚本（不接受外部拼接，无注入面）。
 * @param {string} script
 * @param {string} payload 写入 stdin 的内容
 * @returns {Promise<string>} stdout
 */
function runPowerShell(script, payload) {
  return new Promise((resolveP, rejectP) => {
    const child = spawn("powershell", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
      windowsHide: true,
    });
    const out = [];
    const err = [];
    child.stdout.on("data", (c) => out.push(String(c)));
    child.stderr.on("data", (c) => err.push(String(c)));
    child.on("error", (err) =>
      rejectP(
        new Error(
          `DPAPI 失败（无法启动 powershell：${err.message}）\n` +
            "DPAPI 仅存在于 Windows；Linux/macOS 请改用 VAULT_BACKEND=passphrase + VAULT_MASTER_PASSWORD。",
        ),
      ),
    );
    child.on("close", (code) => {
      if (code === 0) return resolveP(out.join(""));
      const msg = err.join("").trim().split(/\r?\n/).slice(0, 3).join(" ");
      rejectP(
        new Error(
          `DPAPI 失败（exit ${code}）${msg ? `：${msg}` : ""}\n` +
            "常见原因：换了 Windows 用户或换了机器。DPAPI 密文不能跨用户/跨机器解密，" +
            "请用 `vault export` 在旧机导出、再在新机 `vault import`。",
        ),
      );
    });
    child.stdin.end(payload, "utf8");
  });
}

/**
 * 用主密码派生 32 字节密钥（scrypt，参数固定以便跨机一致）。
 * @param {string} password
 * @param {Buffer} salt
 * @returns {Buffer}
 */
export function deriveKey(password, salt) {
  // 128 * N * r = 33.5 MB，超过 Node/OpenSSL 默认的 32 MB 上限，必须显式放宽
  return scryptSync(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

/**
 * 用主密码加密任意 JSON 可序列化对象（AES-256-GCM）。
 * @param {unknown} value
 * @param {string} password
 * @returns {Buffer} 可直接写盘的密文（UTF-8 JSON）
 */
export function encryptWithPassphrase(value, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(password, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value), "utf8")), cipher.final()]);
  const envelope = {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    kdf: { name: "scrypt", salt: salt.toString("base64"), N: 32768, r: 8, p: 1 },
    cipher: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
  return Buffer.from(JSON.stringify(envelope, null, 2) + "\n", "utf8");
}

/**
 * 用主密码解密（与 {@link encryptWithPassphrase} 对称）。
 * @param {Buffer} raw 密文文件内容
 * @param {string} password
 * @returns {unknown}
 * @throws {Error} 格式不对、密码错或文件被篡改
 */
export function decryptWithPassphrase(raw, password) {
  let env;
  try {
    env = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("导出文件不是合法 JSON");
  }
  if (env?.format !== EXPORT_FORMAT || env?.cipher !== "aes-256-gcm") {
    throw new Error("导出文件格式不认识（缺少 format/cipher 字段）");
  }
  const salt = Buffer.from(env.kdf.salt, "base64");
  const key = deriveKey(password, salt);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(env.iv, "base64"));
  decipher.setAuthTag(Buffer.from(env.tag, "base64"));
  try {
    const plain = Buffer.concat([decipher.update(Buffer.from(env.data, "base64")), decipher.final()]);
    return JSON.parse(plain.toString("utf8"));
  } catch {
    throw new Error("解密失败：主密码不对，或文件被改动过");
  }
}

/**
 * 读取并解密凭据库；文件不存在返回空对象。
 * @param {string} [password] passphrase 后端需要的主密码
 * @returns {Promise<Vault>}
 */
export async function loadVault(password) {
  let raw;
  try {
    raw = await readFile(VAULT_FILE);
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === "ENOENT") return {};
    throw err;
  }
  const env = JSON.parse(raw.toString("utf8"));
  // 兼容旧格式：早期版本用 `alg: "dpapi-currentuser"`，后来改成 `backend: "dpapi"`
  const isDpapi = env.backend === "dpapi" || env.alg === "dpapi-currentuser";
  if (isDpapi) {
    // DPAPI 解出来的是明文字节（Buffer），需要这里自己 JSON.parse
    const plain = await dpapiUnprotect(Buffer.from(env.blob, "base64"));
    return JSON.parse(plain.toString("utf8"));
  }
  // passphrase：decryptWithPassphrase 内部已经 JSON.parse 过，返回的就是凭据对象。
  // 修复点：原来对返回对象又做了一次 JSON.parse(plain.toString()) → "[object Object]" 报错，
  // 导致 Linux/macOS（passphrase 后端）能写不能读。
  return decryptWithPassphrase(Buffer.from(env.blob, "base64"), requiredPassword(password));
}

/**
 * 加密并写回凭据库，随后收紧权限。
 * @param {Vault} vault
 * @param {string} [password] passphrase 后端需要的主密码
 * @returns {Promise<void>}
 */
export async function saveVault(vault, password) {
  await ensureDir(DATA_DIR);
  const mode = backend();
  const plain = Buffer.from(JSON.stringify(vault), "utf8");
  const blob =
    mode === "dpapi"
      ? await dpapiProtect(plain)
      : encryptWithPassphrase(JSON.parse(plain.toString("utf8")), requiredPassword(password));
  const envelope = {
    version: 1,
    backend: mode,
    updatedAt: new Date().toISOString(),
    blob: blob.toString("base64"),
  };
  await writeFile(VAULT_FILE, JSON.stringify(envelope, null, 2) + "\n", "utf8");
  await tightenPerms(VAULT_FILE);
}

/**
 * passphrase 后端必须拿到主密码，否则给出可操作提示。
 * @param {string|undefined} password
 * @returns {string}
 */
function requiredPassword(password) {
  const p = password ?? process.env.VAULT_MASTER_PASSWORD ?? "";
  if (!p) throw new Error("当前是主密码后端，需要 --master-password 或环境变量 VAULT_MASTER_PASSWORD");
  return p;
}

/**
 * 收紧文件权限：Windows 用 icacls 去掉继承、只授当前用户；其他平台 chmod 600。
 * @param {string} file
 * @returns {Promise<void>}
 */
export async function tightenPerms(file) {
  if (process.platform === "win32") {
    const user = process.env.USERNAME;
    if (!user) return;
    await new Promise((resolveP) => {
      const child = spawn("icacls", [file, "/inheritance:r", "/grant:r", `${user}:F`], { windowsHide: true });
      child.on("error", () => resolveP(undefined));
      child.on("close", () => resolveP(undefined));
    });
    return;
  }
  await chmod(file, 0o600).catch(() => undefined);
}

/**
 * 追加一条审计记录（不含任何凭据值）。
 * @param {"set"|"get"|"list"|"rm"|"gen"|"totp"|"export"|"import"|"rename"} op
 * @param {string|null} name 凭据名
 * @param {string} [caller] 调用方标识
 * @returns {Promise<void>}
 */
export async function audit(op, name, caller) {
  await ensureDir(DATA_DIR);
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    op,
    name: name ?? null,
    caller: caller ?? process.env.VAULT_CALLER ?? "cli",
  });
  await writeFile(AUDIT_FILE, line + "\n", { flag: "a", encoding: "utf8" });
}

/**
 * 检查数据目录是否落在某个 git 工作区里（防手滑把密文提交）。
 * @returns {Promise<{ ok: boolean, detail: string }>}
 */
export async function checkNotInRepo() {
  let dir = DATA_DIR;
  for (let i = 0; i < 12; i++) {
    try {
      await stat(join(dir, ".git"));
      return { ok: false, detail: `数据目录 ${DATA_DIR} 位于 git 仓库 ${dir} 内，密文可能被提交` };
    } catch {
      /* 继续往上找 */
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { ok: true, detail: DATA_DIR };
}

/**
 * 标准化 TOTP 种子：去掉空格与短横，转大写。
 * @param {string} seed
 * @returns {string}
 */
export function normalizeSeed(seed) {
  return String(seed).replace(/[\s-]/g, "").toUpperCase();
}

/**
 * 计算当前 TOTP 验证码（RFC 6238，默认 SHA1 / 6 位 / 30 秒）。
 * @param {string} seedBase32 base32 种子
 * @param {{ at?: number, digits?: number, period?: number }} [options]
 * @returns {{ code: string, remaining: number, counter: number }}
 */
export function totp(seedBase32, options = {}) {
  const digits = options.digits ?? 6;
  const period = options.period ?? 30;
  const at = options.at ?? Date.now();
  const counter = Math.floor(at / 1000 / period);
  const key = base32Decode(normalizeSeed(seedBase32));
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  // 动态截断（RFC 4226 §5.4）
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  const code = String(bin % 10 ** digits).padStart(digits, "0");
  const remaining = period - Math.floor((at / 1000) % period);
  return { code, remaining, counter };
}

/**
 * Base32 解码（RFC 4648，无填充兼容）。
 * @param {string} input
 * @returns {Buffer}
 */
export function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  /** @type {number[]} */
  const out = [];
  for (const ch of input.replace(/=+$/, "")) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`TOTP 种子里有非法字符：${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * 生成随机强密码（大小写 + 数字 + 符号，去除易混字符）。
 * @param {number} [length]
 * @returns {string}
 */
export function generatePassword(length = 24) {
  const sets = ["abcdefghijkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?"];
  const all = sets.join("");
  const bytes = randomBytes(length * 2);
  /** @type {string[]} */
  const chars = [];
  // 先各取一个，保证四类都有
  sets.forEach((s, i) => chars.push(s[bytes[i] % s.length]));
  for (let i = sets.length; i < length; i++) chars.push(all[bytes[i] % all.length]);
  // 洗牌
  for (let i = chars.length - 1; i > 0; i--) {
    const j = bytes[(i * 7) % bytes.length] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
