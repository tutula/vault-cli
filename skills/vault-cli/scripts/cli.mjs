#!/usr/bin/env node
// @ts-check
/**
 * vault-cli：本地凭据抽屉的命令行入口。
 *
 * 用法（完整说明见 SKILL.md）：
 *   vault set <name> [--user U] [--password P] [--totp SEED] [--url URL] [--note N]
 *   vault get <name> [--json] [--field password]
 *   vault list [--json]
 *   vault rm <name>
 *   vault gen <name> [--length 24] [--user U] [--url URL]
 *   vault totp <name> [--json]
 *   vault search <keyword>
 *   vault rename <old> <new>
 *   vault export -o <file> [--master-password P]
 *   vault import <file> [--replace] [--master-password P]
 *   vault audit [--tail N]
 *   vault doctor
 *
 * 约定：
 * - 密码等敏感字段缺省时走**交互输入**（不回显），避免落在 shell 历史里；
 * - 非交互终端（脚本调用）下缺参数直接报错，绝不静默写空值；
 * - `list` 只显示字段有无，绝不显示值；每次 `get`/`totp` 写审计。
 */

import { createInterface } from "node:readline";
import { readFile, writeFile } from "node:fs/promises";
import {
  audit,
  AUDIT_FILE,
  backend,
  DATA_DIR,
  decryptWithPassphrase,
  encryptWithPassphrase,
  VAULT_FILE,
  checkNotInRepo,
  generatePassword,
  loadVault,
  saveVault,
  totp,
} from "./store.mjs";

/**
 * 解析 `--key value` 与位置参数。
 * @param {string[]} argv
 * @returns {{ _: string[], flags: Record<string, string | true> }}
 */
function parseArgs(argv) {
  /** @type {string[]} */
  const positional = [];
  /** @type {Record<string, string | true>} */
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else if (a === "-o" && argv[i + 1]) {
      flags.output = argv[++i];
    } else {
      positional.push(a);
    }
  }
  return { _: positional, flags };
}

/**
 * 交互提问；hidden=true 时不回显（用于密码）。
 * @param {string} question
 * @param {boolean} [hidden]
 * @returns {Promise<string>}
 */
function ask(question, hidden = false) {
  return new Promise((resolveP) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    if (hidden) {
      // @ts-expect-error readline 内部方法，用于静默输入
      rl._writeToOutput = (s) => {
        if (s.includes(question)) rl.output.write(question);
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write("\n");
      resolveP(answer.trim());
    });
  });
}

/**
 * 取一个必填的敏感值：优先命令行，其次交互输入。
 * @param {string | true | undefined} flagValue
 * @param {string} promptText
 * @returns {Promise<string>}
 */
async function secretFrom(flagValue, promptText) {
  if (typeof flagValue === "string") return flagValue;
  if (!process.stdin.isTTY) throw new Error(`缺少参数且当前不是交互终端：${promptText}`);
  return ask(promptText, true);
}

/**
 * 取主密码（passphrase 后端或导出/导入时使用）。
 * @param {Record<string, string | true>} flags
 * @param {string} [purpose]
 * @returns {Promise<string>}
 */
async function masterPassword(flags, purpose = "主密码") {
  if (typeof flags["master-password"] === "string") return flags["master-password"];
  if (process.env.VAULT_MASTER_PASSWORD) return process.env.VAULT_MASTER_PASSWORD;
  if (!process.stdin.isTTY) throw new Error(`需要 ${purpose}：请用 --master-password 或 VAULT_MASTER_PASSWORD`);
  return ask(`${purpose}：`, true);
}

/** set：新增或更新一条凭据 */
async function cmdSet(name, flags) {
  const vault = await loadVault(typeof flags["master-password"] === "string" ? flags["master-password"] : undefined);
  const prev = vault[name] ?? {};
  const password = await secretFrom(flags.password, `请输入 ${name} 的密码：`);
  const user = typeof flags.user === "string" ? flags.user : prev.user ?? "";
  vault[name] = {
    user,
    password,
    totp: typeof flags.totp === "string" ? flags.totp : prev.totp ?? "",
    url: typeof flags.url === "string" ? flags.url : prev.url ?? "",
    note: typeof flags.note === "string" ? flags.note : prev.note ?? "",
    updatedAt: new Date().toISOString(),
  };
  await saveVault(vault, typeof flags["master-password"] === "string" ? flags["master-password"] : undefined);
  await audit("set", name);
  console.log(`[vault] 已保存 ${name}`);
}

/** get：输出一条凭据 */
async function cmdGet(name, flags) {
  const vault = await loadVault();
  const cred = vault[name];
  if (!cred) {
    console.error(`[vault] 没有 ${name}`);
    process.exit(1);
  }
  await audit("get", name);
  if (typeof flags.field === "string") {
    const v = cred[/** @type {keyof typeof cred} */ (flags.field)];
    if (v === undefined) {
      console.error(`[vault] ${name} 没有字段 ${flags.field}`);
      process.exit(1);
    }
    console.log(String(v));
    return;
  }
  if (flags.json) {
    console.log(JSON.stringify({ user: cred.user ?? "", password: cred.password ?? "", totp: cred.totp ?? "" }));
    return;
  }
  console.log(`name:     ${name}`);
  console.log(`user:     ${cred.user || "(空)"}`);
  console.log(`password: ${cred.password || "(空)"}`);
  console.log(`totp:     ${cred.totp || "(空)"}`);
  if (cred.url) console.log(`url:      ${cred.url}`);
  if (cred.note) console.log(`note:     ${cred.note}`);
}

/** list：只显示字段有无 */
async function cmdList(flags) {
  const vault = await loadVault();
  const names = Object.keys(vault).sort();
  await audit("list", null);
  if (flags.json) {
    console.log(
      JSON.stringify(
        names.map((n) => ({
          name: n,
          hasUser: Boolean(vault[n].user),
          hasPassword: Boolean(vault[n].password),
          hasTotp: Boolean(vault[n].totp),
          updatedAt: vault[n].updatedAt,
        })),
      ),
    );
    return;
  }
  if (names.length === 0) {
    console.log("[vault] 空");
    return;
  }
  console.log("name            user  pass  totp  updatedAt");
  for (const n of names) {
    const c = vault[n];
    console.log(`${n.padEnd(15)} ${(c.user ? "✓" : "-").padEnd(5)} ${(c.password ? "✓" : "-").padEnd(5)} ${(c.totp ? "✓" : "-").padEnd(5)} ${c.updatedAt ?? ""}`);
  }
}

/** rm：删除一条 */
async function cmdRm(name) {
  const vault = await loadVault();
  if (!vault[name]) {
    console.error(`[vault] 没有 ${name}`);
    process.exit(1);
  }
  delete vault[name];
  await saveVault(vault);
  await audit("rm", name);
  console.log(`[vault] 已删除 ${name}`);
}

/** gen：生成强密码并保存 */
async function cmdGen(name, flags) {
  const length = Number(typeof flags.length === "string" ? flags.length : 24);
  const password = generatePassword(Number.isFinite(length) && length >= 8 ? length : 24);
  const vault = await loadVault();
  vault[name] = {
    user: typeof flags.user === "string" ? flags.user : vault[name]?.user ?? "",
    password,
    totp: typeof flags.totp === "string" ? flags.totp : vault[name]?.totp ?? "",
    url: typeof flags.url === "string" ? flags.url : vault[name]?.url ?? "",
    note: typeof flags.note === "string" ? flags.note : vault[name]?.note ?? "",
    updatedAt: new Date().toISOString(),
  };
  await saveVault(vault);
  await audit("gen", name);
  console.log(password);
}

/** totp：输出当前验证码 */
async function cmdTotp(name, flags) {
  const vault = await loadVault();
  const seed = vault[name]?.totp;
  if (!seed) {
    console.error(`[vault] ${name} 没有 totp 种子`);
    process.exit(1);
  }
  const r = totp(seed);
  await audit("totp", name);
  if (flags.json) console.log(JSON.stringify(r));
  else console.log(`${r.code}  （剩余 ${r.remaining}s）`);
}

/** search：按名字/用户名/URL/备注匹配 */
async function cmdSearch(keyword) {
  const vault = await loadVault();
  const kw = keyword.toLowerCase();
  const hits = Object.entries(vault).filter(([n, c]) =>
    [n, c.user ?? "", c.url ?? "", c.note ?? ""].some((f) => f.toLowerCase().includes(kw)),
  );
  await audit("list", null);
  if (hits.length === 0) {
    console.log("[vault] 没有匹配项");
    return;
  }
  for (const [n, c] of hits) console.log(`${n}\t${c.user ?? ""}\t${c.url ?? ""}`);
}

/** rename：改名 */
async function cmdRename(from, to) {
  const vault = await loadVault();
  if (!vault[from]) {
    console.error(`[vault] 没有 ${from}`);
    process.exit(1);
  }
  if (vault[to]) {
    console.error(`[vault] ${to} 已存在，拒绝覆盖`);
    process.exit(1);
  }
  vault[to] = { ...vault[from], updatedAt: new Date().toISOString() };
  delete vault[from];
  await saveVault(vault);
  await audit("rename", to);
  console.log(`[vault] ${from} → ${to}`);
}

/** export：用主密码导出可迁移密文 */
async function cmdExport(flags) {
  const out = typeof flags.output === "string" ? flags.output : "vault.export.enc";
  const password = await masterPassword(flags, "导出主密码");
  const vault = await loadVault();
  const buf = encryptWithPassphrase(vault, password);
  await writeFile(out, buf);
  await audit("export", null);
  console.log(`[vault] 已导出 ${Object.keys(vault).length} 条到 ${out}`);
  console.log("[vault] 提醒：这个文件用主密码加密，主密码忘了就打不开，没有后门。");
}

/** import：从导出文件恢复（默认合并） */
async function cmdImport(file, flags) {
  const password = await masterPassword(flags, "导入主密码");
  const raw = await readFile(file);
  const incoming = /** @type {Record<string, any>} */ (decryptWithPassphrase(raw, password));
  const replace = Boolean(flags.replace);
  const vault = replace ? {} : await loadVault();
  let added = 0;
  let updated = 0;
  for (const [k, v] of Object.entries(incoming)) {
    if (vault[k]) updated++;
    else added++;
    vault[k] = v;
  }
  await saveVault(vault);
  await audit("import", null);
  console.log(`[vault] 导入完成：新增 ${added} / 覆盖 ${updated}（${replace ? "整库替换" : "合并"}）`);
}

/** audit：查看审计尾部 */
async function cmdAudit(flags) {
  const tail = Number(typeof flags.tail === "string" ? flags.tail : 20);
  let text = "";
  try {
    text = await readFile(AUDIT_FILE, "utf8");
  } catch {
    console.log("[vault] 还没有审计记录");
    return;
  }
  console.log(text.trim().split("\n").filter(Boolean).slice(-tail).join("\n"));
}

/** doctor：自检数据目录与后端 */
async function cmdDoctor() {
  const repo = await checkNotInRepo();
  console.log(`后端:      ${backend()}`);
  console.log(`数据目录:  ${DATA_DIR}`);
  console.log(`密文文件:  ${VAULT_FILE}`);
  console.log(`审计日志:  ${AUDIT_FILE}`);
  console.log(`仓库检查:  ${repo.ok ? "通过（不在 git 工作区内）" : `失败 — ${repo.detail}`}`);
  try {
    const vault = await loadVault();
    console.log(`可解密:    是（${Object.keys(vault).length} 条）`);
  } catch (err) {
    console.log(`可解密:    否 — ${/** @type {Error} */ (err).message}`);
  }
  if (!repo.ok) process.exit(1);
}

async function main() {
  const { _, flags } = parseArgs(process.argv.slice(2));
  const [cmd, a1, a2] = _;
  try {
    switch (cmd) {
      case "set":
        if (!a1) throw new Error("用法：set <name>");
        await cmdSet(a1, flags);
        break;
      case "get":
        if (!a1) throw new Error("用法：get <name> [--json] [--field password]");
        await cmdGet(a1, flags);
        break;
      case "list":
        await cmdList(flags);
        break;
      case "rm":
        if (!a1) throw new Error("用法：rm <name>");
        await cmdRm(a1);
        break;
      case "gen":
        if (!a1) throw new Error("用法：gen <name> [--length 24]");
        await cmdGen(a1, flags);
        break;
      case "totp":
        if (!a1) throw new Error("用法：totp <name>");
        await cmdTotp(a1, flags);
        break;
      case "search":
        if (!a1) throw new Error("用法：search <keyword>");
        await cmdSearch(a1);
        break;
      case "rename":
        if (!a1 || !a2) throw new Error("用法：rename <old> <new>");
        await cmdRename(a1, a2);
        break;
      case "export":
        await cmdExport(flags);
        break;
      case "import":
        if (!a1) throw new Error("用法：import <file> [--replace]");
        await cmdImport(a1, flags);
        break;
      case "audit":
        await cmdAudit(flags);
        break;
      case "doctor":
        await cmdDoctor();
        break;
      default:
        console.error(
          "用法：vault <set|get|list|rm|gen|totp|search|rename|export|import|audit|doctor> [参数]\n" +
            "详见 SKILL.md 或 README.md",
        );
        process.exit(1);
    }
  } catch (err) {
    console.error(`[vault] ${/** @type {Error} */ (err).message}`);
    process.exit(1);
  }
}

await main();
