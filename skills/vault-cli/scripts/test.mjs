#!/usr/bin/env node
// @ts-check
/**
 * vault-cli 的自检脚本（零依赖，不碰真实数据）。
 *
 * 覆盖：
 * 1. TOTP 对齐 RFC 6238 官方测试向量
 * 2. Base32 解码
 * 3. 强密码生成的形态约束
 * 4. 主密码加密/解密往返，以及「错密码必须失败」
 * 5. 数据目录落点检查（不在 git 工作区内）
 *
 * 用法：node scripts/test.mjs
 */

import { strict as assert } from "node:assert";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// 必须在导入 store 之前设置，DATA_DIR 是模块加载时求值的
const sandbox = await mkdtemp(join(tmpdir(), "vault-cli-test-"));
process.env.VAULT_DIR = sandbox;

const { base32Decode, decryptWithPassphrase, encryptWithPassphrase, generatePassword, totp, checkNotInRepo } = await import(
  "./store.mjs"
);

let passed = 0;
/**
 * 跑一条断言并计数。
 * @param {string} name
 * @param {() => void | Promise<void>} fn
 */
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    console.error(`  ✗ ${name}\n    ${/** @type {Error} */ (err).message}`);
    process.exitCode = 1;
  }
}

console.log("TOTP");
await test("RFC 6238 测试向量（T=59s, 6 位 → 287082）", () => {
  // 种子是 ASCII "12345678901234567890" 的 base32
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const r = totp(seed, { at: 59_000 });
  assert.equal(r.code, "287082");
});
await test("同一时间窗内结果稳定（59.0s 与 59.9s）", () => {
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(totp(seed, { at: 59_000 }).code, totp(seed, { at: 59_900 }).code);
});
await test("跨时间窗必须变化（59s → 60s）", () => {
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.notEqual(totp(seed, { at: 59_000 }).code, totp(seed, { at: 60_000 }).code);
});
await test("种子含空格/小写也能解析", () => {
  const a = totp("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", { at: 59_000 }).code;
  const b = totp("gezdgnbvgy3tqojqgezdgnbvgy3tqojq", { at: 59_000 }).code;
  assert.equal(a, b);
});

console.log("Base32");
await test("解码 12345678901234567890", () => {
  const buf = base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  assert.equal(buf.toString("ascii"), "12345678901234567890");
});
await test("非法字符必须报错", () => {
  assert.throws(() => base32Decode("ABC1"), /非法字符/);
});

console.log("密码生成");
await test("长度正确且四类字符齐全", () => {
  for (let i = 0; i < 50; i++) {
    const p = generatePassword(24);
    assert.equal(p.length, 24);
    assert.match(p, /[a-z]/);
    assert.match(p, /[A-Z]/);
    assert.match(p, /[0-9]/);
    assert.match(p, /[!@#$%^&*\-_=+?]/);
  }
});
await test("两次生成不相同", () => {
  assert.notEqual(generatePassword(32), generatePassword(32));
});

console.log("主密码加密");
await test("往返一致", () => {
  const data = { a: { user: "u", password: "p" } };
  const enc = encryptWithPassphrase(data, "correct horse battery staple");
  const dec = decryptWithPassphrase(enc, "correct horse battery staple");
  assert.deepEqual(dec, data);
});
await test("错密码必须失败", () => {
  const enc = encryptWithPassphrase({ a: 1 }, "right-password");
  assert.throws(() => decryptWithPassphrase(enc, "wrong-password"), /主密码不对|解密失败/);
});
await test("密文里不含明文", () => {
  const enc = encryptWithPassphrase({ secret: "SUPER-SECRET-VALUE" }, "pw").toString("utf8");
  assert.equal(enc.includes("SUPER-SECRET-VALUE"), false);
});
await test("被篡改必须失败", () => {
  const enc = encryptWithPassphrase({ a: 1 }, "pw").toString("utf8");
  const tampered = Buffer.from(enc.replace(/"data": "[A-Za-z0-9+/]{4}/, '"data": "AAAA'), "utf8");
  assert.throws(() => decryptWithPassphrase(tampered, "pw"));
});

console.log("数据落点");
await test("临时目录不在 git 工作区内", async () => {
  const r = await checkNotInRepo();
  assert.equal(r.ok, true);
});

await rm(sandbox, { recursive: true, force: true });
console.log(`\n通过 ${passed} 项`);
if (process.exitCode) {
  console.error("有测试失败");
} else {
  console.log("全部通过");
}
