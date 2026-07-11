import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const server = fs.readFileSync(new URL("../server.js", import.meta.url), "utf8");
const index = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const alternate = fs.readFileSync(new URL("../ai-chat.html", import.meta.url), "utf8");

test("legacy frontend URL redirects to the canonical page", () => {
  assert.match(alternate, /\.\/index\.html/);
});

test("inline frontend JavaScript parses", () => {
  const match = index.match(/<script>([\s\S]*)<\/script>/);
  assert.ok(match, "inline app script is present");
  assert.doesNotThrow(() => new vm.Script(match[1]));
});

test("authentication never trusts an unverified JWT payload", () => {
  assert.doesNotMatch(server, /jwt\.decode|jsonwebtoken/);
  assert.match(server, /\/auth\/v1\/user/);
  assert.match(server, /Authorization: `Bearer \$\{token\}`/);
});

test("ES256 Supabase tokens are verified by GoTrue instead of local JWKS cache", () => {
  assert.match(server, /Ask GoTrue to validate the token server-side/);
  assert.match(server, /if\(!authRes\.ok \|\| !user\?\.id\)/);
});

test("ES256 verification falls back to the project's current JWKS key", () => {
  assert.match(server, /\.well-known\/jwks\.json/);
  assert.match(server, /crypto\.webcrypto\.subtle\.importKey/);
  assert.match(server, /crypto\.webcrypto\.subtle\.verify/);
  assert.match(server, /name: "ECDSA", hash: "SHA-256"/);
  assert.match(server, /payload\.iss !== `\$\{SUPABASE_URL\}\/auth\/v1`/);
  assert.match(server, /PINNED_SUPABASE_JWK/);
  assert.match(server, /req\.userId = verifiedSub/);
  assert.match(server, /getSupabaseJwks\(true\)/);
  assert.match(server, /Cache-Control": "no-cache"/);
});

test("upload endpoints require authentication", () => {
  assert.match(server, /app\.post\("\/api\/upload\/sign", requireActivatedOrApiKey/);
  assert.match(server, /app\.post\("\/api\/upload\/url", requireActivatedOrApiKey/);
  assert.match(server, /forbidden path/);
});

test("verified login creates a voice-capable session cookie", () => {
  assert.match(server, /app\.post\("\/api\/session"/);
  assert.match(index, /后端会话验证失败/);
  assert.match(index, /setAccessToken\(data\.access_token\)/);
});

test("privacy mode prevents server-side chat persistence", () => {
  assert.match(server, /if\(!stealthOn\) try \{/);
});

test("frontend targets the new service and caps context", () => {
  assert.match(index, /MAX_CONTEXT_MESSAGES = 50/);
  assert.match(index, /https:\/\/yiqun-ai-chat2\.onrender\.com/);
});

test("401 activation uses an in-page modal instead of prompt fallback", () => {
  assert.match(index, /id="activationModal"/);
  assert.match(index, /activationModal\.classList\.add\("show"\)/);
  assert.doesNotMatch(index, /prompt\("请输入邀请码/);
});

test("Chat2 uses its own Supabase project and full cloud sessions", () => {
  assert.match(index, /https:\/\/jxkzhiwjfqwemnljytvt\.supabase\.co/);
  assert.match(index, /syncSessionToCloud/);
  assert.match(server, /app\.get\("\/api\/chat\/sessions"/);
  assert.match(server, /app\.put\("\/api\/chat\/sessions\/:id"/);
  assert.match(server, /app\.delete\("\/api\/chat\/sessions\/:id"/);
});

test("registration validates confirmation and login failure clears stale tokens", () => {
  assert.match(index, /authConfirmPassword/);
  assert.match(index, /两次输入的密码不一致/);
  assert.match(index, /密码至少 8 位/);
  assert.match(index, /catch\(err\)[\s\S]*setAccessToken\(""\)/);
  assert.doesNotMatch(index, /alert\("已退出登录"\)/);
});
