import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const server = fs.readFileSync(new URL("../server.js", import.meta.url), "utf8");
const index = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const app = fs.readFileSync(new URL("../app.js", import.meta.url), "utf8");
const styles = fs.readFileSync(new URL("../styles.css", import.meta.url), "utf8");
const alternate = fs.readFileSync(new URL("../ai-chat.html", import.meta.url), "utf8");

test("legacy frontend URL redirects to the canonical page", () => {
  assert.match(alternate, /\.\/index\.html/);
});

test("split frontend assets are linked, served, and JavaScript parses", () => {
  assert.match(index, /<link rel="stylesheet" href="\.\/styles\.css"/);
  assert.match(index, /<script src="\.\/app\.js"><\/script>/);
  assert.match(server, /app\.get\("\/styles\.css"/);
  assert.match(server, /app\.get\("\/app\.js"/);
  assert.ok(styles.length > 0, "split stylesheet is present");
  assert.doesNotThrow(() => new vm.Script(app));
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
  assert.match(app, /后端会话验证失败/);
  assert.match(app, /setAccessToken\(data\.access_token\)/);
});

test("privacy mode prevents server-side chat persistence", () => {
  assert.match(server, /if\(!stealthOn\) try \{/);
});

test("frontend targets the new service and caps context", () => {
  assert.match(app, /MAX_CONTEXT_MESSAGES = 50/);
  assert.match(app, /https:\/\/yiqun-ai-chat2\.onrender\.com/);
});

test("401 activation uses an in-page modal instead of prompt fallback", () => {
  assert.match(index, /id="activationModal"/);
  assert.match(app, /activationModal\.classList\.add\("show"\)/);
  assert.doesNotMatch(app, /prompt\("请输入邀请码/);
});

test("Chat2 uses its own Supabase project and full cloud sessions", () => {
  assert.match(app, /https:\/\/jxkzhiwjfqwemnljytvt\.supabase\.co/);
  assert.match(app, /syncSessionToCloud/);
  assert.match(server, /app\.get\("\/api\/chat\/sessions"/);
  assert.match(server, /app\.put\("\/api\/chat\/sessions\/:id"/);
  assert.match(server, /app\.delete\("\/api\/chat\/sessions\/:id"/);
});

test("registration validates confirmation and login failure clears stale tokens", () => {
  assert.match(app, /authConfirmPassword/);
  assert.match(app, /两次输入的密码不一致/);
  assert.match(app, /密码至少 8 位/);
  assert.match(app, /catch\(err\)[\s\S]*setAccessToken\(""\)/);
  assert.doesNotMatch(app, /alert\("已退出登录"\)/);
});
