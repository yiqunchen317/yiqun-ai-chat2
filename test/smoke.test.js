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
  assert.match(server, /supabase\.auth\.getUser\(token\)/);
});

test("upload endpoints require authentication", () => {
  assert.match(server, /app\.post\("\/api\/upload\/sign", requireActivatedOrApiKey/);
  assert.match(server, /app\.post\("\/api\/upload\/url", requireActivatedOrApiKey/);
  assert.match(server, /forbidden path/);
});

test("verified login creates a voice-capable session cookie", () => {
  assert.match(server, /app\.post\("\/api\/session"/);
  assert.match(index, /后端登录会话创建失败/);
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
