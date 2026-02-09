import express from "express";
import OpenAI from "openai";
import fetch from "node-fetch";
import https from "https";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
const grokHttpsAgent = new https.Agent({ keepAlive: true });

console.log("🚀 Loaded server.js at", new Date().toISOString());

const app = express();

// ===== SECURITY: trust proxy so IP works on Render =====
app.set("trust proxy", 1);
// ===== Serve frontend (so / works on iPhone) =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static files from project root (expects index.html here)
app.use(express.static(__dirname));

// Home page
app.get("/", (req, res) => {
  const indexPath = path.join(__dirname, "index.html");
  const aiChatPath = path.join(__dirname, "ai-chat.html");

  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  if (fs.existsSync(aiChatPath)) return res.sendFile(aiChatPath);

  res.status(404).send("index.html not found");
});
// ===============================================
// ===== SECURITY: Strict CORS allowlist (NO localhost / NO Origin:null) =====
// Allow ONLY the public GitHub Pages origin and this Render service origin.
// Do NOT allow file:// (Origin: null) or localhost.
const ALLOWED_ORIGINS = new Set([
  "https://yiqnuchen317.github.io",
  "https://yiqun-ai-chat.onrender.com"
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Only set CORS headers for explicitly allowed browser origins.
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  // Preflight: only allow if origin is allowlisted; otherwise hard block
  if (req.method === "OPTIONS") {
    if (origin && ALLOWED_ORIGINS.has(origin)) return res.status(204).end();
    return res.status(403).end();
  }

  next();
});

app.use(express.json({ limit: "8mb" }));

// ===== SECURITY HEADERS =====
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("X-Frame-Options","DENY");
  next();
});

// ===== API KEY AUTH =====
const API_KEY = String(process.env.API_KEY || "").trim();

function getClientKey(req){
  const h = req.headers["x-api-key"];
  if(typeof h === "string" && h.trim()) return h.trim();

  const auth = req.headers["authorization"];
  if(typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")){
    return auth.slice(7).trim();
  }

  return "";
}

function requireApiKey(req, res, next) {
  const origin = req.headers.origin;

  // Allowed browser origins do NOT need a key (frontend must not ship secrets)
  if (origin && ALLOWED_ORIGINS.has(origin)) return next();

  // For any non-allowlisted origin (including no Origin), require server secret
  if (!API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const k = getClientKey(req);
  if (k && k === API_KEY) return next();

  return res.status(401).json({ error: "Unauthorized" });
}

// ===== RATE LIMIT =====
const RATE_WINDOW_MS = Number(process.env.RATE_WINDOW_MS || 60000);
const RATE_CHAT_MAX = Number(process.env.RATE_CHAT_MAX || 30);
const RATE_IMG_MAX  = Number(process.env.RATE_IMG_MAX  || 10);

const _rate = new Map();

function rateLimit(type,max){
  return (req,res,next)=>{
    const ip = (req.headers["x-forwarded-for"]
      ? String(req.headers["x-forwarded-for"]).split(",")[0].trim()
      : req.ip) || "unknown";

    const now = Date.now();
    const key = type + ":" + ip;

    const cur = _rate.get(key) || { ts: now, n: 0 };

    if(now - cur.ts >= RATE_WINDOW_MS){
      cur.ts = now;
      cur.n = 0;
    }

    cur.n++;
    _rate.set(key, cur);

    if(cur.n > max){
      return res.status(429).json({ error: "Rate limit exceeded" });
    }

    next();
  };
}

// 读取环境变量：OPENAI_API_KEY
let _openai = null;
function getOpenAI(){
  const key = process.env.OPENAI_API_KEY;
  if(!key) throw new Error("缺少 OPENAI_API_KEY：当前后端只能用无尽模型（Grok）。如果要用GPT模式，请在终端 export OPENAI_API_KEY=你的key");
  if(!_openai) _openai = new OpenAI({ apiKey: key });
  return _openai;
}

function getGrokKey(){
  return process.env.GROK_KEY || process.env.XAI_API_KEY || "";
}
// ======= OpenAI image helper =======
async function callOpenAIImage(prompt, model = "gpt-image-1"){
    const p = String(prompt || "").trim();
    if(!p) throw new Error("prompt 不能为空");

    const client = getOpenAI();

    let img;
    try{
      img = await client.images.generate({
        model,
        prompt: p,
        size: "1024x1024",
        response_format: "b64_json"
      });
    }catch(err){
      const msg = String(err?.message || "");
      // Some proxies / older endpoints reject response_format
      if(msg.toLowerCase().includes("response_format") || msg.toLowerCase().includes("unknown parameter")){
        img = await client.images.generate({
          model,
          prompt: p,
          size: "1024x1024"
        });
      }else{
        throw err;
      }
    }

    const item = Array.isArray(img?.data) ? img.data[0] : null;
    const b64 = item?.b64_json;
    const url = item?.url;

    if(typeof b64 === "string" && b64.trim()){
      return "data:image/png;base64," + b64.trim();
    }
    if(typeof url === "string" && url.trim()){
      return url.trim();
    }

    throw new Error("OpenAI 没有返回图片数据");
}

// ======= xAI image helper =======
async function callGrokImage(prompt, grokModel = "grok-imagine-image"){
  const GROK_KEY = getGrokKey();
  if(!GROK_KEY) throw new Error("缺少 GROK_KEY：无法使用 Grok 图片生成");

  const p = String(prompt || "").trim();
  if(!p) throw new Error("prompt 不能为空");

  // NOTE: xAI image endpoint (best‑effort implementation)
  const r = await fetch("https://api.x.ai/v1/images/generations", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + GROK_KEY
    },
    body: JSON.stringify({
      model: grokModel,
      prompt: p
    })
  });

  if(!r.ok){
    const t = await r.text().catch(()=>"");
    throw new Error("Grok 图片生成错误: " + r.status + " " + t);
  }

  const data = await r.json();

  // Try to extract base64 or url (xAI Images API is OpenAI-compatible)
  const item = Array.isArray(data?.data) ? data.data[0] : null;
  const b64 = item?.b64_json || item?.base64 || item?.b64;
  const url = item?.url || item?.image_url;

  if(typeof b64 === "string" && b64.trim()) return "data:image/png;base64," + b64.trim();
  if(typeof url === "string" && url.trim()) return url.trim();

  throw new Error("Grok 没有返回图片数据");
}

// ======= xAI model resolver (avoid 404 like grok-2-latest) =======
let _xaiModelsCache = { ts: 0, ids: [] };
const XAI_MODELS_TTL_MS = 60_000; // 1 minute

async function fetchXaiModelIds(apiKey){
  const now = Date.now();
  if(_xaiModelsCache.ids.length && (now - _xaiModelsCache.ts) < XAI_MODELS_TTL_MS){
    return _xaiModelsCache.ids;
  }
  if(!apiKey) return [];

  try{
    const r = await fetch("https://api.x.ai/v1/models", {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${apiKey}`
      }
    });
    if(!r.ok) return [];

    const j = await r.json().catch(()=>null);
    const ids = Array.isArray(j?.data) ? j.data.map(x => x && x.id).filter(Boolean) : [];
    _xaiModelsCache = { ts: now, ids };
    return ids;
  }catch(e){
    return [];
  }
}

function looksLikeChatModel(id){
  const s = String(id || "").toLowerCase();
  if(s.includes("image")) return false;
  if(s.includes("vision")) return false;
  return true;
}

async function resolveXaiModel(requested, apiKey){
  const req = String(requested || "").trim();
  if(!req) return req;

  const ids = await fetchXaiModelIds(apiKey);

  // 1) exact match
  if(ids.includes(req)) return req;

  // 2) common alias fix: <name>-latest => <name>
  if(req.endsWith("-latest")){
    const base = req.replace(/-latest$/, "");
    if(ids.includes(base)) return base;
    // even if list is empty, base is often the real model id
    if(!ids.length) return base;
  }

  // 3) if list is empty, just return requested (best effort)
  if(!ids.length) return req;

  // 4) pick the first grok chat model available
  const grokChat = ids.find(x => String(x).toLowerCase().includes("grok") && looksLikeChatModel(x));
  if(grokChat) return grokChat;

  // 5) fallback: any chat-like model
  const anyChat = ids.find(x => looksLikeChatModel(x));
  return anyChat || req;
}
// ⭐ Grok helper
async function callGrok(messages, grokModel = "grok-2-latest"){
  const GROK_KEY = getGrokKey();
  if(!GROK_KEY) throw new Error("缺少 GROK_KEY：请在终端 export GROK_KEY=你的xai-key（或 export XAI_API_KEY=你的key）");

  grokModel = await resolveXaiModel(grokModel, GROK_KEY);
  console.log("[xai] resolved model =", grokModel);

  const t0 = Date.now();

  const r = await fetch("https://api.x.ai/v1/chat/completions", {
    method: "POST",
    agent: grokHttpsAgent,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + GROK_KEY
    },
    body: JSON.stringify({
      model: grokModel,
      messages
    })
  });
  console.log("⏱ Grok fetch ms =", Date.now() - t0, "model=", grokModel);

  if(!r.ok){
    const t = await r.text().catch(()=>"");
    throw new Error("Grok 后端错误：" + r.status + " model=" + grokModel + " " + t);
  }

  const t1 = Date.now();
  const data = await r.json();
  console.log("⏱ Grok json ms =", Date.now() - t1);
  return data?.choices?.[0]?.message?.content || "";
}

// ⭐ Grok streaming helper: 把 x.ai 的 stream 转成 SSE 发给前端
async function callGrokStream(messages, res, grokModel = "grok-2-latest"){
  const GROK_KEY = getGrokKey();
  if(!GROK_KEY) throw new Error("缺少 GROK_KEY：请在终端 export GROK_KEY=你的xai-key（或 export XAI_API_KEY=你的key）");

  grokModel = await resolveXaiModel(grokModel, GROK_KEY);
  console.log("[xai] resolved model =", grokModel);

  const controller = new AbortController();
  let firstDeltaAt = 0;
  let firstDeltaTimer = null;
  const FIRST_DELTA_TIMEOUT_MS = 2500;
  let forceFallback = false; // 首字超时触发时置 true

  const t0 = Date.now();
  const r = await fetch("https://api.x.ai/v1/chat/completions", {
    method: "POST",
    agent: grokHttpsAgent,
    signal: controller.signal,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + GROK_KEY
    },
    body: JSON.stringify({
      model: grokModel,
      stream: true,
      messages
    })
  });
  console.log("⏱ Grok fetch ms =", Date.now() - t0, "model=", grokModel);

  if(!r.ok){
    const t = await r.text().catch(()=>"");
    throw new Error("Grok 后端错误：" + r.status + " model=" + grokModel + " " + t);
  }

  const body = r.body;
  if(!body) throw new Error("Grok 没有返回 body");

  try{
    let buffer = "";
    let streamedAny = false;
    let sawDone = false;

    // 如果 2.5 秒内没有任何可解析的 delta，就主动 fallback（避免前端显示“没有返回内容”）
    firstDeltaTimer = setTimeout(async () => {
      try{
        if(firstDeltaAt) return; // 已经有首字
        console.log("⚠️ Grok stream no-delta timeout -> fallback to non-stream");
        forceFallback = true;
        controller.abort();
      }catch(_e){
        // ignore
      }
    }, FIRST_DELTA_TIMEOUT_MS);

    // helper: ONLY accept true incremental deltas (avoid repeating full snapshots)
    const extractDelta = (obj) => {
      const c0 = obj?.choices?.[0];
      const d = c0?.delta;
      if(typeof d?.content === "string") return d.content;
      if(typeof d?.text === "string") return d.text;
      // sometimes content might be array of blocks
      const arr = d?.content;
      if(Array.isArray(arr)){
        const t = arr.map(x => (typeof x === "string" ? x : (x?.text || ""))).join("");
        if(t) return t;
      }
      return null;
    };

    for await (const chunk of body) {
      buffer += chunk.toString("utf8");

      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";

      for (const line of lines) {
        const l = line.trim();
        if(!l) continue;
        if(!l.startsWith("data:")) continue;

        const dataStr = l.slice(5).trim();
        if(dataStr === "[DONE]"){
          sawDone = true;
          break;
        }

        try{
          const obj = JSON.parse(dataStr);
          const delta = extractDelta(obj);
          if(typeof delta === "string" && delta.length){
            streamedAny = true;
            if(!firstDeltaAt){
              firstDeltaAt = Date.now();
              if(firstDeltaTimer) clearTimeout(firstDeltaTimer);
              console.log("✅ Grok first delta ms =", firstDeltaAt - t0, "model=", grokModel);
            }
            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
            res.flush && res.flush();
          }
        }catch(_e){
          // ignore
        }
      }

      if(sawDone) break;
    }

    if(firstDeltaTimer) clearTimeout(firstDeltaTimer);

    // ✅ 如果流式结束但一个字都没拿到：fallback 一次非流式，避免前端显示“没有返回内容”
    if(!streamedAny){
      try{
        const full = await callGrok(messages, grokModel);
        if(full && String(full).trim()){
          res.write(`data: ${JSON.stringify({ delta: String(full) })}\n\n`);
          res.flush && res.flush();
          streamedAny = true;
          console.log("✅ Grok fallback full sent, len=", String(full).length, "model=", grokModel);
        }
      }catch(_e){
        // ignore fallback errors; outer catch will handle
      }
    }

    res.write(`event: done\ndata: {}\n\n`);
  }catch(e){
    if(firstDeltaTimer) clearTimeout(firstDeltaTimer);

    const msg = e?.message || "stream error";
    const isAbort = forceFallback || (String(e?.name || "").toLowerCase().includes("abort")) || (String(msg).toLowerCase().includes("abort"));

    // ✅ 首字超时/Abort：走非流式兜底，不要报错给前端
    if(isAbort){
      try{
        const full = await callGrok(messages, grokModel);
        if(full && String(full).trim()){
          res.write(`data: ${JSON.stringify({ delta: String(full) })}\n\n`);
          res.flush && res.flush();
          console.log("✅ Grok abort-timeout fallback full sent, len=", String(full).length, "model=", grokModel);
        }else{
          res.write(`data: ${JSON.stringify({ delta: "[Grok] 空返回（可能无权限/额度/上游异常）" })}\n\n`);
        }
      }catch(fbErr){
        const fbMsg = fbErr?.message || "fallback error";
        res.write(`data: ${JSON.stringify({ delta: "[Grok Fallback Error] " + fbMsg })}\n\n`);
      }

      res.write(`event: done\ndata: {}\n\n`);
      return;
    }

    // 其他异常：用 SSE 告诉前端并结束，不要抛到外层
    try{
      res.write(`data: ${JSON.stringify({ delta: "[Grok Stream Error] " + msg })}\n\n`);
      res.write(`event: error\ndata: ${JSON.stringify({ message: msg })}\n\n`);
      res.write(`event: done\ndata: {}\n\n`);
    }catch(_e){
      // ignore
    }
  }
}

// health check
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});
// ======= image generation =======
app.post("/api/image", requireApiKey, rateLimit("img", RATE_IMG_MAX), async (req, res) => {
  try{
    const { prompt, mode, model } = req.body || {};

    const useGrok = (
      mode === "infinity" ||
      (typeof model === "string" && model.startsWith("grok-"))
    );

    // ⭐ 优先 Grok 图片生成
    if(useGrok){
      try{
        let grokModel = "grok-imagine-image";
        if(typeof model === "string" && model.trim()){
          const m = model.trim();
          // If caller explicitly passes an image-capable xAI model id, respect it.
          // Otherwise, don’t accidentally pass a chat/vision model into the image endpoint.
          if(m.toLowerCase().includes("image") || m.toLowerCase().includes("imagine")){
            grokModel = m;
          }
        }

        const img = await callGrokImage(prompt, grokModel);
        return res.json({ image: img, provider: "grok" });
      }catch(grokErr){
        console.log("⚠️ Grok 图片失败，fallback OpenAI:", grokErr?.message);
      }
    }

    // ⭐ fallback OpenAI
    const imgModel = "gpt-image-1";
    const dataUrl = await callOpenAIImage(prompt, imgModel);

    return res.json({ image: dataUrl, provider: "openai" });

  }catch(e){
    const status = e?.status || 500;
    return res.status(status).send(e?.message || "image server error");
  }
});

app.post("/api/chat", requireApiKey, rateLimit("chat", RATE_CHAT_MAX), async (req, res) => {
  try {
    const { history, mode, model, stream } = req.body || {};
    const wantStream = !!(stream === true || stream === 1 || stream === "1" || String(stream || "").toLowerCase() === "true");

    // 把历史整理成 messages（简单做法）
    // 用最简单安全的格式（避免 content block 类型错误）
    const input = [];

    if (Array.isArray(history)) {
      for (const m of history) {
        if (!m || !m.role || !m.text) continue;
        const role = (m.role === "system") ? "system" : (m.role === "user" ? "user" : "assistant");
        input.push({ role, content: String(m.text) });
      }
    }

    // ✅ 后端严格：只用 history，不再额外追加 message（否则容易重复/空消息）
    // 去掉末尾连续重复的 user（内容完全相同）
    for (let i = input.length - 1; i > 0; i--) {
      const a = input[i];
      const b = input[i - 1];
      if (!a || !b) continue;
      const at = String(a.content || "").trim();
      const bt = String(b.content || "").trim();
      if (a.role === "user" && b.role === "user" && at && at === bt) {
        input.splice(i, 1);
        break;
      }
      // 只处理末尾连续段
      if (a.role === "user" && b.role !== "user") break;
    }

    // 必须至少有一条 user，否则直接报错
    const lastUser = [...input].reverse().find(m => m && m.role === "user" && String(m.content || "").trim());
    if (!lastUser) throw new Error("history 里没有有效的 user 消息");

    // ⭐ 无尽模式（Grok）
    if(mode === "infinity"){
      const grokModel = (typeof model === "string" && model.startsWith("grok-")) ? model : "grok-2";

      if(wantStream){
        res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        res.setHeader("X-Accel-Buffering", "no");
        res.flushHeaders && res.flushHeaders();
        // 先写一行注释，强制浏览器立刻进入“流”模式，避免缓冲
        res.write(":ok\n\n");

        await callGrokStream(input, res, grokModel);
        return res.end();
      }

      const reply = await callGrok(input, grokModel);
      return res.json({ reply });
    }

    // ✅ 其他模式走 GPT（OpenAI Responses API）
    const gptModel = (typeof model === "string" && model.trim()) ? model : "gpt-5.2";

    if(wantStream){
      res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders && res.flushHeaders();
      res.write(":ok\n\n");

      const gptT0 = Date.now();
      let streamedAny = false;

      try{
        const s = await getOpenAI().responses.create({
          model: gptModel,
          input,
          stream: true
        });

        for await (const event of s) {
          // Only forward incremental text deltas.
          // Other events may contain partial/full snapshots and cause repeats.
          if(event?.type !== "response.output_text.delta") continue;
          const delta = (typeof event?.delta === "string") ? event.delta
            : (typeof event?.output_text_delta === "string") ? event.output_text_delta
            : null;
          if(delta){
            streamedAny = true;
            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
            res.flush && res.flush();
          }
        }
      }catch(e){
        console.log("[gpt-stream] fallback:", e?.message || e);
      }

      // fallback: no deltas -> send full text as one chunk
      if(!streamedAny){
        const resp = await getOpenAI().responses.create({ model: gptModel, input });
        const full = resp.output_text || "";
        res.write(`data: ${JSON.stringify({ delta: full })}\n\n`);
      }

      console.log("⏱ GPT responses ms =", Date.now() - gptT0, "model=", gptModel, "input_len=", Array.isArray(input) ? input.length : 0);
      res.write(`event: done\ndata: {}\n\n`);
      return res.end();
    }

    const gptT0 = Date.now();
    const resp = await getOpenAI().responses.create({
      model: gptModel,
      input
    });
    console.log("⏱ GPT responses ms =", Date.now() - gptT0, "model=", gptModel, "input_len=", Array.isArray(input) ? input.length : 0);

    res.json({ reply: resp.output_text || "" });
  } catch (e) {
    // 如果已经开始 SSE/写入了 body，就不能再 setHeader/status/send
    if(res.headersSent){
      try{
        const msg = e?.message || "server error";
        // 兼容前端只解析 data: 的情况：也发一条 delta
        res.write(`data: ${JSON.stringify({ delta: "[Server Error] " + msg })}\n\n`);
        res.write(`event: error\ndata: ${JSON.stringify({ message: msg })}\n\n`);
        res.write(`event: done\ndata: {}\n\n`);
      }catch(_e){
        // ignore
      }
      return res.end();
    }

    const status = e?.status || 500;
    return res.status(status).send(e?.message || "server error");
  }
});

const PORT = process.env.PORT || 8787;

app.listen(PORT, "0.0.0.0", () => {
  console.log("✅ Backend running on port:", PORT);
  console.log("✅ Ping route ready: GET /api/ping");
});
