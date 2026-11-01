/*
 * Raccoon OpenAI Proxy for Loon (v5 · 限流感知版 · 修复顶层 return)
 * v4 失败根因：入口处使用顶层 return，Loon JS 引擎编译失败 -> 脚本不执行 -> 请求放行 -> 官网 404。
 * v5：全部分支封装为函数，仅顶层调用 main()，无顶层 return；整体 try/catch 兜底。
 * 保留 v4 能力：接管响应、429 熔断、并发控制、网络/5xx 自动重试、多 token 轮换。
 */
var A = normalizeArg(typeof $argument === "undefined" ? null : $argument);
var AUTH = "https://xiaohuanxiong.com/api/web/auth/v1";
var LLM = "https://xiaohuanxiong.com/api/web/llm/v2";
var ENC_KEY = "senseraccoon2023";
var TS_KEY = "raccoon_openai_tokens";
var CAT_KEY = "raccoon_openai_catalog";
var CAT_TTL = 10 * 60 * 1000;
var INFLIGHT_KEY = "raccoon_openai_inflight";
var MAX_CONCURRENCY = Math.max(1, parseInt(A.max_concurrency || "3", 10));

var FALLBACK_MODELS = [
  { id: "raccoon-8c4485", name: "Raccoon-Work" },
  { id: "raccoon-chat-ml-5-5", name: "Raccoon Chat (默认)" },
  { id: "raccoon-19b265", name: "Raccoon-Work-260817-A" },
  { id: "raccoon-405a1c", name: "Raccoon-Work-260817-B" },
  { id: "sn-sensenova-6-8-flash-lite", name: "SenseNova 6.8 Flash Lite" },
  { id: "sn-glm-5-3-flash", name: "GLM-5.3 Flash" },
];

function normalizeArg(v) {
  if (v === null || typeof v === "undefined") return {};
  if (typeof v === "object") {
    var o = {};
    for (var k in v) {
      if (Object.prototype.hasOwnProperty.call(v, k)) {
        var raw = v[k];
        if (raw === null || typeof raw === "undefined") continue;
        var s = String(raw).trim();
        if (s && s !== "none" && s !== "REPLACE_ME") o[k] = s;
      }
    }
    return o;
  }
  return parseArg(String(v));
}
function fromB64(s) {
  if (typeof atob === "function") {
    try { return atob(s); } catch (e) {}
  }
  var t = String(s).replace(/[^A-Za-z0-9+/]/g, "");
  var out = "";
  for (var i = 0; i < t.length; i += 4) {
    var n = (B64T.indexOf(t[i]) << 18) | (B64T.indexOf(t[i + 1]) << 12) |
      ((t[i + 2] ? B64T.indexOf(t[i + 2]) : 0) << 6) | (t[i + 3] ? B64T.indexOf(t[i + 3]) : 0);
    out += String.fromCharCode((n >> 16) & 255);
    if (t[i + 2]) out += String.fromCharCode((n >> 8) & 255);
    if (t[i + 3]) out += String.fromCharCode(n & 255);
  }
  return out;
}
function mergeHeaders(src, over) {
  var out = {};
  var skip = { host: 1, "content-length": 1, "accept-encoding": 1 };
  for (var k in (src || {})) {
    if (!skip[String(k).toLowerCase()]) out[k] = src[k];
  }
  for (var k2 in over) out[k2] = over[k2];
  return out;
}

/* AES-128-CFB 加密（等价 CryptoJS） */
function gfMul(a, b) {
  var r = 0;
  while (b) {
    if (b & 1) r ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return r;
}
function gfInv(x) {
  if (!x) return 0;
  var r = 1;
  for (var e = 0; e < 8; e++) {
    if ((254 >> e) & 1) r = gfMul(r, x);
    x = gfMul(x, x);
  }
  return r;
}
function rotl(x, n) { return ((x << n) | (x >> (8 - n))) & 0xff; }
var SBOX = (function () {
  var s = new Uint8Array(256);
  for (var i = 0; i < 256; i++) {
    var v = gfInv(i);
    s[i] = v ^ rotl(v, 1) ^ rotl(v, 2) ^ rotl(v, 3) ^ rotl(v, 4) ^ 0x63;
  }
  return s;
})();
function expandKey(k) {
  var w = new Uint8Array(176);
  w.set(k);
  var rcon = 1;
  for (var i = 16; i < 176; i += 4) {
    var t0 = w[i - 4], t1 = w[i - 3], t2 = w[i - 2], t3 = w[i - 1];
    if (i % 16 === 0) {
      var t = t0;
      t0 = SBOX[t1] ^ rcon; t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[t];
      rcon = gfMul(rcon, 2);
    }
    w[i] = w[i - 16] ^ t0; w[i + 1] = w[i - 15] ^ t1;
    w[i + 2] = w[i - 14] ^ t2; w[i + 3] = w[i - 13] ^ t3;
  }
  return w;
}
function encBlock(w, b) {
  for (var j = 0; j < 16; j++) b[j] ^= w[j];
  for (var round = 1; round <= 10; round++) {
    for (var j2 = 0; j2 < 16; j2++) b[j2] = SBOX[b[j2]];
    var t = b[1]; b[1] = b[5]; b[5] = b[9]; b[9] = b[13]; b[13] = t;
    t = b[2]; b[2] = b[10]; b[10] = t; t = b[6]; b[6] = b[14]; b[14] = t;
    t = b[15]; b[15] = b[11]; b[11] = b[7]; b[7] = b[3]; b[3] = t;
    if (round < 10) {
      for (var c = 0; c < 4; c++) {
        var i2 = c * 4;
        var a0 = b[i2], a1 = b[i2 + 1], a2 = b[i2 + 2], a3 = b[i2 + 3];
        var x = a0 ^ a1 ^ a2 ^ a3;
        b[i2] ^= x ^ gfMul(a0 ^ a1, 2);
        b[i2 + 1] ^= x ^ gfMul(a1 ^ a2, 2);
        b[i2 + 2] ^= x ^ gfMul(a2 ^ a3, 2);
        b[i2 + 3] ^= x ^ gfMul(a3 ^ a0, 2);
      }
    }
    for (var j3 = 0; j3 < 16; j3++) b[j3] ^= w[round * 16 + j3];
  }
}
function randomBytes(n) {
  var a = new Uint8Array(n);
  for (var i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
  return a;
}
function utf8Bytes(s) {
  var out = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c >= 0xd800 && c <= 0xdbff) {
      var c2 = s.charCodeAt(++i);
      c = 0x10000 | ((c - 0xd800) << 10) | (c2 - 0xdc00);
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}
function encryptField(plain) {
  var key = expandKey(utf8Bytes(ENC_KEY));
  var pt = utf8Bytes(plain);
  var iv = randomBytes(16);
  var out = new Uint8Array(16 + pt.length);
  out.set(iv);
  var prev = iv;
  for (var off = 0; off < pt.length; off += 16) {
    var ks = prev.slice(0);
    encBlock(key, ks);
    var n = Math.min(16, pt.length - off);
    var ctBlock = new Uint8Array(16);
    for (var i = 0; i < n; i++) {
      ctBlock[i] = pt[off + i] ^ ks[i];
      out[16 + off + i] = ctBlock[i];
    }
    prev = ctBlock;
  }
  return b64(out);
}

function parseArg(s) {
  var o = {};
  s.split(/[&|]/).forEach(function (p) {
    var i = p.indexOf("=");
    if (i > 0) {
      var k = p.slice(0, i).trim();
      var v = (p.slice(i + 1) || "").trim();
      if (v && v !== "none" && v !== "REPLACE_ME") o[k] = v;
    }
  });
  return o;
}
var B64T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i += 3) {
    var n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += B64T[(n >> 18) & 63] + B64T[(n >> 12) & 63] +
      (i + 1 < bytes.length ? B64T[(n >> 6) & 63] : "=") +
      (i + 2 < bytes.length ? B64T[n & 63] : "=");
  }
  return out;
}
function jsonResp(status, obj) {
  $done({
    response: {
      status: status,
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(obj),
    },
  });
}
function errResp(status, message, type) {
  jsonResp(status, { error: { message: message, type: type || "raccoon_proxy_error" } });
}
function loadTokens() {
  try { return JSON.parse($persistentStore.read(TS_KEY) || "null"); } catch (e) { return null; }
}
function saveTokens(access, refresh) {
  try { $persistentStore.write(JSON.stringify({ access: access, refresh: refresh, at: Date.now() }), TS_KEY); } catch (e) {}
}
function tokenList() {
  var direct = A.token ? A.token.split(",").map(function (s) { return s.trim(); }).filter(function (x) { return x; }) : [];
  var cached = loadTokens();
  var c = cached && cached.access ? (Array.isArray(cached.access) ? cached.access : [cached.access]) : [];
  var all = direct.concat(c);
  if (!all.length) return [];
  var uniq = [];
  var seen = {};
  for (var i = 0; i < all.length; i++) {
    var k = String(all[i]).replace(/^Bearer\s+/i, "");
    if (k && !seen[k]) { seen[k] = 1; uniq.push(k); }
  }
  return uniq;
}
function pickToken() {
  var ts = tokenList();
  if (!ts.length) return null;
  return ts[Math.floor(Math.random() * ts.length)];
}

function inflightCount() {
  try { return parseInt($persistentStore.read(INFLIGHT_KEY) || "0", 10) || 0; } catch (e) { return 0; }
}
function inflightAdd(d) {
  var n = Math.max(0, inflightCount() + d);
  try { $persistentStore.write(String(n), INFLIGHT_KEY); } catch (e) {}
  return n;
}

function login(cb) {
  if (!A.phone || !A.password) {
    cb(new Error("模块未配置 phone/password（或直接填 token）"), null);
    return;
  }
  var body = JSON.stringify({
    nation_code: A.nation || "86",
    phone: encryptField(A.phone),
    password: encryptField(A.password),
  });
  $httpClient.post(
    { url: AUTH + "/login_with_password", headers: { "Content-Type": "application/json" }, body: body },
    function (err, resp, data) {
      if (err) return cb(new Error("登录请求失败: " + err), null);
      var j;
      try { j = JSON.parse(data); } catch (e) { return cb(new Error("登录响应解析失败"), null); }
      if (!j.data || !j.data.access_token) {
        return cb(new Error("登录失败 " + (j.code || "") + ": " + (j.message || j.details || "未知错误")), null);
      }
      saveTokens(j.data.access_token, j.data.refresh_token || "");
      cb(null, j.data.access_token);
    }
  );
}
function refreshToken(cb) {
  var t = loadTokens();
  if (!t || !t.refresh) return login(cb);
  $httpClient.post(
    {
      url: AUTH + "/refresh",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: t.refresh }),
      timeout: 20000,
    },
    function (err, resp, data) {
      if (err) return login(cb);
      var j;
      try { j = JSON.parse(data); } catch (e) { return login(cb); }
      if (!j.data || !j.data.access_token) return login(cb);
      saveTokens(j.data.access_token, j.data.refresh_token || t.refresh);
      cb(null, j.data.access_token);
    }
  );
}
function jwtExp(token) {
  try {
    var parts = token.split(".");
    if (parts.length < 2) return 0;
    var b = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    var pad = b + "===".slice((b.length + 3) % 4);
    var json = decodeURIComponent(fromB64(pad).split("").map(function (c) {
      return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(""));
    return Number(JSON.parse(json).exp || 0) * 1000;
  } catch (e) { return 0; }
}
function ensureToken(cb) {
  var ts = tokenList();
  if (ts.length > 1) {
    for (var i = 0; i < ts.length; i++) {
      var exp = jwtExp(ts[i]);
      if (exp && exp > Date.now() + 120000) return cb(null, ts[i]);
    }
    if (!ts.length) return login(cb);
    var t = loadTokens();
    if (t && t.refresh) return refreshToken(cb);
    return login(cb);
  }
  if (A.token) return cb(null, A.token.replace(/^Bearer\s+/i, ""));
  var t2 = loadTokens();
  if (!t2 || !t2.access) return login(cb);
  var exp2 = jwtExp(t2.access);
  if (exp2 && exp2 < Date.now() + 120000) return refreshToken(cb);
  cb(null, t2.access);
}

function loadCatalog() {
  try { return JSON.parse($persistentStore.read(CAT_KEY) || "null"); } catch (e) { return null; }
}
function parseCatalog(payload) {
  var data = payload && payload.data && typeof payload.data === "object" ? payload.data : payload;
  var out = [];
  var seen = {};
  for (var i = 0; i < ((data && data.categories) || []).length; i++) {
    var cat = data.categories[i];
    for (var j = 0; j < ((cat && cat.models) || []).length; j++) {
      var m = cat.models[j];
      var id = String((m && (m.name || m.model_name)) || "").trim();
      if (!id || seen[id]) continue;
      seen[id] = 1;
      out.push({ id: id, name: String((m && (m.displayName || m.description)) || id).slice(0, 64) });
    }
  }
  return out;
}
function getCatalog(token, cb) {
  var cached = loadCatalog();
  if (cached && cached.models && cached.models.length && Date.now() - cached.at < CAT_TTL) {
    return cb(null, cached.models);
  }
  $httpClient.get(
    { url: LLM + "/model_catalog", headers: { Authorization: "Bearer " + token, Accept: "application/json" }, timeout: 15000 },
    function (err, resp, data) {
      var models = [];
      if (!err && resp && resp.status === 200) {
        try { models = parseCatalog(JSON.parse(data)); } catch (e) { models = []; }
      }
      if (models.length) {
        try { $persistentStore.write(JSON.stringify({ models: models, at: Date.now() }), CAT_KEY); } catch (e) {}
        return cb(null, models);
      }
      if (cached && cached.models && cached.models.length) return cb(null, cached.models);
      cb(null, FALLBACK_MODELS);
    }
  );
}
function mapModel(m) {
  var k = (m || "").toLowerCase().replace(/[^a-z0-9.]/g, "");
  if (!k) return "raccoon-chat-ml-5-5";
  if (k.indexOf("glm") >= 0) return "sn-glm-5-3-flash";
  if (k.indexOf("raccoon") >= 0 || k.indexOf("office") >= 0) {
    var cat = loadCatalog();
    if (cat && cat.models) {
      for (var i = 0; i < cat.models.length; i++) {
        if (cat.models[i].id.toLowerCase() === (m || "").toLowerCase()) return cat.models[i].id;
      }
    }
    if (k === "officeraccoondefault") return "raccoon-chat-ml-5-5";
  }
  return m;
}

function beijingToday() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
function desktopHeaders() {
  return { "X-Client-Platform": "desktop-windows", "X-Client-Version": "v1.0.0", "X-Raccoon-Language": "zh" };
}
function toastText(data) {
  if (!data) return "";
  var parts = [];
  var keys = ["point_grant_toast", "point_grant_popups"];
  for (var i = 0; i < keys.length; i++) {
    var v = data[keys[i]];
    if (v === undefined || v === null) continue;
    try { parts.push(typeof v === "string" ? v : JSON.stringify(v).slice(0, 200)); } catch (e) {}
  }
  return parts.join(" | ");
}
function requestJson(method, path2, token, headers, timeout, cb) {
  var h = { Accept: "application/json", Authorization: "Bearer " + token };
  for (var k in headers) h[k] = headers[k];
  var opt = { url: "https://xiaohuanxiong.com" + path2, headers: h, timeout: (timeout || 20) * 1000 };
  var fn = method === "POST" ? $httpClient.post : $httpClient.get;
  fn(opt, function (err, resp, data) {
    if (err) return cb(new Error("网络失败: " + err), null);
    if (resp && resp.status === 429) return cb(new Error("上游限流(429)"), null);
    if (resp && resp.status === 401) return cb(new Error("登录态已过期（401）"), null);
    if (!resp || resp.status !== 200) return cb(new Error("HTTP " + (resp ? resp.status : 0)), null);
    var j;
    try { j = JSON.parse(data); } catch (e) { return cb(new Error("响应解析失败"), null); }
    if (typeof j.code === "number" && j.code !== 0) return cb(new Error(j.message || ("code=" + j.code)), null);
    cb(null, j.data !== undefined && j.data !== null ? j.data : j);
  });
}
function runCheckin(cb) {
  ensureToken(function (e, token) {
    if (e) return cb({ ok: false, title: "小浣熊签到失败", subtitle: e.message, body: "" });
    requestJson("GET", "/api/web/office/v3/setting_info", token, desktopHeaders(), 20, function (err1, info) {
      var grantNote = err1 ? ("发放接口: " + err1.message) : toastText(info);
      requestJson("GET", "/api/web/points/v1/bills?paging.limit=20&paging.offset=0", token, {}, 25, function (err2, bills) {
        var sum = 0;
        var names = [];
        var today = beijingToday();
        for (var i = 0; i < ((bills && bills.items) || []).length; i++) {
          var it = bills.items[i];
          var pts = Number(it.points || 0);
          var createdAt = String(it.created_at || "");
          if (pts > 0 && createdAt.slice(0, 10) === today) {
            sum += pts;
            names.push((it.event_name || "积分") + " +" + pts);
          }
        }
        requestJson("GET", "/api/web/points/v1/balance", token, {}, 20, function (err3, bal) {
          var wallets = [];
          if (bal && typeof bal === "object") {
            var pairs = [["daily_points", "每日"], ["monthly_points", "会员"], ["reward_points", "奖励"], ["topup_points", "充值"]];
            for (var j = 0; j < pairs.length; j++) {
              var v = Number(bal[pairs[j][0]]);
              if (!isNaN(v)) wallets.push(pairs[j][1] + " " + v);
            }
          }
          var avail = bal ? Number(bal.available_points) : NaN;
          var balanceLine = isNaN(avail)
            ? (err3 ? "余额查询失败: " + err3.message : "")
            : ("总余额 " + avail + "（" + wallets.join(" / ") + "）");
          var r = { ok: sum > 0, today: today, sum: sum, entries: names, balance: isNaN(avail) ? null : avail, wallets: wallets, grant_note: grantNote, err_grant: err1 && err1.message, err_bills: err2 && err2.message, err_balance: err3 && err3.message };
          if (sum > 0) {
            r.title = "小浣熊签到成功"; r.subtitle = "今日 +" + sum + " · " + (isNaN(avail) ? "余额未知" : "余额 " + avail);
            r.body = (names.join("；") + (balanceLine ? "；" + balanceLine : "")) + (grantNote ? "（" + grantNote + "）" : "");
          } else if (err1 && err2) {
            r.title = "小浣熊签到失败"; r.subtitle = "发放与账单查询均失败"; r.body = r.err_grant + "；" + r.err_bills;
          } else {
            r.title = "小浣熊签到"; r.subtitle = "账单未见今日入账" + (isNaN(avail) ? "" : " · 余额 " + avail);
            r.body = grantNote || (err2 ? "账单: " + r.err_bills : "可能今日已领过或发放延迟");
          }
          cb(r);
        });
      });
    });
  });
}

function upstreamChat(token, reqBody, attempt, cb) {
  var headers = {
    "Content-Type": "application/json",
    Accept: "*/*",
    Authorization: "Bearer " + token,
    "X-Client-Platform": "desktop-windows",
    "X-Client-Version": "v1.0.0",
    "X-Raccoon-Language": "zh",
  };
  var opt = {
    url: LLM + "/chat/completions",
    headers: headers,
    body: JSON.stringify(reqBody),
    timeout: 300000,
  };
  $httpClient.post(opt, function (err, resp, data) {
    if (err) {
      if (attempt < 1) return upstreamChat(token, reqBody, attempt + 1, cb);
      return cb({ status: 502, body: { error: { message: "上游网络失败: " + err, type: "upstream_error" } } });
    }
    var st = resp ? resp.status : 0;
    if (st === 429) {
      return cb({ status: 429, body: { error: { message: "小浣熊上游限流(429): " + String(data || "").slice(0, 200), type: "rate_limit" } } });
    }
    if (st >= 500) {
      if (attempt < 1) return upstreamChat(token, reqBody, attempt + 1, cb);
      return cb({ status: 502, body: { error: { message: "上游 5xx(" + st + ")", type: "upstream_error" } } });
    }
    var outH = {};
    for (var k in (resp.headers || {})) {
      var kl = String(k).toLowerCase();
      if (kl === "content-length" || kl === "transfer-encoding" || kl === "connection" || kl === "keep-alive") continue;
      outH[k] = resp.headers[k];
    }
    cb({ status: st, headers: outH, body: data });
  });
}

function handleChat() {
  if (inflightCount() >= MAX_CONCURRENCY) {
    errResp(429, "小浣熊反代并发超限(" + MAX_CONCURRENCY + ")，请降低并发", "rate_limit");
    return;
  }
  inflightAdd(1);
  ensureToken(function (e, token) {
    if (e) {
      inflightAdd(-1);
      errResp(401, "小浣熊代理: " + e.message);
      return;
    }
    var reqBody;
    try { reqBody = JSON.parse($request.body || "{}"); } catch (err) {
      inflightAdd(-1);
      errResp(400, "请求体不是合法 JSON");
      return;
    }
    reqBody.model = mapModel(reqBody.model);
    upstreamChat(token, reqBody, 0, function (res) {
      inflightAdd(-1);
      if (res.status === 429 || res.status >= 500) {
        jsonResp(res.status, res.body);
      } else {
        $done({ response: { status: res.status, headers: res.headers || { "Content-Type": "text/event-stream; charset=utf-8" }, body: res.body } });
      }
    });
  });
}
function handleModels() {
  ensureToken(function (e, token) {
    if (e) {
      jsonResp(200, {
        object: "list",
        data: FALLBACK_MODELS.map(function (m) { return { id: m.id, object: "model", owned_by: "sensetime" }; }),
      });
      return;
    }
    getCatalog(token, function (e2, models) {
      jsonResp(200, {
        object: "list",
        data: (models.length ? models : FALLBACK_MODELS).map(function (m) {
          return { id: m.id, object: "model", owned_by: "sensetime" };
        }),
      });
    });
  });
}
function handleCheckin() {
  runCheckin(function (r) { jsonResp(200, r); });
}
function handleProbe() {
  ensureToken(function (e, token) {
    if (e) { errResp(401, "token: " + e.message); return; }
    $httpClient.get(
      { url: LLM + "/model_catalog", headers: { Authorization: "Bearer " + token, Accept: "application/json" }, timeout: 15000 },
      function (err, resp, data) {
        jsonResp(200, {
          http: resp ? resp.status : 0,
          token_head: token.slice(0, 12),
          body_head: String(data || err || "").slice(0, 3000),
        });
      }
    );
  });
}
function handleReset() {
  jsonResp(200, { ok: true, message: "脚本已无熔断机制（429 原样透传）" });
}

function main() {
  try {
    if (typeof $request === "undefined" || !$request || !$request.url) {
      runCheckin(function (r) {
        $notification.post(r.title, r.subtitle, r.body || "");
        console.log("[raccoon-checkin] " + JSON.stringify(r));
        $done({});
      });
      return;
    }
    var path = $request.url.split("?")[0];
    if (/\/chat\/completions\/?$/.test(path)) {
      handleChat();
    } else if (/\/models\/?$/.test(path)) {
      handleModels();
    } else if (/\/checkin\/?$/.test(path)) {
      handleCheckin();
    } else if (/\/probe\/?$/.test(path)) {
      handleProbe();
    } else if (/\/reset\/?$/.test(path)) {
      handleReset();
    } else {
      errResp(404, "Raccoon OpenAI Proxy: 支持 /v1/models、/v1/chat/completions、/v1/checkin、/v1/probe、/v1/reset");
    }
  } catch (e) {
    try { errResp(500, "脚本内部异常: " + e); } catch (e2) {}
  }
}
main();
