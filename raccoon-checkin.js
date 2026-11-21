/*
 * 小浣熊每日签到（Surge cron 专用） v1.0
 * 每日 00:12 自动登录+查询发放，结果走 Bark/Server酱 webhook 推送（可选）
 * 不依赖反代模块，重复签到幂等：只看今日账单是否入账
 */
var A = normalizeArg(typeof $argument === "undefined" ? null : $argument);
var AUTH = "https://xiaohuanxiong.com/api/web/auth/v1";
var ENC_KEY = "senseraccoon2023";
var TS_KEY = "raccoon_openai_tokens";
var TODAY_KEY = "raccoon_checkin_last";

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
  var o = {};
  v.split(",").forEach(function (p) {
    var i = p.indexOf("=");
    if (i > 0) {
      var k = p.slice(0, i).trim(), val = p.slice(i + 1).trim();
      if (val && val !== "none" && val !== "REPLACE_ME") o[k] = val;
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
function fromB64(s) {
  if (typeof atob === "function") { try { return atob(s); } catch (e) {} }
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

// ---------- 官方 AES-CFB128（随机16字节IV前置） ----------
function encryptField(s) {
  var key = [];
  for (var i = 0; i < 16; i++) key.push(ENC_KEY.charCodeAt(i % ENC_KEY.length));
  var iv = [];
  for (var j = 0; j < 16; j++) iv.push(Math.floor(Math.random() * 256));
  // 手动 AES-128-CFB 实现（内置表）
  var expanded = keyExpansion(key);
  var block = 16, prev = iv.slice(), ctext = [];
  for (var b = 0; b < s.length; b += block) {
    var enc = encryptBlock(prev, expanded);
    for (var k = 0; k < block && b + k < s.length; k++) {
      var byte = s.charCodeAt(b + k) ^ enc[k];
      ctext.push(byte);
      prev[k] = byte;
    }
  }
  return b64(iv.concat(ctext));
}
function keyExpansion(key) {
  var sbox = SBOX();
  var rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  var w = [];
  for (var i = 0; i < 16; i++) w.push(key[i]);
  for (i = 4; i < 44; i++) {
    var t = w.slice((i - 1) * 4, i * 4);
    if (i % 4 === 0) {
      t = [t[1], t[2], t[3], t[0]];
      for (var j = 0; j < 4; j++) t[j] = sbox[t[j]];
      t[0] ^= rcon[(i / 4) - 1];
    }
    for (j = 0; j < 4; j++) w.push(w[(i - 4) * 4 + j] ^ t[j]);
  }
  return w;
}
function encryptBlock(input, w) {
  var sbox = SBOX();
  var state = input.slice();
  for (var i = 0; i < 16; i++) state[i] ^= w[i];
  for (var round = 1; round < 10; round++) {
    for (i = 0; i < 16; i++) state[i] = sbox[state[i]];
    state = shiftRows(state);
    state = mixColumns(state);
    for (i = 0; i < 16; i++) state[i] ^= w[round * 16 + i];
  }
  for (i = 0; i < 16; i++) state[i] = sbox[state[i]];
  state = shiftRows(state);
  for (i = 0; i < 16; i++) state[i] ^= w[160 + i];
  return state;
}
function shiftRows(s) {
  return [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
          s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]];
}
function mixColumns(s) {
  var out = [];
  for (var c = 0; c < 4; c++) {
    var b = c * 4;
    var a0 = s[b], a1 = s[b + 1], a2 = s[b + 2], a3 = s[b + 3];
    out[b] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    out[b + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    out[b + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    out[b + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }
  return out;
}
function gmul(a, b) {
  var p = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}
function SBOX() {
  var sbox = []; var p = 1, q = 1;
  do {
    p = p ^ ((p << 1) & 0xff) ^ ((p & 0x80) ? 0x1b : 0);
    q ^= (q << 1) & 0xff; q ^= (q & 0x80) ? 0x09 : 0;
    var xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
    sbox[p] = xformed ^ 0x63;
  } while (p !== 1);
  sbox[0] = 0x63;
  return sbox;
}
function rotl8(x, n) { return ((x << n) | (x >>> (8 - n))) & 0xff; }

// ---------- token ----------
function loadTokens() {
  try { return JSON.parse($persistentStore.read(TS_KEY) || "null"); } catch (e) { return null; }
}
function saveTokens(access, refresh) {
  try { $persistentStore.write(JSON.stringify({ access: access, refresh: refresh, at: Date.now() }), TS_KEY); } catch (e) {}
}
function login(cb) {
  if (!A.phone || !A.password) return cb(new Error("模块未配置 phone/password（或直接填 token）"), null);
  $httpClient.post(
    {
      url: AUTH + "/login_with_password",
      headers: { "Content-Type": "application/json", "X-Client-Platform": "desktop-windows", "X-Client-Version": "v1.0.0", "X-Raccoon-Language": "zh" },
      body: JSON.stringify({ nation_code: A.nation || "86", phone: encryptField(A.phone), password: encryptField(A.password) }),
      timeout: 20,
    },
    function (err, resp, data) {
      if (err) return cb(new Error("登录请求失败: " + err), null);
      var j; try { j = JSON.parse(data); } catch (e) { return cb(new Error("登录响应解析失败"), null); }
      if (!j.data || !j.data.access_token) return cb(new Error("登录失败 " + (j.code || "") + ": " + (j.message || "未知错误")), null);
      saveTokens(j.data.access_token, j.data.refresh_token || "");
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
  if (A.token) return cb(null, A.token.replace(/^Bearer\s+/i, ""));
  var t = loadTokens();
  if (!t || !t.access) return login(cb);
  var exp = jwtExp(t.access);
  if (exp && exp < Date.now() + 120000) {
    if (t.refresh) {
      $httpClient.post(
        { url: AUTH + "/refresh", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: t.refresh }), timeout: 20 },
        function (err, resp, data) {
          if (err) return login(cb);
          var j; try { j = JSON.parse(data); } catch (e) { return login(cb); }
          if (!j.data || !j.data.access_token) return login(cb);
          saveTokens(j.data.access_token, j.data.refresh_token || t.refresh);
          cb(null, j.data.access_token);
        }
      );
      return;
    }
    return login(cb);
  }
  cb(null, t.access);
}

// ---------- 签到 ----------
function beijingToday() { return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10); }
function requestJson(method, path2, token, headers, cb) {
  var h = { Accept: "application/json", Authorization: "Bearer " + token };
  for (var k in headers) h[k] = headers[k];
  var opt = { url: "https://xiaohuanxiong.com" + path2, headers: h, timeout: 25 };
  var fn = method === "POST" ? $httpClient.post : $httpClient.get;
  fn(opt, function (err, resp, data) {
    if (err) return cb(new Error("网络失败: " + err), null);
    if (resp && resp.status === 429) return cb(new Error("上游限流(429)"), null);
    if (resp && resp.status === 401) return cb(new Error("登录态已过期(401)"), null);
    if (!resp || resp.status !== 200) return cb(new Error("HTTP " + (resp ? resp.status : 0)), null);
    var j; try { j = JSON.parse(data); } catch (e) { return cb(new Error("响应解析失败"), null); }
    if (typeof j.code === "number" && j.code !== 0) return cb(new Error(j.message || ("code=" + j.code)), null);
    cb(null, j.data !== undefined && j.data !== null ? j.data : j);
  });
}
function toastText(data) {
  if (!data) return "";
  var parts = [];
  ["point_grant_toast", "point_grant_popups"].forEach(function (k) {
    var v = data[k];
    if (v === undefined || v === null) return;
    parts.push(typeof v === "string" ? v : JSON.stringify(v).slice(0, 200));
  });
  return parts.join(" | ");
}
function runCheckin(cb) {
  ensureToken(function (e, token) {
    if (e) return cb({ ok: false, title: "小浣熊签到失败", subtitle: e.message, body: "" });
    requestJson("GET", "/api/web/office/v3/setting_info", token, { "X-Client-Platform": "desktop-windows", "X-Client-Version": "v1.0.0", "X-Raccoon-Language": "zh" }, function (err1, info) {
      var grantNote = err1 ? ("发放接口: " + err1.message) : toastText(info);
      requestJson("GET", "/api/web/points/v1/bills?paging.limit=20&paging.offset=0", token, {}, function (err2, bills) {
        var sum = 0, names = [], today = beijingToday();
        for (var i = 0; i < ((bills && bills.items) || []).length; i++) {
          var it = bills.items[i];
          var pts = Number(it.points || 0);
          if (pts > 0 && String(it.created_at || "").slice(0, 10) === today) {
            sum += pts; names.push((it.event_name || "积分") + " +" + pts);
          }
        }
        requestJson("GET", "/api/web/points/v1/balance", token, {}, function (err3, bal) {
          var wallets = [];
          if (bal && typeof bal === "object") {
            var pairs = [["daily_points", "每日"], ["monthly_points", "会员"], ["reward_points", "奖励"], ["topup_points", "充值"]];
            for (var j = 0; j < pairs.length; j++) {
              var v = Number(bal[pairs[j][0]]);
              if (!isNaN(v)) wallets.push(pairs[j][1] + " " + v);
            }
          }
          var avail = bal ? Number(bal.available_points) : NaN;
          var balanceLine = isNaN(avail) ? (err3 ? "余额查询失败: " + err3.message : "") : ("总余额 " + avail + "（" + wallets.join(" / ") + "）");
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
function sendWebhook(r) {
  if (!A.webhook) return;
  var title = encodeURIComponent(r.title);
  var body = encodeURIComponent(r.subtitle + " " + r.body);
  var url = A.webhook
    .replace("{title}", title).replace("{body}", body)
    .replace("TITLE", title).replace("BODY", body);
  $httpClient.post({ url: url, timeout: 15 }, function () {});
}
function main() {
  try {
    runCheckin(function (r) {
      console.log("[raccoon-checkin] " + JSON.stringify(r));
      sendWebhook(r);
      $done({});
    });
  } catch (e) {
    console.log("[raccoon-checkin] error: " + e.message);
    $done({});
  }
}
main();
