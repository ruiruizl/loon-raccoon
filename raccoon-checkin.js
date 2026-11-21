/*
 * 小浣熊每日签到（Surge cron） v2.0
 * 简单可靠：每天 00:12 调本机网关 /v1/checkin（Python 加密登录已实测），
 * 结果可选推送到 Bark/Server酱（webhook 参数）。
 * 前置：iSH 网关运行中（/var/minis/workspace/raccoon2api2/start.sh）
 */
var A = normalizeArg(typeof $argument === "undefined" ? null : $argument);
var GW = "http://127.0.0.1:" + (A.port || "18621");

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

function sendWebhook(title, body) {
  if (!A.webhook) return;
  var t = encodeURIComponent(title);
  var b = encodeURIComponent(body);
  var url = A.webhook.replace("{title}", t).replace("{body}", b);
  $httpClient.post({ url: url, timeout: 15 }, function () {});
}

function main() {
  $httpClient.get(
    { url: GW + "/v1/checkin", timeout: 30 },
    function (err, resp, data) {
      var title, body;
      if (err) {
        title = "小浣熊签到失败";
        body = "网关连接失败: " + err + "（iSH 网关未运行？跑 start.sh）";
        console.log("[raccoon-checkin] " + title + " " + body);
        sendWebhook(title, body);
        $done({});
        return;
      }
      if (!resp || resp.status !== 200) {
        title = "小浣熊签到失败";
        body = "HTTP " + (resp ? resp.status : 0);
        console.log("[raccoon-checkin] " + body);
        sendWebhook(title, body);
        $done({});
        return;
      }
      var j;
      try { j = JSON.parse(data); } catch (e) { j = {}; }
      title = j.title || "小浣熊签到";
      body = (j.subtitle || "") + " " + (j.body || "");
      console.log("[raccoon-checkin] " + JSON.stringify(j));
      sendWebhook(title, body);
      $done({});
    }
  );
}
main();
