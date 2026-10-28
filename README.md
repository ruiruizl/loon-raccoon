# 小浣熊 OpenAI 反代 · Loon 版

把 Surge 模块 [小浣熊OpenAI反代.sgmodule](https://github.com/LinkPass888/Surge/blob/main/sgmodule/%E5%B0%8F%E6%B5%A3%E7%86%8AOpenAI%E5%8F%8D%E4%BB%A3.sgmodule) 移植成 Loon 插件。
GitHub 上没有现成的 Loon 版（只有 Surge 原版，以及几个 Go 写的独立网关），所以这份是逐行适配移植的产物。

## 文件清单

| 文件 | 作用 |
| --- | --- |
| `小浣熊OpenAI反代.plugin` | Loon 插件本体（新版 Script 语法 + `[Argument]` 参数界面） |
| `raccoon-openai-loon.js` | 适配后的脚本（Loon 公共脚本，插件里也可改成自托管地址） |
| `README.md` | 本文件 |

## 安装

1. 装 Loon **3.5.1(983) 或更新**（插件用了新版 Script 语法 + `[Argument]`，旧版不认）。
2. MITM：Loon → 设置 → MitM → 生成/安装证书 → 到 iOS 设置里「已下载描述文件」安装 → 通用 → 关于本机 → 证书信任设置里打开信任。
3. 导入插件（二选一）：
   - 直接复制文件本体：Loon → 配置 → 插件 → 右上角 `+` → 从 URL 添加，粘贴 `https://raw.githubusercontent.com/ruiruizl/loon-raccoon/main/raccoon-openai.plugin`
   - 或把 `小浣熊OpenAI反代.plugin` 存到「文件」App，长按 → 共享 → 用 Loon 打开
4. 导入后在插件参数里填：手机号 + 密码（会自动登录并缓存 token），**或者**只填 Access Token。
   - `Access Token` 填了就不走登录，适合已经有 token 的人。
   - `每日自动签到` 开关 + `签到时间`（五段 cron，默认每天 0:12）。
5. 保存并启用插件，确认 MITM 主机列表里有 `xiaohuanxiong.com`。

## 客户端怎么连

| 项目 | 值 |
| --- | --- |
| Base URL | `https://xiaohuanxiong.com/v1` |
| API Key | 随便填，例如 `sk-raccoon`（真正的小浣熊 token 由脚本在后台注入） |

- `GET /v1/models`：在线拉小浣熊模型目录（缓存 10 分钟，失败回退内置列表）
- `POST /v1/chat/completions`：标准 OpenAI 请求，`stream` 原样透传（真流式，不聚合）
- `GET /v1/checkin`：手动签到，返回今日积分/余额（浏览器打开也行）
- `GET /v1/probe`：诊断，返回上游 HTTP 状态 + token 前缀 + 响应片段

模型名不用手改：客户端从 `/v1/models` 拿到的 id 直接回传即可；`glm*` 会被映射到 `sn-glm-5-3-flash`。

## 相对 Surge 版改了什么

1. `$argument` 兼容 **Object**（Loon `[Argument]` 插件参数）和旧版 String 两种形式。
2. `$httpClient` 的 `timeout` **Loon 是毫秒，Surge 是秒** —— 全部 ×1000（否则请求 20ms 就超时，全挂）。
3. Loon 运行时没有 `atob`，内置了 base64 解码（JWT 过期时间解析用）。
4. 改写 chat 请求时**合并原始请求头**（丢掉 `host` / `content-length` / `accept-encoding`），避免 Loon 直接覆盖导致 UA 等头丢失。
5. 插件外壳换成 Loon 的 `[Argument]` / 新版 `request if ... then script(...)` / `cron ...` 语法。

## 已知坑

- 插件里的脚本直链已指向本仓库 `main` 分支的 raw；仓库文件别删/别改名，否则插件失效。国内直连 `raw.githubusercontent.com` 不稳时可换 jsDelivr 镜像：`https://cdn.jsdelivr.net/gh/ruiruizl/loon-raccoon@main/raccoon-openai.js`。
- 密码是明文存在插件参数里的，别把填好参数的插件再分享出去。
- 走的是小浣熊的 Web 接口（`/api/web/llm/v2/...`），上游改协议就得改脚本。
- 客户端如果开了「非流式 + 大 max_tokens」，请求体会被完整缓冲（`requires_body=true`），这是正常现象。
- 有些客户端会带 `Accept-Encoding: gzip`，脚本已剔除，避免 Loon 透传时出现解压异常。

## 自测

`/tmp/test_loon.js`（node 模拟 Loon 运行时）：登录/加密字段、token 缓存与自动 refresh、模型映射、请求头合并、流式透传、cron 签到、`/v1/checkin`、非法请求体、timeout 单位，共 26 项断言全部通过。
