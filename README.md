# dsh-web-remote-frp

<p align="center">
  <b>DSH 手机 / 外网远程访问插件 · frp 内网穿透版</b>
</p>

[![npm version](https://img.shields.io/npm/v/dsh-web-remote-frp?logo=npm&label=npm)](https://www.npmjs.com/package/dsh-web-remote-frp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DSH Compatible](https://img.shields.io/badge/DSH-1.x-brightgreen)](https://github.com/deepseek-ai/deepseek-harness)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Casually/dsh-web-remote-frp/pulls)

> 复刻自 [dsh-web-remote](https://github.com/godchen520/dsh-web-remote)：公网通道由 Cloudflare Quick Tunnel 换成 **frp**（frpc → 你自己的 frps 服务器），速度、稳定性、域名都自己说了算。

## ✨ 与原版 dsh-web-remote 的区别

| | dsh-web-remote | dsh-web-remote-frp（本插件） |
|---|---|---|
| 公网通道 | Cloudflare Quick Tunnel（cloudflared） | **frp**（frpc，自动探测 / 自动下载最新版） |
| 公网地址 | 随机 `*.trycloudflare.com`，每次重启变化 | 固定：`http://服务器IP:端口` 或你的域名 |
| 需要 | 无需账号、无需服务器 | 一台有公网 IP 的服务器跑 frps |
| 穿透模式 | 仅 HTTPS 隧道 | `tcp`（远程端口直连）/ `http`（域名 + vhost） |
| 其余功能 | — | 完全一致：局域网直连、token 鉴权、gzip、面板、QQ/微信机器人 |

> 两个插件的 DOM id、HTTP 路由、localStorage 键全部不同前缀（`frprm-` / `/frpremote/*`），理论上可同时安装互不冲突。

## 功能亮点

| 功能 | 说明 |
|------|------|
| 🌐 **frp 公网穿透** | frpc 缺失时自动从 GitHub Releases 下载最新版；支持 tcp / http 两种代理模式 |
| 📡 **局域网直连** | HTTP + HTTPS 直连（HTTPS 自动生成自签名证书，零配置） |
| 🔒 **安全认证** | 每次启动生成随机令牌；HttpOnly Cookie；局域网可免 token |
| ⚡ **性能加速** | 反向代理自动 gzip 压缩，大历史会话加载更快 |
| 📱 **侧边栏图标** | 手机快捷按钮常驻侧栏，刷新不消失 |
| 🤖 **微信机器人** | iLink 协议直连微信，支持 AI 对话、会话控制、模型切换 |
| 💬 **QQ 机器人** | NapCat OneBot 11 反向 WebSocket（施工中） |

## 🚀 快速开始

### 1. 准备 frps 服务器

在你的公网服务器上部署 [frp](https://github.com/fatedier/frp)（建议 ≥ 0.52，TOML 配置）：

```toml
# frps.toml
bindPort = 7000
auth.method = "token"
auth.token = "改成你自己的强密码"

# —— 仅 http（域名）模式需要下面两项 ——
# vhostHTTPPort = 80
# subdomainHost = "frp.example.com"
```

```bash
./frps -c frps.toml
```

### 2. 安装插件

**方式一：npm（推荐）**

```bash
# 在 DSH profile 目录执行
cd $DSH_HOME/profiles/web
pnpm add dsh-web-remote-frp
```

**方式二：GitHub 源码**

```bash
cd $DSH_HOME/profiles/web
pnpm add github:Casually/dsh-web-remote-frp
```

> pnpm 11 若因新包发布年龄校验报错，加 `--config.minimumReleaseAge=0` 重试。

然后在 profile `package.json` 的 `"dsh.profile.bundles"` 数组中加入 `"dsh-web-remote-frp"`，重启 DSH：

```bash
dsh web
```

**方式三：手动 patch（免重启安装链路）**

把本包放入 profile 的 `node_modules`，在 profile 的 `cordis.patch.yml` 追加：

```yaml
- insert:
    - id: web-remote-frp
      name: 'dsh-web-remote-frp'
```

> bundle 方式需重启 DSH；cordis.patch.yml 方式会被 HMR 热加载。

### 3. 配置 frps 地址

在 profile 的 `cordis.patch.yml`（或本包 `cordis.patch.yml`）里给插件加 config：

```yaml
- insert:
    - id: web-remote-frp
      name: 'dsh-web-remote-frp'
      config:
        frpServerAddr: 'your.vps.example.com'   # frps 服务器地址（必填）
        frpServerPort: 7000
        frpAuthToken: '改成你自己的强密码'
        frpProxyType: 'tcp'      # tcp：远程端口模式（默认）
        frpRemotePort: 13080     # 公网访问端口
```

重启 DSH 后，侧栏出现「📱 远程frp」按钮 → 打开面板即可看到
`http://your.vps.example.com:13080/?token=...` 公网链接。

## ⚙️ 配置项

在插件行的 `config` 字段覆盖，除 `frpServerAddr` 外全部可选：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `frpServerAddr` | `''` | **frps 服务器地址；留空则仅局域网可用** |
| `frpServerPort` | `7000` | frps 的 bindPort |
| `frpAuthToken` | `''` | frps 的 auth.token |
| `frpProxyType` | `tcp` | `tcp`（远程端口）或 `http`（域名，frps 需开 vhostHTTPPort） |
| `frpRemotePort` | `3080` | tcp 模式下 frps 上暴露的公网端口 |
| `frpCustomDomains` | `''` | http 模式的 customDomains（逗号分隔字符串或数组） |
| `frpSubdomain` | `''` | http 模式的 subdomain（frps 需配置 subdomainHost） |
| `frpSubdomainHost` | `''` | frps 的 subdomainHost（仅用于拼公网链接） |
| `frpVhostHTTPPort` | `80` | frps 的 vhostHTTPPort（仅用于拼公网链接） |
| `frpProxyName` | `''` | 自定义代理名；留空随机生成（多机共用一台 frps 不冲突） |
| `frpcPath` | `''` | 指定 frpc 路径；留空自动探测 PATH / 自动下载 |
| `frpDownloadUrl` | `''` | 自定义 frp 压缩包下载地址（设置后跳过 GitHub，直连该地址，适合内网 / 自建镜像） |
| `targetPort` | `3080` | DSH 自身端口 |
| `httpPortStart` | `3081` | 局域网 HTTP 起始端口（自动跳过占用） |
| `httpsPortStart` | `3082` | 局域网 HTTPS 起始端口 |
| `qqPortStart` | `3001` | QQ OneBot 桥起始端口 |
| `pfxPath` | `''` | 指定 PFX 证书；留空自动生成自签名 |
| `pfxPass` | `''` | PFX 密码 |
| `toolsDir` | `''` | 工具与证书缓存目录；留空使用 `$DSH_HOME/tools` |
| `autoStart` | `true` | 插件加载即自动启动 |
| `lanOpen` | `true` | 局域网免 token（私网来源放行；公网隧道仍要 token） |

### http（域名）模式示例

```yaml
config:
  frpServerAddr: 'frp.example.com'
  frpServerPort: 7000
  frpAuthToken: '***'
  frpProxyType: 'http'
  frpCustomDomains: 'dsh.example.com'   # 该域名需解析到你的 frps 服务器
  frpVhostHTTPPort: 80
```

## 📱 使用方法

1. 启动后侧栏出现「📱 远程frp」按钮
2. 点击 → 面板显示运行状态、公网 / 局域网链接
3. 手机浏览器打开链接即可访问 DSH

**公网**：`http://服务器:端口/?token=...`（或你的域名）
**局域网**：`https://192.168.x.x:3082`（同 Wi-Fi；默认免 token）

> 公网访问始终需要 token；「换链接」会重新生成 token。frpc 掉线时面板会提示，点「停止」再「启动」即可重连。

## 🛠 面板「设置」页（免改 YAML 配置）

面板第四个标签页「设置」可直接填写并持久化配置：

- **frps 连接**：服务器地址 / 端口 / auth.token / 穿透模式（tcp、http）
- **tcp 模式**：公网端口；**http 模式**：自定义域名 / subdomain / vhostHTTPPort
- **frpc 路径**：留空自动探测 PATH 并自动下载；也可指定本地路径
- **自定义下载地址**：内网 / 自建镜像直连

点「保存并重启」后配置写入 `toolsDir/frp-config.json` 并立即重建隧道；
「清除本地配置」恢复为 `cordis.patch.yml` 中的值。

**配置优先级**：面板设置（frp-config.json）＞ cordis.patch.yml 的 config ＞ 内置默认值；面板中留空的项自动沿用 YAML 值。

## 🤖 微信 / QQ 机器人

与原版一致：

**微信（iLink 协议）** — 面板「机器人」标签页扫码绑定，支持：
- `/链接` — 获取公网链接（未启动自动开启）
- `/停止远程` — 关闭远程服务
- `/会话列表` `/选择 N` `/当前会话` `/历史内容` — 会话管理
- `/当前模型` `/切换模型` `/选强度 N` — 模型切换
- 直接发送内容 → 转发到选中会话并回传结果

**QQ（NapCat OneBot 11 反向 WS）** — 施工中，连接后可发「给我链接」取公网地址。

## ❓ 常见问题

**Q: 面板提示"未配置 frpServerAddr"？**
A: frp 不像 Cloudflare Quick Tunnel 有公共隧道，必须有自己的 frps 服务器。在面板「设置」页填写 frps 信息并保存（或配置 cordis.patch.yml）；配置前局域网直连仍然可用。

**Q: frpc 自动下载失败？**
A: 首次启动需要下载 frp 发行版（约 13MB）：默认直连 GitHub Releases，失败自动回退镜像（ghfast.top）。仍失败时可手动下载 [frp 发行版](https://github.com/fatedier/frp/releases) 中的 frpc 放入 `toolsDir`（默认 `$DSH_HOME/tools`），或配置 `frpcPath` / `frpDownloadUrl`（自建镜像）。

**Q: 启动失败"auth token is incorrect"？**
A: `frpAuthToken` 与 frps 的 `auth.token` 不一致。

**Q: tcp 模式启动失败"start error"？**
A: 多半是 `frpRemotePort` 在 frps 服务器上已被占用（或被 frps 的 allowPorts 限制），换一个端口。

**Q: http 模式打不开？**
A: 确认 frps 配置了 `vhostHTTPPort`、域名已解析到 frps 服务器、且 `frpCustomDomains` 与 frpc 配置一致。

**Q: 局域网 HTTPS 提示"不安全"？**
A: 自签名证书的预期行为，选择「继续访问」即可。

## 📄 License

[MIT](LICENSE)
