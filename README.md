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
| 其余功能 | — | 完全一致：局域网直连、token 鉴权、gzip、面板；机器人扩展至 6 通道（微信/QQ/Telegram/钉钉/飞书/企业微信） |

> 两个插件的 DOM id、HTTP 路由、localStorage 键全部不同前缀（`frprm-` / `/frpremote/*`），理论上可同时安装互不冲突。

## 功能亮点

| 功能 | 说明 |
|------|------|
| 🌐 **frp 公网穿透** | frpc 缺失时自动从 GitHub Releases 下载最新版；支持 tcp / http / https 三种代理模式 |
| 📡 **局域网直连** | HTTP + HTTPS 直连（HTTPS 自动生成自签名证书，零配置） |
| 🧩 **局域网 / 公网独立开关** | 两者可单独开/关、互不影响；只开公网时代理切「纯转发」模式自动拦截局域网设备；二维码面板内本地 JS 生成（canvas），不依赖任何外部服务 |
| 🔒 **安全认证** | 每次启动生成随机令牌；HttpOnly Cookie；局域网可免 token |
| ⚡ **性能加速** | 反向代理自动 gzip 压缩，大历史会话加载更快 |
| 📱 **设置里的入口** | 在 DSH「设置」弹窗左侧导航列表注入「远程控制」条目（只插入自己的节点），点击打开面板 |
| 🤖 **六大机器人通道** | 微信 / QQ（NapCat）/ 纸飞机 Telegram / 钉钉 / 飞书 / 企业微信，统一命令路由，面板内一键复制回调地址 |

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

# —— 仅 https（域名 + 证书）模式需要 ——
# vhostHTTPSPort = 443
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

### 插件更新

**在 profile 目录用 pnpm 更新（推荐）**：

```bash
cd $DSH_HOME/profiles/web
pnpm update dsh-web-remote-frp --latest
```

或用 DSH CLI（等效，且自动核对 bundles 登记）：

```bash
dsh plugin --profile web update dsh-web-remote-frp
```

> pnpm 11 对刚发布的版本（如几分钟内发布的新版）可能报「新发布包年龄校验」错误，加 `--config.minimumReleaseAge=0` 重试。

**更新后必须重启 DSH**（bundle 变更不支持热加载）：

```bash
systemctl restart <你的dsh服务>     # systemd 部署
# 或前台模式：kill 旧进程后重新 pnpm dsh web
```

**验证版本生效**：

```bash
cat node_modules/dsh-web-remote-frp/package.json | grep '"version"'
curl -s http://127.0.0.1:3080/frpremote/info | head -c 300
```

> `/frpremote/info` 返回的 JSON 含各版本特性字段，可作运行时验证（如 v1.10.0+ 带 `"lan"` / `"tunnel"` 双状态字段）。

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

重启 DSH 后，打开「设置」弹窗 → 左侧列表底部的「远程控制」→ 打开面板即可看到
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
| `frpTlsEnable` | `''` | frpc↔frps TLS 开关：留空 = frp ≥0.50 默认行为（自动启用）；`'true'` 强制启用 / `'false'` 禁用 |
| `frpTlsCertFile` | `''` | TLS 客户端证书 `transport.tls.certFile`：填文件路径，或直接粘贴 PEM 内容（保存时自动生成文件，可选） |
| `frpTlsKeyFile` | `''` | TLS 客户端私钥 `transport.tls.keyFile`：文件路径或粘贴 PEM（自动落盘，权限 0600，可选） |
| `frpTlsTrustedCaFile` | `''` | TLS CA 证书 `transport.tls.trustedCaFile`（校验自签 frps）：文件路径或粘贴 CA PEM（自动落盘，可选） |
| `frpTlsServerName` | `''` | TLS `transport.tls.serverName`（校验服务端证书主机名，留空用 serverAddr） |
| `frpVhostHTTPSPort` | `443` | https 模式：frps 侧 `vhostHTTPSPort` |
| `frpHttpsCertFile` | `''` | https 模式访客侧域名证书：文件路径或粘贴 PEM（自动落盘；需匹配域名） |
| `frpHttpsKeyFile` | `''` | https 模式访客侧域名私钥：文件路径或粘贴 PEM（自动落盘，0600） |
| `targetPort` | 自动探测 | DSH 自身端口。留空时取 DSH 实际监听端口（`webServer.port`）；取不到才回退 `3080` |
| `httpPortStart` | `3081` | 局域网 HTTP 起始端口（自动跳过占用） |
| `httpsPortStart` | `3082` | 局域网 HTTPS 起始端口 |
| `qqPortStart` | `3001` | QQ OneBot 桥起始端口 |
| `pfxPath` | `''` | 指定 PFX 证书；留空自动生成自签名 |
| `pfxPass` | `''` | PFX 密码 |
| `toolsDir` | `''` | 工具与证书缓存目录；留空使用 `$DSH_HOME/tools` |
| `autoStart` | `true` | 插件加载即自动启动 |
| `lanOpen` | `true` | 局域网免 token（私网来源放行；公网隧道仍要 token） |
| `dshSessionAuth` | `''`（自动开启） | 自动适配 DSH 浏览器会话鉴权（见「桌面客户端」章节）；可设 `'true'`/`'false'`，面板「设置」页也可改 |

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

## 🖥 桌面客户端（DeepSeek Harness 桌面版）

桌面客户端（`DeepSeek Harness.exe`）跑的是 `desktop` profile，和命令行 `dsh web` 有两处关键差异，插件已自动适配，**无需改配置**：

**1. DSH 端口不是 3080。** 桌面客户端由 `dsh-desktop-host` 固定传入 `--port 19387`（写死在客户端内），而插件默认的 `targetPort` 曾是 `3080`，代理会把请求转发到没人监听的端口 → 手机端只能看到 `502 bad gateway`。
现在留空 `targetPort` 时插件直接取 DSH 实际监听端口（`webServer.port`），`dsh web` 用户行为不变；要覆盖仍可显式配置。

**2. 新版 DSH 的 Host 通道要求「浏览器会话」。** 只有 `GET /?token=<launchToken>` 能换取一枚绑定 authority 的签名 cookie，否则 `/`、`/api`、WebSocket 全部返回：

```
HTTP/1.1 401 Unauthorized
dsh web authentication required; reopen the URL printed by dsh web.
```

而 `launchToken` 是每个进程随机生成、只存在内存里的（桌面客户端既不打印也不落盘），手机上拿不到，所以插件给的链接永远停在 401。
插件现在的做法是**复用 DSH 官方接口**：通过 `connection` 服务的 `authenticatedUrl()` 拿到带 token 的 URL、再用 `authorizeIndex()` 让 **DSH 自己铸 cookie**，然后给所有转发请求（含 WebSocket 升级）带上；上游返回 401 时自动重铸并原样重放一次（仅 GET/HEAD）。
好处是不硬编码 cookie 格式——DSH 以后换算法/换 cookie 名也不会失效；旧版 DSH 没有 `connection` 服务时静默跳过，行为和以前一致。

**验证方式**：`http://127.0.0.1:<DSH端口>/frpremote/info` 现在会多两个字段：

```bash
curl -s http://127.0.0.1:19387/frpremote/info
# "targetPort":19387,"dshSession":"ok"     ← 端口解析正确 + 会话 cookie 已铸签
# dshSession 取值：ok 已就绪 | none 尚未铸签（首次请求会自动补） | off 已手动关闭
# "panel":{"stage":"mounted","where":"settings"}   ← 面板入口状态：
#   settingsItem 设置弹窗导航里的「远程控制」条目是否注入成功
#   attachTo 注入到哪个容器 | error 挂载异常（带 message）
```

**入口在哪**：**DSH「设置」弹窗左侧导航列表里的「远程控制」条目**（与「账号与余额 / 通用设置 / 模型 / 内置插件」并列，点击打开面板）。
设置弹窗是懒渲染的，条目由 MutationObserver 在弹窗打开时注入、React 重渲染把它移除时补回；只往宿主里 append 自己那一个节点，其余一律不动。
（右下角的悬浮按钮已按用户要求移除，入口只此一个。）点开面板后，顶部第 4 个标签「设置」才是插件自身的配置入口。

> **重要约束：只插入自己的节点，绝不改写宿主的任何东西。** 早期版本为了把按钮"挤进"侧栏，
> 改写了容器与兄弟按钮的行内样式，踩了两个真实的坑：① 被改写的侧栏底部（账号/设置区）原有内容被挤没；
> ② 插入点整块区域被祖先裁掉 → 上报"已插入"但界面上什么都没有。
> 现在的规则是：`insertBefore` 自己的按钮 → 命中测试（`document.elementFromPoint`）确认真的可见 →
> 不可见就撤销自己的节点。测试第 14 项会断言导航容器/原有导航项的行内样式与子节点数量都没被动过。

**为什么桌面端的面板能出来（实现要点，改代码前务必读）**：桌面客户端主窗口加载的是 `dsh-app://app/`，
index.html 由安装包静态 dist 直出，`webServer.tapIndex` 的函数变换**永远过不去**（同机 `dsh-whale-widget`
的实测结论）。所以插件用两条官方通道并存：

| 通道 | 覆盖 | 说明 |
|---|---|---|
| `webserver/index-inject` 结构化行 | 桌面 + web | `{kind:'script', placement:'body', text: INJECT_SCRIPT}`，**桌面端唯一生效的通道**；注入表在宿主 ready 时只收集一次，因此必须在 `apply()` 里**同步**注册（放进 `ctx.inject` 回调会错过） |
| `webServer.tapIndex` | 仅 web | 先检查 HTML 里有没有 `__frprmBooted`，有就跳过 → 与结构化行天然去重 |

两条通道都到位时，由页内 `window.__frprmBooted` 守卫保证脚本只执行一次。

**面板里也能看、也能改**：点开面板，状态行下方常驻一行生效诊断：

```
上游 127.0.0.1:19387 · DSH 会话 已就绪
```

「设置」页新增分组 **远程适配（高级，一般不用改）**：

| 字段 | 说明 |
|---|---|
| DSH 上游端口 | 留空 = 自动探测（输入框占位符会显示当前解析到的端口）；填了就固定用它 |
| DSH 会话适配 | `自动`（推荐，默认开启）/ `强制开启` / `关闭（旧版行为）` |

改完点「保存并重启」即可，写入 `toolsDir/frp-config.json`，无需碰 YAML。

> 桌面客户端安装/更新插件后**需要重启客户端**：bundle 注册表变更不走热加载。重启会换发新的 `launchToken`，但会话 cookie 由持久化密钥签发，无需重新扫码。

### ⚠️ frpc 自动下载：曾把客户端直接搞崩（v1.10.4 修复）

**现象**：桌面客户端启动即弹「应用无法启动或已意外停止」，crash 日志里是：

```
dsh: fatal uncaught exception: [Error: EPERM: operation not permitted,
  open 'C:\Users\Cotx\.dsh\tools\frp_0.71.0_windows_amd64.zip']
```

**根因**：`frpcPath` 留空且 `toolsDir` 里没有 `frpc.exe` 时，插件会在启动时自动下载压缩包。
旧实现把压缩包**直接写到最终路径**，而这里有两个没有接住的抛出点：

1. `fs.createWriteStream(dest)` 的 open 是**异步**的，失败时以 `'error'` 事件抛出；
   旧实现没挂 `error` 监听器 → 变成 `uncaughtException` → DSH 宿主 fatal 退出。
2. 网络 `error` 回调里的 `fs.rmSync(dest, { force: true })` 没有保护，文件被占用时抛 `EPERM`，同样致命。

**触发条件**：同一个压缩包路径被第二个进程持有——两个 DSH 实例同时启动/重启，
或者杀软正在扫描刚下完的文件。此时后启动的那个实例不是"报错"，而是**整个宿主进程死掉**。

**修复方式**（改这块代码时请保留这些不变量）：

- 下载一律先写「同目录 + pid + 随机后缀」的临时文件，成功后再 `renameSync` 原子改名；
  任何失败只 `reject` 并删掉临时文件，**绝不 emit 未处理的 error**。
- 所有 `rmSync` 走 `safeRm()`（吞掉 EPERM/EBUSY）。
- 归档名与解压目录也带随机后缀，多实例不再共用同一个路径；同进程内 `downloadFrpc` 单飞。
- `cleanupStaleDownloads()` 会清掉 10 分钟前的 `frp-download-*` / `frp-extract-*` / `frp_x.y.z_*` 残留
  （含旧版本直接落在 `toolsDir` 的压缩包），被占用就跳过。
- 如果你想手动放一个 frpc：把 `frpc.exe` 丢进 `toolsDir`，或在设置页填 `frpc 可执行文件路径`，
  就完全不会走下载逻辑。

## 📱 使用方法

1. 打开「设置」弹窗 → 左侧导航列表底部的「远程控制」条目
2. 点击 → 面板显示运行状态（局域网 / 公网 双指示灯）
3. 「公网」标签：**连接公网 / 断开**（控制 frp 隧道）
   「局域网」标签：**开启局域网 / 关闭**（控制局域网直连）
   两者独立，可只开其一；二维码在对应标签页本地生成，手机扫码直达

**公网**：`http://服务器:端口/?token=...`（或你的域名）
**局域网**：`https://192.168.x.x:3082`（同 Wi-Fi；默认免 token）

> 公网访问始终需要 token；「换链接」会重新生成 token。frpc 掉线时面板会提示，点「断开」再「连接公网」即可重连。只开公网时局域网设备会被自动拦截（403）。

## 🖥 命令行控制（无 GUI / 开关被关掉时）

插件控制端点在本机免 token，服务器上直接 curl 即可。**典型场景：局域网开关被关掉、设备连不上时**：

```bash
# 一键重新开启局域网（返回 JSON 里 "lan":true、"port":3081 即成功）
curl -s -X POST http://127.0.0.1:3080/frpremote/control \
  -H 'content-type: application/json' -d '{"action":"lan:start"}'

# 验证状态与端口
curl -s http://127.0.0.1:3080/frpremote/info | head -c 300
ss -tlnp | grep -E '308[12]'
```

全部可用动作（同一端点，替换 `-d` 内容）：

| action | 效果 |
|--------|------|
| `lan:start` / `lan:stop` | 开 / 关局域网直连 |
| `tunnel:start` / `tunnel:stop` | 开 / 关公网 frp 隧道 |
| `start` / `stop` | 全量启动 / 停止（含机器人通道） |
| `renew` | 换链接（重新生成 token，保持当前开关状态） |

> 兜底：插件默认 `autoStart: true`，重启 DSH 也会自动开启局域网；且 DSH 本体的 3080 端口始终在局域网可达（无 token 体系），面板永远可以在 `http://<服务器IP>:3080` 的 GUI 里打开。

### 获取当前 token（命令行）

token 在每次插件启动时随机生成。以下场景需要取当前值：进程重启后、设备访问被 403、拼公网链接、手动配置扫码：

```bash
curl -s http://127.0.0.1:3080/frpremote/info | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])"
```

用法：

- **公网链接**：`http(s)://<你的公网地址>/?token=<token>`（首次访问自动换成 HttpOnly Cookie）
- **设备被 403**：用**无痕窗口**打开 `http://<服务器IP>:3081`（局域网免 token 直接进），或清除该站点旧 Cookie（`dshr_token`）
- 也可打开面板 GUI 重新扫二维码——二维码永远携带当前 token

> **token 变更时机**：进程重启、`renew` 动作、保存配置重启。token 一变，所有旧链接 / 旧 Cookie 立即失效；**遇到 403 先怀疑 token 变了**。

## 🛠 面板「设置」页（免改 YAML 配置）

面板第四个标签页「设置」可直接填写并持久化配置：

- **frps 连接**：服务器地址 / 端口 / auth.token / 穿透模式（tcp、http、**https**）
- **frp TLS 证书**：frpc↔frps 隧道 TLS（开关 / 客户端证书 / 私钥 / CA / serverName）；https 模式访客侧证书（frps vhostHTTPSPort / 域名证书 / 私钥，支持粘贴 PEM 自动落盘）；**一键生成自签证书**（按已填域名自动 openssl 生成证书+私钥，自动写入配置并重启，有效期 10 年）
- **tcp 模式**：公网端口；**http 模式**：自定义域名 / subdomain / vhostHTTPPort
- **frpc 路径 + 一键下载 / 定位文件**：点「一键下载」自动识别当前系统与架构（darwin / linux / windows × amd64 / arm64…），下载对应的 frp 最新版（自动解压）并**自动填入路径**；内置国内加速镜像（fengxiaozi，6 平台直链），下载源顺序：GitHub → 加速镜像 → ghfast；点「定位文件」一键在 Finder / 资源管理器中显示 frpc；若已存在 frpc（配置路径 / PATH / toolsDir）则直接复用，不重复下载
- **自定义下载地址**：内网 / 自建镜像直连

点「保存并重启」后配置写入 `toolsDir/frp-config.json` 并立即重建隧道；
「清除本地配置」恢复为 `cordis.patch.yml` 中的值。

**配置优先级**：面板设置（frp-config.json）＞ cordis.patch.yml 的 config ＞ 内置默认值；面板中留空的项自动沿用 YAML 值。

**分组折叠**：设置项按「frp 服务器穿透 / frpc 与下载」分组，默认全部折叠，点开对应分组填写，面板不会一打开就很长。机器人通道凭据（纸飞机 / 钉钉 / 飞书 / 企业微信）已移到「机器人」标签页各通道详情里填写，设置页只保留 frp 相关配置。

## 🤖 机器人通道（6 通道统一命令路由）

面板「机器人」标签页选择通道，查看接入指引 / 回调地址 / 连接状态。所有通道共用同一套命令：

- `/链接` — 获取公网链接（未启动自动开启）
- `/停止远程` — 关闭远程服务
- `/会话列表` `/选择 N` `/当前会话` `/历史内容` — 会话管理
- `/当前模型` `/切换模型` — 模型切换
- 直接发送内容 → 转发到选中 DSH 会话并回传 AI 结果
- 发送「帮助」查看全部命令

| 通道 | 接入方式 | 需要的配置（「机器人」页该通道详情里填写） |
|---|---|---|
| **微信** | iLink 协议，面板扫码绑定 | 无需配置 |
| **QQ** | NapCat OneBot 11 反向 WS，面板显示 `ws://` 地址填入 NapCat；支持私聊 + 群聊（群内仅响应 / 命令） | 无需配置 |
| **纸飞机 Telegram** | Bot API 长轮询（出站连接，无需公网回调） | `tgBotToken`（@BotFather 获取） |
| **钉钉** | 企业内部机器人 outgoing HTTP 回调，面板提供回调地址（HMAC-SHA256 签名校验，sessionWebhook 回复） | `dingtalkAppSecret` |
| **飞书** | 自建应用事件订阅回调（im.message.receive_v1，支持 Encrypt Key 加密事件） | `feishuAppId` `feishuAppSecret` `feishuVerificationToken`（`feishuEncryptKey` 可选） |
| **企业微信** | 自建应用接收消息回调（GET 验证 + AES-256 加密消息，主动回复 API） | `wecomCorpId` `wecomCorpSecret` `wecomAgentId` `wecomToken` `wecomEncodingAESKey` |

> 钉钉 / 飞书 / 企业微信的回调地址 = 公网链接 + `/frpremote/bot/<通道>`，面板通道详情页可一键复制；因此需要先启动远程服务（frp 隧道）。
> 所有通道均带消息去重（平台重试不会重复回复）。

## 🚑 故障排查：突然连不上了（真实案例）

**症状**：本来正常运行，突然局域网和公网都连不上。

### 第一步：分清「假死」（403）还是「真死」（进程/端口没了）

```bash
ps aux | grep "dsh web" | grep -v grep                          # ① 进程在吗
ss -tlnp | grep -E '308[0-9]'                                   # ② 端口在监听吗（3080 本体 / 3081、3082 代理）
curl -m 5 -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3080/   # ③ DSH 本体响应
curl -m 5 -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3081/   # ④ 代理响应（无 token 返回 403 是正常行为！）
dmesg -T | grep -i -E "oom|killed process" | tail -5            # ⑤ 是否被系统因内存不足杀掉
```

| 现象 | 结论与处理 |
|---|---|
| 进程在 + 端口在 + ④ 返回 **403** | **假死**：进程健康，是 token / Cookie 失效 → 见下节 |
| 无进程 + ⑤ 有 oom 记录 | 内存不足被杀 → 重启并排查内存占用 |
| 无进程 + 无 oom | 崩溃退出 → 看日志（`/var/log/supervisor/dsh-web.out.log` 等）找退出原因 |
| 端口在但 ③ 超时 | DSH 内部挂起 → 重启 |
| 全在但设备连不上 | 防火墙 / 设备与服务器不同网段；先 `curl http://<服务器IP>:3081/?token=<token>` 本机自测 |

> 注意：`curl http://127.0.0.1:3081/` 返回 403 是**正确行为**（环回流量视为隧道、永远要 token），不能据此判断故障；同理服务器 curl 自己的网卡 IP 偶尔受 hairpin 干扰，以**真实设备**访问为准。

### 最常见根因：进程重启过 → token 换新 → 旧 Cookie 全部 403

插件每次启动重新生成 token。一旦守护进程（supervisor/systemd）把服务重启过，设备里存的旧 Cookie、收藏夹旧链接会全部被 403，表象就是「突然连不上」。日志特征：错误日志里刷满

```
[dsh-web-remote-frp] 403 GET / cookie=***
[dsh-web-remote-frp] 403 GET /manifest.webmanifest cookie=***
```

**恢复**：局域网用无痕窗口直开 `http://<服务器IP>:3081`；公网用新 token 拼链接（取法见「获取当前 token」）。同时查日志中段的**启动横幅**（`$ node ... bin.ts web`）确认发生过重启，并往下找重启原因。

### supervisor / systemd 部署两个坑（崩溃循环实录）

非交互环境下跑 `pnpm dsh web` 有两个坑，都会导致**无限重启**（而每次重启又会换 token，叠加成"突然连不上"）：

**坑 1：`ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY`**
`pnpm dsh web` 启动前做依赖状态检查，发现过期会尝试 `pnpm install` 重建；没有交互终端时 pnpm 拒绝继续，退出码 1。
→ 进程环境加 `CI=true`。

**坑 2：`koffi install: Error: Missing HOME environment variable`**
supervisor 的 `environment=` 是**整体替换**（不继承系统环境），缺 `HOME` 时原生依赖（koffi）的安装脚本直接失败。
→ environment 显式加 `HOME="/home/<运行用户>"`。

**正确的 supervisor 配置示例**：

```ini
[program:dsh-web]
command=/www/server/nodejs/v24.19.0/bin/pnpm dsh web
directory=<DSH checkout 路径>
environment=CI="true",HOME="/home/www",PATH=/www/server/nodejs/v24.19.0/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/dsh-web.err.log
stdout_logfile=/var/log/supervisor/dsh-web.out.log
user=www
```

修改后如果 node_modules 已被重装流程弄坏，先手动装一次依赖（用同样的环境变量），再重启服务：

```bash
cd <DSH checkout 路径>
sudo -u www env HOME=/home/www CI=true pnpm install    # 等到 Done 且无 ELIFECYCLE 报错
supervisorctl reread && supervisorctl update && supervisorctl restart dsh-web
```

> 排障口诀：日志里刷 `[ELIFECYCLE] Command failed with exit code 1` = 正在崩溃循环，真正的报错就在每条刷屏信息的**上方**。

## ❓ 常见问题

**Q: 面板提示"未配置 frpServerAddr"？**
A: frp 不像 Cloudflare Quick Tunnel 有公共隧道，必须有自己的 frps 服务器。在面板「设置」页填写 frps 信息并保存（或配置 cordis.patch.yml）；配置前局域网直连仍然可用。

**Q: 本来正常，突然所有设备都连不上 / 全是 403？**
A: 见上方「🚑 故障排查」章节。九成是进程重启过导致 token 换新、旧 Cookie 失效：无痕窗口重开 `http://<服务器IP>:3081` 或取新 token 拼链接即可；若日志刷 `[ELIFECYCLE]`，按文中 supervisor 两个坑修复。

**Q: 局域网和公网能只开一个吗？**
A: 可以，两者独立。面板「公网」标签控制 frp 隧道（连接公网 / 断开），「局域网」标签控制局域网直连（开启局域网 / 关闭），互不影响。只开公网时，本地代理切换为「纯转发」模式：自动拦截非环回的私网来源（局域网设备访问返回 403），但隧道流量（经 127.0.0.1 回环）不受影响；只开局域网时则完全不启动 frpc。机器人通道（QQ/Telegram 等）在任一开启时可用，两者都关才停。控制 API 同步支持 `lan:start/lan:stop/tunnel:start/tunnel:stop`。

**Q: 二维码是怎么生成的？**
A: 面板内置纯 JS 二维码编码器（byte 模式 / EC 等级 M / 版本 1–40），用 `<canvas>` 本地绘制，不调用任何外部服务，离线也能扫码。

**Q: frpc 自动下载失败？**
A: 首次启动需要下载 frp 发行版（约 13MB），下载源按顺序自动切换：① GitHub Releases 直连（最新版）→ ② 国内加速镜像（fengxiaozi，内置 6 平台直链，无需 GitHub API）→ ③ ghfast.top 代理。均失败时可手动下载 [frp 发行版](https://github.com/fatedier/frp/releases) 中的 frpc 放入 `toolsDir`（默认 `$DSH_HOME/tools`），或配置 `frpcPath` / `frpDownloadUrl`（自建镜像）。

**Q: 启动失败"auth token is incorrect"？**
A: `frpAuthToken` 与 frps 的 `auth.token` 不一致。

**Q: tcp 模式启动失败"start error"？**
A: 多半是 `frpRemotePort` 在 frps 服务器上已被占用（或被 frps 的 allowPorts 限制），换一个端口。

**Q: http 模式打不开？**
A: 确认 frps 配置了 `vhostHTTPPort`、域名已解析到 frps 服务器、且 `frpCustomDomains` 与 frpc 配置一致。

**Q: 开了 TLS 开关，公网地址怎么还是 http？**
A: `frpTlsEnable` 及 `transport.tls.*` 证书只加密 **frpc ↔ frps** 之间的隧道（frps 后端看到的仍是 http 代理，这是 frp 的设计，TLS 在传输层不在代理层）。要让**访客浏览器**用上 https，请把「穿透模式」切换为 **https**，填好域名证书（`frpHttpsCertFile` / `frpHttpsKeyFile`，可直接粘贴 PEM），并确认 frps 配置了 `vhostHTTPSPort`。此时生成的 frpc 代理为 `type = "https"`，由 `https2http` 插件在 frpc 端终结 TLS。

**Q: https 模式没有证书怎么办？**
A: 设置页「frp TLS 证书」分组点「一键生成自签证书」：按「自定义域名」里已填的域名（全部进 SAN）用 openssl 自动生成证书+私钥，自动落盘到 `toolsDir/certs/`、自动填入配置并重启生效（需系统装有 openssl）。自签证书浏览器会提示不安全，点继续访问即可；需要正式绿锁请用 Let's Encrypt 等 CA 签发的证书（粘贴 PEM 或填路径）。

**Q: https 模式打不开 / 浏览器提示证书错误？**
A: 确认域名已解析到 frps 服务器；`frpHttpsCertFile` 证书的 CN/SAN 与访问域名一致（通配符证书需匹配子域）；frps 已开启 `vhostHTTPSPort` 且防火墙放行该端口。

**Q: 局域网 HTTPS 提示"不安全"？**
A: 自签名证书的预期行为，选择「继续访问」即可。

## 📄 License

[MIT](LICENSE)
