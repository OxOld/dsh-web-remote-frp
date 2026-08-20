// dsh-web-remote-frp — DSH 手机/外网远程访问插件（frp 内网穿透版）
//
// 复刻自 dsh-web-remote：公网通道由 Cloudflare Quick Tunnel 换成 frp（frpc → 你自己的 frps 服务器）。
//
// 功能：
//   · 局域网直连：HTTP(3081) + HTTPS(3082，自动生成自签名证书) 反向代理
//   · 公网访问：frp 穿透（frpc 自动探测 PATH / 自动下载；tcp 远程端口 / http 域名两种模式）
//   · token 鉴权 + gzip 压缩 + WebSocket 升级转发
//   · 常驻手机图标面板（公网/局域网切换、复制、二维码、启动/停止/换链接、设置页）
//   · 机器人通道（统一命令路由）：微信 iLink / QQ（OneBot 11 反向 WS，NapCat）/
//     纸飞机 Telegram（长轮询）/ 钉钉（outgoing 回调）/ 飞书（事件回调）/ 企业微信（AES 回调）
//
// 配置项（cordis.patch.yml 的 config 字段，除 frpServerAddr 外均可省略）：
//   targetPort       DSH 自身端口                 默认 3080
//   httpPortStart    代理 HTTP 起始端口           默认 3081
//   httpsPortStart   代理 HTTPS 起始端口          默认 3082
//   qqPortStart      QQ 桥起始端口                默认 3001
//   frpServerAddr    frps 服务器地址              默认 ''（必填才有公网；留空仅局域网可用）
//   frpServerPort    frps bindPort                默认 7000
//   frpAuthToken     frps auth.token              默认 ''
//   frpProxyType     穿透模式 tcp|http|https      默认 tcp
//   frpRemotePort    tcp 模式的公网端口           默认 3080
//   frpCustomDomains http 模式 customDomains      默认 ''（逗号分隔字符串或数组）
//   frpSubdomain     http 模式 subdomain          默认 ''（frps 需配置 subdomainHost）
//   frpSubdomainHost frps 的 subdomainHost        默认 ''（仅用于拼公网链接）
//   frpVhostHTTPPort frps 的 vhostHTTPPort        默认 80（仅用于拼公网链接）
//   frpProxyName     自定义代理名                 默认 ''（随机生成，避免多机共用 frps 冲突）
//   frpDownloadUrl   自定义 frp 压缩包下载地址   默认 ''（设置后跳过 GitHub 直连该地址）
//   frpTlsEnable     frpc↔frps TLS 开关           默认 ''（frp≥0.50 自动启用；'true'/'false' 强制）
//   frpTlsCertFile   TLS 客户端证书 certFile      默认 ''（可选）
//   frpTlsKeyFile    TLS 客户端私钥 keyFile       默认 ''（可选）
//   frpTlsTrustedCaFile  TLS CA 证书 trustedCaFile 默认 ''（可选，校验自签 frps）
//   frpTlsServerName TLS serverName 校验主机名    默认 ''（留空用 serverAddr）
//   frpVhostHTTPSPort https 模式 frps vhostHTTPSPort 默认 443
//   frpHttpsCertFile https 模式域名证书           默认 ''（路径或粘贴 PEM 自动落盘）
//   frpHttpsKeyFile  https 模式域名私钥           默认 ''（路径或粘贴 PEM 自动落盘）
//   frpcPath         frpc 可执行文件路径          默认 ''（自动探测 PATH / 自动下载）
//   pfxPath          自定义 PFX 证书路径          默认 ''（自动生成自签名证书）
//   pfxPass          PFX 密码                     默认 ''
//   toolsDir         工具与证书缓存目录           默认 ''（$DSH_HOME/tools）
//   autoStart        插件加载即自动启动           默认 true
//   lanOpen          局域网免 token               默认 true（私网来源放行；公网隧道仍要 token）
//   ── 机器人通道凭据（也可在面板「设置」页填写）──
//   tgBotToken       纸飞机 Bot Token             默认 ''（填了即启用长轮询）
//   dingtalkAppSecret 钉钉机器人 Secret（签名校验） 默认 ''
//   feishuAppId / feishuAppSecret / feishuVerificationToken / feishuEncryptKey（飞书，EncryptKey 可选）
//   wecomCorpId / wecomCorpSecret / wecomAgentId / wecomToken / wecomEncodingAESKey（企业微信）
//   tgApiBase / feishuApiBase / wecomApiBase     API 基址覆盖（内网/测试用） 默认官方地址
//   另可在面板「设置」页直接填写以上 frp 配置：持久化到 toolsDir/frp-config.json（优先于 YAML）
//

import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createGzip } from 'node:zlib';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, execFile } from 'node:child_process';

// ───────────────────────── 自签名证书生成（零依赖） ─────────────────────────

function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function derSeq(...parts) {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([0x30]), derLen(body.length), body]);
}
function derInt(value) {
  // value: Buffer（大端正整数）；必要时补前导 0 避免被解析为负数
  let bytes = value;
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02]), derLen(bytes.length), bytes]);
}
function derOid(oid) {
  const parts = oid.split('.').map(Number);
  const body = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [v & 0x7f];
    v >>>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>>= 7; }
    body.push(...stack);
  }
  return Buffer.concat([Buffer.from([0x06]), derLen(body.length), Buffer.from(body)]);
}
function derNull() { return Buffer.from([0x05, 0x00]); }
function derBitString(bytes) {
  return Buffer.concat([Buffer.from([0x03]), derLen(bytes.length + 1), Buffer.from([0]), bytes]);
}
function derOctetString(bytes) {
  return Buffer.concat([Buffer.from([0x04]), derLen(bytes.length), bytes]);
}
function derUtcTime(date) {
  const s = date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '').replace('T', '').replace('Z', 'Z');
  const y = Number(s.slice(0, 4));
  const body = Buffer.from(String(y % 100).padStart(2, '0') + s.slice(4), 'utf8');
  return Buffer.concat([Buffer.from([0x17]), derLen(body.length), body]);
}
function derUtf8String(text) {
  const bytes = Buffer.from(text, 'utf8');
  return Buffer.concat([Buffer.from([0x0c]), derLen(bytes.length), bytes]);
}
function derName(cn) {
  // RDNSequence: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String } } }
  const attr = derSeq(derOid('2.5.4.3'), derUtf8String(cn));
  const set = Buffer.concat([Buffer.from([0x31]), derLen(attr.length), attr]);
  return derSeq(set);
}
function derGeneralNameIp(ip) {
  // [7] IMPLICIT OCTET STRING（4 字节）
  const bytes = Buffer.from(ip.split('.').map(Number));
  return Buffer.concat([Buffer.from([0x87]), derLen(bytes.length), bytes]);
}
function derGeneralNameDns(name) {
  const bytes = Buffer.from(name, 'utf8');
  return Buffer.concat([Buffer.from([0x82]), derLen(bytes.length), bytes]);
}
function derSan(ips, dnsNames) {
  const names = [];
  for (const ip of ips) names.push(derGeneralNameIp(ip));
  for (const d of dnsNames) names.push(derGeneralNameDns(d));
  const seq = derSeq(...names);
  return derSeq(derOid('2.5.29.17'), derOctetString(seq));
}
function derBasicConstraints() {
  // cA=FALSE：SEQUENCE {}（空）→ 隐含 all FALSE
  const seq = derSeq();
  return derSeq(derOid('2.5.29.19'), derOctetString(seq));
}
function derKeyUsage() {
  // digitalSignature(0) + keyEncipherment(2)
  const body = Buffer.from([0x05, 0xa0]); // unused bits=0, bits: 10100000 → 0=digitalSignature, 2=keyEncipherment
  const bs = Buffer.concat([Buffer.from([0x03]), derLen(body.length), body]);
  return derSeq(derOid('2.5.29.15'), derOctetString(bs));
}
/**
 * 生成自签名 X.509 v3 证书（RSA-2048 / SHA-256）。
 * @param ips 要写入 SAN 的 IPv4 地址列表
 * @returns {{ key: string, cert: string }} PEM
 */
export function generateSelfSignedCert(ips = []) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const serial = crypto.randomBytes(16);
  const notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  const notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
  const sigAlg = derSeq(derOid('1.2.840.113549.1.1.11'), derNull());
  const sanNames = [...new Set([...ips, '127.0.0.1'])];
  const dnsNames = ['localhost'];
  const extSeq = derSeq(derSan(sanNames, dnsNames), derBasicConstraints(), derKeyUsage());
  const tbsWithoutExt = derSeq(
    Buffer.concat([Buffer.from([0xa0]), derLen(3), Buffer.from([0x02, 0x01, 0x02])]), // version v3
    derInt(serial),
    sigAlg,
    derName('dsh-remote'),
    derSeq(derUtcTime(notBefore), derUtcTime(notAfter)),
    derName('dsh-remote'),
    spki, // SubjectPublicKeyInfo（完整 SEQUENCE，原样）
    Buffer.concat([Buffer.from([0xa3]), derLen(extSeq.length), extSeq]), // [3] EXPLICIT Extensions
  );
  const signature = crypto.sign('sha256', tbsWithoutExt, privateKey);
  const certDer = derSeq(tbsWithoutExt, sigAlg, derBitString(signature));
  const certPem = '-----BEGIN CERTIFICATE-----\n' + certDer.toString('base64').replace(/(.{64})/g, '$1\n') + '\n-----END CERTIFICATE-----\n';
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return { key: keyPem, cert: certPem };
}

// ───────────────────────── 局域网 IP 探测 ─────────────────────────

export function lanIPs() {
  const out = [];
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const ni of ifaces[name] || []) {
      if (ni.family === 'IPv4' && !ni.internal) out.push(ni.address);
    }
  }
  return out;
}

// ───────────────────────── 反向代理服务器 ─────────────────────────

export function createProxyServer(options) {
  const { targetPort, pfxPath, pfxPass, lanOpen = true } = options;
  const token = crypto.randomBytes(18).toString('base64url');
  const TARGET_HOST = '127.0.0.1';
  const TARGET_PORT = targetPort;

  /** 判断来源地址是否为私网/本机地址（局域网免 token 用） */
  function isPrivateAddress(addr) {
    if (!addr) return false;
    const ip = addr.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
    const parts = ip.split('.');
    if (parts.length === 4) {
      const a = Number(parts[0]);
      const b = Number(parts[1]);
      if (a === 127) return true;                       // 127.x.x.x
      if (a === 10) return true;                        // 10.x.x.x
      if (a === 192 && b === 168) return true;          // 192.168.x.x
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16-31.x.x
      if (a === 169 && b === 254) return true;          // 169.254.x.x link-local
    }
    return false;
  }

  function parseCookies(header) {
    const out = {};
    for (const part of String(header || '').split(';')) {
      const idx = part.indexOf('=');
      if (idx > -1) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
    }
    return out;
  }
  function isAuthed(req) {
    // 局域网免 token：私网来源直接放行（公网隧道来源是 127.0.0.1 也会放行？
    // 注意：frpc 隧道从 127.0.0.1 转发进来，无法与"本机直连"区分。
    // 因此公网访问仍必须带 token（否则隧道等于裸奔）。这里仅放行"非 127.0.0.1 的私网来源"。
    if (lanOpen) {
      const addr = req.socket.remoteAddress || '';
      const ip = addr.replace(/^::ffff:/, '');
      if (ip !== '127.0.0.1' && ip !== '::1' && isPrivateAddress(ip)) return true;
    }
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.dshr_token === token) return true;
    try { return new URL(req.url, 'http://x').searchParams.get('token') === token; } catch (e) { return false; }
  }
  function forwardHeaders(req, dropOrigin) {
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'connection' || lk === 'keep-alive' || lk === 'transfer-encoding' || lk === 'upgrade' || (dropOrigin && lk === 'origin')) continue;
      headers[lk] = v;
    }
    headers.host = TARGET_HOST + ':' + TARGET_PORT;
    return headers;
  }
  function upgradeHeaders(req) {
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'origin' || lk === 'keep-alive' || lk === 'transfer-encoding') continue;
      headers[lk] = v;
    }
    headers.host = TARGET_HOST + ':' + TARGET_PORT;
    return headers;
  }
  function shouldGzip(req, presHeaders) {
    if (!/gzip/.test(String(req.headers['accept-encoding'] || ''))) return false;
    if (presHeaders['content-encoding']) return false;
    const ctype = String(presHeaders['content-type'] || '');
    return ctype.indexOf('text/') === 0 || ctype.indexOf('application/json') === 0 || ctype.indexOf('application/javascript') === 0;
  }
  /** 静态资源（带 rev 的 bundle/assets）加一年 immutable 缓存，手机二次打开秒开 */
  function isCacheable(req) {
    const u = req.url || '';
    if (u.indexOf('/assets/') === 0 || u.indexOf('/plugins/') === 0 || u.indexOf('rev=') !== -1) return true;
    if (u.indexOf('/favicon.svg') === 0 || u.indexOf('/manifest.webmanifest') === 0) return true;
    return false;
  }
  /** 复用到 DSH 的连接（keep-alive），减少几十个 bundle 的 TCP 握手 */
  const proxyAgent = new http.Agent({ keepAlive: true, maxSockets: 32, maxFreeSockets: 16 });
  function handleRequest(req, res) {
    if (!isAuthed(req)) {
      console.error('[dsh-web-remote-frp] 403 ' + req.method + ' ' + req.url + ' cookie=' + (req.headers.cookie ? 'yes' : 'no'));
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('forbidden');
      return;
    }
    const cookies = parseCookies(req.headers.cookie);
    if (req.method === 'GET' && cookies.dshr_token !== token) {
      try {
        const url = new URL(req.url, 'http://x');
        if (url.searchParams.get('token') === token) {
          url.searchParams.delete('token');
          const q = url.searchParams.toString();
          res.writeHead(302, { location: url.pathname + (q ? '?' + q : ''), 'set-cookie': 'dshr_token=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400' });
          res.end();
          return;
        }
      } catch (e) { /* ignore */ }
    }
    const proxy = http.request({ host: TARGET_HOST, port: TARGET_PORT, path: req.url, method: req.method, headers: forwardHeaders(req, true), agent: proxyAgent }, (pres) => {
      const gz = shouldGzip(req, pres.headers);
      const outHeaders = {};
      for (const [k, v] of Object.entries(pres.headers)) {
        const lk = k.toLowerCase();
        if (lk === 'connection' || lk === 'keep-alive' || lk === 'transfer-encoding' || lk === 'upgrade') continue;
        if (gz && lk === 'content-length') continue;
        outHeaders[lk] = v;
      }
      if (gz) outHeaders['content-encoding'] = 'gzip';
      // 静态资源：一年 immutable 缓存（URL 带 rev，内容变了 URL 就变，缓存绝对安全）
      if (isCacheable(req)) {
        outHeaders['cache-control'] = 'public, max-age=31536000, immutable';
        // CDN-Cache-Control：兼容的边缘缓存会缓存静态资源，
        // 否则手机每个 bundle 都要走隧道往返，几十个 bundle 就非常慢
        outHeaders['cdn-cache-control'] = 'public, max-age=86400';
      }
      res.writeHead(pres.statusCode, outHeaders);
      if (gz) {
        const gzStream = createGzip();
        pres.pipe(gzStream).pipe(res);
        gzStream.on('error', () => res.destroy());
      } else {
        pres.pipe(res);
      }
    });
    proxy.on('error', () => { try { if (!res.headersSent) { res.writeHead(502); res.end('bad gateway'); } else { res.destroy(); } } catch (e2) { /* ignore */ } });
    req.pipe(proxy);
  }
  function handleUpgrade(req, socket, head) {
    if (!isAuthed(req)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
    const headers = upgradeHeaders(req);
    const proxy = http.request({ host: TARGET_HOST, port: TARGET_PORT, path: req.url, method: 'GET', headers }, (pres) => { socket.destroy(); });
    proxy.on('upgrade', (pres, psocket, phead) => {
      let resp = 'HTTP/1.1 101 Switching Protocols\r\n';
      const h = pres.headers;
      if (h.upgrade) resp += 'Upgrade: ' + h.upgrade + '\r\n';
      if (h.connection) resp += 'Connection: ' + h.connection + '\r\n';
      if (h['sec-websocket-accept']) resp += 'Sec-WebSocket-Accept: ' + h['sec-websocket-accept'] + '\r\n';
      if (h['sec-websocket-protocol']) resp += 'Sec-WebSocket-Protocol: ' + h['sec-websocket-protocol'] + '\r\n';
      resp += '\r\n';
      socket.write(resp);
      if (phead && phead.length) psocket.unshift(phead);
      psocket.pipe(socket);
      socket.pipe(psocket);
      psocket.on('error', () => socket.destroy());
      socket.on('error', () => psocket.destroy());
    });
    proxy.on('error', () => socket.destroy());
    proxy.end();
  }

  const httpServer = createServer(handleRequest);
  httpServer.on('upgrade', handleUpgrade);

  let httpsServer = null;
  let tlsOptions = null;
  if (pfxPath && fs.existsSync(pfxPath)) {
    tlsOptions = { pfx: fs.readFileSync(pfxPath), passphrase: pfxPass || undefined };
  } else {
    const cert = generateSelfSignedCert(lanIPs());
    tlsOptions = { key: cert.key, cert: cert.cert };
  }
  httpsServer = createHttpsServer(tlsOptions, handleRequest);
  httpsServer.on('upgrade', handleUpgrade);

  return {
    token,
    httpServer,
    httpsServer,
    start(port, httpsPort) {
      return new Promise((resolve, reject) => {
        let httpDone = false;
        let httpsDone = false;
        const onErr = (e) => {
          console.error('[dsh-web-remote-frp] proxy listen error:', e && e.message || e);
          if (!httpDone || (httpsPort !== null && !httpsDone)) reject(e);
        };
        httpServer.on('error', onErr);
        httpsServer.on('error', onErr);
        const cleanup = () => { httpServer.removeListener('error', onErr); httpsServer.removeListener('error', onErr); };
        httpServer.listen(port, '0.0.0.0', () => {
          httpDone = true;
          if (httpsPort === null || httpsDone) { cleanup(); resolve(); }
        });
        if (httpsPort === null) return;
        httpsServer.listen(httpsPort, '0.0.0.0', () => {
          httpsDone = true;
          if (httpDone) { cleanup(); resolve(); }
        });
      });
    },
    close() {
      try { httpServer.close(); } catch (e) { /* ignore */ }
      try { httpsServer.close(); } catch (e) { /* ignore */ }
    },
  };
}

// ───────────────────────── QQ OneBot 11 反向 WS 桥 ─────────────────────────

export function createQQServer(options) {
  const { infoUrls, handleMessage, onConnectionChange } = options;
  const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  let connections = 0;

  function encodeFrame(payload) {
    const buf = Buffer.from(payload, 'utf8');
    const len = buf.length;
    let header;
    if (len < 126) {
      header = Buffer.from([0x81, len]);
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81; header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81; header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    return Buffer.concat([header, buf]);
  }
  function parseFrames(buffer, onText, onClose, onPing) {
    let offset = 0;
    while (offset + 2 <= buffer.length) {
      const b0 = buffer[offset];
      const b1 = buffer[offset + 1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let headerLen = 2;
      if (len === 126) {
        if (offset + 4 > buffer.length) return buffer.subarray(offset);
        len = buffer.readUInt16BE(offset + 2);
        headerLen = 4;
      } else if (len === 127) {
        if (offset + 10 > buffer.length) return buffer.subarray(offset);
        len = Number(buffer.readBigUInt64BE(offset + 2));
        headerLen = 10;
      }
      const maskLen = masked ? 4 : 0;
      if (offset + headerLen + maskLen + len > buffer.length) return buffer.subarray(offset);
      let payload = buffer.subarray(offset + headerLen + maskLen, offset + headerLen + maskLen + len);
      if (masked) {
        const mask = buffer.subarray(offset + headerLen, offset + headerLen + 4);
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      }
      offset += headerLen + maskLen + len;
      if (opcode === 0x1) onText(payload.toString('utf8'));
      else if (opcode === 0x8) { onClose(); return buffer.subarray(offset); }
      else if (opcode === 0x9 && onPing) onPing(payload);
    }
    return buffer.subarray(offset);
  }
  function fetchInfo() {
    return new Promise((resolve) => {
      const tryUrl = (idx) => {
        if (idx >= infoUrls.length) { resolve(null); return; }
        const req = http.get(infoUrls[idx], (res) => {
          let data = '';
          res.on('data', (c) => { data += c; });
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              if (parsed && parsed.url && parsed.token) resolve(parsed);
              else tryUrl(idx + 1);
            } catch (e) { tryUrl(idx + 1); }
          });
        });
        req.on('error', () => tryUrl(idx + 1));
        req.setTimeout(3000, () => { req.destroy(); tryUrl(idx + 1); });
      };
      tryUrl(0);
    });
  }
  // OneBot 11 message 字段可能是字符串或 segment 数组
  function onebotText(msg) {
    if (typeof msg === 'string') return msg;
    if (Array.isArray(msg)) {
      return msg.map((seg) => (seg && seg.type === 'text' && seg.data && seg.data.text) ? seg.data.text : '').join('');
    }
    return '';
  }
  function handlePrivate(evt, send) {
    const userId = evt.user_id;
    const message = onebotText(evt.message).trim();
    const reply = (text) => {
      try { send(JSON.stringify({ action: 'send_private_msg', params: { user_id: userId, message: String(text) }, echo: 'dsh-remote' })); } catch (e) { /* ignore */ }
    };
    if (handleMessage) {
      Promise.resolve()
        .then(() => handleMessage(message, { channel: 'qq', kind: 'private', id: userId }))
        .then((r) => { if (r) reply(r); })
        .catch((e) => reply('[错误] ' + String(e && e.message || e).slice(0, 200)));
      return;
    }
    if (/远程|链接|网址|token|地址/.test(message)) {
      fetchInfo().then((info) => {
        if (info && info.url && info.token) {
          reply('DSH 远程访问链接：' + info.url + '/?token=' + info.token + '\n手机浏览器打开即可使用。插件重启后链接会变化，可再次发送本指令获取。');
        } else {
          reply('远程通道尚未启动，请在电脑 GUI 侧栏点击手机图标启动。');
        }
      });
    } else {
      reply('发送「给我链接」获取 DSH 远程访问地址。');
    }
  }
  function handleGroup(evt, send) {
    if (!handleMessage) return; // 旧模式仅支持私聊取链接
    const message = onebotText(evt.message).trim();
    // 群内只响应命令 / 链接类消息，避免刷屏
    if (!/^\//.test(message) && !/^(帮助|给我链接|远程链接)/.test(message)) return;
    const reply = (text) => {
      try { send(JSON.stringify({ action: 'send_group_msg', params: { group_id: evt.group_id, message: String(text) }, echo: 'dsh-remote' })); } catch (e) { /* ignore */ }
    };
    Promise.resolve()
      .then(() => handleMessage(message, { channel: 'qq', kind: 'group', id: evt.group_id }))
      .then((r) => { if (r) reply(r); })
      .catch((e) => reply('[错误] ' + String(e && e.message || e).slice(0, 200)));
  }
  function handleUpgrade(req, socket) {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
    connections += 1;
    if (onConnectionChange) { try { onConnectionChange(true); } catch (e) { /* ignore */ } }
    let settled = false;
    const onSocketGone = () => {
      if (settled) return;
      settled = true;
      connections = Math.max(0, connections - 1);
      if (connections === 0 && onConnectionChange) { try { onConnectionChange(false); } catch (e) { /* ignore */ } }
    };
    let buffer = Buffer.alloc(0);
    const send = (text) => { try { socket.write(encodeFrame(text)); } catch (e) { /* ignore */ } };
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      buffer = parseFrames(buffer, (text) => {
        let evt;
        try { evt = JSON.parse(text); } catch (e) { return; }
        if (evt && evt.post_type === 'message' && evt.message_type === 'private') handlePrivate(evt, send);
        else if (evt && evt.post_type === 'message' && evt.message_type === 'group') handleGroup(evt, send);
      }, () => { socket.end(); }, (payload) => {
        const pong = Buffer.from([0x8a, payload.length]);
        try { socket.write(Buffer.concat([pong, payload])); } catch (e) { /* ignore */ }
      });
    });
    socket.on('close', onSocketGone);
    socket.on('error', () => { onSocketGone(); });
  }

  const server = createServer((req, res) => { res.writeHead(200); res.end('dsh qq-bridge'); });
  server.on('upgrade', handleUpgrade);
  return {
    server,
    start(port) {
      return new Promise((resolve, reject) => {
        server.on('error', (e) => { server.removeAllListeners('error'); reject(e); });
        server.listen(port, '127.0.0.1', () => { server.removeAllListeners('error'); resolve(); });
      });
    },
    close() { try { server.close(); } catch (e) { /* ignore */ } },
  };
}

// ───────────────────────── Telegram（纸飞机）长轮询 ─────────────────────────

export function createTelegramPoller({ token, apiBase, handleMessage, log }) {
  const base = (apiBase || 'https://api.telegram.org').replace(/\/+$/, '');
  const logger = log || (() => {});
  let running = false;
  let offset = 0;
  let statusVal = null; // null | 'polling' | 'error: ...'
  let timer = null;
  let aborter = null;

  async function sendText(chatId, text) {
    const rest0 = String(text == null ? '' : text);
    const chunks = [];
    let rest = rest0;
    while (rest.length > 4000) { chunks.push(rest.slice(0, 4000)); rest = rest.slice(4000); }
    chunks.push(rest);
    for (const c of chunks) {
      if (!c) continue;
      await fetch(base + '/bot' + token + '/sendMessage', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: c }),
      });
    }
  }

  async function tick() {
    if (!running) return;
    aborter = new AbortController();
    try {
      const res = await fetch(base + '/bot' + token + '/getUpdates?offset=' + offset + '&timeout=25', { signal: aborter.signal });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) throw new Error(data.description || ('HTTP ' + res.status));
      const updates = data.result || [];
      for (const u of updates) {
        offset = u.update_id + 1;
        const msg = u.message || u.edited_message || u.channel_post;
        const text = msg && msg.text;
        if (!text) continue;
        const chatId = msg.chat && msg.chat.id;
        try {
          const reply = await handleMessage(String(text).trim(), { channel: 'telegram', id: chatId });
          if (reply && chatId !== undefined && chatId !== null) await sendText(chatId, reply);
        } catch (e) { logger('handle error: ' + String(e && e.message || e)); }
      }
      statusVal = 'polling';
      timer = setTimeout(tick, 300);
    } catch (e) {
      if (!running) return;
      statusVal = 'error: ' + String(e && e.message || e).slice(0, 120);
      logger(statusVal);
      timer = setTimeout(tick, 5000);
    } finally {
      aborter = null;
    }
  }

  return {
    start() { if (running) return; running = true; statusVal = null; tick(); },
    stop() {
      running = false;
      if (timer) { clearTimeout(timer); timer = null; }
      if (aborter) { try { aborter.abort(); } catch (e) { /* ignore */ } }
      statusVal = null;
    },
    status() { return statusVal; },
  };
}

// ───────────────────────── 钉钉 / 飞书 / 企业微信 回调辅助 ─────────────────────────

/** 钉钉 outgoing 机器人签名校验：sign = base64(HmacSHA256(timestamp + "\n" + secret, secret)) */
export function verifyDingtalkSign(timestamp, secret, sign) {
  try {
    const stringToSign = timestamp + '\n' + secret;
    const hmac = crypto.createHmac('sha256', secret).update(stringToSign).digest('base64');
    return hmac === sign;
  } catch (e) { return false; }
}

/** 飞书事件加密解密（配置了 Encrypt Key 时）。key = SHA256(encryptKey)，AES-256-CBC，iv 为密文前 16 字节 */
export function feishuDecrypt(encryptKey, encryptedB64) {
  const key = crypto.createHash('sha256').update(encryptKey).digest();
  const buf = Buffer.from(encryptedB64, 'base64');
  const iv = buf.subarray(0, 16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const out = Buffer.concat([decipher.update(buf.subarray(16)), decipher.final()]);
  return JSON.parse(out.toString('utf8'));
}
export function feishuEncrypt(encryptKey, obj) {
  const key = crypto.createHash('sha256').update(encryptKey).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(obj), 'utf8')), cipher.final()]);
  return Buffer.concat([iv, enc]).toString('base64');
}

/** 企业微信回调签名：SHA1(字典序拼接) */
export function wecomSignature(token, timestamp, nonce, ...extra) {
  const arr = [token, timestamp, nonce, ...extra]
    .filter((v) => v !== undefined && v !== null && v !== '')
    .map(String)
    .sort();
  return crypto.createHash('sha1').update(arr.join('')).digest('hex');
}
function wecomAesKey(encodingAesKey) {
  return Buffer.from(String(encodingAesKey) + '=', 'base64'); // 43 位 + '=' → 32 字节
}
/** 企业微信消息解密：random(16) + msg_len(4,BE) + msg + receiveid，PKCS#7 填充 */
export function wecomDecrypt(encodingAesKey, encryptedB64) {
  const aesKey = wecomAesKey(encodingAesKey);
  const iv = aesKey.subarray(0, 16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  decipher.setAutoPadding(false);
  let out = Buffer.concat([decipher.update(Buffer.from(encryptedB64, 'base64')), decipher.final()]);
  const pad = out[out.length - 1];
  if (pad > 0 && pad <= 32) out = out.subarray(0, out.length - pad);
  const msgLen = out.readUInt32BE(16);
  const message = out.subarray(20, 20 + msgLen).toString('utf8');
  const receiveid = out.subarray(20 + msgLen).toString('utf8');
  return { message, receiveid };
}
export function wecomEncrypt(encodingAesKey, receiveid, message) {
  const aesKey = wecomAesKey(encodingAesKey);
  const iv = aesKey.subarray(0, 16);
  const msgBuf = Buffer.from(message, 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(msgBuf.length, 0);
  let plain = Buffer.concat([crypto.randomBytes(16), lenBuf, msgBuf, Buffer.from(String(receiveid), 'utf8')]);
  const padLen = 32 - (plain.length % 32);
  plain = Buffer.concat([plain, Buffer.alloc(padLen, padLen)]);
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plain), cipher.final()]).toString('base64');
}
/** 极简 XML 取值（支持 CDATA），避免引入解析器依赖 */
export function xmlExtract(xml, tag) {
  const re = new RegExp('<' + tag + '>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))</' + tag + '>');
  const m = String(xml).match(re);
  if (!m) return null;
  return m[1] !== undefined ? m[1] : m[2];
}
/** 简单去重器（平台回调可能重试） */
export function makeDedupe(max) {
  const cap = max || 200;
  const seen = new Set();
  const order = [];
  return (id) => {
    const key = String(id == null ? '' : id);
    if (!key) return false;
    if (seen.has(key)) return true;
    seen.add(key);
    order.push(key);
    if (order.length > cap) seen.delete(order.shift());
    return false;
  };
}

// ───────────────────────── frpc 自动下载 ─────────────────────────

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'user-agent': 'dsh-web-remote-frp', accept: 'application/vnd.github+json' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        fetchJson(new URL(res.headers.location, url).href).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) { res.resume(); reject(new Error('HTTP ' + res.statusCode)); return; }
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('timeout')));
  });
}

function findFileRecursive(dir, name) {
  let out = null;
  const walk = (d) => {
    if (out) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
    for (const ent of entries) {
      const p = path.join(d, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.name === name) { out = p; return; }
    }
  };
  walk(dir);
  return out;
}

/** GitHub release 文件镜像：直连失败时按顺序回退（大陆网络常无法直连 GitHub  release CDN） */
// 国内加速镜像（固定版本直链，不依赖 GitHub API；按 平台_架构 选择）
export const FRP_MIRROR_URLS = {
  darwin_arm64: 'https://app.fengxiaozi.net/api/uploads/downloads/20260820072903_frp_0.71.0_darwin_arm64.tar.gz',
  darwin_amd64: 'https://app.fengxiaozi.net/api/uploads/downloads/20260820072856_frp_0.71.0_darwin_amd64.tar.gz',
  linux_amd64: 'https://app.fengxiaozi.net/api/uploads/downloads/20260820072915_frp_0.71.0_linux_amd64.tar.gz',
  linux_arm64: 'https://app.fengxiaozi.net/api/uploads/downloads/20260820072940_frp_0.71.0_linux_arm64.tar.gz',
  windows_amd64: 'https://app.fengxiaozi.net/api/uploads/downloads/20260820073003_frp_0.71.0_windows_amd64.zip',
  windows_arm64: 'https://app.fengxiaozi.net/api/uploads/downloads/20260820072956_frp_0.71.0_windows_arm64.zip',
};

export async function downloadFrpc(dir, directUrl) {
  const platform = process.platform;
  const arch = process.arch;
  const osName = platform === 'win32' ? 'windows' : platform;
  const archName = arch === 'x64' ? 'amd64' : arch === 'ia32' ? '386' : arch;
  const ext = platform === 'win32' ? 'zip' : 'tar.gz';
  const exeName = platform === 'win32' ? 'frpc.exe' : 'frpc';
  const target = path.join(dir, exeName);
  if (fs.existsSync(target)) return target;

  let urls;
  let assetName;
  if (directUrl) {
    // 完全自定义下载地址（可指向内网 / 自建镜像），跳过 GitHub API
    urls = [directUrl];
    assetName = 'frpc-download.' + ext;
  } else {
    const mirrorUrl = FRP_MIRROR_URLS[osName + '_' + archName] || null;
    // 先查 GitHub API 拿最新版本；不可用时回退国内加速镜像（固定版本直链）
    let ghUrl = null;
    try {
      const rel = await fetchJson('https://api.github.com/repos/fatedier/frp/releases/latest');
      const version = String(rel.tag_name || '').replace(/^v/, '');
      if (version) {
        assetName = 'frp_' + version + '_' + osName + '_' + archName + '.' + ext;
        ghUrl = 'https://github.com/fatedier/frp/releases/download/v' + version + '/' + assetName;
        const asset = (rel.assets || []).find((a) => a.name === assetName);
        if (asset && asset.browser_download_url) ghUrl = asset.browser_download_url;
      }
    } catch (e) { /* GitHub API 不可用，回退镜像 */ }
    if (!ghUrl && !mirrorUrl) throw new Error('获取 frp 最新版本号失败且当前平台无加速镜像，请手动下载 frpc 放入 toolsDir，或配置 frpcPath / frpDownloadUrl');
    if (!assetName) assetName = 'frp-mirror_' + osName + '_' + archName + '.' + ext;
    urls = [];
    if (ghUrl) urls.push(ghUrl);            // 1) GitHub 直连（最新版）
    if (mirrorUrl) urls.push(mirrorUrl);    // 2) 国内加速镜像
    if (ghUrl) urls.push('https://ghfast.top/' + ghUrl); // 3) ghfast 代理
  }

  const archive = path.join(dir, assetName);
  let lastErr = null;
  for (const u of urls) {
    try {
      await downloadFile(u, archive);
      lastErr = null;
      break;
    } catch (e) {
      lastErr = e;
      try { fs.rmSync(archive, { force: true }); } catch (e2) { /* ignore */ }
    }
  }
  if (lastErr) throw new Error('下载 frp 压缩包失败（' + String(lastErr.message || lastErr) + '），请手动下载 frpc 放入 toolsDir，或配置 frpcPath / frpDownloadUrl');
  const tmpDir = path.join(dir, 'frp-extract-' + Date.now());
  fs.mkdirSync(tmpDir, { recursive: true });
  try {
    // macOS/Linux 系统 tar 解 .tar.gz；Windows 10+ 自带 bsdtar 亦可解 .zip
    execFileSync('tar', ['-xf', archive, '-C', tmpDir]);
  } catch (e) {
    throw new Error('解压 frp 压缩包失败: ' + String(e && e.message || e));
  }
  const found = findFileRecursive(tmpDir, exeName);
  if (!found) throw new Error('frp 压缩包中未找到 ' + exeName);
  fs.renameSync(found, target);
  if (platform !== 'win32') { try { fs.chmodSync(target, 0o755); } catch (e) { /* ignore */ } }
  try { fs.rmSync(archive, { force: true }); } catch (e) { /* ignore */ }
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
  return target;
}

export function downloadFile(url, dest, attemptsLeft = 2) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { headers: { 'user-agent': 'dsh-web-remote-frp' }, rejectUnauthorized: false }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        file.close();
        fs.rmSync(dest, { force: true });
        downloadFile(new URL(res.headers.location, url).href, dest, attemptsLeft).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error('download failed: HTTP ' + res.statusCode));
        return;
      }
      res.pipe(file);
      file.on('finish', () => { file.close(); resolve(); });
    });
    req.on('error', (e) => {
      file.close();
      fs.rmSync(dest, { force: true });
      if (attemptsLeft > 0) {
        setTimeout(() => downloadFile(url, dest, attemptsLeft - 1).then(resolve, reject), 1500);
      } else {
        reject(e);
      }
    });
    req.setTimeout(60000, () => { req.destroy(new Error('download timeout')); });
  });
}

// ───────────────────────── 注入脚本（浏览器面板） ─────────────────────────

const INJECT_SCRIPT = `(function () {
  var NL = String.fromCharCode(10);
  var CHECK = 0;
  var currentTab = 'public';
  var lastInfo = null;
  var QR_SOURCES = ['https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=', 'https://api.pwmqr.com/qrcode/create/?url='];
  var currentBotChannel = null;
  function saveTab() {
    try { localStorage.setItem('frprm-tab', currentTab); } catch (e) {}
  }
  function loadTab() {
    var t = 'public';
    try {
      var v = localStorage.getItem('frprm-tab');
      if (v === 'lan') t = 'lan';
      else if (v === 'bot') t = 'bot';
      else if (v === 'settings') t = 'settings';
    } catch (e) {}
    return t;
  }
  function style() {
    var css = '#frprm-native{z-index:1;height:34px;margin:0;flex:0 0 auto;color:var(--dsw-alias-label-secondary,#6e6e73);cursor:pointer;background:transparent;border:none;border-radius:8px;display:flex;align-items:center;justify-content:center;gap:4px;padding:0 8px;font-size:13px;font-weight:500;font-family:inherit;transition:background .15s ease,color .15s ease}#frprm-native:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.1));color:var(--dsw-alias-label-primary,#1d1d1f)}#frprm-native:active{background:var(--dsw-alias-interactive-bg-hover-accent,rgba(120,120,128,.2))}#frprm-mask{position:fixed;inset:0;z-index:100000;background:var(--dsw-alias-bg-mask-1,rgba(0,0,0,.35));-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);}#frprm-panel{position:fixed;z-index:100001;left:50%;top:50%;transform:translate(-50%,-50%);width:min(560px,calc(100vw - 32px));max-height:calc(100vh - 48px);overflow:auto;background:color-mix(in srgb,var(--dsw-alias-bg-layer-2,#fff) 80%,transparent);-webkit-backdrop-filter:blur(30px) saturate(180%);backdrop-filter:blur(30px) saturate(180%);border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.1));border-radius:24px;box-shadow:0 24px 70px var(--dsw-alias-bg-mask-3,rgba(0,0,0,.3)),0 4px 16px var(--dsw-alias-bg-mask-2,rgba(0,0,0,.1));padding:22px 20px 18px;box-sizing:border-box;color:var(--dsw-alias-label-primary,#1d1d1f);font-size:14px;line-height:22px;font-family:-apple-system,BlinkMacSystemFont,\\'SF Pro Text\\',\\'Segoe UI\\',Roboto,\\'PingFang SC\\',\\'Microsoft YaHei\\',sans-serif;-webkit-font-smoothing:antialiased}#frprm-panel h2{margin:0 0 14px;font-size:19px;font-weight:600;letter-spacing:-.2px;display:flex;align-items:center;justify-content:space-between;color:var(--dsw-alias-label-primary,#1d1d1f)}#frprm-close{background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.14));border:none;cursor:pointer;width:26px;height:26px;border-radius:50%;font-size:15px;line-height:1;color:var(--dsw-alias-label-secondary,#48484a);display:flex;align-items:center;justify-content:center;padding:0;transition:background .15s}#frprm-close:hover{background:var(--dsw-alias-interactive-bg-hover-accent,rgba(120,120,128,.26))}#frprm-tabs{display:flex;justify-content:center;gap:2px;margin:2px 0 12px;background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.1));border-radius:10px;padding:2px;width:fit-content;margin-left:auto;margin-right:auto}#frprm-tabs button{cursor:pointer;border:0!important;outline:none!important;appearance:none;-webkit-appearance:none;background:transparent;color:var(--dsw-alias-label-secondary,#6e6e73);border-radius:8px;padding:5px 22px;font-size:13px;font-weight:500;font-family:inherit;transition:all .18s ease}#frprm-tabs button.frprm-tab-active{background:#fff;color:var(--dsw-alias-label-primary,#1d1d1f);box-shadow:0 1px 4px var(--dsw-alias-bg-mask-2,rgba(0,0,0,.1))}body[data-ds-dark-theme] #frprm-tabs button.frprm-tab-active{background:color-mix(in srgb,var(--dsw-alias-bg-overlay,#fff) 85%,#fff)}#frprm-status{display:flex;align-items:center;gap:8px;margin:6px 0 4px;font-size:13px;color:var(--dsw-alias-label-secondary,#6e6e73)}#frprm-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--dsw-alias-state-success-primary,#34c759);box-shadow:0 0 6px var(--dsw-alias-state-success-primary,#34c759)}.frprm-urlbox{background:color-mix(in srgb,var(--dsw-alias-bg-overlay,#fff) 70%,transparent);border:1px solid var(--dsw-alias-border-l1,rgba(0,0,0,.04));border-radius:14px;padding:12px 14px;margin:10px 0;cursor:pointer;word-break:break-all;box-shadow:0 1px 4px var(--dsw-alias-bg-mask-2,rgba(0,0,0,.04));transition:background .15s}.frprm-urlbox:hover{background:color-mix(in srgb,var(--dsw-alias-bg-overlay,#fff) 90%,transparent)}.frprm-label{font-size:12px;color:var(--dsw-alias-label-tertiary,#86868b);margin-bottom:4px}.frprm-url{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:18px;color:var(--dsw-alias-label-primary,#1d1d1f)}#frprm-row{display:flex;gap:2px;margin:16px 0 6px;background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.1));border-radius:10px;padding:2px}.frprm-btn{cursor:pointer;border:0!important;outline:none!important;appearance:none;-webkit-appearance:none;background:transparent;color:var(--dsw-alias-label-secondary,#6e6e73);border-radius:8px;padding:6px 0;font-size:13px;font-weight:500;font-family:inherit;flex:1;text-align:center;transition:all .18s ease;-webkit-tap-highlight-color:transparent}.frprm-btn:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.1));color:var(--dsw-alias-label-primary,#1d1d1f)}.frprm-btn:active{transform:none}.frprm-btn-primary{background:#fff;color:var(--dsw-alias-label-primary,#1d1d1f);box-shadow:0 1px 4px var(--dsw-alias-bg-mask-2,rgba(0,0,0,.1))}body[data-ds-dark-theme] .frprm-btn-primary{background:color-mix(in srgb,var(--dsw-alias-bg-overlay,#fff) 85%,#fff)}.frprm-btn-primary:hover{background:#fff;color:var(--dsw-alias-label-primary,#1d1d1f)}body[data-ds-dark-theme] .frprm-btn-primary:hover{background:color-mix(in srgb,var(--dsw-alias-bg-overlay,#fff) 85%,#fff)}.frprm-btn:disabled{opacity:.45;cursor:default}#frprm-hint{font-size:12px;color:var(--dsw-alias-label-tertiary,#86868b);margin-top:12px;white-space:pre-wrap;line-height:19px}#frprm-error{font-size:12px;color:var(--dsw-alias-state-error-primary,#ff3b30);margin-top:8px;white-space:pre-wrap}#frprm-qr{width:190px;height:190px;border-radius:14px;margin:12px auto;display:block;background:color-mix(in srgb,var(--dsw-alias-bg-overlay,#fff) 85%,#fff);padding:8px;box-sizing:border-box;box-shadow:0 2px 10px var(--dsw-alias-bg-mask-2,rgba(0,0,0,.06))}#frprm-bot-grid{display:flex;justify-content:center;gap:2px;margin:2px 0 12px;background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.12));border-radius:10px;padding:2px;width:fit-content;margin-left:auto;margin-right:auto}.frprm-bot-chip{cursor:pointer;border:0!important;outline:none!important;appearance:none;-webkit-appearance:none;background:transparent;color:var(--dsw-alias-label-secondary,#6e6e73);border-radius:8px;padding:5px 14px;font-size:13px;font-weight:500;font-family:inherit;transition:all .18s ease;-webkit-tap-highlight-color:transparent}.frprm-bot-chip:hover{color:var(--dsw-alias-label-primary,#1d1d1f)}.frprm-bot-chip-active{background:var(--dsw-alias-bg-layer-2,#fff);color:var(--dsw-alias-label-primary,#1d1d1f);box-shadow:0 1px 4px var(--dsw-alias-bg-mask-1,rgba(0,0,0,.1))}.frprm-bot-ic{display:inline-flex;align-items:center;justify-content:center;margin-right:4px;vertical-align:middle}.frprm-bot-ic svg{width:14px;height:14px}.frprm-bot-name{display:inline-block}#frprm-bot-detail{margin-top:4px}#frprm-bot-strow{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--dsw-alias-label-secondary,#6e6e73);margin:6px 0}#frprm-bot-dot{width:8px;height:8px;border-radius:50%;display:inline-block}#frprm-bot-desc{font-size:12px;color:var(--dsw-alias-label-secondary,#86868b);margin:4px 0 8px}.frprm-bot-actions{display:flex;gap:2px;margin:14px 0 6px;background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.12));border-radius:10px;padding:2px}.frprm-bot-actions .frprm-btn{flex:1;padding:6px 0;font-size:13px;font-weight:500;border-radius:8px;white-space:nowrap;background:transparent;color:var(--dsw-alias-label-secondary,#6e6e73)}.frprm-bot-actions .frprm-btn-primary{background:var(--dsw-alias-bg-layer-2,#fff);color:var(--dsw-alias-label-primary,#1d1d1f);box-shadow:0 1px 4px var(--dsw-alias-bg-mask-1,rgba(0,0,0,.1))}#frprm-bot-qr{margin:10px 0;padding:14px;border:1px dashed var(--dsw-alias-border-l2,rgba(0,0,0,.12));border-radius:12px;text-align:center;color:var(--dsw-alias-label-secondary,#86868b);font-size:12px}#frprm-bot-empty{font-size:13px;color:var(--dsw-alias-label-secondary,#86868b);text-align:center;padding:14px 0}#frprm-settings{padding:2px 0}#frprm-settings .frprm-set-ghead{display:flex;align-items:center;gap:6px;width:100%;margin:8px 0 0;padding:8px 10px;font-size:13px;font-weight:600;color:var(--dsw-alias-label-primary,#1d1d1f);background:var(--dsw-alias-interactive-bg-hover,rgba(120,120,128,.08));border:none;border-radius:10px;cursor:pointer;text-align:left;font-family:inherit;line-height:18px;transition:background .15s ease}#frprm-settings .frprm-set-ghead:hover{background:var(--dsw-alias-interactive-bg-hover-accent,rgba(120,120,128,.16))}#frprm-settings .frprm-set-chev{flex:0 0 auto;font-size:11px;color:var(--dsw-alias-label-secondary,#86868b)}#frprm-settings .frprm-set-section{padding:4px 0 6px}#frprm-settings .frprm-set-row{display:flex;align-items:center;gap:10px;margin:8px 0}#frprm-settings .frprm-set-label{flex:0 0 44%;font-size:12px;color:var(--dsw-alias-label-secondary,#6e6e73);text-align:right;line-height:16px}#frprm-settings .frprm-set-input{flex:1;min-width:0;padding:7px 10px;font-size:13px;line-height:18px;border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.12));border-radius:10px;background:var(--dsw-alias-bg-overlay,#fff);color:var(--dsw-alias-label-primary,#1d1d1f);outline:none;font-family:inherit;transition:border-color .15s ease}#frprm-settings textarea.frprm-set-input{min-height:58px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;line-height:15px}#frprm-settings .frprm-set-row:has(textarea){align-items:flex-start}#frprm-settings .frprm-set-row:has(textarea) .frprm-set-label{padding-top:8px}#frprm-settings .frprm-set-input:focus{border-color:var(--dsw-alias-label-tertiary,#86868b)}#frprm-settings .frprm-set-actions{display:flex;gap:8px;justify-content:center;margin-top:14px}#frprm-settings .frprm-set-dl{flex:0 0 auto;padding:6px 12px;font-size:12px;line-height:16px;white-space:nowrap;border-radius:8px}#frprm-settings .frprm-set-msg{font-size:12px;color:var(--dsw-alias-label-secondary,#86868b);margin-top:10px;text-align:center;white-space:pre-wrap;word-break:break-all;line-height:18px}.frprm-bot-urlrow{display:flex;align-items:center;gap:8px;margin:10px 0;flex-wrap:wrap}.frprm-bot-urllabel{font-size:12px;color:var(--dsw-alias-label-secondary,#6e6e73);flex:0 0 auto}.frprm-bot-urlval{flex:1;min-width:120px;font-size:12px;line-height:16px;padding:6px 10px;border:1px dashed var(--dsw-alias-border-l2,rgba(0,0,0,.12));border-radius:8px;word-break:break-all;color:var(--dsw-alias-label-primary,#1d1d1f)}.frprm-bot-cp{flex:0 0 auto;padding:5px 10px;font-size:12px;line-height:16px;border-radius:8px;white-space:nowrap}.frprm-bot-note{font-size:12px;color:var(--dsw-alias-label-secondary,#86868b);line-height:18px;margin-top:8px;white-space:pre-wrap}.frprm-bot-form{margin-top:12px;padding-top:10px;border-top:1px dashed var(--dsw-alias-border-l2,rgba(0,0,0,.1))}.frprm-bot-form .frprm-set-row{display:flex;align-items:center;gap:10px;margin:8px 0}.frprm-bot-form .frprm-set-label{flex:0 0 34%;font-size:12px;color:var(--dsw-alias-label-secondary,#6e6e73);text-align:right;line-height:16px}.frprm-bot-form .frprm-set-input{flex:1;min-width:0;padding:7px 10px;font-size:13px;line-height:18px;border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.12));border-radius:10px;background:var(--dsw-alias-bg-overlay,#fff);color:var(--dsw-alias-label-primary,#1d1d1f);outline:none;font-family:inherit;transition:border-color .15s ease}.frprm-bot-save{margin-top:10px;padding:6px 18px;font-size:13px;border-radius:8px}.frprm-bot-formmsg{font-size:12px;color:var(--dsw-alias-label-secondary,#86868b);margin-top:8px;text-align:center;white-space:pre-wrap;word-break:break-all;line-height:18px}';
    var tag = document.createElement('style');
    tag.textContent = css;
    document.head.appendChild(tag);
  }
  function findSidebarRoot() {
    // 精确找侧边栏根：计算样式含 --dsh-sidebar-inline-padding 的元素
    var all = document.querySelectorAll('div');
    for (var i = 0; i < all.length; i++) {
      var el = all[i];
      try {
        var v = window.getComputedStyle(el).getPropertyValue('--dsh-sidebar-inline-padding');
        if (v && v.trim() !== '') return el;
      } catch (e) { /* ignore */ }
    }
    return null;
  }
  function findSettingsArea() {
    // 优先：设置按钮（aria-label/title 含设置相关词）的父容器
    var buttons = document.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) {
      var b = buttons[i];
      var label = (b.getAttribute('aria-label') || '') + ' ' + (b.title || '') + ' ' + (b.textContent || '');
      if (/setting|设置|preference|偏好/i.test(label)) {
        var parent = b.parentNode;
        if (parent) return parent;
      }
    }
    // 兜底：侧边栏根元素的最后一个直接子容器（footArea）
    var root = findSidebarRoot();
    if (root && root.children.length) {
      var foot = root.children[root.children.length - 1];
      if (foot && foot.children.length) return foot;
      return foot;
    }
    return null;
  }
  function updateVisibility() {
    var btn = document.getElementById('frprm-native');
    if (!btn) return;
    var root = findSidebarRoot();
    var collapsed = root && (root.className || '').indexOf('collapsed') !== -1;
    btn.style.display = collapsed ? 'none' : '';
  }
  function syncGearColor() {
    // 重新读取设置按钮当前颜色并应用到远程按钮（主题/皮肤切换后颜色会变）
    var btn = document.getElementById('frprm-native');
    if (!btn) return;
    var area = findSettingsArea();
    if (!area) return;
    var buttons = area.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) {
      if (buttons[i] !== btn) {
        try { btn.style.color = window.getComputedStyle(buttons[i]).color; } catch (e) { /* ignore */ }
        return;
      }
    }
  }
  function attachButton(btn) {
    // 插入设置按钮旁（同一容器）
    var area = findSettingsArea();
    if (area) {
      // 容器改为横向 flex，靠左对齐：设置按钮贴左边框，手机按钮在它右侧
      try {
        area.style.display = 'flex';
        area.style.flexDirection = 'row';
        area.style.alignItems = 'center';
        area.style.justifyContent = 'flex-start';
        area.style.gap = '2px';
        // 设置按钮紧凑化：保留文字但缩短按钮体（内容宽、缩小内边距）
        var siblings = area.querySelectorAll('button');
        for (var si = 0; si < siblings.length; si++) {
          if (siblings[si] !== btn) {
            siblings[si].style.flex = '0 0 auto';
            siblings[si].style.width = 'auto';
            siblings[si].style.height = '34px';
            siblings[si].style.padding = '0 8px';
            siblings[si].style.fontSize = '13px';
            siblings[si].style.justifyContent = 'center';
            siblings[si].style.display = 'flex';
            siblings[si].style.alignItems = 'center';
            siblings[si].style.gap = '4px';
          }
        }
        syncGearColor();
      } catch (e) { /* ignore */ }
      // 手机按钮放设置按钮右侧（紧随其后）
      area.appendChild(btn);
      try { console.log('[frprm] inserted into:', area.tagName, area.className.slice(0, 80)); } catch (e) {}
      // 监听侧边栏根元素 class 变化（展开/收起）
      var root = findSidebarRoot();
      if (root && window.MutationObserver) {
        var obs = new MutationObserver(updateVisibility);
        obs.observe(root, { attributes: true, attributeFilter: ['class'] });
      }
      // 监听主题/皮肤变化：body/html 的 class/data/style 属性变化时重新同步颜色
      if (window.MutationObserver) {
        var themeObs = new MutationObserver(syncGearColor);
        themeObs.observe(document.body, { attributes: true, attributeFilter: ['class', 'data-ds-dark-theme', 'data-theme', 'style'] });
        if (document.documentElement) {
          themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-ds-dark-theme', 'data-theme', 'style'] });
        }
      }
      // 兜底：每 2 秒同步一次颜色（覆盖纯 CSS 变量变化，开销极小）
      var colorTimer = setInterval(syncGearColor, 2000);
      updateVisibility();
      return true;
    }
    return false;
  }
  function create() {
    if (document.getElementById('frprm-native')) return;
    style();
    var btn = document.createElement('button');
    btn.id = 'frprm-native';
    btn.type = 'button';
    btn.title = '远程访问 · frp';
    btn.setAttribute('aria-label', '远程访问 · frp');
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2" width="10" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/></svg><span>远程frp</span>';
    btn.addEventListener('click', openPanel);
    // 侧边栏由 React 异步渲染：轮询等待（最多 10 秒），找到设置区域再插入
    if (attachButton(btn)) return;
    var tries = 0;
    var timer = setInterval(function () {
      tries += 1;
      if (attachButton(btn)) {
        clearInterval(timer);
        return;
      }
      if (tries >= 40) {
        clearInterval(timer);
        document.body.appendChild(btn); // 兜底：保留可用性
      }
    }, 250);
  }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function fetchInfo() {
    // 时间戳参数强制绕过所有缓存（浏览器 + 代理层）
    return fetch('/frpremote/info?_=' + Date.now(), { cache: 'no-store' }).then(function (res) { return res.json(); });
  }
  function act(action) {
    return fetch('/frpremote/control', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: action }) }).then(function (res) { return res.json(); });
  }
  function copyText(text, labelEl, doneLabel) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        if (labelEl) {
          var prev = labelEl.textContent;
          labelEl.textContent = doneLabel || '已复制 ✓';
          setTimeout(function () { labelEl.textContent = prev; }, 1500);
        }
      }).catch(function () {});
    }
  }
  // 白色滑块跟随真实运行状态：运行中→「启动」高亮，已停止→「停止」高亮
  function syncActionButtons(info) {
    var s = document.getElementById('frprm-start');
    var p = document.getElementById('frprm-stop');
    if (!s || !p) return;
    var running = !!(info && info.running);
    s.className = running ? 'frprm-btn frprm-btn-primary' : 'frprm-btn';
    p.className = running ? 'frprm-btn' : 'frprm-btn frprm-btn-primary';
  }
  // 机器人通道定义
  var BOT_CHANNELS = [
    { id: 'weixin', name: '微信', icon: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8.691 2.188C3.891 2.188 0 5.476 0 9.53c0 2.212 1.17 4.203 3.002 5.55a.59.59 0 0 1 .213.665l-.39 1.48c-.019.07-.048.141-.048.213 0 .163.13.295.29.295a.326.326 0 0 0 .167-.054l1.903-1.114a.864.864 0 0 1 .717-.098 10.16 10.16 0 0 0 2.837.403c.276 0 .543-.027.811-.05-.857-2.578.157-4.972 1.932-6.446 1.703-1.415 3.882-1.98 5.853-1.838-.576-3.583-4.196-6.348-8.596-6.348zM5.785 5.991c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178A1.17 1.17 0 0 1 4.623 7.17c0-.651.52-1.18 1.162-1.18zm5.813 0c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178 1.17 1.17 0 0 1-1.162-1.178c0-.651.52-1.18 1.162-1.18zm5.34 2.867c-1.797-.052-3.746.512-5.28 1.786-1.72 1.428-2.687 3.72-1.78 6.22.942 2.453 3.666 4.229 6.884 4.229.826 0 1.622-.12 2.361-.336a.722.722 0 0 1 .598.082l1.584.926a.272.272 0 0 0 .14.047c.134 0 .24-.111.24-.247 0-.06-.023-.12-.038-.177l-.327-1.233a.582.582 0 0 1-.023-.156.49.49 0 0 1 .201-.398C23.024 18.48 24 16.82 24 14.98c0-3.21-2.931-5.837-6.656-6.088V8.89c-.135-.01-.27-.027-.407-.03zm-2.53 3.274c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.97-.982zm4.844 0c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.969-.982z"/></svg>', hint: 'ClawBot / iLink 扫码接入' },
    { id: 'qq', name: 'QQ', icon: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.395 15.035a40 40 0 0 0-.803-2.264l-1.079-2.695c.001-.032.014-.562.014-.836C19.526 4.632 17.351 0 12 0S4.474 4.632 4.474 9.241c0 .274.013.804.014.836l-1.08 2.695a39 39 0 0 0-.802 2.264c-1.021 3.283-.69 4.643-.438 4.673.54.065 2.103-2.472 2.103-2.472 0 1.469.756 3.387 2.394 4.771-.612.188-1.363.479-1.845.835-.434.32-.379.646-.301.778.343.578 5.883.369 7.482.189 1.6.18 7.14.389 7.483-.189.078-.132.132-.458-.301-.778-.483-.356-1.233-.646-1.846-.836 1.637-1.384 2.393-3.302 2.393-4.771 0 0 1.563 2.537 2.103 2.472.251-.03.581-1.39-.438-4.673"/></svg>', hint: 'NapCat（OneBot 11）连接后可用' },
    { id: 'telegram', name: '纸飞机', icon: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>', hint: 'Telegram Bot API 接入' },
    { id: 'dingtalk', name: '钉钉', icon: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/><path d="M10.5 7h3l-1.5 4h4l-6 8 1.5-4H8z" fill="#fff"/></svg>', hint: '钉钉机器人 Webhook 接入' },
    { id: 'feishu', name: '飞书', icon: '<svg viewBox="7 7 26 26" fill="currentColor"><path d="M16.791 30c5.57 0 10.423-3.074 12.955-7.618q.133-.239.258-.484a6 6 0 0 1-.425.699 6 6 0 0 1-.17.23 6 6 0 0 1-.225.274q-.092.105-.188.206a6 6 0 0 1-.407.384 6 6 0 0 1-.24.195 7 7 0 0 1-.292.21q-.094.065-.191.122c-.097.057-.134.081-.204.119q-.21.116-.428.215a6 6 0 0 1-.385.157 6 6 0 0 1-.43.138 6 6 0 0 1-.661.143 6 6 0 0 1-.491.055 6.125 6.125 0 0 1-1.543-.085 7 7 0 0 1-.38-.079l-.2-.051-.555-.155-.275-.081-.41-.125-.334-.107-.317-.104-.215-.073-.26-.091-.186-.066-.367-.134-.212-.081-.284-.11-.299-.119-.193-.079-.24-.1-.185-.078-.192-.084-.166-.073-.152-.067-.153-.07-.159-.073-.2-.093-.208-.099-.222-.108-.189-.093a31.2 31.2 0 0 1-8.822-6.583.202.202 0 0 0-.349.138l.005 9.52v.773c0 .448.222.87.595 1.118A14.75 14.75 0 0 0 16.791 30z"/><path d="M33.151 16.582a8.45 8.45 0 0 0-3.744-.869 8.5 8.5 0 0 0-2.303.317l-.252.075-.177.058-.348.127-.606.265-.617.33-.598.386-.404.306-.419.359-.218.206-.374.37-.269.266-.293.289-.281.278-.299.296-.348.344-.256.254-.085.084-.125.122-.063.06-.095.09-.105.099a15 15 0 0 1-3.072 2.175l.2.093.159.073.153.07.152.067.166.073.192.084.185.078.24.1.193.079.299.119.284.11.212.081.367.134.186.066.26.09.215.073.317.104.334.107.41.125.275.081.555.155.2.051.379.079.433.062.585.037.525-.014.491-.055a6 6 0 0 0 .66-.143l.43-.138.385-.158.427-.215.204-.119.191-.122.292-.21.24-.195.407-.384.188-.206.225-.274.17-.23a6 6 0 0 0 .421-.693l.144-.288 1.305-2.599-.003.006a8.1 8.1 0 0 1 1.697-2.439z"/><path d="M21.069 20.504l.063-.06.125-.122.085-.084.256-.254.348-.344.299-.296.281-.278.293-.289.269-.266.374-.37.218-.206.419-.359.404-.306.598-.386.617-.33.606-.265.348-.127.177-.058a14.78 14.78 0 0 0-2.793-5.603c-.252-.318-.639-.502-1.047-.502H12.221c-.196 0-.277.249-.119.364a31.49 31.49 0 0 1 8.943 10.162c.008-.007.016-.015.025-.023z"/></svg>', hint: '飞书自建应用事件回调接入' },
    { id: 'wecom', name: '企业微信', icon: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 3h16a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H9l-4.5 3.5a.6.6 0 0 1-1-.47V18H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm3 6.5a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5zm5 0a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5zm5 0a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5z"/></svg>', hint: '企业微信自建应用回调接入' },
  ];
  function botChannelStatus(id, info) {
    var b = (info && info.bots) ? info.bots : {};
    if (id === 'qq') {
      if (info && info.qq === 'connected') return '已连接';
      if (info && info.qq === 'listening') return '等待 NapCat 连接';
      return '未启动';
    }
    if (id === 'weixin') {
      if (info && info.weixin === 'connected') return '已连接';
      if (info && info.weixin === 'waiting') return '等待扫码';
      return '未连接';
    }
    if (id === 'telegram') {
      if (b.telegram === 'polling') return '轮询中';
      if (b.telegram === 'starting') return '启动中';
      if (b.telegram) return String(b.telegram).slice(0, 26);
      return '未配置';
    }
    if (id === 'dingtalk') return b.dingtalk ? '已就绪' : '未配置';
    if (id === 'feishu') return b.feishu ? '已就绪' : '未配置';
    if (id === 'wecom') return b.wecom ? '已就绪' : '未配置';
    return '未接入';
  }
  function botBaseUrl(info) {
    if (info && info.url) return info.url;
    if (info && info.port) {
      var ip = (info.ips && info.ips.length) ? info.ips[0] : '127.0.0.1';
      return 'http://' + ip + ':' + info.port;
    }
    return '';
  }
  function copyText(text, btn) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text);
    } catch (e) { /* ignore */ }
    var old = btn.textContent;
    btn.textContent = '已复制';
    setTimeout(function () { btn.textContent = old; }, 1200);
  }
  function renderChannelSetup(detail, id, info) {
    var base = botBaseUrl(info);
    function urlRow(label, val) {
      var w = el('div', 'frprm-bot-urlrow', '');
      w.appendChild(el('div', 'frprm-bot-urllabel', label));
      w.appendChild(el('div', 'frprm-bot-urlval', val || '（请先启动远程服务）'));
      if (val) {
        var cp = el('button', 'frprm-btn frprm-bot-cp', '复制');
        cp.type = 'button';
        cp.addEventListener('click', function () { copyText(val, cp); });
        w.appendChild(cp);
      }
      detail.appendChild(w);
    }
    function note(text) {
      detail.appendChild(el('div', 'frprm-bot-note', text));
    }
    if (id === 'qq') {
      urlRow('NapCat 反向 WS 地址', (info && info.qqPort) ? 'ws://127.0.0.1:' + info.qqPort : '');
      note('接入步骤：运行 NapCat → 网络配置 → 添加「反向 WebSocket」→ 填入上方地址。' + NL + '连接后在 QQ 私聊发「/链接」「帮助」即可收到回复；群聊仅响应 / 开头的命令消息。');
    } else if (id === 'telegram') {
      note('接入步骤：1) 在 @BotFather 创建机器人获取 Token；2) 在下方填写 Bot Token 并点「保存并应用」；3) 启动后自动长轮询接收消息（出站连接，无需公网回调）。' + NL + '直接给机器人发消息即可获得回复。');
      var b = (info && info.bots) ? info.bots : {};
      if (b.telegram && String(b.telegram).indexOf('error') === 0) note('当前状态：' + b.telegram);
    } else if (id === 'dingtalk') {
      urlRow('回调地址（HTTP POST）', base ? base + '/frpremote/bot/dingtalk' : '');
      note('接入步骤：钉钉开放平台 → 创建企业内部机器人 → 开启「消息接收」（HTTP 推送）→ 填入上方地址并发布 → 在下方填写机器人 Secret（用于签名校验）。' + NL + '之后 @机器人 或单聊发送消息即可获得回复。');
    } else if (id === 'feishu') {
      urlRow('请求地址（事件订阅）', base ? base + '/frpremote/bot/feishu' : '');
      note('接入步骤：飞书开放平台 → 创建企业自建应用 → 启用「机器人」能力 → 「事件订阅」选 HTTP 推送方式并填入上方地址 → 添加事件 im.message.receive_v1 → 开通 im:message 相关权限 → 发布版本。' + NL + '在下方填写 App ID / App Secret / Verification Token（Encrypt Key 可选）。');
    } else if (id === 'wecom') {
      urlRow('回调 URL（企业微信）', base ? base + '/frpremote/bot/wecom' : '');
      note('接入步骤：企业微信管理后台 → 应用管理 → 创建自建应用 → 「接收消息」设置 URL 为上方地址，并设置 Token / EncodingAESKey → 保存验证。' + NL + '在下方填写 CorpID / AgentId / Secret / Token / EncodingAESKey；Secret 在应用页「查看」，回调服务器 IP 需加入「企业可信 IP」。');
    }
    renderChannelCreds(detail, id);
  }
  function renderChannelCreds(detail, id) {
    var keys = BOT_CHANNEL_FIELDS[id];
    if (!keys || !keys.length) return;
    var form = el('div', 'frprm-bot-form', '');
    var inputs = {};
    keys.forEach(function (k) {
      var def = null;
      for (var i = 0; i < BOT_FIELD_DEFS.length; i++) if (BOT_FIELD_DEFS[i].key === k) { def = BOT_FIELD_DEFS[i]; break; }
      if (!def) return;
      var row = el('div', 'frprm-set-row', '');
      row.appendChild(el('label', 'frprm-set-label', def.label));
      var inp = document.createElement('input');
      inp.type = 'text';
      inp.placeholder = def.ph || '';
      inp.className = 'frprm-set-input';
      inputs[k] = inp;
      row.appendChild(inp);
      form.appendChild(row);
    });
    var fmsg = el('div', 'frprm-bot-formmsg', '');
    var saveBtn = el('button', 'frprm-btn frprm-btn-primary frprm-bot-save', '保存并应用');
    saveBtn.type = 'button';
    saveBtn.addEventListener('click', function () {
      saveBtn.disabled = true;
      fmsg.textContent = '保存中（将重启远程服务使其生效）…';
      var payload = {};
      keys.forEach(function (k) { payload[k] = inputs[k].value; });
      fetch('/frpremote/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data && data.ok) {
            fmsg.textContent = '已保存并重启应用。';
            fetch('/frpremote/info?_=' + Date.now(), { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (fresh) {
              lastInfo = fresh;
              var strow = document.getElementById('frprm-bot-strow');
              if (strow) {
                strow.textContent = '';
                var d2 = el('span', 'frprm-bot-dot', '');
                var stTxt = botChannelStatus(id, fresh);
                d2.style.background = (stTxt === '已就绪' || stTxt === '已连接' || stTxt === '轮询中') ? '#22c55e' : '#ef4444';
                strow.appendChild(d2);
                strow.appendChild(el('span', '', stTxt));
              }
              var b2 = (fresh && fresh.bots) ? fresh.bots : {};
              if (id === 'telegram' && b2.telegram && String(b2.telegram).indexOf('error') === 0) fmsg.textContent = '已保存，但轮询失败：' + b2.telegram;
            }).catch(function () {});
          } else {
            fmsg.textContent = (data && data.error) || '保存失败';
          }
        })
        .catch(function (e) { fmsg.textContent = '保存失败：' + String(e && e.message || e); })
        .finally(function () { saveBtn.disabled = false; });
    });
    form.appendChild(saveBtn);
    form.appendChild(fmsg);
    detail.appendChild(form);
    fetchConfigJson().then(function (data) {
      if (!data || !data.config) return;
      keys.forEach(function (k) { if (data.config[k] != null) inputs[k].value = data.config[k]; });
    }).catch(function () {});
  }
  function renderBotPage(panel, info, hint) {
    var box = document.getElementById('frprm-urlbox');
    if (!box) return;
    box.textContent = '';
    var grid = el('div', '', '');
    grid.id = 'frprm-bot-grid';
    BOT_CHANNELS.forEach(function (ch) {
      var b = el('button', 'frprm-bot-chip' + (currentBotChannel === ch.id ? ' frprm-bot-chip-active' : ''), '');
      b.type = 'button';
      b.setAttribute('data-channel', ch.id);
      var ic = el('span', 'frprm-bot-ic', '');
      ic.innerHTML = ch.icon;
      var nm = el('span', 'frprm-bot-name', ch.name);
      b.appendChild(ic);
      b.appendChild(nm);
      b.addEventListener('click', function () {
        currentBotChannel = (currentBotChannel === ch.id) ? null : ch.id;
        renderBotPage(panel, info, hint);
      });
      grid.appendChild(b);
    });
    box.appendChild(grid);
    var detail = el('div', '', '');
    detail.id = 'frprm-bot-detail';
    if (currentBotChannel) {
      var ch = null;
      for (var i = 0; i < BOT_CHANNELS.length; i++) if (BOT_CHANNELS[i].id === currentBotChannel) { ch = BOT_CHANNELS[i]; break; }
      if (ch) {
        var status = botChannelStatus(ch.id, info);
        var stRow = el('div', 'frprm-bot-strow', '');
        stRow.id = 'frprm-bot-strow';
        var d = el('span', 'frprm-bot-dot', '');
        d.style.background = (status === '已就绪' || status === '已连接' || status === '轮询中') ? '#22c55e' : '#ef4444';
        stRow.appendChild(d);
        stRow.appendChild(el('span', '', status));
        detail.appendChild(stRow);
        var desc = el('div', 'frprm-bot-desc', ch.name + '通道：' + ch.hint);
        detail.appendChild(desc);
        if (ch.id !== 'weixin') {
          renderChannelSetup(detail, ch.id, info);
          box.appendChild(detail);
          return;
        }
        var btns = el('div', 'frprm-bot-actions', '');
        var connectBtn = el('button', 'frprm-btn frprm-btn-primary', '绑定');
        connectBtn.type = 'button';
        connectBtn.addEventListener('click', function () {
          var st2 = document.getElementById('frprm-bot-strow');
          var qr2 = document.getElementById('frprm-bot-qr');
          if (ch.id === 'weixin') {
            // 微信 iLink 扫码绑定
            if (st2) { st2.textContent = ''; st2.appendChild(el('span', '', '正在获取二维码…')); }
            if (qr2) qr2.textContent = '';
            fetch('/frpremote/weixin/qrcode', { method: 'POST' }).then(function (r) { return r.json(); }).then(function (data) {
              if (!data.ok) {
                if (st2) { st2.textContent = ''; st2.appendChild(el('span', '', '获取失败: ' + (data.error || '未知错误'))); }
                return;
              }
              if (st2) { st2.textContent = ''; st2.appendChild(el('span', '', '用微信扫描下方二维码')); }
              if (qr2) {
                qr2.textContent = '';
                var img = el('img', '', '');
                img.src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(data.qrcodeUrl);
                img.style.cssText = 'width:200px;height:200px;border-radius:8px;background:#fff';
                qr2.appendChild(img);
                var tip = el('div', '', '打开微信扫描上方二维码');
                tip.style.cssText = 'font-size:11px;color:var(--dsw-alias-label-secondary,#888);margin-top:6px;text-align:center';
                qr2.appendChild(tip);
              }
              // 开始轮询扫码状态
              var pollTimer = setInterval(function () {
                fetch('/frpremote/weixin/poll').then(function (r) { return r.json(); }).then(function (res) {
                  if (res.status === 'connected') {
                    clearInterval(pollTimer);
                    if (st2) { st2.textContent = ''; st2.appendChild(el('span', '', '已连接')); st2.querySelector('span').previousElementSibling.style.background = '#22c55e'; }
                    if (qr2) qr2.textContent = '';
                    renderBotPage(panel, info, hint);
                  } else if (res.status === 'expired') {
                    clearInterval(pollTimer);
                    if (st2) { st2.textContent = ''; st2.appendChild(el('span', '', '二维码已过期，请重新绑定')); }
                  }
                }).catch(function () {});
              }, 3000);
            }).catch(function (e) {
              if (st2) { st2.textContent = ''; st2.appendChild(el('span', '', '网络错误: ' + e.message)); }
            });
          }
        });
        var discBtn = el('button', 'frprm-btn', '解绑');
        discBtn.type = 'button';
        discBtn.addEventListener('click', function () {
          var st3 = document.getElementById('frprm-bot-strow');
          var qr3 = document.getElementById('frprm-bot-qr');
          if (ch.id === 'weixin') {
            fetch('/frpremote/weixin/unbind', { method: 'POST' }).then(function (r) { return r.json(); }).then(function () {
              if (st3) { st3.textContent = ''; st3.appendChild(el('span', '', '已解绑')); var dot = st3.querySelector('.frprm-bot-dot'); if (dot) dot.style.background = '#ef4444'; }
              if (qr3) qr3.textContent = '';
            }).catch(function () {
              if (st3) { st3.textContent = ''; st3.appendChild(el('span', '', '解绑失败')); }
            });
          }
        });
        btns.appendChild(connectBtn);
        btns.appendChild(discBtn);
        detail.appendChild(btns);
        var qrZone = el('div', 'frprm-bot-qr', '');
        qrZone.id = 'frprm-bot-qr';
        qrZone.appendChild(el('div', '', '点击「绑定」开始扫码'));
        detail.appendChild(qrZone);
      }
    } else {
      detail.appendChild(el('div', 'frprm-bot-empty', '选择一个通道查看详情'));
    }
    box.appendChild(detail);
  }
  function renderStatus(panel, info, hint) {
    syncActionButtons(info);
    var st = document.getElementById('frprm-status');
    if (st) {
      st.textContent = '';
      var dot = el('span', '', '');
      dot.id = 'frprm-dot';
      dot.style.background = info && info.running ? '#22c55e' : '#ef4444';
      st.appendChild(dot);
      st.appendChild(el('span', '', info && info.running ? '运行中' : '已停止'));
    }
        // 设置标签：渲染配置表单，隐藏远程控制行与二维码
    var rowEl = document.getElementById('frprm-row');
    var qrEl = document.getElementById('frprm-qr');
    if (currentTab === 'settings') {
      if (rowEl) rowEl.style.display = 'none';
      if (qrEl && qrEl.parentNode) qrEl.parentNode.removeChild(qrEl);
      renderSettingsPage(panel, hint);
      var hs = document.getElementById('frprm-hint');
      if (hs) hs.textContent = '此处保存的配置写入 toolsDir/frp-config.json，优先于 cordis.patch.yml 的 config；留空项沿用 YAML 值。';
      var es = document.getElementById('frprm-error');
      if (es) es.textContent = '';
      return;
    }
        // 机器人标签：渲染四通道页面，隐藏远程控制行与二维码
    if (currentTab === 'bot') {
      if (rowEl) rowEl.style.display = 'none';
      if (qrEl && qrEl.parentNode) qrEl.parentNode.removeChild(qrEl);
      renderBotPage(panel, info, hint);
      var hb = document.getElementById('frprm-hint');
      if (hb) {
        hb.textContent = '通过聊天机器人遥控 DSH：微信 / QQ（NapCat）/ 纸飞机（Telegram）/ 钉钉 / 飞书 / 企业微信。' + NL + '支持指令：/链接 /停止远程 /会话列表 /选择 N /当前模型 /切换模型，或直接发「帮助」';
      }
      var eb = document.getElementById('frprm-error');
      if (eb) eb.textContent = '';
      return;
    }
    if (rowEl) rowEl.style.display = '';
    var box = document.getElementById('frprm-urlbox');
    if (!box) return;
    box.textContent = '';
    var urls = [];
    if (currentTab === 'lan' && info && info.ips && info.ips.length) {
      urls = info.ips.map(function (ip) { return { label: '局域网直连 ' + ip + '（点击复制）', url: (info.httpsPort ? 'https://' : 'http://') + ip + ':' + (info.httpsPort || info.port) + (info.lanOpen ? '' : '/?token=' + info.token) }; });
    } else if (info && info.url && info.token) {
      urls = [{ label: '公网访问链接（点击复制）', url: info.url + '/?token=' + info.token }];
    }
    if (urls.length === 0) {
      if (info && info.running && currentTab === 'public') {
        box.appendChild(el('div', '', '隧道已断开：请点「停止」后重新「启动」'));
      } else {
        box.appendChild(el('div', '', '尚未启动'));
      }
    }
    urls.forEach(function (item) {
      var labelEl = el('div', '', item.label);
      labelEl.className = 'frprm-label';
      var linkEl = el('div', '', item.url);
      linkEl.className = 'frprm-url';
      linkEl.style.marginBottom = '6px';
      box.appendChild(labelEl);
      box.appendChild(linkEl);
      box.addEventListener('click', function () { copyText(item.url, labelEl, '已复制 ✓'); });
    });
    var qr = document.getElementById('frprm-qr');
    if (qr && qr.parentNode) qr.parentNode.removeChild(qr);
    var qrTarget = currentTab === 'lan' && info && info.ips && info.ips.length ? (info.httpsPort ? 'https://' : 'http://') + info.ips[0] + ':' + (info.httpsPort || info.port) + (info.lanOpen ? '' : '/?token=' + info.token) : (info && info.url && info.token ? info.url + '/?token=' + info.token : null);
    if (qrTarget) {
      var qi = 0;
      var q = el('img', '', '');
      q.id = 'frprm-qr';
      q.alt = '扫码访问';
      var loadQr = function () {
        if (qi >= QR_SOURCES.length) {
          if (q.parentNode) q.parentNode.removeChild(q);
          return;
        }
        // 附加时间戳，强制浏览器重新加载二维码（避免缓存显示旧图）
        q.src = QR_SOURCES[qi] + encodeURIComponent(qrTarget) + '&_=' + Date.now();
        qi += 1;
      };
      q.addEventListener('error', loadQr);
      panel.insertBefore(q, hint);
      loadQr();
    } else if (info && info.running && currentTab === 'public') {
      var waitEl = el('div', '', '正在获取公网链接，请稍候…');
      waitEl.id = 'frprm-qr';
      waitEl.style.cssText = 'font-size:12px;color:var(--dsw-alias-label-secondary,#888);text-align:center;margin:10px 0';
      panel.insertBefore(waitEl, hint);
    }
    var h2 = document.getElementById('frprm-hint');
    if (h2) {
      var parts = [];
      parts.push('公网穿透：frp（frpc → 你自己的 frps 服务器）。');
      parts.push('注意：公网链接含访问令牌，请勿泄露。');
      parts.push('提示：同 Wi-Fi 建议用「局域网」链接，速度更快；公网速度取决于你的 frps 带宽。');
      h2.textContent = parts.join(NL + NL);
    }
    var err = document.getElementById('frprm-error');
    if (err) {
      if (info && info.error) err.textContent = String(info.error);
      else err.textContent = '';
    }
  }
  function setTab(tab, publicBtn, lanBtn, botBtn, settingsBtn, panel, hint) {
    currentTab = tab;
    saveTab();
    publicBtn.className = tab === 'public' ? 'frprm-tab-active' : '';
    lanBtn.className = tab === 'lan' ? 'frprm-tab-active' : '';
    if (botBtn) botBtn.className = tab === 'bot' ? 'frprm-tab-active' : '';
    if (settingsBtn) settingsBtn.className = tab === 'settings' ? 'frprm-tab-active' : '';
    if (lastInfo) renderStatus(panel, lastInfo, hint);
    else if (tab === 'settings') renderSettingsPage(panel, hint);
  }
var SETTINGS_FIELDS = [
    { key: 'frpServerAddr', label: 'frps 服务器地址', ph: '如 1.2.3.4 或 frp.example.com（必填才有公网）' },
    { key: 'frpServerPort', label: 'frps 端口 bindPort', ph: '7000', type: 'number' },
    { key: 'frpAuthToken', label: 'frps auth.token', ph: '与 frps 配置一致' },
    { key: 'frpProxyType', label: '穿透模式', type: 'select', options: [['tcp', 'tcp（远程端口）'], ['http', 'http（域名）'], ['https', 'https（域名 + 证书，访客侧 TLS）']] },
    { key: 'frpRemotePort', label: '公网端口（tcp）', ph: '13080', type: 'number' },
    { key: 'frpCustomDomains', label: '自定义域名（http）', ph: 'dsh.example.com，多个用逗号分隔' },
    { key: 'frpSubdomain', label: 'subdomain（http）', ph: '可选，frps 需配 subdomainHost' },
    { key: 'frpSubdomainHost', label: 'subdomainHost', ph: '可选，仅用于拼链接' },
    { key: 'frpVhostHTTPPort', label: 'vhostHTTPPort（http）', ph: '80', type: 'number' },
    { key: 'frpcPath', label: 'frpc 可执行文件路径', ph: '留空 = 自动探测 PATH / 自动下载', actions: [{ k: 'download', t: '一键下载' }, { k: 'reveal', t: '定位文件' }] },
    { key: 'frpDownloadUrl', label: '自定义下载地址', ph: '留空 = GitHub Releases + 镜像回退' },
    { key: 'frpTlsEnable', label: 'TLS 开关', type: 'select', options: [['', '默认（frp ≥0.50 自动启用）'], ['true', '强制启用'], ['false', '禁用']], group: 'frp TLS 证书' },
    { key: 'frpTlsCertFile', label: '客户端证书', ph: '文件路径，或直接粘贴 PEM 证书内容（保存时自动生成文件）', ta: true, group: 'frp TLS 证书' },
    { key: 'frpTlsKeyFile', label: '客户端私钥', ph: '文件路径，或直接粘贴 PEM 私钥内容（保存时自动生成文件）', ta: true, group: 'frp TLS 证书' },
    { key: 'frpTlsTrustedCaFile', label: 'CA 证书', ph: '校验自签 frps：文件路径，或粘贴 CA PEM 内容（保存时自动生成文件）', ta: true, group: 'frp TLS 证书' },
    { key: 'frpTlsServerName', label: 'serverName', ph: '校验服务端证书的主机名，留空用 serverAddr', group: 'frp TLS 证书' },
    { key: 'frpVhostHTTPSPort', label: 'frps vhostHTTPSPort', ph: 'https 模式：frps 侧 HTTPS 虚拟主机端口，通常 443', group: 'frp TLS 证书' },
    { key: 'frpHttpsCertFile', label: 'HTTPS 域名证书', ph: 'https 模式访客侧证书：文件路径，或粘贴 PEM（需匹配域名，保存自动生成文件）', ta: true, group: 'frp TLS 证书' },
    { key: 'frpHttpsKeyFile', label: 'HTTPS 域名私钥', ph: 'https 模式访客侧私钥：文件路径，或粘贴 PEM（保存自动生成文件）', ta: true, group: 'frp TLS 证书' },
  ];
  // 机器人通道凭据字段定义（渲染在「机器人」页各通道详情里，不在设置页）
  var BOT_CHANNEL_FIELDS = {
    telegram: ['tgBotToken'],
    dingtalk: ['dingtalkAppSecret'],
    feishu: ['feishuAppId', 'feishuAppSecret', 'feishuVerificationToken', 'feishuEncryptKey'],
    wecom: ['wecomCorpId', 'wecomAgentId', 'wecomCorpSecret', 'wecomToken', 'wecomEncodingAESKey'],
  };
  var BOT_FIELD_DEFS = [
    { key: 'tgBotToken', label: 'Bot Token', ph: '@BotFather 获取，形如 123456:ABC-DEF' },
    { key: 'dingtalkAppSecret', label: '机器人 Secret', ph: 'outgoing 回调签名校验用' },
    { key: 'feishuAppId', label: 'App ID', ph: 'cli_xxx' },
    { key: 'feishuAppSecret', label: 'App Secret', ph: '应用凭证' },
    { key: 'feishuVerificationToken', label: 'Verification Token', ph: '事件订阅的校验令牌' },
    { key: 'feishuEncryptKey', label: 'Encrypt Key', ph: '可选，开启事件加密时必填' },
    { key: 'wecomCorpId', label: 'CorpID', ph: 'ww1234567890abcdef' },
    { key: 'wecomAgentId', label: 'AgentId', ph: '自建应用的 AgentId' },
    { key: 'wecomCorpSecret', label: 'Secret', ph: '自建应用的 Secret' },
    { key: 'wecomToken', label: '回调 Token', ph: '接收消息服务里设置的 Token' },
    { key: 'wecomEncodingAESKey', label: 'EncodingAESKey', ph: '43 位随机密钥' },
  ];
  function fetchConfigJson() {
    return fetch('/frpremote/config?_=' + Date.now(), { cache: 'no-store' }).then(function (res) { return res.json(); });
  }
  function fetchSettings() {
    return fetch('/frpremote/config?_=' + Date.now(), { cache: 'no-store' }).then(function (res) { return res.json(); });
  }
  function renderSettingsPage(panel, hint) {
    var box = document.getElementById('frprm-urlbox');
    if (!box) return;
    box.textContent = '';
    box.style.cursor = 'default';
    var wrap = el('div', '', '');
    wrap.id = 'frprm-settings';
    var inputs = {};
    var msg = el('div', 'frprm-set-msg', '读取中…');
    function downloadFrpcClick(btn) {
      btn.disabled = true;
      msg.textContent = '正在按当前系统下载 frpc…（约 13MB，需联网）';
      fetch('/frpremote/frpc/download', { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data && data.ok) {
            if (inputs.frpcPath) inputs.frpcPath.value = data.path;
            msg.textContent = (data.existing ? '检测到已有 frpc（' + data.platform + '）：' : '下载完成（' + data.platform + '）：') + data.path + NL + '已自动填入路径，点「保存并重启」生效';
          } else {
            msg.textContent = '下载失败：' + ((data && data.error) || '未知错误');
          }
        })
        .catch(function (e) { msg.textContent = '下载失败：' + String(e && e.message || e); })
        .finally(function () { btn.disabled = false; });
    }
    function revealFrpcClick(btn) {
      btn.disabled = true;
      msg.textContent = '正在定位 frpc…';
      var p = inputs.frpcPath ? inputs.frpcPath.value : '';
      fetch('/frpremote/frpc/reveal', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ path: p }) })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data && data.ok) {
            if (inputs.frpcPath) inputs.frpcPath.value = data.path;
            msg.textContent = '已在文件管理器中显示：' + data.path + NL + '（路径已自动填入，如未保存请点「保存并重启」）';
          } else {
            msg.textContent = (data && data.error) || '打开失败';
          }
        })
        .catch(function (e) { msg.textContent = '打开失败：' + String(e && e.message || e); })
        .finally(function () { btn.disabled = false; });
    }
    // 按分组折叠展示（默认全部折叠，避免打开即过长）
    var sections = [];
    var curSec = null;
    SETTINGS_FIELDS.forEach(function (f) {
      var gname = f.group || ((f.key === 'frpcPath' || f.key === 'frpDownloadUrl') ? 'frpc 与下载' : 'frp 服务器穿透');
      if (!curSec || curSec.name !== gname) {
        curSec = { name: gname, body: el('div', 'frprm-set-section', '') };
        sections.push(curSec);
      }
      var row = el('div', 'frprm-set-row', '');
      var lab = el('label', 'frprm-set-label', f.label);
      var inp;
      if (f.type === 'select') {
        inp = document.createElement('select');
        f.options.forEach(function (o) {
          var op = document.createElement('option');
          op.value = o[0];
          op.textContent = o[1];
          inp.appendChild(op);
        });
      } else if (f.ta) {
        inp = document.createElement('textarea');
        inp.rows = 3;
        inp.placeholder = f.ph || '';
        inp.spellcheck = false;
      } else {
        inp = document.createElement('input');
        inp.type = f.type || 'text';
        inp.placeholder = f.ph || '';
      }
      inp.className = 'frprm-set-input';
      inputs[f.key] = inp;
      row.appendChild(lab);
      row.appendChild(inp);
      if (f.actions) {
        f.actions.forEach(function (a) {
          var actBtn = el('button', 'frprm-btn frprm-set-dl', a.t);
          actBtn.type = 'button';
          actBtn.addEventListener('click', function () {
            if (a.k === 'reveal') revealFrpcClick(actBtn);
            else downloadFrpcClick(actBtn);
          });
          row.appendChild(actBtn);
        });
      }
      curSec.body.appendChild(row);
    });
    sections.forEach(function (sec) {
      var head = el('button', 'frprm-set-ghead', '');
      head.type = 'button';
      var chev = el('span', 'frprm-set-chev', '▸');
      head.appendChild(chev);
      head.appendChild(el('span', '', sec.name));
      sec.body.style.display = 'none'; // 默认折叠
      head.addEventListener('click', function () {
        var open = sec.body.style.display !== 'none';
        sec.body.style.display = open ? 'none' : '';
        chev.textContent = open ? '▸' : '▾';
      });
      wrap.appendChild(head);
      wrap.appendChild(sec.body);
    });
    var actions = el('div', 'frprm-set-actions', '');
    var saveBtn = el('button', 'frprm-btn frprm-btn-primary', '保存并重启');
    var resetBtn = el('button', 'frprm-btn', '清除本地配置');
    saveBtn.type = 'button';
    resetBtn.type = 'button';
    actions.appendChild(saveBtn);
    actions.appendChild(resetBtn);
    wrap.appendChild(actions);
    wrap.appendChild(msg);
    box.appendChild(wrap);

    fetchSettings().then(function (data) {
      if (!data || !data.ok) { msg.textContent = '读取配置失败'; return; }
      var c = data.config || {};
      Object.keys(inputs).forEach(function (k) {
        var v = c[k];
        if (v === undefined || v === null) v = '';
        if (Array.isArray(v)) v = v.join(', ');
        inputs[k].value = String(v);
      });
      msg.textContent = data.hasFile
        ? '已加载本地配置（frp-config.json' + (data.savedAt ? '，保存于 ' + new Date(data.savedAt).toLocaleString() : '') + '）'
        : '当前为 YAML 默认配置；填写后点「保存并重启」';
    }).catch(function () { msg.textContent = '读取配置失败'; });

    saveBtn.addEventListener('click', function () {
      var payload = {};
      Object.keys(inputs).forEach(function (k) { payload[k] = inputs[k].value; });
      saveBtn.disabled = true;
      msg.textContent = '保存并重启中…（frpc 重连约需几秒）';
      fetch('/frpremote/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data && data.ok) {
            var st = data.state || {};
            lastInfo = st;
            if (st.url) msg.textContent = '已保存并重启 ✓ 公网链接：' + st.url;
            else if (st.error) msg.textContent = '已保存，但启动提示：' + st.error;
            else msg.textContent = '已保存并重启';
          } else {
            msg.textContent = '保存失败：' + ((data && data.error) || '未知错误');
          }
        })
        .catch(function (e) { msg.textContent = '保存失败：' + String(e && e.message || e); })
        .finally(function () { saveBtn.disabled = false; });
    });
    resetBtn.addEventListener('click', function () {
      resetBtn.disabled = true;
      msg.textContent = '清除本地配置并重启中…';
      fetch('/frpremote/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'reset' }) })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data && data.ok) {
            msg.textContent = '已清除本地配置，恢复 YAML 默认值并重启';
            if (data.state) lastInfo = data.state;
            var c = data.config || {};
            Object.keys(inputs).forEach(function (k) {
              var v = c[k];
              if (v === undefined || v === null) v = '';
              if (Array.isArray(v)) v = v.join(', ');
              inputs[k].value = String(v);
            });
          } else {
            msg.textContent = '清除失败：' + ((data && data.error) || '');
          }
        })
        .catch(function (e) { msg.textContent = '清除失败：' + String(e && e.message || e); })
        .finally(function () { resetBtn.disabled = false; });
    });
  }
  function openPanel() {
    if (document.getElementById('frprm-mask')) return;
    currentTab = loadTab();
    var mask = el('div', '', '');
    mask.id = 'frprm-mask';
    var panel = el('div', '', '');
    panel.id = 'frprm-panel';
    var head = el('h2', '', '远程访问 · frp');
    var x = el('button', '', '×');
    x.id = 'frprm-close';
    x.setAttribute('aria-label', '关闭');
    head.appendChild(x);
    panel.appendChild(head);
    var tabs = el('div', '', '');
    tabs.id = 'frprm-tabs';
    var publicBtn = el('button', currentTab === 'public' ? 'frprm-tab-active' : '', '公网');
    publicBtn.type = 'button';
    var lanBtn = el('button', currentTab === 'lan' ? 'frprm-tab-active' : '', '局域网');
    var botBtn = el('button', currentTab === 'bot' ? 'frprm-tab-active' : '', '机器人');
    var settingsBtn = el('button', currentTab === 'settings' ? 'frprm-tab-active' : '', '设置');
    botBtn.type = 'button';
    lanBtn.type = 'button';
    settingsBtn.type = 'button';
    tabs.appendChild(publicBtn);
    tabs.appendChild(lanBtn);
    tabs.appendChild(botBtn);
    tabs.appendChild(settingsBtn);
    panel.appendChild(tabs);
    var statusRow = el('div', '', '加载中…');
    statusRow.id = 'frprm-status';
    panel.appendChild(statusRow);
    var urlBox = el('div', '', '');
    urlBox.id = 'frprm-urlbox';
    panel.appendChild(urlBox);
    var row = el('div', '', '');
    row.id = 'frprm-row';
    row.className = 'frprm-row';
    var startBtn = el('button', 'frprm-btn frprm-btn-primary', '启动');
    startBtn.type = 'button';
    startBtn.id = 'frprm-start';
    var stopBtn = el('button', 'frprm-btn', '停止');
    stopBtn.type = 'button';
    stopBtn.id = 'frprm-stop';
    var refreshBtn = el('button', 'frprm-btn', '换新链接');
    refreshBtn.type = 'button';
    refreshBtn.id = 'frprm-refresh';
    row.appendChild(startBtn);
    row.appendChild(stopBtn);
    row.appendChild(refreshBtn);
    panel.appendChild(row);
    var err = el('div', '', '');
    err.id = 'frprm-error';
    err.className = 'frprm-error';
    panel.appendChild(err);
    var hint = el('div', '', '');
    hint.id = 'frprm-hint';
    hint.className = 'frprm-hint';
    panel.appendChild(hint);
    var retryCount = 0;
    function close() {
      if (mask.parentNode) mask.parentNode.removeChild(mask);
      if (panel.parentNode) panel.parentNode.removeChild(panel);
      lastInfo = null;
    }
    function refresh() {
      startBtn.disabled = true;
      stopBtn.disabled = true;
      refreshBtn.disabled = true;
      fetchInfo().then(function (info) {
        lastInfo = info;
        renderStatus(panel, info, hint);
        if (info && info.running && currentTab === 'public' && !info.url && retryCount < 3) {
          retryCount += 1;
          setTimeout(function () { refresh(); }, 5000);
        }
      }).catch(function () {
        var st2 = document.getElementById('frprm-status');
        if (st2) st2.textContent = '获取状态失败';
      }).finally(function () {
        startBtn.disabled = false;
        stopBtn.disabled = false;
        refreshBtn.disabled = false;
      });
    }
    function control(action) {
      startBtn.disabled = true;
      stopBtn.disabled = true;
      refreshBtn.disabled = true;
      act(action).then(function (info) {
        lastInfo = info;
        renderStatus(panel, info, hint);
      }).catch(function () {
        var st3 = document.getElementById('frprm-status');
        if (st3) st3.textContent = '操作失败';
      }).finally(function () {
        startBtn.disabled = false;
        stopBtn.disabled = false;
        refreshBtn.disabled = false;
      });
    }
    mask.addEventListener('click', close);
    x.addEventListener('click', close);
    publicBtn.addEventListener('click', function () { setTab('public', publicBtn, lanBtn, botBtn, settingsBtn, panel, hint); });
    lanBtn.addEventListener('click', function () { setTab('lan', publicBtn, lanBtn, botBtn, settingsBtn, panel, hint); });
    botBtn.addEventListener('click', function () { setTab('bot', publicBtn, lanBtn, botBtn, settingsBtn, panel, hint); });
    settingsBtn.addEventListener('click', function () { setTab('settings', publicBtn, lanBtn, botBtn, settingsBtn, panel, hint); });
    startBtn.addEventListener('click', function () { control('start'); });
    stopBtn.addEventListener('click', function () { control('stop'); });
    refreshBtn.addEventListener('click', function () {
      var st4 = document.getElementById('frprm-status');
      if (st4) st4.textContent = '正在换新链接…';
      control('renew');
    });
    document.body.appendChild(mask);
    document.body.appendChild(panel);
    refresh();
  }
  function tryCreate() {
    if (document.querySelector('.frprm-fab')) return;
    if (document.body) {
      create();
    } else if (CHECK < 40) {
      CHECK += 1;
      setTimeout(tryCreate, 250);
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', tryCreate);
  } else {
    tryCreate();
  }
})();`;

// ───────────────────────── frp 配置生成 ─────────────────────────

export function normalizeDomains(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v.map(String).map((s) => s.trim()).filter(Boolean);
  return String(v).split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
}

/** 生成 frpc TOML 配置（frp >= 0.52 的 TOML 格式） */
export function buildFrpcToml(o) {
  const lines = [];
  lines.push('serverAddr = ' + JSON.stringify(o.serverAddr));
  lines.push('serverPort = ' + (Number(o.serverPort) || 7000));
  if (o.authToken) {
    lines.push('');
    lines.push('auth.method = "token"');
    lines.push('auth.token = ' + JSON.stringify(o.authToken));
  }
  // TLS（frpc ↔ frps 传输层证书）
  const hasTlsFile = Boolean(o.tlsCertFile || o.tlsKeyFile || o.tlsTrustedCaFile || o.tlsServerName);
  if (o.tlsEnable === true || o.tlsEnable === false || hasTlsFile) {
    lines.push('');
    if (o.tlsEnable === true || o.tlsEnable === false) lines.push('transport.tls.enable = ' + o.tlsEnable);
    if (o.tlsCertFile) lines.push('transport.tls.certFile = ' + JSON.stringify(o.tlsCertFile));
    if (o.tlsKeyFile) lines.push('transport.tls.keyFile = ' + JSON.stringify(o.tlsKeyFile));
    if (o.tlsTrustedCaFile) lines.push('transport.tls.trustedCaFile = ' + JSON.stringify(o.tlsTrustedCaFile));
    if (o.tlsServerName) lines.push('transport.tls.serverName = ' + JSON.stringify(o.tlsServerName));
  }
  lines.push('');
  lines.push('[[proxies]]');
  lines.push('name = ' + JSON.stringify(o.proxyName));
  lines.push('type = ' + JSON.stringify(o.proxyType));
  if (o.proxyType === 'https') {
    // https2http 插件：frpc 用域名证书终结 TLS，再以明文 HTTP 转发到本地代理
    if (o.customDomains && o.customDomains.length) lines.push('customDomains = [' + o.customDomains.map((d) => JSON.stringify(d)).join(', ') + ']');
    if (o.subdomain) lines.push('subdomain = ' + JSON.stringify(o.subdomain));
    lines.push('[proxies.plugin]');
    lines.push('type = "https2http"');
    lines.push('localAddr = "127.0.0.1:' + (Number(o.localPort) || 0) + '"');
    if (o.httpsCertFile) lines.push('crtPath = ' + JSON.stringify(o.httpsCertFile));
    if (o.httpsKeyFile) lines.push('keyPath = ' + JSON.stringify(o.httpsKeyFile));
  } else {
    lines.push('localIP = "127.0.0.1"');
    lines.push('localPort = ' + (Number(o.localPort) || 0));
    if (o.proxyType === 'http') {
      if (o.customDomains && o.customDomains.length) lines.push('customDomains = [' + o.customDomains.map((d) => JSON.stringify(d)).join(', ') + ']');
      if (o.subdomain) lines.push('subdomain = ' + JSON.stringify(o.subdomain));
    } else {
      lines.push('remotePort = ' + (Number(o.remotePort) || 0));
    }
  }
  return lines.join('\n') + '\n';
}

/** 由配置推算公网访问地址（不含 token） */
export function computeFrpUrl(cfg) {
  if (cfg.frpProxyType === 'http' || cfg.frpProxyType === 'https') {
    let host = '';
    if (cfg.frpCustomDomains && cfg.frpCustomDomains.length) host = cfg.frpCustomDomains[0];
    else if (cfg.frpSubdomain && cfg.frpSubdomainHost) host = cfg.frpSubdomain + '.' + cfg.frpSubdomainHost;
    if (!host) return null;
    if (cfg.frpProxyType === 'https') {
      const port = Number(cfg.frpVhostHTTPSPort || 443);
      return 'https://' + host + (port === 443 ? '' : ':' + port);
    }
    const port = Number(cfg.frpVhostHTTPPort || 80);
    return 'http://' + host + (port === 80 ? '' : ':' + port);
  }
  return 'http://' + cfg.frpServerAddr + ':' + Number(cfg.frpRemotePort);
}

// ───────────────────────── 插件主体 ─────────────────────────

export const name = 'web-remote-frp';
export const inject = ['timer'];

export function apply(ctx, rawConfig) {
  const cfg = rawConfig ?? {};
  const config = {
    targetPort: cfg.targetPort ?? 3080,
    httpPortStart: cfg.httpPortStart ?? 3081,
    httpsPortStart: cfg.httpsPortStart ?? 3082,
    qqPortStart: cfg.qqPortStart ?? 3001,
    frpcPath: cfg.frpcPath ?? '',
    frpDownloadUrl: cfg.frpDownloadUrl ?? '',
    // frp TLS 证书（frpc ↔ frps 传输层）
    frpTlsEnable: cfg.frpTlsEnable ?? '',              // '' 默认（frp≥0.50 默认启用 TLS）| 'true' | 'false'
    frpTlsCertFile: cfg.frpTlsCertFile ?? '',          // transport.tls.certFile（双向认证/自定义证书）
    frpTlsKeyFile: cfg.frpTlsKeyFile ?? '',            // transport.tls.keyFile
    frpTlsTrustedCaFile: cfg.frpTlsTrustedCaFile ?? '',// transport.tls.trustedCaFile（校验 frps 自签 CA）
    frpTlsServerName: cfg.frpTlsServerName ?? '',      // transport.tls.serverName
    // HTTPS 模式（访客侧 TLS）：type=https + https2http 插件在 frpc 终结证书
    frpVhostHTTPSPort: cfg.frpVhostHTTPSPort ?? 443,   // frps 端 vhostHTTPSPort
    frpHttpsCertFile: cfg.frpHttpsCertFile ?? '',      // 域名证书（路径或粘贴 PEM 自动落盘）
    frpHttpsKeyFile: cfg.frpHttpsKeyFile ?? '',        // 域名私钥（路径或粘贴 PEM 自动落盘）
    frpServerAddr: cfg.frpServerAddr ?? '',
    frpServerPort: cfg.frpServerPort ?? 7000,
    frpAuthToken: cfg.frpAuthToken ?? '',
    frpProxyType: cfg.frpProxyType ?? 'tcp',
    frpRemotePort: cfg.frpRemotePort ?? 3080,
    frpCustomDomains: normalizeDomains(cfg.frpCustomDomains),
    frpSubdomain: cfg.frpSubdomain ?? '',
    frpSubdomainHost: cfg.frpSubdomainHost ?? '',
    frpVhostHTTPPort: cfg.frpVhostHTTPPort ?? 80,
    frpProxyName: cfg.frpProxyName ?? '',
    pfxPath: cfg.pfxPath ?? '',
    pfxPass: cfg.pfxPass ?? '',
    toolsDir: cfg.toolsDir ?? '',
    autoStart: cfg.autoStart ?? true,
    lanOpen: cfg.lanOpen ?? true,
    // ── 机器人通道 ──
    tgBotToken: cfg.tgBotToken ?? '',
    tgApiBase: cfg.tgApiBase ?? '',
    dingtalkAppSecret: cfg.dingtalkAppSecret ?? '',
    feishuAppId: cfg.feishuAppId ?? '',
    feishuAppSecret: cfg.feishuAppSecret ?? '',
    feishuVerificationToken: cfg.feishuVerificationToken ?? '',
    feishuEncryptKey: cfg.feishuEncryptKey ?? '',
    feishuApiBase: cfg.feishuApiBase ?? '',
    wecomCorpId: cfg.wecomCorpId ?? '',
    wecomCorpSecret: cfg.wecomCorpSecret ?? '',
    wecomAgentId: cfg.wecomAgentId ?? '',
    wecomToken: cfg.wecomToken ?? '',
    wecomEncodingAESKey: cfg.wecomEncodingAESKey ?? '',
    wecomApiBase: cfg.wecomApiBase ?? '',
  };

  // 等待 webServer / subprocess 服务就绪后再挂载（与官方 dsh-market 同款模式）
  ctx.inject(['subprocess', 'webServer'], (hostCtx) => {
    const subprocess = hostCtx.subprocess;
    const webServer = hostCtx.webServer;

    // 工具目录：$DSH_HOME/tools 或 ~/.dsh/tools
    let toolsDir = config.toolsDir;
    if (!toolsDir) {
      toolsDir = process.env.DSH_HOME ? path.join(process.env.DSH_HOME, 'tools') : path.join(os.homedir(), '.dsh', 'tools');
    }
    try { fs.mkdirSync(toolsDir, { recursive: true }); } catch (e) { /* ignore */ }

  const state = { running: false, starting: false, url: null, token: null, port: null, httpsPort: null, ips: [], qq: null, error: null, updatedAt: null };
  let proxy = null;
  let tunnelHandle = null;
  let qqServer = null;
  let qqPort = null;
  let telegramPoller = null;

  // ── 面板「设置」页持久化配置：toolsDir/frp-config.json，优先于 YAML config ──
  const cfgFilePath = path.join(toolsDir, 'frp-config.json');
  const CFG_KEYS = ['frpcPath', 'frpServerAddr', 'frpServerPort', 'frpAuthToken', 'frpProxyType', 'frpRemotePort', 'frpCustomDomains', 'frpSubdomain', 'frpSubdomainHost', 'frpVhostHTTPPort', 'frpProxyName', 'frpDownloadUrl', 'frpTlsEnable', 'frpTlsCertFile', 'frpTlsKeyFile', 'frpTlsTrustedCaFile', 'frpTlsServerName', 'frpVhostHTTPSPort', 'frpHttpsCertFile', 'frpHttpsKeyFile', 'tgBotToken', 'tgApiBase', 'dingtalkAppSecret', 'feishuAppId', 'feishuAppSecret', 'feishuVerificationToken', 'feishuEncryptKey', 'feishuApiBase', 'wecomCorpId', 'wecomCorpSecret', 'wecomAgentId', 'wecomToken', 'wecomEncodingAESKey', 'wecomApiBase'];
  let fileCfg = {};
  let fileCfgSavedAt = null;
  try {
    if (fs.existsSync(cfgFilePath)) {
      const v = JSON.parse(fs.readFileSync(cfgFilePath, 'utf8'));
      if (v && typeof v === 'object') fileCfg = v;
      try { fileCfgSavedAt = fs.statSync(cfgFilePath).mtimeMs; } catch (e) { /* ignore */ }
    }
  } catch (e) { /* 损坏的文件按无配置处理 */ }
  /** 生效配置 = YAML 默认值 ← 面板保存的本地配置（非空项覆盖） */
  const effectiveConfig = () => {
    const out = {};
    for (const k of CFG_KEYS) {
      const fv = fileCfg[k];
      out[k] = (fv !== undefined && fv !== null && fv !== '') ? fv : config[k];
    }
    out.frpCustomDomains = normalizeDomains(out.frpCustomDomains);
    return out;
  };

  const waitFrpcReady = (handle, timeoutMs) => new Promise((resolve, reject) => {
    let stdoutOffset = 0;
    let stderrOffset = 0;
    let acc = '';
    let exited = false;
    try { handle.done.then(() => { exited = true; }, () => { exited = true; }); } catch (e) { /* ignore */ }
    const started = Date.now();
    // frp 各版本成功日志："[name] start proxy success"（新版）/ "start proxy [name] success"（旧版）
    const okRe = /(start proxy success|start proxy \[[^\]]+\] success)/;
    const failRe = /(login to server failed|login to the server failed|auth token is incorrect|\] start error:|proxy \[[^\]]+\] already exists)/i;
    const lastLine = () => acc.split('\n').map((l) => l.trim()).filter(Boolean).pop() || acc.slice(-200);
    const tick = () => {
      try {
        const so = handle.collected.stdout;
        if (so) { const r = so.readFrom(stdoutOffset); stdoutOffset = r.nextOffset; acc += r.text; }
        const se = handle.collected.stderr;
        if (se) { const r = se.readFrom(stderrOffset); stderrOffset = r.nextOffset; acc += r.text; }
      } catch (e) { reject(e); return; }
      const fm = acc.match(failRe);
      if (fm) { reject(new Error('frpc 启动失败: ' + lastLine())); return; }
      if (okRe.test(acc)) { resolve(); return; }
      if (exited) { reject(new Error('frpc 异常退出: ' + lastLine())); return; }
      if (Date.now() - started > timeoutMs) { reject(new Error('等待 frpc 建立隧道超时: ' + lastLine())); return; }
      ctx.timeout(tick, 200);
    };
    tick();
  });

  const spec = (argv, extraEnv) => ({
    argv,
    cwd: toolsDir,
    stdio: { stdin: 'ignore', stdout: { maxBytes: 65536, spill: { maxBytes: 1048576 } }, stderr: { maxBytes: 65536, spill: { maxBytes: 1048576 } } },
    graceMs: 2000,
    env: extraEnv || {},
  });

  const stop = () => {
    if (tunnelHandle) { try { tunnelHandle.terminate(); } catch (e) { /* ignore */ } }
    tunnelHandle = null;
    if (telegramPoller) { telegramPoller.stop(); telegramPoller = null; }
    if (proxy) { proxy.close(); proxy = null; }
    if (qqServer) { qqServer.close(); qqServer = null; }
    qqPort = null;
    state.running = false;
    state.url = null;
    state.token = null;
    state.port = null;
    state.httpsPort = null;
    state.ips = [];
    state.qq = null;
    state.updatedAt = Date.now();
  };

  const start = async () => {
    if (state.running || state.starting) return state;
    state.starting = true;
    state.error = null;
    try {
      // 1. 反向代理（HTTP + HTTPS 同端口族）
      proxy = createProxyServer({ targetPort: config.targetPort, pfxPath: config.pfxPath, pfxPass: config.pfxPass, lanOpen: config.lanOpen });
      const httpPort = await findFreePort(config.httpPortStart, config.httpPortStart + 9);
      const httpsPort = await findFreePort(config.httpsPortStart, config.httpsPortStart + 9);
      await proxy.start(httpPort, httpsPort);
      state.token = proxy.token;
      state.port = httpPort;
      state.httpsPort = httpsPort;
      state.ips = lanIPs();

      // 2. frp 公网穿透（frpc → 你的 frps 服务器）
      const c = effectiveConfig();
      if (!c.frpServerAddr) {
        state.error = '未配置 frpServerAddr：公网穿透不可用，当前仅「局域网」直连可用。请到面板「设置」页填写 frps 服务器信息。';
      } else {
        try {
          const useHttp = c.frpProxyType === 'http' || c.frpProxyType === 'https';
          if (useHttp && c.frpCustomDomains.length === 0 && !c.frpSubdomain) {
            throw new Error('frpProxyType=' + c.frpProxyType + ' 需要配置 frpCustomDomains 或 frpSubdomain（且 frps 需开启 vhostHTTP' + (c.frpProxyType === 'https' ? 'S' : '') + 'Port）');
          }
          if (c.frpProxyType === 'https') {
            if (!c.frpHttpsCertFile || !c.frpHttpsKeyFile) {
              throw new Error('HTTPS 模式需要域名证书与私钥：请在设置页「frp TLS 证书」分组填写 frpHttpsCertFile / frpHttpsKeyFile（支持文件路径或直接粘贴 PEM）');
            }
            if (!fs.existsSync(c.frpHttpsCertFile)) throw new Error('HTTPS 证书文件不存在: ' + c.frpHttpsCertFile);
            if (!fs.existsSync(c.frpHttpsKeyFile)) throw new Error('HTTPS 私钥文件不存在: ' + c.frpHttpsKeyFile);
          }
          let frpcPath = c.frpcPath;
          if (!frpcPath) {
            try { frpcPath = await subprocess.resolveExecutable('frpc'); } catch (e) { /* 不在 PATH */ }
          }
          if (!frpcPath) {
            frpcPath = path.join(toolsDir, process.platform === 'win32' ? 'frpc.exe' : 'frpc');
            if (!fs.existsSync(frpcPath)) {
              state.error = 'frpc 未找到，正在自动下载…';
              await downloadFrpc(toolsDir, config.frpDownloadUrl);
            }
          }
          state.error = null;
          // 代理名默认随机：多台 DSH 共用一个 frps 时互不冲突
          const proxyName = config.frpProxyName || ('dsh-frp-' + crypto.randomBytes(4).toString('hex'));
          const tomlPath = path.join(toolsDir, 'frpc-dsh.toml');
          fs.writeFileSync(tomlPath, buildFrpcToml({
            serverAddr: c.frpServerAddr,
            serverPort: c.frpServerPort,
            authToken: c.frpAuthToken,
            proxyName,
            proxyType: c.frpProxyType,
            localPort: httpPort,
            remotePort: c.frpRemotePort,
            customDomains: c.frpCustomDomains,
            subdomain: c.frpSubdomain,
            tlsEnable: c.frpTlsEnable === 'true' ? true : (c.frpTlsEnable === 'false' ? false : undefined),
            tlsCertFile: c.frpTlsCertFile,
            tlsKeyFile: c.frpTlsKeyFile,
            tlsTrustedCaFile: c.frpTlsTrustedCaFile,
            tlsServerName: c.frpTlsServerName,
            httpsCertFile: c.frpHttpsCertFile,
            httpsKeyFile: c.frpHttpsKeyFile,
          }));
          tunnelHandle = subprocess.spawn(spec([frpcPath, '-c', tomlPath]));
          await waitFrpcReady(tunnelHandle, 30000);
          state.url = computeFrpUrl(c);
          if (!state.url) throw new Error('无法计算公网地址：http 模式需要 frpCustomDomains，或 frpSubdomain + frpSubdomainHost');

          // 监听 frpc 进程退出：隧道断了立刻标记，面板不再显示失效的旧链接
          const currentTunnel = tunnelHandle;
          currentTunnel.done.then(() => {
            if (tunnelHandle === currentTunnel && state.running) {
              state.url = null;
              state.error = '隧道已断开（frpc 退出），请点「停止」后重新「启动」';
              state.updatedAt = Date.now();
            }
          }, () => {});
        } catch (e) {
          // 隧道失败不影响局域网直连：保留代理，面板显示错误
          if (tunnelHandle) { try { tunnelHandle.terminate(); } catch (e2) { /* ignore */ } tunnelHandle = null; }
          state.url = null;
          state.error = String(e && e.message || e);
        }
      }

      // 3. QQ 桥（OneBot 11 反向 WS，接入统一命令路由）
      qqServer = createQQServer({
        infoUrls: ['http://127.0.0.1:' + config.targetPort + '/frpremote/info', 'http://127.0.0.1:' + config.targetPort + '/frpremote/access'],
        handleMessage: (text) => botRouter(text),
        onConnectionChange: (connected) => { state.qq = connected ? 'connected' : 'listening'; },
      });
      qqPort = await findFreePort(config.qqPortStart, config.qqPortStart + 4);
      await qqServer.start(qqPort);
      state.qq = 'listening';

      // 4. Telegram（纸飞机）长轮询（出站长连接，无需公网回调）
      const cBot = effectiveConfig();
      if (telegramPoller) { telegramPoller.stop(); telegramPoller = null; }
      if (cBot.tgBotToken) {
        telegramPoller = createTelegramPoller({
          token: cBot.tgBotToken,
          apiBase: cBot.tgApiBase,
          handleMessage: (text) => botRouter(text),
          log: (m) => console.log('[dsh-tg]', m),
        });
        telegramPoller.start();
      }

      state.running = true;
      state.updatedAt = Date.now();
    } catch (e) {
      state.error = String(e && e.message || e);
      stop();
    } finally {
      state.starting = false;
    }
    return state;
  };

  // ====== 微信 iLink 状态 ======
  const weixinTokenPath = path.join(toolsDir, 'weixin-token.json');
  const weixinState = { status: 'idle', botToken: null, qrcode: null, qrcodeUrl: null, error: null };
  function saveWeixinToken(token) {
    try { fs.writeFileSync(weixinTokenPath, JSON.stringify({ botToken: token, savedAt: Date.now() })); } catch (e) { console.error('[dsh-weixin] save token failed:', e.message); }
  }
  function loadWeixinToken() {
    try { if (fs.existsSync(weixinTokenPath)) { const d = JSON.parse(fs.readFileSync(weixinTokenPath, 'utf8')); return d.botToken || null; } } catch (e) { /* ignore */ }
    return null;
  }
  function clearWeixinToken() {
    try { if (fs.existsSync(weixinTokenPath)) fs.unlinkSync(weixinTokenPath); } catch (e) { /* ignore */ }
  }
  const ILINK_BASE = 'https://ilinkai.weixin.qq.com';
  function iLinkHeaders(token) {
    const uin = Buffer.from(String(Math.floor(Math.random() * 0xFFFFFFFF))).toString('base64');
    const h = { 'Content-Type': 'application/json', 'AuthorizationType': 'ilink_bot_token', 'X-WECHAT-UIN': uin };
    if (token) h['Authorization'] = 'Bearer ' + token;
    return h;
  }
  async function iLinkGet(path, token) {
    const https = await import('node:https');
    return new Promise((resolve, reject) => {
      const req = https.request(ILINK_BASE + path, { method: 'GET', headers: iLinkHeaders(token) }, (res) => {
        let data = '';
        res.on('data', (c) => data += c);
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { resolve(data); } });
      });
      req.on('error', reject);
      req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
      req.end();
    });
  }
  async function iLinkPost(path, body, token) {
    const https = await import('node:https');
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify(body || {});
      const req = https.request(ILINK_BASE + path, { method: 'POST', headers: { ...iLinkHeaders(token), 'Content-Length': Buffer.byteLength(payload) } }, (res) => {
        let data = '';
        res.on('data', (c) => data += c);
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { resolve(data); } });
      });
      req.on('error', reject);
      req.setTimeout(40000, () => { req.destroy(); reject(new Error('timeout')); });
      req.write(payload);
      req.end();
    });
  }
  async function weixinGetQR() {
    const res = await iLinkGet('/ilink/bot/get_bot_qrcode?bot_type=3');
    if (res.ret !== 0) throw new Error('get_bot_qrcode failed: ' + JSON.stringify(res));
    weixinState.qrcode = res.qrcode;
    weixinState.qrcodeUrl = res.qrcode_img_content;
    weixinState.status = 'waiting';
    weixinState.error = null;
    return { qrcode: res.qrcode, qrcodeUrl: res.qrcode_img_content };
  }
  async function weixinPollQR() {
    if (!weixinState.qrcode) return { status: 'idle' };
    const res = await iLinkGet('/ilink/bot/get_qrcode_status?qrcode=' + encodeURIComponent(weixinState.qrcode));
    if (res.status === 'confirmed' && res.bot_token) {
      weixinState.status = 'connected';
      weixinState.botToken = res.bot_token;
      weixinState.qrcode = null;
      weixinState.qrcodeUrl = null;
      weixinState.error = null;
      console.log('[dsh-weixin] connected! saving token & starting poll loop...');
      saveWeixinToken(res.bot_token);
      weixinPollLoop();
      return { status: 'connected', botToken: res.bot_token, baseurl: res.baseurl };
    }
    if (res.status === 'expired') {
      weixinState.status = 'idle';
      weixinState.qrcode = null;
      weixinState.qrcodeUrl = null;
      return { status: 'expired' };
    }
    return { status: res.status || 'waiting' };
  }
  function weixinDisconnect() {
    weixinState.status = 'idle';
    weixinState.botToken = null;
    weixinState.qrcode = null;
    weixinState.qrcodeUrl = null;
    weixinState.error = null;
    weixinState._polling = false;
    clearWeixinToken();
  }

  // ====== 微信消息轮询（AI 回复）======
  let weixinPollLoopRunning = false;
  let weixinGenerateReply = null; // 由 apply(ctx) 注入
  // 所有机器人通道（QQ / 纸飞机 / 钉钉 / 飞书 / 企业微信）共用的统一消息路由
  async function botRouter(text) {
    if (typeof weixinGenerateReply !== 'function') return '消息路由尚未就绪，请稍候再试';
    return await weixinGenerateReply(text);
  }
  // 当前消息的发送上下文（命令系统可主动发"思考中"等中间消息）
  let weixinActiveSend = null;
  // 主回复发出后要补发的下一条消息（如链接后的使用提示）
  let weixinFollowup = null;

  async function weixinSendMsg(botToken, toUserId, text, contextToken) {
    const clientId = 'dsh-weixin-' + Math.random().toString(36).slice(2, 10);
    const body = {
      msg: {
        from_user_id: '',
        to_user_id: toUserId,
        message_type: 2,
        message_state: 2,
        context_token: contextToken || '',
        client_id: clientId,
        item_list: [{ type: 1, text_item: { text: text } }]
      },
      base_info: { channel_version: '1.0.2' }
    };
    return iLinkPost('/ilink/bot/sendmessage', body, botToken);
  }

  async function weixinPollLoop() {
    if (weixinPollLoopRunning) return;
    weixinPollLoopRunning = true;
    let cursor = '';
    console.log('[dsh-weixin] poll loop started');
    while (weixinState.status === 'connected' && weixinState.botToken) {
      try {
        const res = await iLinkPost('/ilink/bot/getupdates', {
          get_updates_buf: cursor,
          base_info: { channel_version: '1.0.2' }
        }, weixinState.botToken);
        if (res.get_updates_buf) cursor = res.get_updates_buf;
        if (res.msgs && res.msgs.length > 0) {
          for (const msg of res.msgs) {
            if (msg.message_type === 1 && msg.item_list && msg.item_list.length > 0) {
              const textItem = msg.item_list.find(function (i) { return i.type === 1 && i.text_item; });
              if (textItem && msg.from_user_id) {
                const userText = textItem.text_item.text;
                console.log('[dsh-weixin] received:', userText);
                let reply;
                // 暴露发送上下文，供命令系统发"思考中"等中间消息
                weixinActiveSend = { botToken: weixinState.botToken, toUserId: msg.from_user_id, contextToken: msg.context_token };
                try {
                  if (weixinGenerateReply) {
                    reply = await weixinGenerateReply(userText);
                  } else {
                    reply = '[回声] ' + userText;
                  }
                } catch (e) {
                  console.error('[dsh-weixin] AI error:', e.message || e);
                  reply = '[AI 回复失败: ' + String(e.message || e).slice(0, 100) + ']';
                } finally {
                  weixinActiveSend = null;
                }
                // iLink 文本消息有长度限制，超长截断
                if (reply.length > 2000) reply = reply.slice(0, 2000) + '…';
                await weixinSendMsg(weixinState.botToken, msg.from_user_id, reply, msg.context_token);
                console.log('[dsh-weixin] replied:', reply.slice(0, 100));
                // 主回复发出后补发 followup（如链接使用提示）
                if (weixinFollowup) {
                  const f = weixinFollowup;
                  weixinFollowup = null;
                  try {
                    await weixinSendMsg(weixinState.botToken, msg.from_user_id, f, msg.context_token);
                    console.log('[dsh-weixin] followup sent');
                  } catch (e) { console.error('[dsh-weixin] followup failed:', e.message); }
                }
              }
            }
          }
        }
      } catch (e) {
        console.error('[dsh-weixin] poll error:', e.message || e);
        await new Promise(function (r) { setTimeout(r, 5000); });
      }
    }
    weixinPollLoopRunning = false;
    console.log('[dsh-weixin] poll loop stopped');
  }

  const snapshot = () => {
    const cEff = effectiveConfig();
    return {
      running: state.running, url: state.url, token: state.token, port: state.port, httpsPort: state.httpsPort, ips: state.ips,
      qq: state.qq, qqPort, weixin: weixinState.status, error: state.error, lanOpen: config.lanOpen,
      bots: {
        telegram: telegramPoller ? (telegramPoller.status() || 'starting') : null,
        dingtalk: cEff.dingtalkAppSecret ? 'ready' : null,
        feishu: (cEff.feishuAppId && cEff.feishuAppSecret) ? 'ready' : null,
        wecom: (cEff.wecomCorpId && cEff.wecomToken && cEff.wecomEncodingAESKey) ? 'ready' : null,
      },
    };
  };

  if (webServer) {
    const infoHandler = async (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
      res.end(JSON.stringify(snapshot()));
    };
    const controlHandler = async (req, res) => {
      if (req.method !== 'POST') {
        res.writeHead(405);
        res.end();
        return;
      }
      let body = '';
      for await (const chunk of req) body += chunk;
      let action = null;
      try { action = JSON.parse(body).action; } catch (e) { /* ignore */ }
      if (action === 'start') await start();
      else if (action === 'stop') stop();
      else if (action === 'renew') { stop(); await start(); }
      else {
        res.writeHead(400);
        res.end('bad action');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
      res.end(JSON.stringify(snapshot()));
    };
    // ====== 设置读写（面板「设置」页）======
    const configHandler = async (req, res) => {
      const send = (obj) => {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify(obj));
      };
      if (req.method === 'GET') {
        send({ ok: true, config: effectiveConfig(), hasFile: Object.keys(fileCfg).length > 0, savedAt: fileCfgSavedAt });
        return;
      }
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      let body = '';
      for await (const chunk of req) body += chunk;
      let incoming = null;
      try { incoming = JSON.parse(body); } catch (e) { send({ ok: false, error: '请求体不是合法 JSON' }); return; }
      // 清除本地配置，恢复 YAML 默认值
      if (incoming && incoming.action === 'reset') {
        fileCfg = {};
        fileCfgSavedAt = null;
        try { fs.rmSync(cfgFilePath, { force: true }); } catch (e) { /* ignore */ }
        try { stop(); await start(); } catch (e) { /* start 内部自行记录错误 */ }
        send({ ok: true, config: effectiveConfig(), hasFile: false, savedAt: null, state: snapshot() });
        return;
      }
      // 白名单 + 类型规整（合并语义：未提交的键保留上次保存值；提交空串视为显式清空）
      const str = (v) => (v === undefined || v === null ? '' : String(v).trim());
      const prev = fileCfg;
      const has = (k) => incoming[k] !== undefined && incoming[k] !== null;
      const keepStr = (k) => (has(k) ? str(incoming[k]) : (prev[k] !== undefined ? String(prev[k]) : ''));
      const keepNum = (k, dflt) => (has(k) ? (Number(incoming[k]) || dflt) : (prev[k] !== undefined ? (Number(prev[k]) || dflt) : dflt));
      const clean = {};
      for (const k of CFG_KEYS) {
        if (k === 'frpServerPort') clean[k] = keepNum(k, 7000);
        else if (k === 'frpRemotePort') clean[k] = keepNum(k, 3080);
        else if (k === 'frpVhostHTTPPort') clean[k] = keepNum(k, 80);
        else if (k === 'frpVhostHTTPSPort') clean[k] = keepNum(k, 443);
        else if (k === 'frpProxyType') clean[k] = has(k) ? (incoming[k] === 'http' ? 'http' : 'tcp') : (prev[k] === 'http' ? 'http' : 'tcp');
        else clean[k] = keepStr(k);
      }
      // 证书支持直接粘贴 PEM 内容：自动落盘到 toolsDir/certs/，配置里只存文件路径
      const PEM_FILENAMES = {
        frpTlsCertFile: 'frp-tls-certfile',
        frpTlsKeyFile: 'frp-tls-keyfile',
        frpTlsTrustedCaFile: 'frp-tls-trustedcafile',
        frpHttpsCertFile: 'frp-https-certfile',
        frpHttpsKeyFile: 'frp-https-keyfile',
      };
      const materializeTlsPem = (key) => {
        const v = clean[key];
        if (!v || !v.includes('-----BEGIN')) return; // 路径或空值原样保留
        try {
          const certDir = path.join(toolsDir, 'certs');
          fs.mkdirSync(certDir, { recursive: true });
          const isKey = v.includes('PRIVATE KEY');
          const ext = isKey ? 'key' : (v.includes('CERTIFICATE') ? 'crt' : 'pem');
          const file = path.join(certDir, PEM_FILENAMES[key] + '.' + ext);
          fs.writeFileSync(file, v.endsWith('\n') ? v : v + '\n', { mode: isKey ? 0o600 : 0o644 });
          clean[key] = file;
        } catch (e) { /* 落盘失败保留原值，由 frpc 报错暴露 */ }
      };
      for (const k of Object.keys(PEM_FILENAMES)) materializeTlsPem(k);
      fileCfg = clean;
      fileCfgSavedAt = Date.now();
      try {
        fs.writeFileSync(cfgFilePath, JSON.stringify(fileCfg, null, 2));
      } catch (e) {
        send({ ok: false, error: '写入配置文件失败: ' + String(e && e.message || e) });
        return;
      }
      // 保存后立即重启使配置生效
      try { stop(); await start(); } catch (e) { /* start 内部自行记录错误 */ }
      send({ ok: true, config: effectiveConfig(), hasFile: true, savedAt: fileCfgSavedAt, state: snapshot() });
    };
    // ====== 一键下载 frpc（自动按当前系统选择发行版）======
    let downloadingFrpc = false;
    const frpcDownloadHandler = async (req, res) => {
      const send = (obj) => {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify(obj));
      };
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      if (downloadingFrpc) { send({ ok: false, error: '正在下载中，请稍候…' }); return; }
      const c = effectiveConfig();
      const osInfo = process.platform + '/' + process.arch;
      // 1. 已配置的路径可用 → 直接复用
      if (c.frpcPath && fs.existsSync(c.frpcPath)) {
        send({ ok: true, path: c.frpcPath, existing: true, platform: osInfo });
        return;
      }
      // 2. PATH 中已有 frpc
      let inPath = null;
      try { inPath = await subprocess.resolveExecutable('frpc'); } catch (e) { /* 不在 PATH */ }
      if (inPath && fs.existsSync(inPath)) {
        send({ ok: true, path: inPath, existing: true, platform: osInfo });
        return;
      }
      // 3. toolsDir 已有 frpc
      const localExe = path.join(toolsDir, process.platform === 'win32' ? 'frpc.exe' : 'frpc');
      if (fs.existsSync(localExe)) {
        send({ ok: true, path: localExe, existing: true, platform: osInfo });
        return;
      }
      // 4. 下载（自动识别系统/架构，GitHub 直连 + 镜像回退，或自定义 frpDownloadUrl）
      downloadingFrpc = true;
      try {
        const target = await downloadFrpc(toolsDir, c.frpDownloadUrl);
        send({ ok: true, path: target, existing: false, platform: osInfo });
      } catch (e) {
        send({ ok: false, error: String(e && e.message || e) });
      } finally {
        downloadingFrpc = false;
      }
    };
    // ====== 在文件管理器中显示 frpc ======
    const frpcRevealHandler = async (req, res) => {
      const send = (obj) => {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify(obj));
      };
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      let body = '';
      for await (const chunk of req) body += chunk;
      let want = '';
      try { want = String((JSON.parse(body) || {}).path || '').trim(); } catch (e) { /* ignore */ }
      const c = effectiveConfig();
      let target = '';
      if (want && fs.existsSync(want)) target = want;
      else if (c.frpcPath && fs.existsSync(c.frpcPath)) target = c.frpcPath;
      else {
        let inPath = null;
        try { inPath = await subprocess.resolveExecutable('frpc'); } catch (e) { /* 不在 PATH */ }
        if (inPath && fs.existsSync(inPath)) target = inPath;
        else {
          const localExe = path.join(toolsDir, process.platform === 'win32' ? 'frpc.exe' : 'frpc');
          if (fs.existsSync(localExe)) target = localExe;
        }
      }
      if (!target) { send({ ok: false, error: '未找到 frpc：请先点「一键下载」，或在输入框填写有效路径' }); return; }
      try {
        // 异步调起系统文件管理器，不阻塞响应
        if (process.platform === 'darwin') execFile('open', ['-R', target], () => {});
        else if (process.platform === 'win32') execFile('explorer', ['/select,' + target], () => {});
        else execFile('xdg-open', [path.dirname(target)], () => {});
        send({ ok: true, path: target });
      } catch (e) {
        send({ ok: false, error: '调起文件管理器失败: ' + String(e && e.message || e), path: target });
      }
    };
    // ====== 钉钉 outgoing 机器人回调 ======
    const dingtalkDedupe = makeDedupe();
    const dingtalkHandler = async (req, res) => {
      const done = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };
      if (req.method !== 'POST') { done(405, { ok: false }); return; }
      const c = effectiveConfig();
      if (!c.dingtalkAppSecret) { done(400, { ok: false, error: '未配置 dingtalkAppSecret（面板「设置」页填写）' }); return; }
      const timestamp = String(req.headers['timestamp'] || '');
      const sign = String(req.headers['sign'] || '');
      if (!timestamp || !verifyDingtalkSign(timestamp, c.dingtalkAppSecret, sign)) { done(401, { ok: false, error: '签名校验失败' }); return; }
      let body = '';
      for await (const chunk of req) body += chunk;
      let msg = null;
      try { msg = JSON.parse(body); } catch (e) { done(400, { ok: false }); return; }
      done(200, { ok: true }); // 先应答，避免钉钉 3s 超时重试
      if (!msg || msg.msgtype !== 'text' || dingtalkDedupe(msg.msgId || msg.msgid)) return;
      const text = msg.text && msg.text.content ? String(msg.text.content).trim() : '';
      if (!text) return;
      (async () => {
        try {
          const reply = await botRouter(text);
          if (reply && msg.sessionWebhook) {
            await fetch(msg.sessionWebhook, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ msgtype: 'text', text: { content: String(reply) } }),
            });
          }
        } catch (e) { console.log('[dsh-bot] dingtalk error:', String(e && e.message || e)); }
      })();
    };
    // ====== 飞书事件回调 ======
    const feishuDedupe = makeDedupe();
    const feishuTokenCache = { token: null, expiresAt: 0 };
    async function feishuAccessToken(c) {
      if (feishuTokenCache.token && Date.now() < feishuTokenCache.expiresAt) return feishuTokenCache.token;
      const base = (c.feishuApiBase || 'https://open.feishu.cn').replace(/\/+$/, '');
      const res = await fetch(base + '/open-apis/auth/v3/tenant_access_token/internal', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ app_id: c.feishuAppId, app_secret: c.feishuAppSecret }),
      });
      const data = await res.json().catch(() => ({}));
      if (data.code !== 0 || !data.tenant_access_token) throw new Error('tenant_access_token 获取失败: ' + (data.msg || res.status));
      feishuTokenCache.token = data.tenant_access_token;
      feishuTokenCache.expiresAt = Date.now() + (Math.max(120, Number(data.expire) || 7200) - 300) * 1000;
      return feishuTokenCache.token;
    }
    const feishuHandler = async (req, res) => {
      const done = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };
      if (req.method !== 'POST') { done(405, { ok: false }); return; }
      const c = effectiveConfig();
      if (!c.feishuAppId || !c.feishuAppSecret) { done(400, { ok: false, error: '未配置 feishuAppId / feishuAppSecret（面板「设置」页填写）' }); return; }
      let body = '';
      for await (const chunk of req) body += chunk;
      let evt = null;
      try { evt = JSON.parse(body); } catch (e) { done(400, { ok: false }); return; }
      // 配置了 Encrypt Key 时事件整体加密
      if (evt && evt.encrypt && c.feishuEncryptKey) {
        try { evt = feishuDecrypt(c.feishuEncryptKey, evt.encrypt); } catch (e) { done(400, { ok: false, error: '解密失败' }); return; }
      }
      // URL 验证（控制台保存回调地址时触发）
      if (evt && evt.type === 'url_verification') { done(200, { challenge: evt.challenge }); return; }
      done(200, { ok: true }); // 先应答，异步处理
      if (!evt || !evt.header || evt.header.event_type !== 'im.message.receive_v1') return;
      if (c.feishuVerificationToken && evt.header.token !== c.feishuVerificationToken) return;
      if (feishuDedupe(evt.header.event_id)) return;
      const message = evt.event && evt.event.message;
      if (!message || message.message_type !== 'text' || (message.chat_type !== 'p2p' && message.chat_type !== 'group')) return;
      let text = '';
      try { text = JSON.parse(message.content).text || ''; } catch (e) { return; }
      // 去掉 @机器人 占位符
      const mentions = (message.mentions || []);
      for (const mn of mentions) { if (mn && mn.key) text = text.split(mn.key).join(''); }
      text = text.trim();
      if (!text) return;
      (async () => {
        try {
          const reply = await botRouter(text);
          if (!reply) return;
          const token = await feishuAccessToken(c);
          const base = (c.feishuApiBase || 'https://open.feishu.cn').replace(/\/+$/, '');
          await fetch(base + '/open-apis/im/v1/messages?receive_id_type=chat_id', {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: ('Bea' + 'rer ') + token },
            body: JSON.stringify({ receive_id: message.chat_id, msg_type: 'text', content: JSON.stringify({ text: String(reply) }) }),
          });
        } catch (e) { console.log('[dsh-bot] feishu error:', String(e && e.message || e)); }
      })();
    };
    // ====== 企业微信回调（GET 验证 + POST 消息）======
    const wecomDedupe = makeDedupe();
    const wecomTokenCache = { token: null, expiresAt: 0 };
    async function wecomAccessToken(c) {
      if (wecomTokenCache.token && Date.now() < wecomTokenCache.expiresAt) return wecomTokenCache.token;
      const base = (c.wecomApiBase || 'https://qyapi.weixin.qq.com').replace(/\/+$/, '');
      const res = await fetch(base + '/cgi-bin/gettoken?corpid=' + encodeURIComponent(c.wecomCorpId) + '&corpsecret=' + encodeURIComponent(c.wecomCorpSecret));
      const data = await res.json().catch(() => ({}));
      if (data.errcode !== 0 || !data.access_token) throw new Error('access_token 获取失败: ' + (data.errmsg || res.status));
      wecomTokenCache.token = data.access_token;
      wecomTokenCache.expiresAt = Date.now() + (Math.max(300, Number(data.expires_in) || 7200) - 300) * 1000;
      return wecomTokenCache.token;
    }
    const wecomHandler = async (req, res) => {
      const c = effectiveConfig();
      if (!c.wecomToken || !c.wecomEncodingAESKey || !c.wecomCorpId) {
        res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: false, error: '未配置企业微信参数（面板「设置」页填写 CorpID/Token/EncodingAESKey）' }));
        return;
      }
      const url = new URL(req.url, 'http://127.0.0.1');
      const msgSignature = url.searchParams.get('msg_signature') || '';
      const timestamp = url.searchParams.get('timestamp') || '';
      const nonce = url.searchParams.get('nonce') || '';
      if (req.method === 'GET') {
        // 回调 URL 验证：解密 echostr 并原样返回
        const echostr = url.searchParams.get('echostr') || '';
        if (wecomSignature(c.wecomToken, timestamp, nonce, echostr) !== msgSignature) { res.writeHead(401); res.end(); return; }
        try {
          const d = wecomDecrypt(c.wecomEncodingAESKey, echostr);
          res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
          res.end(d.message);
        } catch (e) { res.writeHead(400); res.end(); }
        return;
      }
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      let body = '';
      for await (const chunk of req) body += chunk;
      const encrypted = xmlExtract(body, 'Encrypt');
      if (!encrypted || wecomSignature(c.wecomToken, timestamp, nonce, encrypted) !== msgSignature) { res.writeHead(401); res.end(); return; }
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('success'); // 先应答，异步处理
      let plain = null;
      try { plain = wecomDecrypt(c.wecomEncodingAESKey, encrypted).message; } catch (e) { return; }
      const msgId = xmlExtract(plain, 'MsgId');
      if (wecomDedupe(msgId)) return;
      const content = xmlExtract(plain, 'Content'); // 仅处理文本消息
      const fromUser = xmlExtract(plain, 'FromUserName');
      if (!content || !fromUser) return;
      (async () => {
        try {
          const reply = await botRouter(String(content).trim());
          if (!reply) return;
          const token = await wecomAccessToken(c);
          const base = (c.wecomApiBase || 'https://qyapi.weixin.qq.com').replace(/\/+$/, '');
          await fetch(base + '/cgi-bin/message/send?' + new URLSearchParams([['access_' + 'token', token]]), {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              touser: fromUser,
              msgtype: 'text',
              agentid: Number(c.wecomAgentId) || 0,
              text: { content: String(reply) },
            }),
          });
        } catch (e) { console.log('[dsh-bot] wecom error:', String(e && e.message || e)); }
      })();
    };
    // ====== 微信 iLink 路由 ======
    const weixinQRHandler = async (req, res) => {
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      try {
        const qr = await weixinGetQR();
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ ok: true, qrcodeUrl: qr.qrcodeUrl }));
      } catch (e) {
        weixinState.error = String(e && e.message || e);
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ ok: false, error: weixinState.error }));
      }
    };
    const weixinPollHandler = async (req, res) => {
      try {
        const result = await weixinPollQR();
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ ok: true, ...result }));
      } catch (e) {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ ok: false, error: String(e && e.message || e) }));
      }
    };
    const weixinUnbindHandler = async (req, res) => {
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      weixinDisconnect();
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ ok: true }));
    };
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/info', handler: infoHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/access', handler: infoHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/control', handler: controlHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/config', handler: configHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/frpc/download', handler: frpcDownloadHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/frpc/reveal', handler: frpcRevealHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/bot/dingtalk', handler: dingtalkHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/bot/feishu', handler: feishuHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/bot/wecom', handler: wecomHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/weixin/qrcode', handler: weixinQRHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/weixin/poll', handler: weixinPollHandler }));
    ctx.effect(() => webServer.register({ kind: 'exact', path: '/frpremote/weixin/unbind', handler: weixinUnbindHandler }));
    ctx.effect(() => webServer.tapIndex((transform) => {
      if (transform.indexOf('frprm-native') !== -1) return transform;
      return transform.replace('</body>', '<script>' + INJECT_SCRIPT + '</scr' + 'ipt></body>');
    }));

    // ====== 接入 DSH：查/建「微信远程」会话 ======
    const sessions = ctx.get('sessions') || hostCtx.get('sessions');
    const agents = ctx.get('agents') || hostCtx.get('agents');
    const sessionQuery = ctx.get('sessionQuery') || hostCtx.get('sessionQuery');
    const llm = ctx.get('llm') || hostCtx.get('llm');
    const agentDefaultModel = ctx.get('agentDefaultModel') || hostCtx.get('agentDefaultModel');
    const apiProxy = ctx.get('apiProxy') || hostCtx.get('apiProxy');
    console.log('[dsh-weixin] services - sessions:', !!sessions, 'agents:', !!agents, 'sessionQuery:', !!sessionQuery, 'llm:', !!llm, 'agentDefaultModel:', !!agentDefaultModel, 'apiProxy:', !!apiProxy);

    // ====== 微信命令系统 ======
    let weixinSelectedSession = null; // 当前选中的目标会话 id
    let weixinModelPick = null; // { step: 'model'|'effort', models: [...], efforts: [...], provider, model }

    // 通过本地 DSH web 的 /api RPC 端点调用会话级方法（bundle 插件取不到 apiProxy 服务）
    // method 如 'session.selectModel' / 'session.models'
    function callRpc(method, payload) {
      return new Promise(function (resolve, reject) {
        const body = JSON.stringify({ type: 'client-request', rpcId: 'wx-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8), method, payload });
        const req = http.request({
          host: '127.0.0.1',
          port: config.targetPort,
          path: '/api/' + method,
          method: 'POST',
          headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
          timeout: 15000,
        }, function (res) {
          let data = '';
          res.on('data', function (c) { data += c; });
          res.on('end', function () {
            try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
            catch (e) { resolve({ status: res.statusCode, body: data }); }
          });
        });
        req.on('error', reject);
        req.on('timeout', function () { req.destroy(new Error('rpc timeout')); });
        req.write(body);
        req.end();
      });
    }

    // 模型切换 helper：优先会话级（走本地 RPC），无选中则全局
    async function switchModel(provider, model, reasoningEffort) {
      const sel = { provider, model };
      if (reasoningEffort !== undefined) sel.reasoningEffort = reasoningEffort;
      console.log('[dsh-weixin] switchModel called:', JSON.stringify(sel), 'session:', weixinSelectedSession);
      if (weixinSelectedSession) {
        try {
          const res = await callRpc('session.selectModel', { sessionId: weixinSelectedSession, ...sel });
          const ok = res && res.body && res.body.result && res.body.result.ok;
          console.log('[dsh-weixin] selectModel rpc:', res.status, JSON.stringify(res.body && res.body.result || res.body).slice(0, 300));
          if (ok) return true;
        } catch (e) { console.log('[dsh-weixin] selectModel http error:', e.message); }
      }
      // 兜底：全局默认
      if (agentDefaultModel) {
        await agentDefaultModel.saveSelection(sel);
        return true;
      }
      return false;
    }
    const WEIXIN_HELP =
      '可用命令：\n' +
      '· 帮助 —— 显示本列表\n' +
      '· /链接 —— 查看远程链接（未启动会自动开启）\n' +
      '· /停止远程 —— 关闭远程服务\n' +
      '· /会话列表 —— 列出所有会话\n' +
      '· /选择 N —— 选中第 N 个会话\n' +
      '· /当前会话 —— 查看选中的会话名称\n' +
      '· /历史内容 —— 查看选中会话最近一次输出\n' +
      '· /当前模型 —— 查看当前使用的模型\n' +
      '· /切换模型 —— 列出所有模型并切换\n' +
      '· 直接发送内容（无需前缀）—— 发送到选中的会话\n' +
      '· 未选择会话时，先 /会话列表 再 /选择 N';

    async function sendToSession(sessionId, content) {
      // 取 live agent：先 get，再 resume
      let agent = null;
      if (agents) {
        try { agent = agents.get(sessionId); } catch (e) { /* ignore */ }
      }
      if (!agent && agents) {
        try {
          console.log('[dsh-weixin] resuming agent for session', String(sessionId));
          const handle = await agents.resume({ resumeSessionId: sessionId });
          agent = (handle && handle.agent) ? handle.agent : handle;
        } catch (e) { console.log('[dsh-weixin] resume failed:', e.message); }
      }
      if (!agent || typeof agent.send !== 'function') {
        return '无法激活会话 ' + String(sessionId) + '（agent 不可用）';
      }
      const msgId = 'wxcmd-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
      agent.send({ id: msgId, role: 'user', content: [{ type: 'text', text: content }], source: { kind: 'user' } }, 'next-turn', true);
      await agent.whenIdle();
      const events = agent.session.events;
      for (let i = events.length - 1; i >= 0; i--) {
        if (events[i].type === 'assistant/message') {
          const msg = events[i].data.message;
          const parts = [];
          if (msg.content) msg.content.forEach(function (b) { if (b.type === 'text' && b.text) parts.push(b.text); });
          if (parts.length > 0) return parts.join('');
        }
      }
      return '(会话未产生回复)';
    }

    // 取会话最近一次 assistant 输出
    async function getSessionLastOutput(sessionId) {
      let events = null;
      if (agents) {
        try {
          const a = agents.get(sessionId);
          if (a && a.session) events = a.session.events;
        } catch (e) { /* ignore */ }
      }
      if (!events && sessionQuery) {
        try {
          const snap = await sessionQuery.readSession(sessionId);
          events = (snap && snap.events) ? snap.events : null;
        } catch (e) { /* ignore */ }
      }
      if (!events) return null;
      for (let i = events.length - 1; i >= 0; i--) {
        if (events[i].type === 'assistant/message') {
          const msg = events[i].data.message;
          const parts = [];
          if (msg.content) msg.content.forEach(function (b) { if (b.type === 'text' && b.text) parts.push(b.text); });
          if (parts.length > 0) return parts.join('');
        }
      }
      return '(该会话暂无输出)';
    }

    // 取会话标题
    async function getSessionTitle(sessionId) {
      if (!sessionQuery) return '';
      try {
        const ts = await sessionQuery.readTitle(sessionId);
        return (ts && ts.title) ? ts.title : '';
      } catch (e) { return ''; }
    }

    async function handleWeixinCommand(text) {
      const t = String(text || '').trim();
      if (!t) return null;
      // 帮助（无 / 也可）
      if (/^(帮助|命令|help|\/帮助)$/i.test(t)) return WEIXIN_HELP;
      if (/^\//.test(t)) {
        // /链接
        if (/^\/链接$/.test(t) || /^\/公网链接$/.test(t) || /^\/获取公网链接$/.test(t)) {
          if (!state.running) {
            state.error = null;
            console.log('[dsh-weixin] starting remote (via wechat command)...');
            await start();
          }
          if (state.url && state.token) {
            weixinFollowup = '[如果用外部浏览器，请直接复制链接，从微信内部浏览器跳转，会丢失验证信息导致验证失败]';
            return '[手机浏览器建议页面缩放比例调整为50%-75%，以获得更好的显示效果]\n公网链接：\n' + state.url + '/?token=' + state.token;
          }
          if (state.error) return '启动失败：' + state.error;
          return '正在获取链接，请稍候（隧道建立约 10~30 秒）…';
        }
        // /停止远程
        if (/^\/停止远程$/.test(t) || /^\/关闭远程$/.test(t)) { stop(); return '已停止远程服务'; }
        // /会话列表
        if (/^\/会话列表$/.test(t) || /^\/会话$/.test(t)) {
          if (!sessionQuery) return '会话服务不可用';
          const records = await sessionQuery.listSessions();
          if (!records || records.length === 0) return '当前没有会话';
          // workspace 层：归档集合 + 所有 workspace 内会话 id（用于过滤孤儿会话）
          let archived = null;
          let knownSessions = null;
          try {
            const wsr = ctx.get('workspaceRegistry') || hostCtx.get('workspaceRegistry');
            if (wsr) {
              if (wsr.archivedSessionIds) archived = new Set(wsr.archivedSessionIds);
              const workspaces = wsr.list();
              if (workspaces) {
                knownSessions = new Set();
                for (const w of workspaces) {
                  if (w.sessionIds) for (const sid of w.sessionIds) knownSessions.add(sid);
                }
              }
            }
          } catch (e) { /* ignore */ }
          const lines = [];
          let n = 0;
          for (const r of records) {
            // 过滤：归档会话、子代理会话、不在任何 workspace 的孤儿会话
            if (archived && archived.has(r.header.id)) continue;
            if (r.header.origin === 'subagent' || (r.header.delegationDepth || 0) > 0) continue;
            if (knownSessions && !knownSessions.has(r.header.id)) continue;
            n += 1;
            const title = await getSessionTitle(r.header.id);
            lines.push(n + '. ' + (title || '(无标题)'));
          }
          if (lines.length === 0) return '当前没有会话';
          return '会话列表：\n' + lines.join('\n') + '\n\n回复「/选择 N」切换目标会话';
        }
        // /选择 N
        let m = t.match(/^\/选择[\s：:]*(\d+)$/);
        if (m) {
          const idx = parseInt(m[1], 10) - 1;
          if (!sessionQuery) return '会话服务不可用';
          // 与 /会话列表 相同的过滤（归档 / 子代理 / 孤儿）
          let archived = null;
          let knownSessions = null;
          try {
            const wsr = ctx.get('workspaceRegistry') || hostCtx.get('workspaceRegistry');
            if (wsr) {
              if (wsr.archivedSessionIds) archived = new Set(wsr.archivedSessionIds);
              const workspaces = wsr.list();
              if (workspaces) {
                knownSessions = new Set();
                for (const w of workspaces) {
                  if (w.sessionIds) for (const sid of w.sessionIds) knownSessions.add(sid);
                }
              }
            }
          } catch (e) { /* ignore */ }
          const all = await sessionQuery.listSessions();
          const visible = (all || []).filter(function (r) {
            if (archived && archived.has(r.header.id)) return false;
            if (r.header.origin === 'subagent' || (r.header.delegationDepth || 0) > 0) return false;
            if (knownSessions && !knownSessions.has(r.header.id)) return false;
            return true;
          });
          if (visible[idx]) {
            weixinSelectedSession = visible[idx].header.id;
            const title = await getSessionTitle(visible[idx].header.id);
            return '已选择会话 ' + (idx + 1) + '：' + (title || '(无标题)');
          }
          return '编号无效，请先查看「/会话列表」';
        }
        // /当前会话
        if (/^\/当前会话$/.test(t)) {
          if (!weixinSelectedSession) return '当前未选择会话，请先「/会话列表」并「/选择 N」';
          const title = await getSessionTitle(weixinSelectedSession);
          return '当前选中会话：' + (title || String(weixinSelectedSession));
        }
        // /历史内容
        if (/^\/历史内容$/.test(t)) {
          if (!weixinSelectedSession) return '当前未选择会话，请先「/会话列表」并「/选择 N」';
          return await getSessionLastOutput(weixinSelectedSession);
        }
        // /当前模型
        if (/^\/当前模型$/.test(t)) {
          // 优先查选中会话的模型
          if (weixinSelectedSession) {
            try {
              const res = await callRpc('session.models', { sessionId: weixinSelectedSession });
              const cur = res && res.body && res.body.result && res.body.result.ok ? res.body.result.value.current : null;
              if (cur) {
                return '会话模型：' + (cur.model || '(未设置)') + ' (' + (cur.provider || '?') + ')' + (cur.reasoningEffort ? '\n思考强度：' + cur.reasoningEffort : '');
              }
              console.log('[dsh-weixin] session.models rpc:', res.status, JSON.stringify(res.body && res.body.result || res.body).slice(0, 300));
            } catch (e) { console.log('[dsh-weixin] session.models error:', e.message); }
          }
          // 兜底：全局默认
          if (!agentDefaultModel) return '模型服务不可用';
          const sel = agentDefaultModel.currentSelection();
          return '当前模型（全局默认）：' + (sel.model || '(未设置)') + ' (' + (sel.provider || '?') + ')' + (sel.reasoningEffort ? '\n思考强度：' + sel.reasoningEffort : '');
        }
        // /选强度 N → 设置思考强度（独立命令，不嵌套在 /切换模型 里）
        if (weixinModelPick && weixinModelPick.step === 'effort' && /^\/选强度/.test(t)) {
          const earg = t.replace(/^\/选强度/, '').trim();
          if (/^\d+$/.test(earg)) {
            const eidx = parseInt(earg, 10);
            const pick = weixinModelPick;
            let effort = undefined;
            if (eidx === 0) {
              effort = undefined;
            } else if (eidx >= 1 && eidx <= pick.efforts.length) {
              effort = pick.efforts[eidx - 1].id;
            } else {
              return '编号无效，请选 0-' + pick.efforts.length;
            }
            const sel = { provider: pick.provider, model: pick.model };
            if (effort !== undefined) sel.reasoningEffort = effort;
            await switchModel(pick.provider, pick.model, effort);
            weixinModelPick = null;
            return '✅ 模型已切换：' + pick.model + ' (' + pick.provider + ')' + (effort ? ' / ' + effort : ' / 默认');
          }
          return '请回复数字编号，如「/选强度 2」';
        }
        // /切换模型（多步交互）
        if (/^\/切换模型/.test(t)) {
          const arg = t.replace(/^\/切换模型/, '').trim();
          // 第 2 步：/切换模型 N → 选择模型
          if (weixinModelPick && weixinModelPick.step === 'model' && /^\d+$/.test(arg)) {
            const idx = parseInt(arg, 10) - 1;
            const pick = weixinModelPick;
            if (idx >= 0 && idx < pick.models.length) {
              const m = pick.models[idx];
              // 尝试获取思考强度（从 resolveModelInfo 或 listing 中的 reasoning）
              let efforts = null;
              if (m.reasoning && m.reasoning.efforts && m.reasoning.efforts.length > 0) {
                efforts = m.reasoning.efforts;
              } else if (llm && llm.resolveModelInfo) {
                try {
                  const info = await llm.resolveModelInfo(m.provider, m.id);
                  if (info && info.reasoning && info.reasoning.efforts) efforts = info.reasoning.efforts;
                } catch (e) { /* ignore */ }
              }
              if (efforts && efforts.length > 0) {
                const effortLines = efforts.map(function (e, i) { return (i + 1) + '. ' + e.name + (e.description ? ' — ' + e.description : ''); });
                weixinModelPick = { step: 'effort', provider: m.provider, model: m.id, efforts: efforts };
                return '已选择：' + m.name + ' (' + m.provider + ')\n思考强度：\n0. 默认\n' + effortLines.join('\n') + '\n回复「/选强度 N」选择';
              }
              // 无思考强度，直接切换
              await switchModel(m.provider, m.id);
              weixinModelPick = null;
              return '✅ 模型已切换：' + m.name + ' (' + m.provider + ')';
            }
            return '编号无效，请重新「/切换模型」查看列表';
          }
          // 第 1 步：/切换模型（无参数）→ 列出所有模型
          if (!llm) return 'LLM 服务不可用';
          if (!agentDefaultModel) return '模型服务不可用';
          const currentSel = agentDefaultModel.currentSelection();
          const allModels = [];
          try {
            const providers = await llm.listProviders();
            for (const p of providers) {
              try {
                const models = await llm.listModels(p.id);
                for (const m of models) {
                  allModels.push({ name: m.name || m.id, id: m.id, provider: p.id, providerName: p.name || p.id, reasoning: m.reasoning });
                }
              } catch (e) { /* skip provider */ }
            }
          } catch (e) { /* ignore */ }
          if (allModels.length === 0) return '未找到可用模型';
          const lines = allModels.map(function (m, i) {
            const isCurrent = m.provider === currentSel.provider && m.id === currentSel.model;
            return (i + 1) + '. ' + m.name + ' (' + m.provider + ')' + (isCurrent ? ' ← 当前' : '') + (m.reasoning ? ' ⚙' : '');
          });
          weixinModelPick = { step: 'model', models: allModels };
          return '可用模型（⚙=支持思考强度）：\n' + lines.join('\n') + '\n\n回复「/切换模型 N」选择';
        }
        return '未知命令，发「帮助」查看可用命令';
      }
      // 非命令消息 → 发送到选中的会话（无需 // 前缀）
      if (!weixinSelectedSession) {
        return '请先在「/会话列表」中选择一个会话，再发送内容\n更多命令请发送「/帮助」获取';
      }
      // 先发"思考中"（避免长时间无回复），再执行
      if (weixinActiveSend) {
        try {
          await weixinSendMsg(weixinActiveSend.botToken, weixinActiveSend.toUserId, '已收到指令，AI 思考中，请稍等…', weixinActiveSend.contextToken);
        } catch (e) { /* ignore */ }
      }
      return await sendToSession(weixinSelectedSession, t);
    }

    (async function () {
      // 查找已有的「微信远程」会话
      let weixinSession = null;
      if (sessionQuery) {
        try {
          const list = await sessionQuery.listSessions();
          for (const s of list) {
            if (s.title && s.title.includes('微信远程')) { weixinSession = s; break; }
            if (s.id && String(s.id).includes('weixin')) { weixinSession = s; break; }
          }
          if (weixinSession) console.log('[dsh-weixin] found existing session:', String(weixinSession.id), weixinSession.title);
          else console.log('[dsh-weixin] no existing session found');
        } catch (e) { console.log('[dsh-weixin] listSessions error:', e.message); }
      }

      // 统一消息处理：命令 → 命令；非命令 → 发到选中会话（handleWeixinCommand 内部处理）
      weixinGenerateReply = async function (userText) {
        try {
          return await handleWeixinCommand(userText);
        } catch (e) {
          console.error('[dsh-weixin] handle error:', e.message);
          return '[错误: ' + String(e.message).slice(0, 200) + ']';
        }
      };
      console.log('[dsh-weixin] ✓ weixin message router ready');
    })();
  }

  ctx.effect(() => () => {
    if (tunnelHandle) { try { tunnelHandle.terminate(); } catch (e) { /* ignore */ } }
    if (telegramPoller) { try { telegramPoller.stop(); } catch (e) { /* ignore */ } }
    if (proxy) { try { proxy.close(); } catch (e) { /* ignore */ } }
    if (qqServer) { try { qqServer.close(); } catch (e) { /* ignore */ } }
  });

  if (config.autoStart) {
    start().catch((e) => { state.error = String(e && e.message || e); });
  }

  // 启动时尝试恢复微信连接
  const savedToken = loadWeixinToken();
  if (savedToken) {
    weixinState.status = 'connected';
    weixinState.botToken = savedToken;
    console.log('[dsh-weixin] restored token from file, starting poll loop...');
    weixinPollLoop();
  }
  });
}

async function findFreePort(start, end) {
  for (let port = start; port <= end; port++) {
    if (await isPortFree(port)) return port;
  }
  throw new Error('no free port in ' + start + '..' + end);
}

function isPortFree(port) {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

export default { name, inject, apply };
