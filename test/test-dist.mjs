// 分发包集成测试：起一个假的"DSH 服务器"(127.0.0.1:18080)，
// 用 createProxyServer 起 HTTP(18081)+HTTPS(18082)，验证鉴权/302/gzip/WS/HTTPS，
// 另起一个"要求浏览器会话"的假 DSH(18084) 验证会话 cookie 的注入与 401 重放，
// 再加 frp 相关纯函数（buildFrpcToml / computeFrpUrl / normalizeDomains）断言。
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert';
import { createHash, createHmac } from 'node:crypto';
import { createProxyServer, generateSelfSignedCert, createQQServer, lanIPs, buildFrpcToml, computeFrpUrl, normalizeDomains, verifyDingtalkSign, feishuEncrypt, feishuDecrypt, wecomSignature, wecomEncrypt, wecomDecrypt, xmlExtract, makeDedupe, FRP_MIRROR_URLS, findFreePort, apply } from '../lib/index.mjs';

// ─────────── 机器人通道纯函数断言 ───────────
{
  // 钉钉签名
  const secret = 'ding-secret-123';
  const ts = String(Date.now());
  const sign = createHmac('sha256', secret).update(ts + '\n' + secret).digest('base64');
  assert.strictEqual(verifyDingtalkSign(ts, secret, sign), true, 'dingtalk sign valid');
  assert.strictEqual(verifyDingtalkSign(ts, secret, 'wrong'), false, 'dingtalk sign invalid');
  console.log('0e. verifyDingtalkSign OK');

  // 飞书事件加解密
  const fk = 'feishu-encrypt-key-test';
  const obj = { hello: '飞书', n: 42 };
  const enc = feishuEncrypt(fk, obj);
  const dec = feishuDecrypt(fk, enc);
  assert.deepStrictEqual(dec, obj, 'feishu roundtrip');
  console.log('0f. feishuEncrypt/Decrypt roundtrip OK');

  // 企业微信签名 + 消息加解密
  const wtoken = 'wecom-token';
  const wts = '1700000000';
  const wnonce = 'nonce1';
  const sig = wecomSignature(wtoken, wts, wnonce, 'extra');
  assert.strictEqual(sig, createHash('sha1').update([wtoken, wts, wnonce, 'extra'].sort().join('')).digest('hex'), 'wecom signature');
  const aesKey43 = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'; // 43 位
  const inner = '<xml><Content><![CDATA[你好]]></Content></xml>';
  const encW = wecomEncrypt(aesKey43, 'corpid-1', inner);
  const decW = wecomDecrypt(aesKey43, encW);
  assert.strictEqual(decW.message, inner, 'wecom decrypt message');
  assert.strictEqual(decW.receiveid, 'corpid-1', 'wecom decrypt receiveid');
  console.log('0g. wecomSignature/Encrypt/Decrypt roundtrip OK');

  // XML 取值
  assert.strictEqual(xmlExtract('<xml><Content><![CDATA[hello]]></Content></xml>', 'Content'), 'hello');
  assert.strictEqual(xmlExtract('<xml><MsgId>123</MsgId></xml>', 'MsgId'), '123');
  assert.strictEqual(xmlExtract('<xml><a>1</a></xml>', 'b'), null);
  console.log('0h. xmlExtract OK');

  // 去重器
  const dedupe = makeDedupe(2);
  assert.strictEqual(dedupe('a'), false);
  assert.strictEqual(dedupe('a'), true);
  dedupe('b'); dedupe('c'); // 挤出 'a'
  assert.strictEqual(dedupe('a'), false, 'evicted after cap');
  console.log('0i. makeDedupe OK');

  // frp 加速镜像映射：6 平台齐全且与包名后缀一致
  const mirrorKeys = Object.keys(FRP_MIRROR_URLS).sort();
  assert.deepStrictEqual(mirrorKeys, ['darwin_amd64', 'darwin_arm64', 'linux_amd64', 'linux_arm64', 'windows_amd64', 'windows_arm64']);
  for (const [k, u] of Object.entries(FRP_MIRROR_URLS)) {
    const [osN, archN] = k.split('_');
    assert.ok(u.includes('frp_') && u.includes(osN) && u.includes(archN), 'mirror url matches platform: ' + k);
    assert.ok(u.endsWith('.tar.gz') !== u.endsWith('.zip'), 'single archive ext: ' + k);
    if (osN === 'windows') assert.ok(u.endsWith('.zip'), 'windows uses zip');
  }
  console.log('0j. FRP_MIRROR_URLS OK');
}

const TARGET = 18080;
const HTTP_PORT = 18081;
const HTTPS_PORT = 18082;
const QQ_PORT = 18083;

// ─────────── frp 纯函数断言 ───────────
{
  const toml = buildFrpcToml({
    serverAddr: 'frps.example.com',
    serverPort: 7000,
    authToken: 'secret',
    proxyName: 'dsh-frp-test',
    proxyType: 'tcp',
    localPort: 3081,
    remotePort: 13080,
  });
  assert.ok(toml.includes('serverAddr = "frps.example.com"'), 'toml serverAddr');
  assert.ok(toml.includes('serverPort = 7000'), 'toml serverPort');
  assert.ok(toml.includes('auth.token = "secret"'), 'toml auth.token');
  assert.ok(toml.includes('name = "dsh-frp-test"'), 'toml proxy name');
  assert.ok(toml.includes('type = "tcp"'), 'toml type');
  assert.ok(toml.includes('localPort = 3081'), 'toml localPort');
  assert.ok(toml.includes('remotePort = 13080'), 'toml remotePort');
  console.log('0a. buildFrpcToml(tcp) OK');

  const tomlHttp = buildFrpcToml({
    serverAddr: 'frps.example.com',
    serverPort: 7000,
    authToken: '',
    proxyName: 'dsh-frp-http',
    proxyType: 'http',
    localPort: 3081,
    customDomains: ['dsh.example.com', 'dsh2.example.com'],
    subdomain: '',
  });
  assert.ok(tomlHttp.includes('type = "http"'), 'toml http type');
  assert.ok(tomlHttp.includes('customDomains = ["dsh.example.com", "dsh2.example.com"]'), 'toml customDomains');
  assert.ok(!tomlHttp.includes('auth.'), 'no auth block when token empty');
  console.log('0b. buildFrpcToml(http) OK');

  const tomlTls = buildFrpcToml({
    serverAddr: 'frps.example.com',
    serverPort: 7000,
    authToken: 'secret',
    proxyName: 'dsh-tls',
    proxyType: 'tcp',
    localPort: 3081,
    remotePort: 13080,
    tlsEnable: true,
    tlsCertFile: '/certs/client.crt',
    tlsKeyFile: '/certs/client.key',
    tlsTrustedCaFile: '/certs/ca.crt',
    tlsServerName: 'frps.example.com',
  });
  assert.ok(tomlTls.includes('transport.tls.enable = true'), 'tls enable');
  assert.ok(tomlTls.includes('transport.tls.certFile = "/certs/client.crt"'), 'tls certFile');
  assert.ok(tomlTls.includes('transport.tls.keyFile = "/certs/client.key"'), 'tls keyFile');
  assert.ok(tomlTls.includes('transport.tls.trustedCaFile = "/certs/ca.crt"'), 'tls trustedCaFile');
  assert.ok(tomlTls.includes('transport.tls.serverName = "frps.example.com"'), 'tls serverName');
  // 未配置 TLS 时不输出 transport.tls 段
  assert.ok(!toml.includes('transport.tls'), 'no tls section by default');
  // 仅禁用
  const tomlTlsOff = buildFrpcToml({ serverAddr: 's', serverPort: 7000, proxyName: 'p', proxyType: 'tcp', localPort: 1, remotePort: 2, tlsEnable: false });
  assert.ok(tomlTlsOff.includes('transport.tls.enable = false'), 'tls disable');
  // 只给 CA（enable 省略，frp 默认启用 TLS）
  const tomlCaOnly = buildFrpcToml({ serverAddr: 's', serverPort: 7000, proxyName: 'p', proxyType: 'tcp', localPort: 1, remotePort: 2, tlsTrustedCaFile: '/ca.crt' });
  assert.ok(tomlCaOnly.includes('transport.tls.trustedCaFile = "/ca.crt"') && !tomlCaOnly.includes('transport.tls.enable'), 'ca-only without enable');
  console.log('0b2. buildFrpcToml(tls) OK');

  const tomlHttps = buildFrpcToml({
    serverAddr: 'frps.example.com',
    serverPort: 7000,
    proxyName: 'dsh-https',
    proxyType: 'https',
    localPort: 3081,
    customDomains: ['dsh.example.com'],
    httpsCertFile: '/certs/dsh.crt',
    httpsKeyFile: '/certs/dsh.key',
  });
  assert.ok(tomlHttps.includes('type = "https"'), 'https proxy type');
  assert.ok(tomlHttps.includes('customDomains = ["dsh.example.com"]'), 'https customDomains');
  assert.ok(tomlHttps.includes('[proxies.plugin]'), 'plugin section');
  assert.ok(tomlHttps.includes('type = "https2http"'), 'https2http plugin');
  assert.ok(tomlHttps.includes('localAddr = "127.0.0.1:3081"'), 'plugin localAddr');
  assert.ok(tomlHttps.includes('crtPath = "/certs/dsh.crt"'), 'plugin crtPath');
  assert.ok(tomlHttps.includes('keyPath = "/certs/dsh.key"'), 'plugin keyPath');
  assert.ok(!tomlHttps.includes('localIP'), 'no localIP in plugin mode');
  console.log('0b3. buildFrpcToml(https/https2http) OK');

  assert.strictEqual(
    computeFrpUrl({ frpProxyType: 'tcp', frpServerAddr: '1.2.3.4', frpRemotePort: 13080 }),
    'http://1.2.3.4:13080',
  );
  assert.strictEqual(
    computeFrpUrl({ frpProxyType: 'http', frpCustomDomains: ['dsh.example.com'], frpVhostHTTPPort: 80 }),
    'http://dsh.example.com',
  );
  assert.strictEqual(
    computeFrpUrl({ frpProxyType: 'http', frpCustomDomains: [], frpSubdomain: 'dsh', frpSubdomainHost: 'frp.example.com', frpVhostHTTPPort: 8080 }),
    'http://dsh.frp.example.com:8080',
  );
  assert.strictEqual(computeFrpUrl({ frpProxyType: 'http', frpCustomDomains: [], frpSubdomain: 'dsh', frpSubdomainHost: '' }), null);
  assert.strictEqual(
    computeFrpUrl({ frpProxyType: 'https', frpCustomDomains: ['dsh.example.com'], frpVhostHTTPSPort: 443 }),
    'https://dsh.example.com',
  );
  assert.strictEqual(
    computeFrpUrl({ frpProxyType: 'https', frpCustomDomains: ['dsh.example.com'], frpVhostHTTPSPort: 8443 }),
    'https://dsh.example.com:8443',
  );
  console.log('0c. computeFrpUrl OK');

  assert.deepStrictEqual(normalizeDomains('a.com, b.com c.com'), ['a.com', 'b.com', 'c.com']);
  assert.deepStrictEqual(normalizeDomains(['x.com', ' y.com ']), ['x.com', 'y.com']);
  assert.deepStrictEqual(normalizeDomains(''), []);
  console.log('0d. normalizeDomains OK');
}

// ─────────── 反向代理集成测试 ───────────
// 假 DSH 服务器
const target = http.createServer((req, res) => {
  if (req.url === '/big') {
    const body = 'x'.repeat(100000);
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(body);
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ hello: 'dsh', url: req.url, host: req.headers.host }));
});
let wsAccepted = false;
target.on('upgrade', (req, socket) => {
  wsAccepted = true;
  const key = req.headers['sec-websocket-key'];
  const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.write(Buffer.from([0x81, 0x02, 0x6f, 0x6b])); // text "ok"
});

await new Promise(r => target.listen(TARGET, '127.0.0.1', r));

// 代理服务器
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-frp-test-'));
const cert = generateSelfSignedCert(lanIPs());
fs.writeFileSync(path.join(tmpDir, 't-key.pem'), cert.key);
fs.writeFileSync(path.join(tmpDir, 't-cert.pem'), cert.cert);
const proxy = createProxyServer({ targetPort: TARGET, pfxPath: '', pfxPass: '' });
await proxy.start(HTTP_PORT, HTTPS_PORT);
const TOKEN = proxy.token;
console.log('proxy started, token =', TOKEN);
const cookie = "dshr_token" + '=' + TOKEN;

// 1. 无 token → 403
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: HTTP_PORT, path: '/api/x' }, r => {
    console.log('1. no-token status:', r.statusCode, '(expect 403)');
    assert.strictEqual(r.statusCode, 403);
    r.resume(); r.on('end', res);
  }).on('error', rej);
});

// 2. ?token= → 302 + set-cookie
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: HTTP_PORT, path: '/api/x?token=' + TOKEN }, r => {
    console.log('2. token-query status:', r.statusCode, '(expect 302)');
    assert.strictEqual(r.statusCode, 302);
    r.resume(); r.on('end', res);
  }).on('error', rej);
});

// 3. cookie → 200 且转发到目标
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: HTTP_PORT, path: '/api/x', headers: { Cookie: cookie } }, r => {
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => {
      console.log('3. cookie status:', r.statusCode, '(expect 200)');
      console.log('   body:', d.slice(0, 80));
      assert.strictEqual(r.statusCode, 200);
      res();
    });
  }).on('error', rej);
});

// 4. gzip 大响应
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: HTTP_PORT, path: '/big', headers: { Cookie: cookie, 'Accept-Encoding': 'gzip' } }, r => {
    let d = Buffer.alloc(0);
    r.on('data', c => d = Buffer.concat([d, c]));
    r.on('end', () => {
      console.log('4. gzip status:', r.statusCode, 'encoding:', r.headers['content-encoding'], 'size:', d.length, '(expect gzip, <100000)');
      assert.strictEqual(r.headers['content-encoding'], 'gzip');
      assert.ok(d.length < 100000);
      res();
    });
  }).on('error', rej);
});

// 5. HTTPS 握手 + cookie
await new Promise((res, rej) => {
  https.get({ host: '127.0.0.1', port: HTTPS_PORT, path: '/api/x', headers: { Cookie: cookie }, rejectUnauthorized: false }, r => {
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => {
      console.log('5. https status:', r.statusCode, '(expect 200) body:', d.slice(0, 60));
      assert.strictEqual(r.statusCode, 200);
      res();
    });
  }).on('error', rej);
});

// 6. WS 升级（简化验证）
await new Promise((res, rej) => {
  const timer = setTimeout(() => { console.log('6. WS TIMEOUT'); rej(new Error('ws timeout')); }, 5000);
  const ws = http.request({
    host: '127.0.0.1', port: HTTP_PORT, path: '/ws', method: 'GET',
    headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': 13, 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', Cookie: cookie },
  });
  ws.on('upgrade', (r, socket) => {
    clearTimeout(timer);
    console.log('6. ws upgrade OK, target accepted:', wsAccepted);
    assert.ok(wsAccepted);
    socket.destroy();
    res();
  });
  ws.on('response', (r) => { console.log('6. got response status', r.statusCode, 'instead of upgrade'); r.resume(); clearTimeout(timer); rej(new Error('no upgrade')); });
  ws.on('error', (e) => { clearTimeout(timer); rej(e); });
  ws.end();
});

// 7. QQ 桥
const qq = createQQServer({ infoUrls: ['http://127.0.0.1:' + TARGET + '/frpremote/info'] });
await qq.start(QQ_PORT);
console.log('7. QQ bridge listening on', QQ_PORT);
qq.close();

// ─────────── DSH 浏览器会话 cookie 注入（新版 Host 通道要求会话）───────────
// 假 DSH：没有有效会话 cookie 就一律 401（等价于 dsh web authentication required）
const SESSION_TARGET = 18084;
const SESSION_HTTP_PORT = 18085;
const SESSION_HTTPS_PORT = 18086;
const SESSION_COOKIE = 'dsh-auth-test=session-ok';
const sessionSeen = [];
const sessionTarget = http.createServer((req, res) => {
  const ck = String(req.headers.cookie || '');
  sessionSeen.push(ck);
  if (!ck.includes(SESSION_COOKIE)) {
    res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('dsh web authentication required; reopen the URL printed by dsh web.\n');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end('<html>dsh app</html>');
});
sessionTarget.on('upgrade', (req, socket) => {
  sessionSeen.push('WS:' + String(req.headers.cookie || ''));
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n');
});
await new Promise(r => sessionTarget.listen(SESSION_TARGET, '127.0.0.1', r));

let mintCalls = 0;
let sessionCookie = null;
const sessionProxy = createProxyServer({
  targetPort: SESSION_TARGET, pfxPath: '', pfxPass: '',
  getSessionCookie: () => sessionCookie,
  refreshSessionCookie: async () => { mintCalls++; sessionCookie = SESSION_COOKIE; return sessionCookie; },
});
await sessionProxy.start(SESSION_HTTP_PORT, SESSION_HTTPS_PORT);
const STOKEN = sessionProxy.token;

// 8. 没有会话 cookie → 上游 401 → 自动铸签重放 → 200（手机端不该看到 401）
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: SESSION_HTTP_PORT, path: '/', headers: { Cookie: 'dshr_token=' + STOKEN } }, r => {
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => {
      console.log('8. session 401->retry status:', r.statusCode, 'mintCalls:', mintCalls, '(expect 200, 1)');
      assert.strictEqual(r.statusCode, 200);
      assert.strictEqual(mintCalls, 1);
      assert.ok(d.includes('dsh app'));
      assert.ok(!sessionSeen[0].includes(SESSION_COOKIE), 'first upstream attempt carried no session cookie');
      assert.ok(sessionSeen.some(c => c.includes(SESSION_COOKIE)), 'upstream saw injected session cookie');
      res();
    });
  }).on('error', rej);
});

// 9. 会话 cookie 已在内存：直接注入，不再重复铸签
await new Promise((res, rej) => {
  const before = mintCalls;
  http.get({ host: '127.0.0.1', port: SESSION_HTTP_PORT, path: '/api/x', headers: { Cookie: 'dshr_token=' + STOKEN } }, r => {
    r.resume();
    r.on('end', () => {
      console.log('9. session cached status:', r.statusCode, 'extra mints:', mintCalls - before, '(expect 200, 0)');
      assert.strictEqual(r.statusCode, 200);
      assert.strictEqual(mintCalls, before);
      res();
    });
  }).on('error', rej);
});

// 10. WebSocket 升级同样带上会话 cookie（/api 流走 WS）
await new Promise((res, rej) => {
  const timer = setTimeout(() => { rej(new Error('session ws timeout')); }, 5000);
  const ws = http.request({
    host: '127.0.0.1', port: SESSION_HTTP_PORT, path: '/ws', method: 'GET',
    headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': 13, 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', Cookie: 'dshr_token=' + STOKEN },
  });
  ws.on('upgrade', (r, socket) => {
    clearTimeout(timer);
    const last = sessionSeen[sessionSeen.length - 1];
    console.log('10. ws carries session cookie:', last.startsWith('WS:') && last.includes(SESSION_COOKIE), '(expect true)');
    assert.ok(last.startsWith('WS:') && last.includes(SESSION_COOKIE));
    socket.destroy();
    res();
  });
  ws.on('error', e => { clearTimeout(timer); rej(e); });
  ws.end();
});

// 11. 未启用适配（旧版 DSH / dshSessionAuth: false）：401 原样透传，不做重放
const plainProxy = createProxyServer({ targetPort: SESSION_TARGET, pfxPath: '', pfxPass: '' });
await plainProxy.start(SESSION_HTTP_PORT + 10, SESSION_HTTPS_PORT + 10);
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: SESSION_HTTP_PORT + 10, path: '/', headers: { Cookie: 'dshr_token=' + plainProxy.token } }, r => {
    console.log('11. no session adapter status:', r.statusCode, '(expect 401)');
    assert.strictEqual(r.statusCode, 401);
    r.resume();
    r.on('end', res);
  }).on('error', rej);
});
// 12. 首个请求就是带 body 的 POST（/api RPC）：无法重放 → 该次 401，但会先补铸会话，
//     随后请求即恢复正常（浏览器实际总是先 GET / 拿到 index，所以这条只是兜底语义）
let postMints = 0;
let postCookie = null;
const postProxy = createProxyServer({
  targetPort: SESSION_TARGET, pfxPath: '', pfxPass: '',
  getSessionCookie: () => postCookie,
  // 模拟真实实现的异步铸签时机（微任务之后才可用），确保断言反映真实行为
  refreshSessionCookie: async () => { await new Promise(r => setTimeout(r, 0)); postMints++; postCookie = SESSION_COOKIE; return postCookie; },
});
await postProxy.start(SESSION_HTTP_PORT + 20, SESSION_HTTPS_PORT + 20);
await new Promise((res, rej) => {
  const body = '{"x":1}';
  const r = http.request({
    host: '127.0.0.1', port: SESSION_HTTP_PORT + 20, path: '/api/rpc', method: 'POST',
    headers: { Cookie: 'dshr_token=' + postProxy.token, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
  }, (pres) => {
    console.log('12a. first request POST status:', pres.statusCode, '(expect 401)');
    assert.strictEqual(pres.statusCode, 401);
    pres.resume();
    pres.on('end', res);
  });
  r.on('error', rej);
  r.end(body);
});
await new Promise(r => setTimeout(r, 50)); // 补铸是异步的：等它落地再断言
assert.ok(postMints >= 1, 'body request without session still triggers a mint');
assert.ok(postCookie, 'session cookie minted after the body request');
console.log('12a2. mint triggered asynchronously, mints:', postMints, '(expect >=1)');
await new Promise((res, rej) => {
  http.get({ host: '127.0.0.1', port: SESSION_HTTP_PORT + 20, path: '/', headers: { Cookie: 'dshr_token=' + postProxy.token } }, r => {
    console.log('12b. after mint status:', r.statusCode, '(expect 200)');
    assert.strictEqual(r.statusCode, 200);
    r.resume();
    r.on('end', res);
  }).on('error', rej);
});
postProxy.close();
plainProxy.close();
sessionProxy.close();
sessionTarget.close();

// 14. 注入脚本：语法正确；入口注入 DSH「设置」弹窗的导航列表，且只插入自己的节点
//     真实故障①：脚本压根没执行（桌面端 tapIndex 不生效）→ 见第 15 项
//     真实故障②：为了"挤进"侧栏改写容器与兄弟按钮行内样式 → 把用户侧栏底部原有内容挤没
//     真实故障③：挂到侧栏某个"设置"按钮旁边，React 局部重渲染后节点被移除 → 图标时有时无
//     现在的做法：往设置弹窗左侧导航列表里 append 自己的条目（点击打开面板），
//     入口只此一个（右下角悬浮按钮已按要求移除）；全程不改动宿主样式，被 React 移除时由 MutationObserver 补回。
{
  const src = fs.readFileSync(new URL('../lib/index.mjs', import.meta.url), 'utf8');
  const unescape = (s) => s.replace(/\\([\s\S])/g, '$1');
  const qr = unescape(src.match(/const QR_RUNTIME = `([\s\S]*?)`;/)[1]);
  const rawInject = unescape(src.match(/const INJECT_SCRIPT = `([\s\S]*?)`;/)[1]);
  const code = rawInject.replace('${QR_RUNTIME}', qr);
  assert.ok(code.length > 50000, 'inject script extracted, got ' + code.length);

  const harness = (opts) => {
    const navLabels = opts.nav === 'full' ? ['账号与余额', '通用设置', '模型', '内置插件']
      : opts.nav === 'single' ? ['通用设置'] : [];
    const byId = new Map();
    const intervals = [];
    const mkEl = (tag) => {
      const el = {
        tagName: String(tag).toUpperCase(), id: '', className: '', style: {}, children: [], parentNode: null,
        textContent: '', innerHTML: '', title: '', type: '', _h: {},
        appendChild(c) { c.parentNode = el; el.children.push(c); if (c.id) byId.set(c.id, c); return c; },
        insertBefore(c, ref) {
          c.parentNode = el;
          const i = ref ? el.children.indexOf(ref) : -1;
          if (i < 0) el.children.push(c); else el.children.splice(i, 0, c);
          if (c.id) byId.set(c.id, c);
          return c;
        },
        removeChild(c) { el.children = el.children.filter((x) => x !== c); c.parentNode = null; return c; },
        setAttribute(k, v) { el[k] = v; if (k === 'id') { el.id = v; byId.set(v, el); } },
        getAttribute(k) { return el[k] === undefined ? null : el[k]; },
        addEventListener(t, fn) { (el._h[t] = el._h[t] || []).push(fn); },
        removeEventListener() {},
        contains(n) { return n === el || (n && n._inside === true) || el.children.indexOf(n) !== -1; },
        querySelector() { return null; },
        querySelectorAll() { return []; },
        getBoundingClientRect() { return { width: 120, height: 28, top: 200, left: 260, right: 380, bottom: 228 }; },
        getContext() { return { fillRect() {}, fillStyle: '' }; },
      };
      return el;
    };
    const body = mkEl('body');
    const head = mkEl('head');
    // 模拟 DSH 设置弹窗左侧导航：一个容器 + 若干导航按钮（带既有行内样式）
    const nav = mkEl('div');
    nav.className = '_2H3hWW_settingsNav';
    nav.style.width = '180px';
    const navButtons = navLabels.map((t) => { const b = mkEl('button'); b.textContent = t; b.style.padding = '8px 10px'; nav.appendChild(b); return b; });
    if (navLabels.length) body.appendChild(nav);
    const before = { navStyle: JSON.stringify(nav.style), navChildren: nav.children.length };

    const doc = {
      readyState: 'complete', body, head, documentElement: mkEl('html'),
      createElement: mkEl,
      getElementById: (id) => byId.get(id) || null,
      querySelector: () => null,
      querySelectorAll: (sel) => (sel === 'button, [role="button"]' ? navButtons : []),
      addEventListener() {},
      elementFromPoint: () => ({ _inside: true }),
    };
    const win = {
      innerWidth: 1920, innerHeight: 1080,
      getComputedStyle: () => ({ getPropertyValue: () => '', display: 'block', visibility: 'visible', opacity: '1' }),
      MutationObserver: function () { this.observe = () => {}; this.disconnect = () => {}; },
    };
    const posts = [];
    const fetchStub = (url, o) => {
      posts.push({ url, body: o && o.body });
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ ok: true, config: {}, state: {} }) });
    };
    const mo = function () { this.observe = () => {}; this.disconnect = () => {}; };
    const run = new Function('document', 'window', 'localStorage', 'fetch', 'setTimeout', 'setInterval', 'clearInterval', 'console', 'MutationObserver', code);
    run(doc, win, { getItem: () => null, setItem() {} }, fetchStub,
      (fn) => { try { fn(); } catch (e) { /* ignore */ } return 0; },
      (fn) => { intervals.push(fn); return intervals.length; },
      (id) => { if (id) intervals[id - 1] = null; },
      console, mo);
    return {
      byId, body, nav, navButtons, before, posts,
      fire: (el, t) => { for (const fn of (el && el._h && el._h[t]) || []) fn(); },
      mounted: () => posts.filter((p) => p.url === '/frpremote/client-report').map((p) => JSON.parse(p.body)).filter((x) => x.stage === 'mounted').pop(),
    };
  };

  // A. 设置弹窗打开（导航齐全）→ 条目注入导航列表，点击能打开面板，且没碰宿主样式
  const a = harness({ nav: 'full' });
  const aItem = a.byId.get('frprm-setitem');
  assert.ok(aItem, 'A: 设置导航条目已创建');
  assert.strictEqual(aItem.parentNode, a.nav, 'A: 注入到了设置导航容器里');
  assert.strictEqual(a.nav.children.indexOf(aItem), a.before.navChildren, 'A: 追加在导航末尾');
  assert.ok(String(aItem.innerHTML).indexOf('远程控制') !== -1, 'A: 条目带文字「远程控制」');
  assert.strictEqual(JSON.stringify(a.nav.style), a.before.navStyle, 'A: 未改写导航容器行内样式');
  assert.strictEqual(a.navButtons[0].style.padding, '8px 10px', 'A: 未改写原有导航项样式');
  assert.strictEqual(a.nav.children.length, a.before.navChildren + 1, 'A: 只多了我们自己一个节点');
  assert.strictEqual(a.mounted().settingsItem, true, 'A: 上报 settingsItem=true');
  // 按用户要求：右下角悬浮按钮已移除，入口只有设置里这一个
  assert.strictEqual(a.byId.get('frprm-fab'), undefined, 'A: 不再创建右下角悬浮按钮');
  assert.strictEqual(a.body.children.length, 1, 'A: body 下只多了设置导航容器（没有悬浮按钮）');

  // A2. 点击该条目 → 打开远程控制面板
  a.fire(aItem, 'click');
  assert.ok(a.byId.get('frprm-mask') && a.byId.get('frprm-panel'), 'A2: 点击设置里的条目会打开面板');

  // B. 设置弹窗没开（页面里没有导航）→ 不插任何节点
  const b = harness({ nav: 'none' });
  assert.strictEqual(b.byId.get('frprm-setitem'), undefined, 'B: 没有导航容器时不注入');
  assert.strictEqual(b.byId.get('frprm-fab'), undefined, 'B: 也没有悬浮按钮');
  assert.strictEqual(b.nav.children.length, b.before.navChildren, 'B: 宿主节点数量不变');
  assert.strictEqual(JSON.stringify(b.nav.style), b.before.navStyle, 'B: 宿主样式不变');
  assert.strictEqual(b.mounted().settingsItem, false, 'B: 上报 settingsItem=false');

  // C. 只有一个疑似导航项 → 不误判（要求同容器 >= 2 个），避免插到无关位置
  const c = harness({ nav: 'single' });
  assert.strictEqual(c.byId.get('frprm-setitem'), undefined, 'C: 单个候选不误判');
  assert.strictEqual(c.nav.children.length, c.before.navChildren, 'C: 宿主节点数量不变');
  console.log('14. 设置弹窗导航注入 + 点击打开面板 + 不误判/不碰宿主 OK');
}

// 13. findFreePort：Windows 下 SO_REUSEADDR 会让纯 bind 探测漏判（0.0.0.0 与 127.0.0.1 可同时绑上），
//     于是同机第二个 DSH 实例会选中已占用端口、真正 listen 时才 EADDRINUSE。
const OCCUPIED = 18120;
const blocker = http.createServer((req, res) => res.end('x'));
await new Promise(r => blocker.listen(OCCUPIED, '0.0.0.0', r));
assert.strictEqual(await findFreePort(OCCUPIED, OCCUPIED + 1), OCCUPIED + 1, 'skips wildcard-occupied port');
await new Promise(r => blocker.close(r));

const loopBlocker = http.createServer((req, res) => res.end('y'));
await new Promise(r => loopBlocker.listen(OCCUPIED + 2, '127.0.0.1', r));
assert.strictEqual(await findFreePort(OCCUPIED + 2, OCCUPIED + 3), OCCUPIED + 3, 'skips loopback-occupied port');
await new Promise(r => loopBlocker.close(r));

assert.strictEqual(await findFreePort(OCCUPIED, OCCUPIED), OCCUPIED, 'picks a free port');

// 13b. http/https 两个区间重叠：必须能用 exclude 选出互不相同的端口
const p1 = await findFreePort(OCCUPIED, OCCUPIED + 3);
const p2 = await findFreePort(OCCUPIED, OCCUPIED + 3, [p1]);
assert.notStrictEqual(p1, p2, 'exclude keeps http/https ports distinct');
assert.strictEqual(await findFreePort(OCCUPIED, OCCUPIED + 3, [p1, p2]), OCCUPIED + 2, 'exclude skips several ports');
console.log('13. findFreePort skips occupied ports (wildcard + loopback), respects exclude OK');

// 15. 桌面客户端唯一通道：apply() 必须**同步**注册 webserver/index-inject 结构化行
//     （桌面壳 index.html 由静态 dist 直出 → tapIndex 永远不生效；注入表宿主启动时只收集一次）
{
  const prevHome = process.env.DSH_HOME;
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-frp-apply-'));
  process.env.DSH_HOME = tmpHome;
  try {
    const listeners = new Map();
    const stubWebServer = { port: 19080, host: '127.0.0.1', register: () => ({ dispose() {} }), tapIndex: () => ({ dispose() {} }), on() {}, off() {} };
    const services = {
      subprocess: { spawn: async () => { throw new Error('stub'); } },
      webServer: stubWebServer,
      connection: { authenticatedUrl: (u) => u, authorizeIndex: () => false },
    };
    const ctx = {
      logger: { info() {}, warn() {}, error() {} },
      get: (k) => services[k],
      on(evt, cb) { if (!listeners.has(evt)) listeners.set(evt, []); listeners.get(evt).push(cb); },
      off() {},
      effect(fn) { try { const d = fn(); if (typeof d === 'function') d(); } catch (e) { /* ignore */ } return () => {}; },
      timeout(fn) { return setTimeout(fn, 0); },
      inject(deps, cb) { try { cb(ctx); } catch (e) { /* ignore */ } },
    };
    apply(ctx, { autoStart: false });
    const cbs = listeners.get('webserver/index-inject') || [];
    assert.strictEqual(cbs.length, 1, 'apply() 同步注册了 index-inject 行');
    const table = [];
    cbs[0](table);
    const rows = table.filter((r) => r && r.kind === 'script' && typeof r.text === 'string' && r.text.indexOf('__frprmBooted') !== -1);
    assert.strictEqual(rows.length, 1, '推送了一行内联 script');
    assert.strictEqual(rows[0].placement, 'body', '行放在 body');
    cbs[0](table); // 宿主可能重复收集
    assert.strictEqual(table.filter((r) => r.kind === 'script').length, 1, '同一张表里不重复推');
    console.log('15. apply() 同步注册桌面端注入行（kind=script, placement=body）OK');
  } finally {
    if (prevHome === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = prevHome;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
}

// 0k. 纯 JS 二维码生成器（结构 + 确定性；可解码性由开发期 jsQR 回环验证）
{
  const src = fs.readFileSync(new URL('../lib/index.mjs', import.meta.url), 'utf8');
  const m = src.match(/const QR_RUNTIME = `([\s\S]*?)`;/);
  assert.ok(m, 'QR_RUNTIME block found');
  const frprmQr = new Function(m[1] + '; return frprmQr;')();
  const qrCases = ['HELLO', 'http://192.168.5.3:3081/?token=abcDEF123', '中文 Mixed 0123456789'];
  for (const text of qrCases) {
    const qr = frprmQr(text);
    assert.strictEqual(qr.size, qr.version * 4 + 17, 'size = v*4+17');
    const corner = (ox, oy) => {
      for (let y = 0; y < 7; y++) {
        for (let x = 0; x < 7; x++) {
          const border = (x === 0 || x === 6 || y === 0 || y === 6);
          const core = (x >= 2 && x <= 4 && y >= 2 && y <= 4);
          assert.strictEqual(qr.modules[oy + y][ox + x], border || core, 'finder pixel at ' + (ox + x) + ',' + (oy + y));
        }
      }
    };
    corner(0, 0); corner(qr.size - 7, 0); corner(0, qr.size - 7);
    for (let i = 8; i < qr.size - 8; i++) {
      assert.strictEqual(qr.modules[6][i], i % 2 === 0, 'timing row alternates');
      assert.strictEqual(qr.modules[i][6], i % 2 === 0, 'timing col alternates');
    }
    assert.deepStrictEqual(frprmQr(text).modules, qr.modules, 'deterministic output');
  }
  console.log('0k. QR encoder structure OK');
}

proxy.close();
target.close();
fs.rmSync(tmpDir, { recursive: true, force: true });
console.log('ALL TESTS DONE');
process.exit(0);
