// 分发包集成测试：起一个假的"DSH 服务器"(127.0.0.1:18080)，
// 用 createProxyServer 起 HTTP(18081)+HTTPS(18082)，验证鉴权/302/gzip/WS/HTTPS，
// 另加 frp 相关纯函数（buildFrpcToml / computeFrpUrl / normalizeDomains）断言。
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert';
import { createHash, createHmac } from 'node:crypto';
import { createProxyServer, generateSelfSignedCert, createQQServer, lanIPs, buildFrpcToml, computeFrpUrl, normalizeDomains, verifyDingtalkSign, feishuEncrypt, feishuDecrypt, wecomSignature, wecomEncrypt, wecomDecrypt, xmlExtract, makeDedupe, FRP_MIRROR_URLS } from '../lib/index.mjs';

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
