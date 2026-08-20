// 分发包集成测试：起一个假的"DSH 服务器"(127.0.0.1:18080)，
// 用 createProxyServer 起 HTTP(18081)+HTTPS(18082)，验证鉴权/302/gzip/WS/HTTPS，
// 另加 frp 相关纯函数（buildFrpcToml / computeFrpUrl / normalizeDomains）断言。
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { createProxyServer, generateSelfSignedCert, createQQServer, lanIPs, buildFrpcToml, computeFrpUrl, normalizeDomains } from '../lib/index.mjs';

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

proxy.close();
target.close();
fs.rmSync(tmpDir, { recursive: true, force: true });
console.log('ALL TESTS DONE');
process.exit(0);
