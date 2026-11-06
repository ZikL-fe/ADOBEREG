'use strict';
/**
 * 沙箱的 Chrome 传输层：按真 Chrome（netlog 实测）的头顺序和取值拼请求，
 * 跨源非简单请求先发 OPTIONS 预检，再交给 Go 中继（Chrome TLS/HTTP2 + cookie 罐）发出。
 */
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const RELAY_EXE = path.join(__dirname, 'out', 'relay.exe');

function startRelay() {
  // 后端进程内已经跑着中继（BDA_RELAY_ADDR 带路径密钥），不再起 relay.exe。
  if (process.env.BDA_RELAY_ADDR) {
    return Promise.resolve({ addr: process.env.BDA_RELAY_ADDR, close: () => {} });
  }
  return new Promise((resolve, reject) => {
    const child = spawn(RELAY_EXE, ['relay'], { stdio: ['pipe', 'pipe', 'ignore'] });
    let buf = '';
    const timer = setTimeout(() => reject(new Error('relay 没起来')), 10000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const m = /RELAY (\S+)/.exec(buf);
      if (m) {
        clearTimeout(timer);
        resolve({ addr: m[1], close: () => { try { child.stdin.end(); child.kill(); } catch (e) {} } });
      }
    });
    child.once('error', reject);
  });
}

function chromeBrands(maj) {
  const v = Number(maj);
  const chars = [' ', '(', ':', '-', '.', '/', ')', ';', '=', '?', '_'];
  const fake = { brand: `Not${chars[v % 11]}A${chars[(v + 1) % 11]}Brand`, version: ['8', '99', '24'][v % 3] };
  const list = [fake, { brand: 'Chromium', version: String(maj) }, { brand: 'Google Chrome', version: String(maj) }];
  const order = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]][v % 6];
  const out = [];
  list.forEach((b, i) => { out[order[i]] = b; });
  return out;
}

function acceptLanguage(langs) {
  const list = (langs && langs.length ? langs : ['en-US', 'en']).slice(0, 10);
  return list.map((l, i) => (i === 0 ? l : `${l};q=${(1 - i * 0.1).toFixed(1)}`)).join(',');
}

function siteOf(host) {
  const parts = String(host).split('.');
  return parts.slice(-2).join('.');
}

const SIMPLE_HEADERS = new Set(['accept', 'accept-language', 'content-language', 'content-type']);
const SIMPLE_TYPES = ['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'];

// 头顺序来自 netlog（Chrome 154/155）：脚本加的自定义头穿插在固定位置。
function orderFetch(names, hasBody) {
  const first = ['ark-build-id', 'x-ark-esync-value'];
  const rank = (n) => (first.includes(n) ? first.indexOf(n) : first.length);
  const custom = names.filter((n) => !['accept', 'content-type', 'accept-language'].includes(n))
    .sort((a, b) => rank(a) - rank(b));
  const order = [];
  if (hasBody) order.push('content-length');
  if (custom[0]) order.push(custom[0]);
  order.push('sec-ch-ua-platform');
  custom.slice(1).forEach((n) => order.push(n));
  order.push('user-agent', 'sec-ch-ua');
  if (names.includes('content-type')) order.push('content-type');
  order.push('sec-ch-ua-mobile', 'accept', 'origin', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
    'referer', 'accept-encoding', 'accept-language', 'cookie', 'priority');
  return order;
}

function createTransport(cfg) {
  const ua = cfg.userAgent;
  const maj = (/Chrome\/(\d+)/.exec(ua) || [])[1] || '155';
  const secChUa = chromeBrands(maj).map((b) => `"${b.brand}";v="${b.version}"`).join(', ');
  const site = new URL(cfg.site);
  const pageOrigin = site.origin;
  const referer = pageOrigin + '/';
  const lang = acceptLanguage(cfg.languages);
  const session = crypto.randomBytes(8).toString('hex');
  const preflighted = new Set();
  const log = cfg.log || (() => {});

  async function send(method, url, pairs, body) {
    const res = await fetch(`http://${cfg.relayAddr}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session, proxy: cfg.proxy || '', method, url, headers: pairs,
        body: body == null ? '' : Buffer.from(body).toString('base64'),
      }),
    });
    const out = await res.json();
    if (out.error) throw new Error(out.error);
    const buf = Buffer.from(out.body || '', 'base64');
    log({ method, url, status: out.status, protocol: out.protocol, headers: pairs.map((p) => p[0]), setCookie: (out.setCookie || []).map((c) => c.split('=')[0]) });
    return { status: out.status, headers: out.headers || {}, buf, body: buf.toString('utf8') };
  }

  function fetchSite(target) {
    if (target.origin === pageOrigin) return 'same-origin';
    return siteOf(target.hostname) === siteOf(site.hostname) ? 'same-site' : 'cross-site';
  }

  function toBuffer(body) {
    if (body == null) return null;
    if (typeof body === 'string') return Buffer.from(body);
    if (Buffer.isBuffer(body)) return body;
    if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
    if (body instanceof ArrayBuffer) return Buffer.from(body);
    return Buffer.from(String(body));
  }

  // 页面脚本发的 XHR / fetch。
  async function request(method, url, headers, body) {
    const target = new URL(url);
    method = String(method || 'GET').toUpperCase();
    const h = Object.assign({}, headers || {});
    delete h['user-agent']; delete h.origin; delete h.referer;
    const buf = toBuffer(body);
    const sfs = fetchSite(target);
    const cross = sfs !== 'same-origin';
    const names = Object.keys(h);
    const ctype = (h['content-type'] || '').split(';')[0].trim().toLowerCase();
    const nonSimple = names.filter((n) => !SIMPLE_HEADERS.has(n) || (n === 'content-type' && !SIMPLE_TYPES.includes(ctype)));
    const needPreflight = cross && (nonSimple.length > 0 || !['GET', 'HEAD', 'POST'].includes(method));
    if (needPreflight) {
      const key = `${method} ${target.origin}${target.pathname} ${nonSimple.sort().join(',')}`;
      if (!preflighted.has(key)) {
        preflighted.add(key);
        const pre = [['accept', '*/*'], ['access-control-request-method', method]];
        if (nonSimple.length) pre.push(['access-control-request-headers', nonSimple.slice().sort().join(',')]);
        pre.push(['origin', pageOrigin], ['user-agent', ua], ['sec-fetch-mode', 'cors'], ['sec-fetch-site', sfs],
          ['sec-fetch-dest', 'empty'], ['referer', referer], ['accept-encoding', 'gzip, deflate, br, zstd'],
          ['accept-language', lang], ['priority', 'u=1, i']);
        await send('OPTIONS', url, pre, null);
      }
    }
    const values = Object.assign({
      'sec-ch-ua-platform': '"Windows"', 'user-agent': ua, 'sec-ch-ua': secChUa, 'sec-ch-ua-mobile': '?0',
      accept: '*/*', 'sec-fetch-site': sfs, 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty',
      referer, 'accept-encoding': 'gzip, deflate, br, zstd', 'accept-language': lang, priority: 'u=1, i',
    }, h);
    if (cross || method !== 'GET') values.origin = pageOrigin;
    const order = orderFetch(names, buf != null && method !== 'GET');
    const pairs = [];
    for (const n of order) {
      if (n === 'content-length' || n === 'cookie') pairs.push([n, '']);
      else if (values[n] !== undefined) pairs.push([n, values[n]]);
    }
    for (const n of Object.keys(values)) if (!order.includes(n)) pairs.push([n, values[n]]);
    return send(method, url, pairs, buf);
  }

  // <script src> 加载（api.js、jsonp）。
  function script(url) {
    const target = new URL(url);
    const pairs = [
      ['sec-ch-ua-platform', '"Windows"'], ['user-agent', ua], ['sec-ch-ua', secChUa], ['sec-ch-ua-mobile', '?0'],
      ['accept', '*/*'], ['sec-fetch-site', fetchSite(target)], ['sec-fetch-mode', 'no-cors'], ['sec-fetch-dest', 'script'],
      ['referer', referer], ['accept-encoding', 'gzip, deflate, br, zstd'], ['accept-language', lang], ['cookie', ''],
    ];
    return send('GET', url, pairs, null);
  }

  return { request, script, session };
}

module.exports = { startRelay, createTransport, chromeBrands, acceptLanguage };
