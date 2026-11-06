/**
 * browser_env.js —— 给 Node `vm` 用的浏览器环境工厂（共享给多个沙箱）
 * ============================================================================
 * Adobe 的几套风控脚本都是"在浏览器里采指纹"：
 *   · arkose_sandbox.js  跑 arks-client 的 api.js（JSVMP）→ 产出 ark
 *   · bfp_sandbox.js     跑 bfp.adobe.com 的 bfp.min.js（FingerprintJS）→ 产出 bfp
 * 两者要的浏览器面高度重合，所以环境集中放这里，避免两份 stub 各自漂移。
 *
 * 用法:
 *   const createEnv = require('./browser_env');
 *   const env = createEnv({ userAgent, proxy, site, script:{src, attrs}, onResponse });
 *   const context = vm.createContext(env.win);
 *
 * ⚠️ 这里每一条 stub 基本都是被真实报错逼出来的，删之前先看注释里写的后果。
 *    完整排查过程见 ARKOSE_REVERSE.md §12'。
 */
'use strict';
const http = require('http');
const https = require('https');
const tls = require('tls');
const { URL, URLSearchParams } = require('url');

const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
  'Chrome/150.0.0.0 Safari/537.36';

// 真机指纹默认值。canvas/audio 两个 hash 仍是占位——它们直接影响被判机器人的概率，
// 建议从真机采一份填进来（见 ARKOSE_REVERSE.md §12' 剩余工作 4）。
const DEFAULT_FINGERPRINT = {
  platform: 'Win32',
  language: 'en-US',
  languages: ['en-US', 'en'],
  hardwareConcurrency: 8,
  deviceMemory: 8,
  // availTop/availLeft 不能少: screenFrame = [availTop, availLeft,
  // height-availHeight-availTop, width-availWidth-availLeft], 缺了会变成长度 2 的残缺数组
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040,
            availTop: 0, availLeft: 0, colorDepth: 24, pixelDepth: 24 },
  timezoneOffset: -480,
  canvasHash: 'TODO_REAL_CANVAS_DATAURL',
  webglVendor: 'Google Inc. (NVIDIA)',
  webglRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
  audioHash: 'TODO_REAL_AUDIO_FP',
  fonts: ['Arial', 'Calibri', 'Cambria', 'Consolas', 'Segoe UI', 'Times New Roman', 'Verdana'],
  // [名称, 语言, 是否默认] —— 中文 Windows + Chrome 的典型语音包
  voices: [
    ['Microsoft Huihui - Chinese (Simplified, PRC)', 'zh-CN', true],
    ['Microsoft Yaoyao - Chinese (Simplified, PRC)', 'zh-CN'],
    ['Microsoft Kangkang - Chinese (Simplified, PRC)', 'zh-CN'],
    ['Microsoft David - English (United States)', 'en-US'],
    ['Microsoft Zira - English (United States)', 'en-US'],
    ['Microsoft Mark - English (United States)', 'en-US'],
    ['Google 普通话（中国大陆）', 'zh-CN'],
    ['Google US English', 'en-US'],
  ],
  plugins: ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer',
            'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'],
};

module.exports = function createBrowserEnv(opts = {}) {
  const UA = opts.userAgent || DEFAULT_UA;
  const SITE = opts.site || 'https://commerce.adobe.com';
  const PAGE_PATH = opts.pagePath || '/store/checkout';
  const PAGE_TITLE = opts.pageTitle || 'Checkout';
  const PROXY = opts.proxy || '';
  // 相对 URL(如 "/fc/gt2/...")补全用的基址
  const BASE_ORIGIN = opts.baseOrigin || SITE;
  const FINGERPRINT = Object.assign({}, DEFAULT_FINGERPRINT, opts.fingerprint || {});
  // 窗口：没给就按最大化的 Chrome 155（Win11 实测：外框 = 可用区，内高 = 外高 - 121 的标签栏和地址栏）。
  const WIN = (() => {
    const s = FINGERPRINT.screen || {};
    const aw = s.availWidth || 1920, ah = s.availHeight || 1032;
    const w = Object.assign({ dpr: 1, ow: aw, oh: ah, iw: aw, ih: ah - 121, sx: 0, sy: 0 }, FINGERPRINT.win || {});
    FINGERPRINT.win = w;
    return w;
  })();
  // 真 Chrome 录下来的接口应答表（bda_chrome.js BDA_RECORD=1 → meta.rec）。
  // 表里有的问题一律照表答，没有的才走下面的启发式。
  const ANSWERS = Object.assign({ canPlayType: {}, isTypeSupported: {}, matchMedia: {}, gl: {}, gl2: {} }, opts.answers || {});
  const has = (o, k) => !!o && Object.prototype.hasOwnProperty.call(o, k);
  const SCRIPT = Object.assign({ src: SITE + '/main.js', attrs: {} }, opts.script || {});
  const onRequest = opts.onRequest || function () {};
  const onResponse = opts.onResponse || function () {};
  const START = Date.now();
  const requests = [];   // 通用请求记录: {method, url, status, reqBody, resBody}
  const logs = [];       // VM 内 console 输出(裸 vm 上下文没有 console, 不补则脚本调用即 ReferenceError)

  // --------------------------------------------------------------------------
  // 代理: 用 Node 内置 http/tls 手写 CONNECT 隧道, 不引 npm 依赖
  //   (沙箱是被 Python 以子进程方式调用的, 零依赖才好部署)
  //   只支持 http(s):// 代理; socks 需额外实现, 由调用方提前拦下。
  // --------------------------------------------------------------------------
  let proxyAgent = null;
  if (PROXY) {
    const p = new URL(PROXY);
    const auth = p.username
      ? 'Basic ' + Buffer.from(
          decodeURIComponent(p.username) + ':' + decodeURIComponent(p.password || '')
        ).toString('base64')
      : null;
    class ConnectAgent extends https.Agent {
      createConnection(options, cb) {
        const target = `${options.host}:${options.port || 443}`;
        const req = http.request({
          host: p.hostname,
          port: p.port || (p.protocol === 'https:' ? 443 : 80),
          method: 'CONNECT',
          path: target,
          headers: Object.assign({ host: target }, auth ? { 'proxy-authorization': auth } : {}),
        });
        req.once('connect', (res, socket) => {
          if (res.statusCode !== 200) {
            socket.destroy();
            cb(new Error(`代理 CONNECT ${target} 失败: HTTP ${res.statusCode}`));
            return;
          }
          cb(null, tls.connect({ socket, servername: options.host || options.servername }));
        });
        req.once('error', cb);
        req.end();
      }
    }
    proxyAgent = new ConnectAgent({ keepAlive: false });
  }

  // Chromium 的 GREASE 品牌：字符、伪版本号、排列都由主版本号决定（154/155 实测一致）。
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

  function plainHeaders(h) {
    const out = {};
    if (!h) return out;
    if (typeof h.forEach === 'function' && !Array.isArray(h)) h.forEach((v, k) => { out[String(k).toLowerCase()] = String(v); });
    else if (Array.isArray(h)) h.forEach(([k, v]) => { out[String(k).toLowerCase()] = String(v); });
    else Object.keys(h).forEach((k) => { out[k.toLowerCase()] = String(h[k]); });
    return out;
  }

  function realHttps(method, urlStr, headers, body) {
    if (typeof opts.transport === 'function') {
      return opts.transport(method, urlStr, plainHeaders(headers), body);
    }
    return new Promise((resolve, reject) => {
      const u = new URL(urlStr);
      // Origin / Referer 是浏览器自动加的, 抓包里两者都在。这里补上, 否则
      // 服务端看到的是"没有来源的裸请求"。调用方显式给了就不覆盖。
      const o = {
        method,
        hostname: u.hostname,
        path: u.pathname + u.search,
        headers: Object.assign(
          { 'user-agent': UA, origin: SITE, referer: SITE + PAGE_PATH },
          headers || {}
        ),
      };
      if (proxyAgent) o.agent = proxyAgent;
      const req = https.request(o, (res) => {
        // ⚠️ 必须按 Buffer 收: FingerprintJS Pro 的识别接口请求/响应都是【加密二进制】,
        //    用 `data += chunk` 拼成 utf8 字符串会把不可映射字节替换成 U+FFFD, 数据就废了。
        //    这里保留原始 Buffer, 再按需派生出文本。
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({ status: res.statusCode, headers: res.headers, buf, body: buf.toString('utf8') });
        });
      });
      req.on('error', reject);
      if (body !== undefined && body !== null) {
        // body 可能是 ArrayBuffer / TypedArray(加密载荷) 或字符串
        if (typeof body === 'string') req.write(body);
        else if (Buffer.isBuffer(body)) req.write(body);
        else if (ArrayBuffer.isView(body)) req.write(Buffer.from(body.buffer, body.byteOffset, body.byteLength));
        else if (body instanceof ArrayBuffer) req.write(Buffer.from(body));
        else req.write(String(body));
      }
      req.end();
    });
  }

  function absolute(u) {
    return String(u).startsWith('http') ? String(u) : BASE_ORIGIN + u;
  }

  function record(method, url, status, reqBody, resBody) {
    const rec = { method, url, status, reqBody: reqBody || '', resBody: (resBody || '').slice(0, 2000) };
    requests.push(rec);
    return rec;
  }

  // 完整一点的 XHR: FingerprintJS Pro agent 走的是 XHR 而不是 fetch, 并且会用
  // responseType='arraybuffer' 读加密响应、设 timeout/ontimeout、addEventListener('load')。
  // 少任何一样都表现为 "Client timeout"(它自己的超时兜底), 且一个请求都发不出去。
  class FakeXHR {
    constructor() {
      this._headers = {}; this._resHeaders = {}; this._listeners = {};
      this.readyState = 0; this.status = 0; this.statusText = '';
      this.responseText = ''; this.response = null; this.responseType = '';
      this.timeout = 0; this.withCredentials = false;
      this.upload = { addEventListener() {}, removeEventListener() {} };
      this._aborted = false;
    }
    addEventListener(ev, fn) { (this._listeners[ev] = this._listeners[ev] || []).push(fn); }
    removeEventListener(ev, fn) {
      const l = this._listeners[ev]; if (!l) return;
      const i = l.indexOf(fn); if (i >= 0) l.splice(i, 1);
    }
    _fire(ev, arg) {
      const h = this['on' + ev];
      if (typeof h === 'function') { try { h.call(this, arg || { type: ev }); } catch (e) {} }
      (this._listeners[ev] || []).forEach((fn) => { try { fn.call(this, arg || { type: ev }); } catch (e) {} });
    }
    open(method, url) { this._method = method; this._url = url; this.readyState = 1; }
    setRequestHeader(k, v) { this._headers[String(k).toLowerCase()] = v; }
    getResponseHeader(k) { return this._resHeaders[String(k).toLowerCase()] ?? null; }
    getAllResponseHeaders() {
      return Object.entries(this._resHeaders).map(([k, v]) => `${k}: ${v}`).join('\r\n');
    }
    abort() { this._aborted = true; this.readyState = 4; this._fire('abort'); }
    send(body) {
      const full = absolute(this._url);
      try { onRequest(this._method, full, body); } catch (e) {}
      let timer = null;
      if (this.timeout > 0) {
        timer = setTimeout(() => {
          if (this.readyState !== 4) { this.readyState = 4; this._fire('timeout'); }
        }, this.timeout);
      }
      realHttps(this._method, full, this._headers, body)
        .then((r) => {
          if (timer) clearTimeout(timer);
          if (this._aborted) return;
          this.status = r.status;
          this.statusText = String(r.status);
          this._resHeaders = r.headers || {};
          this.responseText = r.body;
          // responseType 决定 .response 的形态 —— 加密响应必须给 ArrayBuffer
          if (this.responseType === 'arraybuffer') {
            this.response = r.buf.buffer.slice(r.buf.byteOffset, r.buf.byteOffset + r.buf.byteLength);
          } else if (this.responseType === 'json') {
            try { this.response = JSON.parse(r.body); } catch (e) { this.response = null; }
          } else {
            this.response = r.body;
          }
          this.readyState = 4;
          record(this._method, full, r.status, body, r.body);
          try { onResponse(full, r.status, r.body); } catch (e) {}
          this._fire('readystatechange');
          this._fire('load');
          this._fire('loadend');
        })
        .catch((e) => {
          if (timer) clearTimeout(timer);
          if (this._aborted) return;
          this.status = 0; this.readyState = 4;
          record(this._method, full, 0, body, 'ERR: ' + e.message);
          this._fire('readystatechange');
          this._fire('error', e);
          this._fire('loadend');
        });
    }
  }

  function fakeFetch(url, o) {
    o = o || {};
    const full = absolute(url);
    const method = o.method || 'GET';
    try { onRequest(method, full, o.body); } catch (e) {}
    return realHttps(method, full, o.headers, o.body).then((r) => {
      record(method, full, r.status, o.body, r.body);
      try { onResponse(full, r.status, r.body); } catch (e) {}
      // arrayBuffer() 不能省: FPJS Pro agent 读的是二进制密文, 只给 text() 它会拿到乱码
      return {
        status: r.status, ok: r.status >= 200 && r.status < 300,
        statusText: '', type: 'basic', url: full, redirected: false,
        text: () => Promise.resolve(r.body),
        json: () => Promise.resolve(JSON.parse(r.body)),
        arrayBuffer: () => Promise.resolve(
          r.buf.buffer.slice(r.buf.byteOffset, r.buf.byteOffset + r.buf.byteLength)
        ),
        bytes: () => Promise.resolve(new Uint8Array(r.buf)),
        clone() { return this; },
        headers: {
          get: (k) => r.headers[String(k).toLowerCase()] ?? null,
          has: (k) => r.headers[String(k).toLowerCase()] !== undefined,
          forEach: (fn) => Object.entries(r.headers).forEach(([k, v]) => fn(v, k)),
        },
      };
    });
  }

  // --------------------------------------------------------------------------
  // 轻量 stub
  // --------------------------------------------------------------------------
  class FakeMessageChannel {
    constructor() {
      this.port1 = { onmessage: null, postMessage: () => {}, close: () => {} };
      this.port2 = {
        onmessage: null,
        postMessage: () => { if (this.port1.onmessage) setTimeout(() => this.port1.onmessage({ data: 0 }), 0); },
        close: () => {},
      };
    }
  }

  // ★ 必须是"能真触发回调"的实现, 不能是空 stub。
  // 这些脚本内置 es6-promise, 其微任务调度器优先选 MutationObserver:
  //     var e=new p(E), n=document.createTextNode("");
  //     e.observe(n,{characterData:true});
  //     return function(){ n.data = ++t%2 }
  // 若 observe() 是空函数, 排水函数 E() 永不被调用 => 整个 polyfill 的 .then
  // 全部静默不执行 => 指纹采集永远 pending 且无任何报错。
  class FakeMutationObserver {
    constructor(cb) { this._cb = cb; }
    observe(node, o) {
      if (!node || !(o && o.characterData)) return;
      const self = this;
      let v = node.data;
      try {
        Object.defineProperty(node, 'data', {
          configurable: true,
          get() { return v; },
          set(nv) {
            v = nv;
            setTimeout(() => self._cb([{ type: 'characterData', target: node }], self), 0);
          },
        });
      } catch (e) { /* 退化: 让 es6-promise 走 setTimeout 分支 */ }
    }
    disconnect() {} takeRecords() { return []; }
  }

  // 音频指纹: 方法链要齐, startRendering 必须立即 resolve(否则指纹采集挂起)
  class FakeAudioContext {
    constructor(channels, length, sampleRate) {
      if (channels && typeof channels === 'object') {
        this.numberOfChannels = channels.numberOfChannels || 1;
        this.length = channels.length || 44100;
        this.sampleRate = channels.sampleRate || 44100;
      } else {
        this.numberOfChannels = channels || 1;
        this.length = length || 44100;
        this.sampleRate = sampleRate || 44100;
      }
      this.state = 'suspended';
      this.currentTime = 0;
      this.oncomplete = null;
      this.destination = { channelCount: this.numberOfChannels, connect() {}, disconnect() {} };
    }
    createOscillator() { return { type: 'triangle', frequency: { value: 10000, setValueAtTime() {} }, connect() {}, start() {}, stop() {}, disconnect() {} }; }
    createAnalyser() { return { connect() {}, disconnect() {}, frequencyBinCount: 1024, getFloatFrequencyData() {} }; }
    createGain() { return { gain: { value: 0, setValueAtTime() {} }, connect() {}, disconnect() {} }; }
    createScriptProcessor() { return { connect() {}, disconnect() {}, onaudioprocess: null }; }
    createDynamicsCompressor() { return { threshold: { value: 0, setValueAtTime() {} }, knee: { value: 0, setValueAtTime() {} }, ratio: { value: 0, setValueAtTime() {} }, attack: { value: 0, setValueAtTime() {} }, release: { value: 0, setValueAtTime() {} }, reduction: 0, connect() {}, disconnect() {} }; }
    createBuffer() { return { getChannelData: () => new Float32Array(44100) }; }
    createBufferSource() { return { buffer: null, connect() {}, start() {}, disconnect() {} }; }
    startRendering() {
      // 4.5.1 等的是 oncomplete，只返回 Promise 时音频指纹会停在 null。
      const v = (FINGERPRINT.audioSeed != null) ? FINGERPRINT.audioSeed : 0.0001;
      const n = this.length || 44100;
      const data = new Float32Array(n);
      const freq = 10000;
      const rate = this.sampleRate || 44100;
      for (let i = 0; i < n; i++) {
        const phase = (i * freq / rate) % 1;
        const tri = phase < 0.5 ? 4 * phase - 1 : 3 - 4 * phase;
        data[i] = Math.tanh(tri * 1.8) * (0.25 + (v % 0.01));
      }
      if (FINGERPRINT.audioValue != null && n >= 5000) fillAudioSum(data, Number(FINGERPRINT.audioValue));
      const buffer = {
        length: n,
        sampleRate: this.sampleRate,
        numberOfChannels: this.numberOfChannels || 1,
        duration: n / (this.sampleRate || 44100),
        getChannelData: () => data,
      };
      this.state = 'closed';
      const event = { renderedBuffer: buffer };
      setTimeout(() => {
        if (typeof this.oncomplete === 'function') {
          try { this.oncomplete(event); } catch (e) {}
        }
      }, 0);
      return Promise.resolve(buffer);
    }
    close() { return Promise.resolve(); }
    resume() { return Promise.resolve(); }
  }

  // api.js 的音频指纹 = 渲染结果第 4500..4999 个 float32 样本绝对值按顺序累加（double）。
  // 把这 500 个样本凑成真 Chrome 的那个和：倒数第二个取余数向下取整的 float32，
  // 最后一个放剩下的零头（不到 24 位有效数字，float32 能精确表示），累加结果逐位相等。
  function fillAudioSum(data, target) {
    const lo = 4500, hi = 5000;
    const base = Math.fround(target / (hi - lo));
    let s = 0;
    for (let i = lo; i < hi - 2; i++) { data[i] = base; s += base; }
    const rest = target - s;
    let v1 = Math.fround(rest);
    if (v1 > rest) v1 = Math.fround(v1 - Math.pow(2, Math.floor(Math.log2(v1)) - 23));
    data[hi - 2] = v1;
    data[hi - 1] = Math.fround(rest - v1);
  }

  // 把 stub 函数伪装成原生函数: 真浏览器里 window.close.toString() 是
  // "function close() { [native code] }"。反自动化探针会 toString() 这些函数,
  // 拿到 "function close(){}" 这种 JS 源码 = 直接自曝。
  function nativeFn(name, impl) {
    const fn = impl || function () {};
    try {
      Object.defineProperty(fn, 'name', { value: name, configurable: true });
      Object.defineProperty(fn, 'toString', {
        value: function toString() { return 'function ' + name + '() { [native code] }'; },
        writable: true, configurable: true,
      });
    } catch (e) {}
    return fn;
  }

  // 桌面 Chrome 对不认识的权限名同步 reject（TypeError），认识的要走一次浏览器进程才回。
  // api.js 按完成先后写进对象再哈希，所以先拒后答的时序也要一样。
  function PermissionStatus() {}
  Object.defineProperty(PermissionStatus.prototype, 'name', { get() { return this._name; }, configurable: true, enumerable: true });
  function permissionQuery(desc) {
    const name = desc && desc.name;
    const table = ANSWERS.perms;
    const st = table ? table[name] : 'prompt';
    if (st === undefined || /^unknown/.test(st)) {
      const kind = st ? st.split(':')[1] : 'TypeError';
      const err = kind === 'TypeError'
        ? new TypeError(`Failed to execute 'query' on 'Permissions': Failed to read the 'name' property from 'PermissionDescriptor': The provided value '${name}' is not a valid enum value of type PermissionName.`)
        : Object.assign(new Error(`Failed to execute 'query' on 'Permissions': ${name} is not supported.`), { name: kind });
      const p = Promise.reject(err);
      p.catch(() => {});
      return p;
    }
    return Promise.resolve(Object.assign(Object.create(PermissionStatus.prototype), { _name: name, state: st, onchange: null }));
  }

  // 真 Chrome 第一次枚举设备要一两百毫秒，api.js 只等 100ms，所以这个字段在真浏览器里是 null。
  let devicesAsked = false;
  function enumerateDevices() {
    const list = (ANSWERS.devices || [
      { kind: 'audioinput', deviceId: '', groupId: '', label: '' },
      { kind: 'videoinput', deviceId: '', groupId: '', label: '' },
      { kind: 'audiooutput', deviceId: '', groupId: '', label: '' },
    ]).map((d) => Object.assign({ toJSON() { return { deviceId: d.deviceId, kind: d.kind, label: d.label, groupId: d.groupId }; } }, d));
    const delay = devicesAsked ? 0 : 300;
    devicesAsked = true;
    return new Promise((resolve) => setTimeout(() => resolve(list), delay));
  }

  const US_LAYOUT = (() => {
    const out = [['Backquote', '`'], ['Backslash', '\\'], ['BracketLeft', '['], ['BracketRight', ']'], ['Comma', ','],
      ['Equal', '='], ['IntlBackslash', '\\'], ['Minus', '-'], ['Period', '.'], ['Quote', "'"], ['Semicolon', ';'], ['Slash', '/']];
    for (let i = 0; i < 10; i++) out.push(['Digit' + i, String(i)]);
    for (let c = 97; c <= 122; c++) out.push(['Key' + String.fromCharCode(c - 32), String.fromCharCode(c)]);
    return out;
  })();

  // 编解码支持表: video.canPlayType() / MediaSource.isTypeSupported() 探 HDR/杜比视界。
  // 返回值要和 matchMedia('(dynamic-range: high)') 自洽 —— 这里统一按"普通 SDR 桌面 Chrome"。
  function codecSupport(type) {
    if (has(ANSWERS.canPlayType, String(type))) return ANSWERS.canPlayType[String(type)];
    const s = String(type || '').toLowerCase();
    if (/hev1|hvc1|dvh1|dvhe|theora|dirac|ac3|ec-3|a52|samr/.test(s)) return '';
    if (/avc1|mp4a|av01|vp8|vp09|vp9|opus|vorbis|flac|mp3|mpeg|wav|webm|ogg|aac/.test(s)) return 'probably';
    if (/video\/mp4|audio\/mp4|video\/webm|audio\/ogg/.test(s)) return 'maybe';
    return '';
  }

  // 字体探测: 脚本造一批 <span>, 分别套 'X',monospace / 'X',sans-serif / 'X',serif,
  // 比对 offsetWidth 与纯 base 字体是否不同来判断字体是否已安装。
  // 若所有宽度恒定 => 一个字体都探不到 => 强机器人特征。这里按 FINGERPRINT.fonts 造差异。
  function fontWidth(spec) {
    const s = String(spec || '');
    const quoted = [];
    const re = /'([^']+)'|"([^"]+)"/g;
    let found;
    while ((found = re.exec(s))) quoted.push(found[1] || found[2]);
    const names = quoted.length ? quoted : s.split(',').map((part) => part.replace(/^\s*\d+px\s*/i, '').trim());
    const generic = { monospace: 1, 'sans-serif': 1, serif: 1, cursive: 1, fantasy: 1, 'system-ui': 1 };
    const base = /monospace/.test(s) ? 100 : /sans-serif/.test(s) ? 104 : /serif/.test(s) ? 108 : 102;
    const fonts = FINGERPRINT.fonts || [];
    for (const name of names) {
      if (!name || generic[name.toLowerCase()] || fonts.indexOf(name) < 0) continue;
      let h = 0;
      for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
      return base + 3 + (h % 17);
    }
    return base;
  }

  const behaviorListeners = {};
  const styleSheets = [];
  let behaviorScheduled = false;
  let behaviorResolve;
  const behaviorDone = new Promise((resolve) => { behaviorResolve = resolve; });
  const rnd = (a, b) => a + Math.random() * (b - a);
  const rint = (a, b) => Math.floor(rnd(a, b + 1));

  // 一个真人在出图页上的操作：点提示词框，打字或粘贴，再把鼠标沿曲线移到生成按钮按下。
  // 返回 [毫秒偏移, 事件类型, 事件] 列表；桌面设备不产生触摸事件。
  function humanPlan(width, height) {
    const plan = [];
    let t = rint(180, 420);
    let pos = [rint(width * 0.1, width * 0.9), rint(height * 0.55, height * 0.95)];
    const mouse = (type, x, y, extra) => plan.push([t, type, Object.assign({
      type, pageX: x, pageY: y, clientX: x, clientY: y, screenX: x, screenY: y, button: 0,
      buttons: type === 'mousedown' ? 1 : 0, pointerType: 'mouse', isTrusted: true,
    }, extra || {})]);
    const moveTo = (tx, ty) => {
      const [sx, sy] = pos;
      const dist = Math.hypot(tx - sx, ty - sy);
      const dur = Math.max(180, Math.min(1100, 120 + dist * rnd(0.9, 1.6)));
      const bend = rnd(-0.25, 0.25) * dist;
      const nx = -(ty - sy) / (dist || 1), ny = (tx - sx) / (dist || 1);
      const c1 = [sx + (tx - sx) * 0.3 + nx * bend, sy + (ty - sy) * 0.3 + ny * bend];
      const c2 = [sx + (tx - sx) * 0.7 + nx * bend * 0.5, sy + (ty - sy) * 0.7 + ny * bend * 0.5];
      const start = t;
      let last = null;
      for (let e = rnd(6, 10); e < dur; e += rnd(6.5, 9.5)) {
        const u = e / dur;
        const s = u * u * u * (10 - 15 * u + 6 * u * u);
        const k = 1 - s;
        const x = Math.round(k * k * k * sx + 3 * k * k * s * c1[0] + 3 * k * s * s * c2[0] + s * s * s * tx + rnd(-0.8, 0.8));
        const y = Math.round(k * k * k * sy + 3 * k * k * s * c1[1] + 3 * k * s * s * c2[1] + s * s * s * ty + rnd(-0.8, 0.8));
        if (last && last[0] === x && last[1] === y) continue;
        t = start + Math.round(e);
        mouse('pointermove', x, y);
        mouse('mousemove', x, y);
        last = [x, y];
      }
      t = start + Math.round(dur);
      mouse('mousemove', tx, ty);
      pos = [tx, ty];
    };
    const click = () => {
      t += rint(90, 320);
      mouse('pointerdown', pos[0], pos[1]);
      mouse('mousedown', pos[0], pos[1]);
      t += rint(60, 140);
      mouse('pointerup', pos[0], pos[1]);
      mouse('mouseup', pos[0], pos[1]);
      mouse('click', pos[0], pos[1]);
    };
    const key = (code, k) => {
      plan.push([t, 'keydown', { type: 'keydown', code, key: k, isTrusted: true }]);
      t += rint(35, 110);
      plan.push([t, 'keyup', { type: 'keyup', code, key: k, isTrusted: true }]);
    };
    moveTo(rint(width * 0.2, width * 0.6), rint(height * 0.25, height * 0.5));
    click();
    t += rint(150, 450);
    if (Math.random() < 0.35) {
      plan.push([t, 'keydown', { type: 'keydown', code: 'ControlLeft', key: 'Control', isTrusted: true }]);
      t += rint(80, 200);
      key('KeyV', 'v');
      t += rint(40, 120);
      plan.push([t, 'keyup', { type: 'keyup', code: 'ControlLeft', key: 'Control', isTrusted: true }]);
    } else {
      const n = rint(5, 14);
      if (Math.random() < 0.4) {
        plan.push([t, 'keydown', { type: 'keydown', code: 'ShiftLeft', key: 'Shift', isTrusted: true }]);
        t += rint(60, 150);
        key('KeyA', 'A');
        t += rint(30, 90);
        plan.push([t, 'keyup', { type: 'keyup', code: 'ShiftLeft', key: 'Shift', isTrusted: true }]);
      }
      for (let i = 0; i < n; i++) {
        t += rint(60, 190);
        if (Math.random() < 0.18) key('Space', ' ');
        else if (Math.random() < 0.05) key('Backspace', 'Backspace');
        else { const c = String.fromCharCode(rint(97, 122)); key('Key' + c.toUpperCase(), c); }
      }
    }
    t += rint(200, 600);
    moveTo(rint(width * 0.55, width * 0.9), rint(height * 0.15, height * 0.5));
    click();
    return plan;
  }

  let behaviorPlan = null;
  let behaviorPlayed = false;
  function behaviorPlanOnce() {
    if (!behaviorPlan) {
      const win = FINGERPRINT.win || {};
      behaviorPlan = humanPlan(win.iw || 1920, win.ih || 940);
    }
    return behaviorPlan;
  }
  function playBehavior(onlyType, onlyFn) {
    if (FINGERPRINT.human === false) return;
    const plan = behaviorPlanOnce();
    const origNow = Date.now;
    const t0 = origNow();
    for (const [t, eventType, ev] of plan) {
      if (onlyType && eventType !== onlyType) continue;
      const cbs = onlyFn ? [onlyFn] : (behaviorListeners[eventType] || []);
      if (!cbs.length) continue;
      Date.now = () => t0 + t;
      ev.timeStamp = t;
      for (const cb of cbs) {
        try { cb(ev); } catch (e) {}
      }
    }
    Date.now = origNow;
  }
  function listenBehavior(type, fn) {
    if (fn && typeof fn !== 'function' && typeof fn.handleEvent === 'function') fn = fn.handleEvent.bind(fn);
    if (typeof fn !== 'function') return;
    (behaviorListeners[type] = behaviorListeners[type] || []).push(fn);
    if (!/mouse|key|pointer|click|touch/.test(String(type))) return;
    if (FINGERPRINT.human === false) { behaviorResolve(); return; }
    if (behaviorPlayed) {
      playBehavior(type, fn);
      return;
    }
    if (behaviorScheduled) return;
    behaviorScheduled = true;
    queueMicrotask(() => {
      behaviorPlayed = true;
      playBehavior(null, null);
      behaviorResolve();
    });
  }

  function ruleFont(node) {
    const classes = String(node.className || '').split(/\s+/).filter(Boolean);
    const css = styleSheets.join('\n');
    for (let i = classes.length - 1; i >= 0; i--) {
      const cls = classes[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const matched = css.match(new RegExp('\\.' + cls + '[^{]*\\{[^}]*font-family\\s*:\\s*([^;}]+)', 'i'));
      if (matched) return matched[1].trim();
    }
    return '';
  }

  function makeElement(tag) {
    // style 不能是裸对象: FingerprintJS 用 style.setProperty() 设字体,
    // 缺了会让 fonts / fontPreferences / mathml / clientRect 四个源一起抛
    // "a.setProperty is not a function"。
    const camel = (k) => String(k).replace(/-(\w)/g, (m, c) => c.toUpperCase());
    const style = {
      setProperty(k, v) { style[camel(k)] = v; },
      getPropertyValue(k) { return style[camel(k)] || ''; },
      removeProperty(k) { const p = camel(k); const old = style[p]; delete style[p]; return old || ''; },
      get cssText() { return ''; },
      set cssText(v) {},
    };
    const measure = () => fontWidth(ruleFont(el) || style.fontFamily || style.font || '');
    const el = {
      tagName: String(tag).toUpperCase(),
      nodeType: 1, style, className: '', id: '',
      innerHTML: '', outerHTML: '', textContent: '', innerText: '',
      children: [], childNodes: [], parentNode: null, firstChild: null,
      classList: {
        add(...names) { el.className = (String(el.className || '') + ' ' + names.join(' ')).trim(); },
        remove() {}, toggle() {}, contains: () => false, length: 0,
      },
      dataset: {},
      // 挂载即触发子节点 onload —— FingerprintJS 的 withIframe() 是
      //   iframe.onload = resolve; document.body.appendChild(iframe)
      // 不触发 onload 就永远 await 下去, 表现为 fonts/clientRect/mathml 全空。
      appendChild(c) {
        el.children.push(c);
        if (c && typeof c === 'object') {
          setTimeout(() => {
            try { if (typeof c.onload === 'function') c.onload({ target: c }); } catch (e) {}
          }, 0);
        }
        return c;
      },
      removeChild(c) { return c; },
      insertBefore(c) { return c; },
      insertAdjacentElement() {}, insertAdjacentHTML() {}, insertAdjacentText() {},
      // append 是 ParentNode 的新 API(可变参、接受字符串), fontPreferences 源在用
      append(...cs) { cs.forEach((c) => el.appendChild(typeof c === 'string' ? { nodeValue: c } : c)); },
      prepend(...cs) { cs.forEach((c) => el.appendChild(typeof c === 'string' ? { nodeValue: c } : c)); },
      replaceChildren() { el.children.length = 0; },
      setAttribute() {}, getAttribute: () => null, hasAttribute: () => false,
      removeAttribute() {}, remove() {}, cloneNode: () => makeElement(tag),
      addEventListener(type, fn) { listenBehavior(type, fn); }, removeEventListener() {}, dispatchEvent: () => true,
      getContext: () => null, focus() {}, blur() {},
      querySelector: () => null, querySelectorAll: () => [],
      getBoundingClientRect: () => ({
        width: measure(), height: 20, top: 0, left: 0,
        right: measure(), bottom: 20, x: 0, y: 0,
      }),
      get offsetWidth() { return measure(); },
      get offsetHeight() { return 20; },
      get clientWidth() { return measure(); },
      get clientHeight() { return 20; },
      scrollWidth: 0, scrollHeight: 0, offsetTop: 0, offsetLeft: 0,
    };
    if (String(tag).toLowerCase() === 'style') {
      let css = '';
      Object.defineProperty(el, 'textContent', {
        configurable: true,
        get() { return css; },
        set(v) { css = String(v == null ? '' : v); styleSheets.push(css); },
      });
    }
    return el;
  }

  function makeMediaElement(tag) {
    return {
      tagName: tag.toUpperCase(),
      style: {}, currentSrc: '', src: '', networkState: 0, readyState: 0,
      videoWidth: 0, videoHeight: 0, duration: NaN, paused: true, volume: 1,
      canPlayType: nativeFn('canPlayType', (t) => codecSupport(t)),
      load: nativeFn('load'), pause: nativeFn('pause'),
      play: nativeFn('play', () => Promise.resolve()),
      getVideoPlaybackQuality: nativeFn('getVideoPlaybackQuality', () => ({
        creationTime: 0, droppedVideoFrames: 0, totalVideoFrames: 0,
      })),
      setAttribute() {}, getAttribute: () => null, appendChild() {},
      remove() {}, addEventListener() {}, removeEventListener() {},
    };
  }

  function WebGLRenderingContext() {}

  // 数值来自 WebGL 1 规范。缺了这些常量时，采集会把 getParameter(undefined) 的结果当字符串，整组变成 null。
  const GL = {
    VENDOR: 7936, RENDERER: 7937, VERSION: 7938, SHADING_LANGUAGE_VERSION: 35724,
    ALIASED_LINE_WIDTH_RANGE: 33902, ALIASED_POINT_SIZE_RANGE: 33901, MAX_VIEWPORT_DIMS: 3386,
    MAX_TEXTURE_SIZE: 3379, MAX_RENDERBUFFER_SIZE: 34024, MAX_VERTEX_ATTRIBS: 34921,
    MAX_VERTEX_UNIFORM_VECTORS: 36347, MAX_TEXTURE_IMAGE_UNITS: 34930,
    MAX_VERTEX_TEXTURE_IMAGE_UNITS: 35660, MAX_COMBINED_TEXTURE_IMAGE_UNITS: 35661,
    MAX_FRAGMENT_UNIFORM_VECTORS: 36349, MAX_VARYING_VECTORS: 36348, MAX_CUBE_MAP_TEXTURE_SIZE: 34076,
    RED_BITS: 3410, GREEN_BITS: 3411, BLUE_BITS: 3412, ALPHA_BITS: 3413, DEPTH_BITS: 3414, STENCIL_BITS: 3415,
    VERTEX_SHADER: 35633, FRAGMENT_SHADER: 35632,
    HIGH_FLOAT: 36338, MEDIUM_FLOAT: 36337, LOW_FLOAT: 36336,
    HIGH_INT: 36341, MEDIUM_INT: 36340, LOW_INT: 36339,
    UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446,
  };

  function glPair(v, fallback) {
    if (v && typeof v === 'object') return [Number(v[0]), Number(v[1])];
    return fallback;
  }

  const GL_FLOAT_PAIRS = { 33901: 1, 33902: 1 };
  const GL_INT_PAIRS = { 3386: 1 };

  function makeGLContext(el, profile, answers) {
    const rec = answers || {};
    const params = profile.maxParams || {};
    const strings = {
      7936: profile.vendor || 'WebKit',
      7937: profile.renderer || 'WebKit WebGL',
      7938: profile.version || 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
      35724: profile.slv || 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)',
      37445: profile.unmaskedVendor || FINGERPRINT.webglVendor,
      37446: profile.unmaskedRenderer || FINGERPRINT.webglRenderer,
    };
    const arrays = {
      33902: glPair(params.ALIASED_LINE_WIDTH_RANGE, [1, 1]),
      33901: glPair(params.ALIASED_POINT_SIZE_RANGE, [1, 1024]),
      3386: glPair(params.MAX_VIEWPORT_DIMS, [32767, 32767]),
    };
    const nums = {
      3379: params.MAX_TEXTURE_SIZE || 16384,
      34024: params.MAX_RENDERBUFFER_SIZE || 16384,
      34921: params.MAX_VERTEX_ATTRIBS || 16,
      36347: params.MAX_VERTEX_UNIFORM_VECTORS || 4095,
      34930: params.MAX_TEXTURE_IMAGE_UNITS || 16,
      35660: params.MAX_VERTEX_TEXTURE_IMAGE_UNITS || 16,
      35661: params.MAX_COMBINED_TEXTURE_IMAGE_UNITS || 32,
      36349: params.MAX_FRAGMENT_UNIFORM_VECTORS || 1024,
      36348: params.MAX_VARYING_VECTORS || 30,
      34076: params.MAX_CUBE_MAP_TEXTURE_SIZE || 16384,
      3410: 8, 3411: 8, 3412: 8, 3413: 8, 3414: 24, 3415: 0,
    };
    const gl = Object.assign(Object.create(WebGLRenderingContext.prototype), {
      canvas: el,
      drawingBufferWidth: el.width || 300,
      drawingBufferHeight: el.height || 150,
      getParameter(p) {
        if (p !== 37445 && p !== 37446 && has(rec, 'p' + p)) {
          const v = rec['p' + p];
          if (Array.isArray(v)) return GL_INT_PAIRS[p] ? new Int32Array(v) : GL_FLOAT_PAIRS[p] ? new Float32Array(v) : v.slice();
          return v;
        }
        if (Object.prototype.hasOwnProperty.call(strings, p)) return strings[p];
        if (Object.prototype.hasOwnProperty.call(arrays, p)) return arrays[p];
        if (Object.prototype.hasOwnProperty.call(nums, p)) return nums[p];
        return 0;
      },
      getExtension(name) {
        if (name === 'WEBGL_debug_renderer_info') {
          return { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
        }
        if (name === 'EXT_texture_filter_anisotropic') return { MAX_TEXTURE_MAX_ANISOTROPY_EXT: 34047 };
        if (has(rec, 'e' + name) && !rec['e' + name]) return null;
        return {};
      },
      getSupportedExtensions() { return (rec.extensions || profile.extensions || ['WEBGL_debug_renderer_info']).slice(); },
      getContextAttributes() {
        if (rec.attrs) return Object.assign({}, rec.attrs);
        return {
          alpha: true, antialias: true, depth: true, stencil: false,
          premultipliedAlpha: true, preserveDrawingBuffer: false, failIfMajorPerformanceCaveat: false,
        };
      },
      getShaderPrecisionFormat(shader, precision) {
        const r = rec['s' + shader + '_' + precision];
        if (Array.isArray(r)) return { rangeMin: r[0], rangeMax: r[1], precision: r[2] };
        // 桌面 Chrome（ANGLE）高中低精度都一样
        if (precision >= 36339) return { rangeMin: 31, rangeMax: 30, precision: 0 };
        return { rangeMin: 127, rangeMax: 127, precision: 23 };
      },
      createShader() { return {}; }, createProgram() { return {}; }, createBuffer() { return {}; },
      getShaderParameter() { return true; }, getProgramParameter() { return true; },
      isContextLost() { return false; },
    }, GL);
    return new Proxy(gl, {
      get(target, key) {
        if (key in target) return target[key];
        if (typeof key !== 'string' || key[0] !== key[0].toLowerCase()) return 0;
        return function () { return null; };
      },
    });
  }

  function makeCanvas() {
    // 基于 makeElement: 否则缺 addEventListener/style, webGlBasics 与
    // webGlExtensions 两个源会抛 "e.addEventListener is not a function"。
    const el = makeElement('canvas');
    const webgl1 = FINGERPRINT.webgl || {};
    const webgl2 = FINGERPRINT.webgl2 || webgl1;
    return Object.assign(el, {
      width: 300, height: 150,
      getContext: (type) => {
        if (type === '2d') return {
          canvas: el,
          fillRect() {}, clearRect() {}, strokeRect() {},
          fillText() {}, strokeText() {},
          getImageData: () => ({ data: new Uint8Array(4), width: 1, height: 1 }),
          putImageData() {}, createImageData: () => ({ data: new Uint8Array(4) }),
          drawImage() {},
          measureText(t) { return { width: fontWidth(String(this.font || '')) + String(t || '').length }; },
          fill() {}, stroke() {}, clip() {},
          arc() {}, arcTo() {}, ellipse() {}, rect() {}, roundRect() {},
          beginPath() {}, closePath() {}, moveTo() {}, lineTo() {},
          bezierCurveTo() {}, quadraticCurveTo() {},
          save() {}, restore() {}, translate() {}, rotate() {}, scale() {},
          transform() {}, setTransform() {}, resetTransform() {},
          createLinearGradient: () => ({ addColorStop() {} }),
          createRadialGradient: () => ({ addColorStop() {} }),
          createPattern: () => null,
          // ★ canvas 指纹源直接调它, 缺了整个 canvas 组件抛错
          isPointInPath: () => true,
          isPointInStroke: () => false,
          font: '', fillStyle: '', strokeStyle: '', textBaseline: '', textAlign: '',
          globalCompositeOperation: 'source-over', globalAlpha: 1,
          lineWidth: 1, shadowBlur: 0, shadowColor: '',
        };
        const isGL2 = String(type).indexOf('webgl2') >= 0;
        return makeGLContext(el, isGL2 ? webgl2 : webgl1, isGL2 ? ANSWERS.gl2 : ANSWERS.gl);
      },
      toDataURL: () => 'data:image/png;base64,' + FINGERPRINT.canvasHash,
    });
  }

  // window 的原型链：Window.prototype → WindowProperties → EventTarget.prototype → Object.prototype，
  // 每层自有属性名和顺序都按真 Chrome（api.js 的 wh 后半段就是对它们取哈希）。
  let windowChain = null;
  function shapeWindowChain(win) {
    const levels = ANSWERS.winProto || [
      ['TEMPORARY', 'PERSISTENT', 'constructor'], [],
      ['addEventListener', 'dispatchEvent', 'removeEventListener', 'when', 'constructor'],
    ];
    const ctor = (name) => nativeFn(name, function () { throw new TypeError('Illegal constructor'); });
    const EventTarget = nativeFn('EventTarget', function EventTarget() {
      const map = {};
      Object.defineProperty(this, '__listeners', { value: map, enumerable: false });
    });
    const Window = ctor('Window');
    const etValues = {
      addEventListener: nativeFn('addEventListener', function (type, fn) {
        if (this && this.__listeners) (this.__listeners[type] = this.__listeners[type] || []).push(fn);
        else listenBehavior(type, fn);
      }),
      removeEventListener: nativeFn('removeEventListener', function (type, fn) {
        const l = this && this.__listeners && this.__listeners[type];
        if (l && l.indexOf(fn) >= 0) l.splice(l.indexOf(fn), 1);
      }),
      dispatchEvent: nativeFn('dispatchEvent', function (ev) {
        const l = this && this.__listeners && ev && this.__listeners[ev.type];
        if (l) for (const fn of l.slice()) { try { typeof fn === 'function' ? fn.call(this, ev) : fn.handleEvent(ev); } catch (e) {} }
        return true;
      }),
      when: nativeFn('when', () => ({ subscribe() {}, takeUntil() { return this; } })),
      constructor: EventTarget,
    };
    const winValues = { TEMPORARY: 0, PERSISTENT: 1, constructor: Window };
    const build = (names, values, proto) => {
      const o = Object.create(proto);
      for (const n of names) {
        const v = Object.prototype.hasOwnProperty.call(values, n) ? values[n] : nativeFn(n);
        Object.defineProperty(o, n, { value: v, writable: typeof v === 'function', enumerable: n !== 'constructor' && typeof v !== 'number', configurable: typeof v === 'function' });
      }
      return o;
    };
    const etProto = build(levels[2] || [], etValues, Object.prototype);
    const wpProto = build(levels[1] || [], {}, etProto);
    const winProto = build(levels[0] || [], winValues, wpProto);
    EventTarget.prototype = etProto;
    Window.prototype = winProto;
    delete win.addEventListener;
    delete win.removeEventListener;
    delete win.dispatchEvent;
    Object.setPrototypeOf(win, winProto);
    // vm 全局自己的那条链另起一份：WindowProperties 是"按 id 取元素"那一层，window.ark 能取到
    // <div id="ark">，但 getOwnPropertyNames 列不出来（api.js 看 window.ark 在不在，决定要不要自己挂全局）。
    // 这层用 Proxy 做；不能放进 env.win 的链里，vm 解析全局名时会走 env.win 的链，碰到 Proxy 就坏。
    const named = {};
    for (const id of opts.elementIds || []) {
      const el = makeElement('div');
      el.id = id;
      named[id] = el;
    }
    const hasNamed = (k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(named, k);
    const wpGlobal = new Proxy(build(levels[1] || [], {}, etProto), {
      get: (t, k, r) => (hasNamed(k) ? named[k] : Reflect.get(t, k, r)),
      has: (t, k) => hasNamed(k) || Reflect.has(t, k),
    });
    windowChain = { etProto, globalProto: build(levels[0] || [], winValues, wpGlobal) };
    win.EventTarget = EventTarget;
    win.Window = Window;
  }

  // vm.createContext(env.win) 之后调用：
  //   · 把真 Chrome 有、沙箱没有的全局名补上（JS 内置取上下文自己 realm 的值，其余按 Chrome 的类型造桩）；
  //   · 删掉 Chrome 没有的全局名；
  //   · 按 Chrome 的属性顺序和计算结果重建 Math。
  const stubCalls = [];
  function finishContext(context) {
    const vm = require('vm');
    const types = ANSWERS.winTypes;
    if (!types) return;
    const win = context;
    const builtins = new Set(vm.runInNewContext('Object.getOwnPropertyNames(this)'));
    const removed = [];
    for (const k of Object.getOwnPropertyNames(win)) {
      if (!Object.prototype.hasOwnProperty.call(types, k)) { delete win[k]; removed.push(k); }
    }
    // 上下文自带、但 Chrome 页面上没有的内置（如未跨源隔离时的 SharedArrayBuffer）
    const extraBuiltins = [...builtins].filter((k) => !Object.prototype.hasOwnProperty.call(types, k));
    vm.runInContext('(function (names) { for (const n of names) delete this[n]; }).call(this, ' + JSON.stringify(extraBuiltins) + ')', context);
    removed.push(...extraBuiltins);
    // 在 vm 里 window 就是上下文的全局代理，原型链要挂在它身上，末端接上下文自己的 Object.prototype
    if (windowChain) {
      Object.setPrototypeOf(windowChain.etProto, vm.runInContext('Object.prototype', context));
      vm.runInContext('(function (p) { Object.setPrototypeOf(this, p); })', context).call(undefined, windowChain.globalProto);
    }
    const special = { isSecureContext: true, origin: SITE, frames: win, length: 0, name: '', status: '', closed: false, crossOriginIsolated: false };
    const added = [];
    for (const k of Object.keys(types)) {
      if (Object.prototype.hasOwnProperty.call(win, k)) continue;
      let v;
      let enumerable = true;
      if (k === 'Math') continue;
      if (builtins.has(k)) {
        v = vm.runInContext(k, context);
        enumerable = false;
      } else if (Object.prototype.hasOwnProperty.call(special, k)) {
        v = special[k];
      } else {
        switch (types[k]) {
          case 'function':
            if (k === 'PermissionStatus') v = PermissionStatus;
            else if (typeof globalThis[k] === 'function') v = globalThis[k];  // Node 自带的同名 Web API（AbortController/DOMException/Headers/流…）
            else if (/^[A-Z]/.test(k)) v = nativeFn(k, function () { stubCalls.push(k); throw new TypeError('Illegal constructor'); });
            else v = nativeFn(k);
            enumerable = !/^[A-Z]/.test(k);
            break;
          case 'object': v = {}; break;
          case 'null': v = null; break;
          case 'number': v = 0; break;
          case 'string': v = ''; break;
          case 'boolean': v = false; break;
          default: v = undefined;
        }
      }
      Object.defineProperty(win, k, { value: v, writable: true, enumerable, configurable: true });
      added.push(k);
    }
    const names = ANSWERS.mathNames;
    if (names) {
      const build = vm.runInContext(`(function (names, overrides) {
        const base = Math;
        const own = Object.prototype.hasOwnProperty;
        const extra = {
          sumPrecise(items) { let s = 0; for (const x of items) s += Number(x); return s; },
        };
        const M = {};
        for (const n of names) {
          let v = own.call(base, n) ? base[n] : extra[n];
          const keys = Object.keys(overrides).filter((k) => k.slice(0, k.indexOf(':')) === n);
          if (keys.length && typeof v === 'function') {
            const orig = v;
            v = new Proxy(orig, { apply(t, self, args) {
              const key = n + ':' + Array.prototype.join.call(args, ',');
              return own.call(overrides, key) ? overrides[key] : Reflect.apply(t, self, args);
            } });
          }
          const num = typeof v === 'number';
          Object.defineProperty(M, n, { value: v, writable: !num, enumerable: false, configurable: !num });
        }
        Object.defineProperty(M, Symbol.toStringTag, { value: 'Math', configurable: true });
        return M;
      })`, context);
      Object.defineProperty(win, 'Math', { value: build(names, ANSWERS.math || {}), writable: true, enumerable: false, configurable: true });
    }
    return { removed, added: added.length };
  }

  function buildWindow() {
    const idbDatabases = new Map();
    const storage = (() => {
      const m = {};
      if (opts.aridToken) m['x-ark-arid'] = opts.aridToken;
      return {
        getItem: (k) => {
          if (k in m) return m[k];
          if (opts.aridToken && String(k).indexOf('x-ark-arid') === 0) return opts.aridToken;
          return null;
        },
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
        clear: () => { for (const k in m) delete m[k]; },
        key: (i) => Object.keys(m)[i] || null,
        get length() { return Object.keys(m).length; },
      };
    })();

    const pageHost = new URL(SITE).host;

    const navigatorProto = {};
    Object.defineProperty(navigatorProto, 'webdriver', {
      configurable: true, enumerable: true, get() { return false; },
    });
    const navigator = Object.assign(Object.create(navigatorProto), {
      userAgent: UA,
      appName: 'Netscape',
      appVersion: UA.replace('Mozilla/', ''),
      platform: FINGERPRINT.platform,
      language: FINGERPRINT.language,
      languages: FINGERPRINT.languages,
      hardwareConcurrency: FINGERPRINT.hardwareConcurrency,
      deviceMemory: FINGERPRINT.deviceMemory,
      vendor: 'Google Inc.',
      product: 'Gecko',
      productSub: '20030107',
      cookieEnabled: true,
      onLine: true,
      doNotTrack: null,
      maxTouchPoints: 0,
      // 真 Chrome 的 plugin 条目带 description 和 mimeTypes, 只有 name 会被看出来
      plugins: Object.assign(
        FINGERPRINT.plugins.map((n) => ({
          name: n,
          description: n.includes('PDF') ? 'Portable Document Format' : '',
          filename: n.includes('PDF') ? 'internal-pdf-viewer' : '',
          length: 2,
          0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
          1: { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
          item(i) { return this[i] || null; },
          namedItem(t) { return this[0].type === t ? this[0] : (this[1].type === t ? this[1] : null); },
        })),
        { item(i) { return this[i] || null; }, namedItem(n) { return this.find((p) => p.name === n) || null; } }
      ),
      mimeTypes: Object.assign(
        [{ type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
         { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format' }],
        { item(i) { return this[i] || null; }, namedItem(t) { return this.find((m) => m.type === t) || null; } }
      ),
      pdfViewerEnabled: true,
      // navigator.userAgentData: 必须和 UA / platform 自洽 —— 主版本从 UA 里抠,
      // 平台用 FINGERPRINT.uaPlatform(Windows/macOS)。写死会和随机 UA 打架。
      userAgentData: (() => {
        const maj = FINGERPRINT.uaMajor || (String(UA).match(/Chrome\/(\d+)/) || [])[1] || '150';
        const plat = FINGERPRINT.uaPlatform || (/Macintosh/.test(UA) ? 'macOS' : 'Windows');
        const full = FINGERPRINT.uaFullVersion || (String(maj) === '155' ? '155.0.8059.40' : `${maj}.0.0.0`);
        return {
          brands: chromeBrands(maj),
          mobile: false,
          platform: plat,
          getHighEntropyValues: () => Promise.resolve({
            architecture: 'x86', bitness: '64', model: '', wow64: false, formFactors: ['Desktop'],
            platform: plat, platformVersion: FINGERPRINT.platformVersion || (plat === 'macOS' ? '14.0.0' : '19.0.0'),
            uaFullVersion: full,
            fullVersionList: chromeBrands(maj).map((b) => ({ brand: b.brand, version: b.brand.startsWith('Not') ? `${b.version}.0.0.0` : full })),
          }),
          toJSON() { return { brands: this.brands, mobile: this.mobile, platform: this.platform }; },
        };
      })(),
      // 桌面 Chrome 没有 downlinkMax / type
      connection: { effectiveType: '4g', rtt: 100, downlink: 10, saveData: false },
      permissions: { query: nativeFn('query', permissionQuery) },
      getBattery: () => Promise.resolve({ charging: true, level: 1, addEventListener() {} }),
      mediaDevices: { enumerateDevices: nativeFn('enumerateDevices', enumerateDevices), getUserMedia: () => Promise.reject(new Error('denied')) },
      keyboard: {
        getLayoutMap: nativeFn('getLayoutMap', () => Promise.resolve(new Map(ANSWERS.keyboard || US_LAYOUT))),
        lock: () => Promise.resolve(), unlock() {},
      },
      usb: { getDevices: () => Promise.resolve([]), requestDevice: () => Promise.reject(new Error('NotFoundError')) },
      bluetooth: { getAvailability: nativeFn('getAvailability', () => Promise.resolve(true)) },
      storage: { estimate: () => Promise.resolve({ quota: 1e11, usage: 1e6 }) },
      // 隐私模式探测走这个老 API; 缺了 browserDetails 与 speech 两个源会抛
      // "Cannot read properties of undefined (reading 'queryUsageAndQuota')"
      webkitTemporaryStorage: {
        queryUsageAndQuota: (cb) => { if (typeof cb === 'function') setTimeout(() => cb(0, 1e11), 0); },
        requestQuota: (n, cb) => { if (typeof cb === 'function') setTimeout(() => cb(n), 0); },
      },
      webkitPersistentStorage: {
        queryUsageAndQuota: (cb) => { if (typeof cb === 'function') setTimeout(() => cb(0, 1e11), 0); },
      },
      getGamepads: () => [],
      javaEnabled: () => false,
      // 以下几个 Pro 版采集会碰, 缺了容易变成"永远 pending"
      locks: {
        request: (name, opts, cb) => {
          const fn = typeof opts === 'function' ? opts : cb;
          return Promise.resolve(fn ? fn({ name, mode: 'exclusive' }) : undefined);
        },
        query: () => Promise.resolve({ held: [], pending: [] }),
      },
      serviceWorker: {
        ready: Promise.resolve({ active: null, scope: SITE + '/' }),
        getRegistrations: () => Promise.resolve([]),
        register: () => Promise.resolve({}),
        addEventListener() {}, controller: null,
      },
      clipboard: { readText: () => Promise.reject(new Error('denied')) },
      credentials: { get: () => Promise.resolve(null) },
    });

    const win = {
      navigator,
      screen: Object.assign({}, FINGERPRINT.screen, {
        colorDepth: 24,
        pixelDepth: 24,
        orientation: (FINGERPRINT.screen && FINGERPRINT.screen.orientation) || { type: 'landscape-primary', angle: 0 },
      }),
      location: { href: SITE + PAGE_PATH, origin: SITE, protocol: 'https:',
                  host: pageHost, hostname: pageHost, pathname: PAGE_PATH,
                  search: '', hash: '', ancestorOrigins: [] },
      document: null,   // 下面补
      localStorage: storage,
      sessionStorage: storage,
      crypto: require('crypto').webcrypto,
      performance: {
        now: () => Date.now() - START,
        timing: {},
        getEntriesByType: () => [],
        memory: { jsHeapSizeLimit: 4294705152, totalJSHeapSize: 52000000, usedJSHeapSize: 38000000 },
      },
      navigation: { currentEntry: { index: 1 }, entries: () => [{}, {}] },
      orientation: { angle: 0, type: 'landscape-primary' },
      devicePixelRatio: WIN.dpr,
      innerWidth: WIN.iw,
      innerHeight: WIN.ih,
      outerWidth: WIN.ow,
      outerHeight: WIN.oh,
      screenX: WIN.sx, screenY: WIN.sy, scrollX: 0, scrollY: 0,
      XMLHttpRequest: FakeXHR,
      fetch: fakeFetch,
      setTimeout: (fn, t) => setTimeout(fn, Math.min(t || 0, 50)),  // 加速: 压缩延时
      clearTimeout, setInterval: () => 0, clearInterval: () => {},
      queueMicrotask: (fn) => setTimeout(fn, 0),
      requestAnimationFrame: (fn) => setTimeout(() => fn(Date.now()), 16),
      cancelAnimationFrame: () => {},
      requestIdleCallback: (fn) => setTimeout(() => fn({ timeRemaining: () => 5, didTimeout: false }), 0),
      cancelIdleCallback: () => {},
      addEventListener(type, fn) { listenBehavior(type, fn); }, removeEventListener() {}, postMessage: () => {},
      dispatchEvent: () => true,
      btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
      atob: (s) => Buffer.from(s, 'base64').toString('binary'),
      // 裸 vm 上下文没有 console。指纹脚本在 debug 模式会往 console 打关键诊断
      // (FingerprintJS 的 debug 输出里含每个 source 的报错), 所以这里捕获下来。
      console: (() => {
        const mk = (lvl) => (...a) => {
          logs.push(lvl + ': ' + a.map((x) => {
            try { return typeof x === 'string' ? x : JSON.stringify(x); } catch (e) { return String(x); }
          }).join(' '));
        };
        return { log: mk('log'), warn: mk('warn'), error: mk('error'),
                 info: mk('info'), debug: mk('debug'), trace: mk('trace') };
      })(),

      // ⚠️ 不要在这里注入 Object/Array/Promise/Uint8Array 等【标准内置对象】。
      //    vm.createContext() 已经给上下文配了它自己 realm 的全套内置对象; 再塞一份
      //    外层 realm 的进来会造成 realm 错配, 后果非常隐蔽:
      //      JSVMP 的 async-call 操作码判断 `o instanceof Object && !(o instanceof Function)`
      //      → Object 是外层的(命中), Function 是内层的(不命中) → 把函数误判成对象
      //      → on = o.start = undefined → on++ = NaN → 取指循环静默退出。
      //    我们的 stub 函数本身就来自外层 realm, 但那没问题: 走的是 typeof o === "function"
      //    分支, typeof 跨 realm 正常。
      //    TextEncoder/TextDecoder 是 Web API 不是 JS 内置, 裸 vm 上下文没有, 必须补。
      TextEncoder, TextDecoder,

      // DOM 构造器 stub(指纹脚本会 typeof/instanceof 探测这些, 缺则 ReferenceError)
      Element: function Element() {}, HTMLElement: function HTMLElement() {},
      HTMLCanvasElement: function HTMLCanvasElement() {}, Node: function Node() {},
      Event: function Event() {}, MouseEvent: function MouseEvent() {},
      KeyboardEvent: function KeyboardEvent() {}, TouchEvent: function TouchEvent() {},
      CustomEvent: function CustomEvent() {}, MessageChannel: FakeMessageChannel,
      MutationObserver: FakeMutationObserver, WebGLRenderingContext,
      CanvasRenderingContext2D: function () {}, XMLHttpRequestEventTarget: function () {},
      Worker: function () {}, SharedWorker: function () {},
      Blob: function () {}, FileReader: function () {},
      Image: function () {
        const img = { addEventListener(ev, fn) { if (ev === 'load') this.onload = fn; },
                      width: 1, height: 1, complete: true };
        Object.defineProperty(img, 'src', { set() { setTimeout(() => { img.complete = true; if (img.onload) img.onload(); }, 0); }, get() { return ''; } });
        return img;
      },
      Audio: function () { return makeMediaElement('audio'); },
      AudioContext: FakeAudioContext, webkitAudioContext: FakeAudioContext,
      OfflineAudioContext: FakeAudioContext,
      // WebRTC(常见挂起源): 立即回 null candidate 结束 ICE, 否则指纹采集永久等待
      RTCPeerConnection: function () {
        return {
          createDataChannel() {}, createOffer() { return Promise.resolve({ sdp: '', type: 'offer' }); },
          setLocalDescription() { return Promise.resolve(); },
          onicecandidate: null, close() {},
          addEventListener(ev, fn) { if (ev === 'icecandidate') setTimeout(() => fn({ candidate: null }), 0); },
        };
      },
      URL, URLSearchParams, WebSocket: function () {},

      // ---- 指纹采集实际会读的面(缺则采集函数直接抛错) --------------------------
      history: { length: 3, state: null, scrollRestoration: 'auto',
                 pushState() {}, replaceState() {}, back() {}, forward() {}, go() {} },
      // ⚠️ open() 必须【真的把 onsuccess 触发出去】。原来只返回一个空 request 对象,
      //    调用方 `await new Promise(r => req.onsuccess = r)` 就永远挂着 ——
      //    FingerprintJS Pro 的采集里有这么一步, 表现为 get() 恒定 Client timeout
      //    (60s 也不出), 而且一个网络请求都发不出去。
      indexedDB: {
        open(name, version) {
          const req = { onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
                        readyState: 'pending', result: null, error: null };
          // Arkose 读 request.result，并且 put 之后的 get 必须还能读到。
          // 每次 new 一个空仓库会让 x-ark-arid 永远是 null，gt2 就不带头。
          function idbReq(result) {
            const r = { onsuccess: null, onerror: null, readyState: 'pending', result, error: null };
            setTimeout(() => {
              r.readyState = 'done';
              if (typeof r.onsuccess === 'function') { try { r.onsuccess({ target: r }); } catch (e) {} }
            }, 0);
            return r;
          }
          setTimeout(() => {
            let rec = idbDatabases.get(name);
            const oldVersion = rec ? rec.version : 0;
            if (!rec) {
              rec = { version: 0, stores: new Map() };
              idbDatabases.set(name, rec);
            }
            const db = {
              name, version: version || 1,
              objectStoreNames: {
                contains: (store) => rec.stores.has(store),
                get length() { return rec.stores.size; },
              },
              close() {},
              deleteObjectStore(store) { rec.stores.delete(store); },
              createObjectStore(store) {
                if (!rec.stores.has(store)) rec.stores.set(store, new Map());
                return idbStore(rec.stores.get(store));
              },
              transaction(store) {
                if (!rec.stores.has(store)) rec.stores.set(store, new Map());
                return {
                  objectStore: () => idbStore(rec.stores.get(store)),
                  oncomplete: null, onerror: null, abort() {},
                };
              },
            };
            function idbStore(map) {
              return {
                add: (value, key) => { map.set(key, value); return idbReq(undefined); },
                put: (value, key) => { map.set(key, value); return idbReq(undefined); },
                get: (key) => {
                  if (map.has(key)) return idbReq(map.get(key));
                  if (opts.aridToken && String(key).indexOf('x-ark-arid') === 0) return idbReq(opts.aridToken);
                  return idbReq(undefined);
                },
                getAll: () => idbReq([...map.values()]),
                createIndex() { return {}; },
              };
            }
            req.result = db;
            if ((version || 1) > oldVersion) {
              if (typeof req.onupgradeneeded === 'function') {
                try { req.onupgradeneeded({ target: req, oldVersion, newVersion: version || 1 }); } catch (e) {}
              }
              rec.version = version || 1;
            }
            req.readyState = 'done';
            if (typeof req.onsuccess === 'function') { try { req.onsuccess({ target: req }); } catch (e) {} }
          }, 0);
          return req;
        },
        deleteDatabase() {
          const req = { onsuccess: null, onerror: null, onblocked: null };
          setTimeout(() => { if (typeof req.onsuccess === 'function') { try { req.onsuccess({ target: req }); } catch (e) {} } }, 0);
          return req;
        },
        databases: () => Promise.resolve([]),
        cmp: () => 0,
      },
      // matchMedia 必须"会答题": FingerprintJS 的 colorGamut / contrast / hdr /
      // monochrome / forcedColors / invertedColors / reducedMotion /
      // reducedTransparency 全部靠它逐个试探, 恒返回 false = 一个都探不到 =>
      // 这些字段在 payload 里直接消失(实测缺 8 个字段)。这里按"普通 SDR 桌面
      // Chrome + 无辅助功能"作答, 并与 codecSupport() 的 HDR 结论保持一致。
      matchMedia: (q) => {
        const s = String(q);
        let matches = false;
        if (has(ANSWERS.matchMedia, s)) matches = ANSWERS.matchMedia[s];
        else if (/video-color-gamut:/.test(s)) matches = false;
        else if (/color-gamut:\s*srgb/.test(s)) matches = true;                    // srgb 支持
        else if (/color-gamut:/.test(s)) matches = false;                     // p3 / rec2020 不支持
        else if (/dynamic-range:\s*high|video-dynamic-range:\s*high/.test(s)) matches = false;
        else if (/inverted-colors:/.test(s)) matches = false;                 // Chrome 不认这个特性
        else if (/forced-colors:\s*none/.test(s)) matches = true;
        else if (/prefers-contrast:\s*no-preference/.test(s)) matches = true;
        else if (/prefers-reduced-motion:\s*no-preference/.test(s)) matches = true;
        else if (/prefers-reduced-transparency:\s*no-preference/.test(s)) matches = true;
        else if (/monochrome:\s*0/.test(s)) matches = true;                    // 彩色屏
        else if (/prefers-color-scheme:\s*light/.test(s)) matches = true;
        else if (/pointer:\s*fine/.test(s) || /any-pointer:\s*fine/.test(s)) matches = true;
        else if (/hover:\s*hover/.test(s) || /any-hover:\s*hover/.test(s)) matches = true;
        return { matches, media: s, onchange: null,
                 addListener() {}, removeListener() {},
                 addEventListener() {}, removeEventListener() {} };
      },
      getComputedStyle: () => ({ getPropertyValue: () => '', fontFamily: '', length: 0 }),
      // CSS.supports: FingerprintJS 在模块顶层就调, 缺了整个脚本加载即崩
      CSS: { supports: () => false, escape: (s) => String(s) },
      // 真 Chrome 必有 window.chrome, 缺失是强机器人信号
      chrome: { runtime: {}, app: { isInstalled: false }, loadTimes() {}, csi() {} },
      external: { AddSearchProvider() {}, IsSearchProviderInstalled() {} },
      // speech 指纹取 {numVoices, voices[]}; 空列表会让该字段变成 {}
      speechSynthesis: (() => {
        const listeners = [];
        const voices = () => (FINGERPRINT.voices || []).map((v) => ({
          name: v[0], lang: v[1], voiceURI: v[0], localService: v[3] !== false, default: v[2] === true,
        }));
        const api = {
          speaking: false, pending: false, paused: false,
          onvoiceschanged: null,
          addEventListener(type, fn) {
            if (type === 'voiceschanged' && typeof fn === 'function') {
              listeners.push(fn);
              queueMicrotask(() => { try { fn(); } catch (e) {} });
            }
          },
          removeEventListener() {},
          getVoices: voices,
        };
        queueMicrotask(() => {
          if (typeof api.onvoiceschanged === 'function') {
            try { api.onvoiceschanged(); } catch (e) {}
          }
        });
        return api;
      })(),
      caches: { open: () => Promise.resolve({}), keys: () => Promise.resolve([]) },
      PerformanceObserver: function () { return { observe() {}, disconnect() {} }; },
      ResizeObserver: function () { return { observe() {}, disconnect() {} }; },
      IntersectionObserver: function () { return { observe() {}, disconnect() {} }; },
      visualViewport: { width: WIN.iw, height: WIN.ih, scale: 1,
                        addEventListener() {}, removeEventListener() {} },

      // ⚠️ 下面这些在浏览器里是【构造函数】, 写成普通对象会让 JSVMP 的 async-call
      //    操作码走错分支(见上方 realm 注释), 表现为 VM 半路静默停止。务必保持函数身份。
      MediaSource: Object.assign(nativeFn('MediaSource'), {
        isTypeSupported: nativeFn('isTypeSupported', (t) => (
          has(ANSWERS.isTypeSupported, String(t)) ? ANSWERS.isTypeSupported[String(t)] : codecSupport(t) !== '')),
      }),
      Notification: Object.assign(nativeFn('Notification'), {
        permission: 'default',
        requestPermission: nativeFn('requestPermission', () => Promise.resolve('default')),
      }),
      HTMLMediaElement: function HTMLMediaElement() {},
      HTMLAudioElement: function HTMLAudioElement() {},
      VideoPlaybackQuality: function VideoPlaybackQuality() {},

      // ★ 反自动化探针会做 window.close.toString().indexOf("ELECTRON")
      //   缺 close 直接 TypeError, 整个指纹采集失败(不是"可疑", 是"崩")。
      close: nativeFn('close'),
      open: nativeFn('open', function () { return null; }),
      alert: nativeFn('alert'),
      confirm: nativeFn('confirm', function () { return false; }),
      prompt: nativeFn('prompt', function () { return null; }),
      focus: nativeFn('focus'),
      blur: nativeFn('blur'),
      print: nativeFn('print'),
      stop: nativeFn('stop'),
      scrollTo: nativeFn('scrollTo'),
      scrollBy: nativeFn('scrollBy'),
    };

    // FingerprintJS 顶层就读 HTMLVideoElement.prototype.getVideoPlaybackQuality
    win.HTMLVideoElement = function HTMLVideoElement() {};
    win.HTMLVideoElement.prototype.getVideoPlaybackQuality = nativeFn('getVideoPlaybackQuality');

    win.window = win;
    win.self = win;
    win.top = win;
    win.parent = win;
    win.globalThis = win;
    shapeWindowChain(win);

    const scriptTag = {
      src: SCRIPT.src,
      getAttribute: (k) => (k === 'src' ? SCRIPT.src
                            : (Object.prototype.hasOwnProperty.call(SCRIPT.attrs, k) ? SCRIPT.attrs[k] : null)),
      dataset: Object.keys(SCRIPT.attrs).reduce((acc, k) => {
        if (k.startsWith('data-')) acc[k.slice(5).replace(/-(\w)/g, (m, c) => c.toUpperCase())] = SCRIPT.attrs[k];
        return acc;
      }, {}),
      hasAttribute: (k) => k === 'src' || Object.prototype.hasOwnProperty.call(SCRIPT.attrs, k),
      setAttribute() {}, addEventListener() {}, parentNode: null,
    };

    const doc = {
      documentElement: makeElement('html'),
      currentScript: scriptTag,
      scripts: [scriptTag],
      createElement: (tag) => {
        const t = String(tag).toLowerCase();
        if (t === 'canvas') return makeCanvas();
        if (t === 'video' || t === 'audio') return makeMediaElement(t);
        const el = makeElement(t);
        if (t === 'iframe') {
          // withIframe() 会在 iframe 里建元素做测量(字体宽度/clientRect/mathml),
          // 所以 contentWindow / contentDocument 必须指回同一套环境。
          el.contentWindow = win;
          el.contentDocument = doc;
          el.onload = null;
        }
        return el;
      },
      // 桌面 Chrome 上 createEvent('TouchEvent') 是抛异常的, 返回对象会让
      // touchSupport.touchEvent 变成 true —— 桌面浏览器报有触摸事件 = 可疑。
      createEvent: (type) => {
        if (/touch/i.test(String(type))) {
          throw new Error("Failed to execute 'createEvent' on 'Document': " +
                          'The provided event type (' + type + ') is invalid.');
        }
        return { initEvent() {} };
      },
      createTextNode: (t) => ({ data: t, nodeValue: t }),
      // withIframe 里把节点搬进 iframe 用的; 缺了 mathml / clientRect 两源抛错
      importNode: (node) => node,
      adoptNode: (node) => node,
      createDocumentFragment: () => makeElement('#fragment'),
      createElementNS: (ns, tag) => {
        const t = String(tag || 'span').toLowerCase();
        if (t === 'canvas') return makeCanvas();
        return makeElement(t);
      },
      getElementsByTagName: () => [scriptTag],
      getElementById: () => null,
      querySelector: (sel) => (String(sel).includes('script') ? scriptTag : null),
      querySelectorAll: (sel) => (String(sel).includes('script') ? [scriptTag] : []),
      addEventListener(type, fn) { listenBehavior(type, fn); }, removeEventListener() {},
      cookie: '', referrer: opts.referrer !== undefined ? opts.referrer : SITE, title: PAGE_TITLE, readyState: 'complete',
      fonts: { ready: Promise.resolve(), check: () => true, load: () => Promise.resolve([]),
               forEach() {}, add() {}, delete() {}, size: 0, values: () => [][Symbol.iterator]() },
      location: win.location, body: makeElement('body'), head: makeElement('head'),
      hidden: false, visibilityState: 'visible',
      hasStorageAccess: () => Promise.resolve(true),
      requestStorageAccess: () => Promise.resolve(),
      hasFocus: () => true,
      elementFromPoint: () => null,
    };
    win.document = doc;
    return win;
  }

  return {
    win: buildWindow(),
    finishContext,
    stubCalls,
    requests,
    logs,
    realHttps,
    nativeFn,
    makeElement,
    FINGERPRINT,
    UA, PROXY, SITE,
    startedAt: START,
    behaviorDone,
  };
};

module.exports.DEFAULT_UA = DEFAULT_UA;
module.exports.DEFAULT_FINGERPRINT = DEFAULT_FINGERPRINT;
