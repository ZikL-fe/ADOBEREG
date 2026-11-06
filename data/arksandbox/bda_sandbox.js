'use strict';
/**
 * 沙箱采集 BDA 明文，钩子和 bda_chrome.js 相同。
 * 输出 out/bda_sandbox.json 和 out/sandbox.token。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const LAB = process.env.COLLECT_LAB || path.join(__dirname, 'data');
const API_FILE = path.join(LAB, 'arkose_api_live.js');
const FP_FILE = path.join(LAB, 'real_fp.json');
// BDA_TARGET=register：注册页的 Arkose（pk 436DD567），BDA_BLOB 为建号接口给的 x-ims-captcha-encrypted。
const TARGETS = {
  firefly: { pk: 'BBCC314C-4937-4CCD-B0A3-FDF0F0F7603C', site: 'https://firefly.adobe.com', path: '/generate/image', title: 'Create an account' },
  express: { pk: 'BBCC314C-4937-4CCD-B0A3-FDF0F0F7603C', site: 'https://express.adobe.com', path: '/', title: 'Adobe Express' },
  register: { pk: '436DD567-5435-4B14-89A6-2F1188E11334', site: 'https://auth.services.adobe.com', path: '/en_US/deeplink.html', title: 'Adobe Account' },
};
const TARGET = TARGETS[process.env.BDA_TARGET || 'firefly'];
const PK = TARGET.pk;
// Adobe renames the minify locals; match either the current live api.js
// (pe/po/xn/ho) or the older cached shape (se/io/Tn/co).
const ANCHORS = [
  'r=pe(po.fp),t.n=5,xn(r,ho,po.publicKey)',
  'r=se(io.fp),t.n=5,Tn(r,co,io.publicKey)',
];
function snapFor(anchor) {
  // Keep the encrypt call from the matched anchor so we don't mix pe/se eras.
  const encrypt = anchor.slice(anchor.indexOf(',t.n=5,') + 1); // t.n=5,xn(...) or t.n=5,Tn(...)
  const build = anchor.slice(0, anchor.indexOf(',t.n=5,')); // r=pe(po.fp) or r=se(io.fp)
  return {
    anchor,
    patched: build + ',globalThis.__ARK_PRE=JSON.parse(JSON.stringify(r)),globalThis.__ARK_BDA=r,' + encrypt,
    grafted: build.replace(/^r=/, 'r=globalThis.__ARK_GRAFT(') + '),globalThis.__ARK_PRE=JSON.parse(JSON.stringify(r)),globalThis.__ARK_BDA=r,' + encrypt,
  };
}
const API_REFRESH_MS = Number(process.env.BDA_API_REFRESH_MS || 30 * 60 * 1000);
const OUT = process.env.BDA_OUT || path.join(__dirname, 'out');
const TAG = process.env.BDA_TAG || 'sandbox';
const UA = process.env.BDA_UA ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36';
// BDA_LOCALE=us：语言、时区、语音包换成美国 Windows Chrome 的样子，和美国出口一致。
// 时区靠进程 TZ，要在任何 Date 使用之前设。
// BDA_LOCALE=jp：同理换成日本 Windows Chrome（ja、东京时区、日语语音包），配日本出口。
const LOCALE = process.env.BDA_LOCALE || '';
if (LOCALE === 'us') process.env.TZ = 'America/New_York';
if (LOCALE === 'jp') process.env.TZ = 'Asia/Tokyo';
// BDA_TZ / BDA_LANGUAGES：按代理出口国家覆盖时区和 navigator.languages（Go 侧 internal/geo 给出）。
if (process.env.BDA_TZ) process.env.TZ = process.env.BDA_TZ;
const LANGUAGES = (process.env.BDA_LANGUAGES || '').split(',').map((s) => s.trim()).filter(Boolean);
const GOOGLE_VOICES = [['Google Deutsch', 'de-DE'], ['Google US English', 'en-US'], ['Google UK English Female', 'en-GB'],
  ['Google UK English Male', 'en-GB'], ['Google español', 'es-ES'], ['Google español de Estados Unidos', 'es-US'],
  ['Google français', 'fr-FR'], ['Google हिन्दी', 'hi-IN'], ['Google Bahasa Indonesia', 'id-ID'],
  ['Google italiano', 'it-IT'], ['Google 日本語', 'ja-JP'], ['Google 한국의', 'ko-KR'],
  ['Google Nederlands', 'nl-NL'], ['Google polski', 'pl-PL'], ['Google português do Brasil', 'pt-BR'],
  ['Google русский', 'ru-RU'], ['Google 普通话（中国大陆）', 'zh-CN'], ['Google 粤語（香港）', 'zh-HK'],
  ['Google 國語（臺灣）', 'zh-TW']].map(([n, l]) => [n, l, false, false]);
const US_VOICES = [
  ['Microsoft David - English (United States)', 'en-US', true],
  ['Microsoft Mark - English (United States)', 'en-US'],
  ['Microsoft Zira - English (United States)', 'en-US'],
  ...GOOGLE_VOICES,
];
const JP_VOICES = [
  ['Microsoft Ayumi - Japanese (Japan)', 'ja-JP'],
  ['Microsoft Haruka - Japanese (Japan)', 'ja-JP', true],
  ['Microsoft Ichiro - Japanese (Japan)', 'ja-JP'],
  ['Microsoft Sayaka - Japanese (Japan)', 'ja-JP'],
  ...GOOGLE_VOICES,
];
const crypto = require('crypto');
const createBrowserEnv = require('./browser_env');

function aridToken(seed) {
  const raw = Buffer.concat([
    crypto.createHash('sha512').update('arid-a:' + seed).digest(),
    crypto.createHash('sha512').update('arid-b:' + seed).digest(),
  ]).toString('base64').replace(/=+$/, '');
  const right = crypto.createHash('sha256').update('arid-c:' + seed).digest().subarray(0, 12).toString('base64').replace(/=+$/, '');
  const mark = '**';
  const left = raw.slice(0, 178 - mark.length - right.length);
  return left + mark + right;
}

function aridFile(id) {
  return path.join(__dirname, 'arid', String(id || 'device').replace(/[^\w.-]/g, '_') + '.txt');
}

function loadOrMakeArid(id) {
  const file = aridFile(id);
  try {
    const cur = fs.readFileSync(file, 'utf8').trim();
    if (cur) return cur;
  } catch (e) { /* first visit for this device */ }
  const token = aridToken(id || crypto.randomBytes(16).toString('hex'));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, token);
  return token;
}

function rememberArid(id, header) {
  if (!header) return;
  let token = String(header);
  try {
    const parsed = JSON.parse(token);
    token = parsed.idb || parsed.ls || '';
  } catch (e) { /* header is already the inner token */ }
  if (!token || token.length < 40) return;
  const file = aridFile(id);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, token);
}
let relay = null;

// BDA_DEVICE：设备档案（make_devices.js 生成），给文件就用这台，给目录就随机挑一台。
// 没给时用 profiles/devices；设 none 或目录不存在时用 real_fp.json（单台设备，量大会被按设备标记）。
function pickDeviceFile() {
  const fallback = path.join(__dirname, 'profiles', 'devices');
  const spec = process.env.BDA_DEVICE || (fs.existsSync(fallback) ? fallback : '');
  if (!spec || spec === 'none') return null;
  if (!fs.statSync(spec).isDirectory()) return spec;
  const files = fs.readdirSync(spec).filter((f) => f.endsWith('.json'));
  if (!files.length) throw new Error('设备目录是空的: ' + spec);
  return path.join(spec, files[Math.floor(Math.random() * files.length)]);
}

function loadFingerprint(report) {
  const deviceFile = pickDeviceFile();
  const fp = JSON.parse(fs.readFileSync(deviceFile || FP_FILE, 'utf8'));
  report.device = deviceFile ? (fp.id || path.basename(deviceFile, '.json')) : 'real_fp';
  const screen = fp.screen || {};
  const gl = fp.webgl1 || {};
  let canvas = String(fp.canvas || '');
  if (canvas.startsWith('data:image/png;base64,')) canvas = canvas.slice(22);
  return {
    platform: fp.platform, language: fp.language, languages: fp.languages,
    hardwareConcurrency: fp.hardwareConcurrency, deviceMemory: fp.deviceMemory,
    timezoneOffset: fp.tzOffset, plugins: fp.plugins, fonts: fp.fonts,
    canvasHash: canvas, audioHash: fp.audio, audioSeed: 0.000172671,
    audioValue: fp.audioValue != null ? fp.audioValue : AUDIO_CHROME155,
    webglVendor: gl.unmaskedVendor, webglRenderer: gl.unmaskedRenderer,
    webgl: fp.webgl1, webgl2: fp.webgl2,
    win: fp.win && fp.win.ow ? fp.win : undefined,
    uaFullVersion: deviceFile && fp.uaData ? fp.uaData.uaFullVersion : undefined,
    platformVersion: deviceFile && fp.uaData ? fp.uaData.platformVersion : undefined,
    human: process.env.BDA_HUMAN !== '0',
    screen: {
      width: screen.w, height: screen.h, availWidth: screen.aw, availHeight: screen.ah,
      availTop: 0, availLeft: 0, colorDepth: 24, pixelDepth: 24,
    },
  };
}

// 真 Chrome 155（Win x64）在 api.js 音频探针上的值，本机实录。
const AUDIO_CHROME155 = '124.04347776696522';

// BDA_VARY=1：每次出码换一台"设备"——canvas 数据改一个字符、音频种子微调、核数换一个常见值。
// 屏幕不动，matchMedia 应答表是按录制机器的分辨率答的。
function varyFingerprint(fp) {
  const pick = (a) => a[Math.floor(Math.random() * a.length)];
  const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const c = fp.canvasHash;
  if (c && c.length > 400) {
    const i = 200 + Math.floor(Math.random() * (c.length - 400));
    fp.canvasHash = c.slice(0, i) + pick(b64.replace(c[i], '').split('')) + c.slice(i + 1);
  }
  fp.audioSeed = fp.audioSeed * (1 + (Math.random() - 0.5) * 0.02);
  fp.hardwareConcurrency = pick([4, 8, 12, 16]);
  return { hardwareConcurrency: fp.hardwareConcurrency };
}

// BDA_GRAFT=all 或逗号分隔的键（顶层键如 fe，或 enhanced_fp 内的键如 webgl_vsf_params）。
// 来源是 out/bda_<BDA_GRAFT_FROM|chrome>.json；n（时间戳）始终保留沙箱自己的。
function loadGraft() {
  const spec = process.env.BDA_GRAFT;
  if (!spec) return null;
  const from = process.env.BDA_GRAFT_FROM || 'chrome';
  const src = JSON.parse(fs.readFileSync(path.join(OUT, `bda_${from}.json`), 'utf8')).pre;
  const top = new Map(src.map((x) => [x.key, x.value]));
  const ef = new Map((top.get('enhanced_fp') || []).map((x) => [x.key, x.value]));
  const keys = spec === 'all' ? null : new Set(spec.split(',').map((s) => s.trim()).filter(Boolean));
  const skip = new Set((process.env.BDA_GRAFT_SKIP || '').split(',').map((s) => s.trim()).filter(Boolean));
  const meta = JSON.parse(fs.readFileSync(path.join(OUT, `bda_${from}.json`), 'utf8')).meta || {};
  return { label: `${from}:${spec}${skip.size ? ' -' + [...skip].join(',') : ''}`, top, ef, keys, skip, userAgent: meta.userAgent };
}

function applyGraft(items, g, report) {
  const want = (k) => !g.skip.has(k) && (g.keys === null || g.keys.has(k));
  let n = 0;
  for (const item of items) {
    if (item.key === 'n') continue;
    if (item.key === 'enhanced_fp' && Array.isArray(item.value)) {
      for (const inner of item.value) {
        if (g.ef.has(inner.key) && want(inner.key)) {
          inner.value = JSON.parse(JSON.stringify(g.ef.get(inner.key)));
          n++;
        }
      }
      continue;
    }
    if (g.top.has(item.key) && want(item.key)) {
      item.value = JSON.parse(JSON.stringify(g.top.get(item.key)));
      n++;
    }
  }
  report.grafted = n;
  return items;
}

// 没指定 UA 时用最新一份应答表录制时的 UA，保证 UA 和应答表是同一个 Chrome 版本。
function newestProfileUA() {
  const dir = path.join(__dirname, 'profiles');
  if (!fs.existsSync(dir)) return '';
  const majors = fs.readdirSync(dir).map((f) => Number((/^chrome(\d+)\.json$/.exec(f) || [])[1])).filter(Boolean).sort((a, b) => b - a);
  if (!majors.length) return '';
  return JSON.parse(fs.readFileSync(path.join(dir, `chrome${majors[0]}.json`), 'utf8')).userAgent || '';
}

// 真 Chrome 应答表：profiles/chrome<UA 主版本>.json（make_profile.js 生成）。BDA_PROFILE 可指定文件，设 none 关闭。
function loadAnswers(report, ua) {
  const spec = process.env.BDA_PROFILE;
  if (spec === 'none') return null;
  const major = (/Chrome\/(\d+)/.exec(ua) || [])[1];
  const file = spec || path.join(__dirname, 'profiles', `chrome${major}.json`);
  if (!fs.existsSync(file)) { report.profile = null; return null; }
  report.profile = path.basename(file);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const LONG = new Set(['c', 'bda', 'token', 'session_token', 'sessionToken']);
function redactPairs(str) {
  const out = {};
  for (const part of String(str).split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const k = decodeURIComponent(i < 0 ? part : part.slice(0, i));
    let v = i < 0 ? '' : decodeURIComponent(part.slice(i + 1).replace(/\+/g, ' '));
    if (LONG.has(k) || v.length > 120) v = `<${v.length}>`;
    out[k] = v;
  }
  return out;
}

function fileMtime(p) {
  try { return fs.statSync(p).mtimeMs; } catch { return 0; }
}

// Use the on-disk api.js while it is younger than BDA_API_REFRESH_MS.
// When it is due, one mint downloads the live script. It replaces the cache
// only if a known gt2 hook is still in the file; otherwise the last good
// copy stays and the next try waits out the same interval.
async function loadApiJs(transport) {
  const stamp = API_FILE + '.checked';
  const lockPath = API_FILE + '.lock';
  let cached = '';
  try { cached = fs.readFileSync(API_FILE, 'utf8'); } catch { cached = ''; }
  const cachedOk = ANCHORS.some((a) => cached.includes(a));
  const last = Math.max(fileMtime(API_FILE), fileMtime(stamp));
  const due = !cached || !cachedOk || (Date.now() - last >= API_REFRESH_MS);
  const age = last ? Date.now() - last : -1;
  if (!transport || !due) {
    return { apiJs: cached, apiStatus: 0, apiLive: false, apiRefresh: cached ? 'cache' : 'missing', apiAgeMs: age };
  }
  try {
    const st = fs.statSync(lockPath);
    if (Date.now() - st.mtimeMs > 120000) fs.unlinkSync(lockPath);
  } catch { /* no lock */ }
  let fd = null;
  try { fd = fs.openSync(lockPath, 'wx'); } catch {
    return { apiJs: cached, apiStatus: 0, apiLive: false, apiRefresh: 'busy', apiAgeMs: age };
  }
  try {
    const live = await transport.script('https://arks-client.adobe.com/v2/' + PK + '/api.js');
    const body = String(live.body || '');
    const usable = live.status === 200 && ANCHORS.some((a) => body.includes(a));
    const now = new Date();
    fs.writeFileSync(stamp, now.toISOString());
    if (usable) {
      if (body !== cached) {
        const tmp = API_FILE + '.tmp';
        fs.writeFileSync(tmp, body);
        fs.renameSync(tmp, API_FILE);
      } else {
        fs.utimesSync(API_FILE, now, now);
      }
      return { apiJs: body, apiStatus: live.status, apiLive: true, apiRefresh: body === cached ? 'checked' : 'updated', apiAgeMs: 0 };
    }
    return { apiJs: cached, apiStatus: live.status || 0, apiLive: false, apiRefresh: cached ? 'kept' : 'missing', apiAgeMs: age };
  } finally {
    try { fs.closeSync(fd); } catch { /* already closed */ }
    try { fs.unlinkSync(lockPath); } catch { /* already gone */ }
  }
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const net = [];
  const wire = [];
  const graft = loadGraft();
  const ua = process.env.BDA_UA || (graft && graft.userAgent) || newestProfileUA() || UA;
  const report0 = {};
  const fingerprint = loadFingerprint(report0);
  const report = { at: new Date().toISOString(), tag: TAG, target: process.env.BDA_TARGET || 'firefly', userAgent: ua, transport: process.env.BDA_TRANSPORT || 'node', ...report0 };
  if (process.env.BDA_VARY === '1') report.vary = varyFingerprint(fingerprint);
  if (LOCALE === 'us') {
    Object.assign(fingerprint, { language: 'en-US', languages: ['en-US', 'en'], voices: US_VOICES });
    report.locale = 'us';
  }
  if (LOCALE === 'jp') {
    Object.assign(fingerprint, { language: 'ja', languages: ['ja', 'en-US', 'en'], voices: JP_VOICES });
    report.locale = 'jp';
  }
  if (LANGUAGES.length) {
    Object.assign(fingerprint, { language: LANGUAGES[0], languages: LANGUAGES });
    report.languages = LANGUAGES;
  }
  report.tz = process.env.TZ || '';
  let proxy = process.env.COLLECT_PROXY || '';
  if (process.env.BDA_VIA_PROXY) {
    const bridge = await require('./socks_bridge').start();
    report.sid = bridge.sid;
    proxy = bridge.url;
  }
  let transport = null;
  if (process.env.BDA_TRANSPORT === 'chrome') {
    const { startRelay, createTransport } = require('./chrome_transport');
    relay = await startRelay();
    const langs = graft && typeof graft.ef.get('navigator_languages') === 'string'
      ? graft.ef.get('navigator_languages').split(',') : fingerprint.languages;
    transport = createTransport({
      relayAddr: relay.addr, proxy, userAgent: ua, languages: langs, site: TARGET.site,
      log: (row) => wire.push(row),
    });
  }
  const loaded = await loadApiJs(transport);
  let apiJs = loaded.apiJs;
  report.apiStatus = loaded.apiStatus;
  report.apiLive = loaded.apiLive;
  report.apiRefresh = loaded.apiRefresh;
  report.apiAgeMs = loaded.apiAgeMs;
  const hook = snapFor(ANCHORS.find((a) => apiJs.includes(a)) || ANCHORS[0]);
  report.patched = apiJs.includes(hook.anchor);
  report.anchor = hook.anchor.slice(0, 48);
  report.graft = graft ? graft.label : null;
  apiJs = apiJs.replace(hook.anchor, graft ? hook.grafted : hook.patched);
  const env = createBrowserEnv({
    userAgent: ua,
    proxy,
    transport: transport ? async (m, u, h, b) => {
      const res = await transport.request(m, u, h, b);
      if (m === 'POST' && String(u).includes('/fc/gt2/')) {
        try {
          const hdrs = res.headers || {};
          const rawIssued = hdrs['x-ark-arid'] || hdrs['X-Ark-Arid'];
          const issued = Array.isArray(rawIssued) ? rawIssued[0] : rawIssued;
          if (issued) rememberArid(report.device, issued);
          const j = JSON.parse(res.body);
          const flags = {};
          String(j.token || '').split('|').slice(1).forEach((p) => {
            const [k, v] = p.split('=');
            if (['sup', 'r', 'meta', 'at', 'ag', 'pk'].includes(k) || /^(sup|r|pk)$/.test(k)) flags[k] = v;
          });
          report.gt2 = { keys: Object.keys(j), flags, challenge_url: j.challenge_url || undefined, noscript: j.noscript ? 'yes' : undefined };
        } catch (e) { report.gt2 = { parseError: true }; }
      }
      return res;
    } : null,
    site: TARGET.site,
    pagePath: TARGET.path,
    pageTitle: TARGET.title,
    aridToken: loadOrMakeArid(report.device),
    baseOrigin: 'https://arks-client.adobe.com',
    fingerprint,
    answers: loadAnswers(report, ua),
    referrer: '',
    elementIds: ['ark'],
    script: { src: 'https://arks-client.adobe.com/v2/' + PK + '/api.js', attrs: { 'data-callback': 'setupEnforcement' } },
    onRequest(method, url, body) {
      const [base, query] = String(url).split('?');
      net.push({ method, url: base, query: query ? redactPairs(query) : '', form: typeof body === 'string' ? redactPairs(body) : (body ? '<binary>' : null) });
    },
    onResponse(url, status) {
      const row = [...net].reverse().find((r) => String(url).startsWith(r.url));
      if (row && row.status === undefined) row.status = status;
    },
  });
  if (typeof env.win.ProgressEvent !== 'function') {
    env.win.ProgressEvent = function ProgressEvent(type, init) { this.type = type; Object.assign(this, init || {}); };
  }
  if (!process.env.BDA_KEEP_ENV) {
    if (env.win.performance && env.win.performance.memory) env.win.performance.memory.jsHeapSizeLimit = 4395630592;
  }
  const context = vm.createContext(env.win);
  const shaped = env.finishContext(context);
  if (shaped) report.shaped = { removed: shaped.removed, added: shaped.added };
  if (graft) context.__ARK_GRAFT = (items) => applyGraft(items, graft, report);
  const done = new Promise((resolve) => {
    env.win.setupEnforcement = function (enforcement) {
      // Cast Firefly tickets omit |lang=... from the ark token. Passing
      // language:'en' forces lang=en and correlates with 408 in A/B grafts.
      const cfg = {
        publicKey: PK, mode: 'inline',
        ...(process.env.BDA_BLOB ? { data: { blob: process.env.BDA_BLOB } } : {}),
        onReady() { try { enforcement.run(); } catch (e) {} },
        onCompleted: (r) => resolve({ kind: 'completed', token: r && r.token }),
        onSuppress: (r) => resolve({ kind: 'suppress', token: r && r.token }),
        onShown: (r) => resolve({ kind: 'challenge', token: r && r.token }),
        onError(r) { report.error = JSON.stringify(r || null); },
      };
      if (process.env.BDA_LANGUAGE) cfg.language = process.env.BDA_LANGUAGE;
      enforcement.setConfig(cfg);
    };
    setTimeout(() => resolve(null), 30000);
  });
  try {
    vm.runInContext(apiJs, context, { filename: 'arkose_api.js', timeout: 20000 });
  } catch (e) {
    report.loadError = String(e && e.message || e).slice(0, 180);
  }
  const state = await done;
  if (process.env.BDA_PROBE) {
    try {
      report.probe = JSON.parse(await vm.runInContext(require('./probe_src'), context, { timeout: 10000 }));
    } catch (e) { report.probe = { error: String(e && e.message || e) }; }
  }
  const bda = context.__ARK_BDA || null;
  const token = state && state.token;
  report.kind = state ? state.kind : null;
  report.tokenLen = token ? token.length : 0;
  report.sup = token ? /(?:^|\|)sup=1(?:\||$)/.test(token) : null;
  report.region = token ? ((/\|r=([^|]+)/.exec(token) || [])[1] || '') : '';
  report.bdaItems = Array.isArray(bda) ? bda.length : 0;
  if (pageErrors.length) report.pageErrors = pageErrors.slice(0, 5);
  if (env.stubCalls.length) report.stubCalls = [...new Set(env.stubCalls)];
  fs.writeFileSync(path.join(OUT, `net_${TAG}.json`), JSON.stringify({ page: net, wire }, null, 2));
  if (relay) relay.close();
  fs.writeFileSync(path.join(OUT, `bda_${TAG}.json`), JSON.stringify({ meta: report, bda: JSON.parse(JSON.stringify(bda)), pre: JSON.parse(JSON.stringify(context.__ARK_PRE || null)) }, null, 2));
  if (token) fs.writeFileSync(path.join(OUT, `${TAG}.token`), token);
  process.stdout.write(JSON.stringify(Object.assign({}, report, { probe: report.probe ? 'saved' : undefined })) + '\n');
  setTimeout(() => process.exit(0), 200);
}

// 浏览器里页面脚本的未捕获异常只会报到 onerror，不会让页面死掉。
const pageErrors = [];
process.on('unhandledRejection', (e) => { pageErrors.push('rejection: ' + String(e && e.message || e).slice(0, 160)); });
process.on('uncaughtException', (e) => { pageErrors.push('exception: ' + String(e && e.stack || e).slice(0, 400)); });
main().catch((e) => { console.error(String(e && e.stack || e).split('\n').slice(0, 4).join('\n')); process.exit(1); });
