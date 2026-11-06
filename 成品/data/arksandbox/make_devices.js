'use strict';
// node make_devices.js [数量=200] [输出目录=profiles/devices] [种子]
// 生成一批彼此不同、各自自洽的 Windows + NVIDIA 台式机设备档案（real_fp.json 同格式），
// 给 bda_sandbox.js 的 BDA_DEVICE 用。WebGL 参数和扩展走 chrome155 应答表（D3D11 下 NVIDIA 各型号一致），
// 这里只换显卡型号；屏幕、窗口、核数、内存、字体、canvas 按真实分布挑，同一台设备的值固定不变。
const fs = require('fs');
const path = require('path');

const LAB = process.env.COLLECT_LAB ||
  'C:\\Users\\Administrator\\Downloads\\adobe_ok_8001_clean_20260811_155637(1)(1)\\adobe_ok_8001_clean_20260811_155637\\backend\\alipay_cli';
const BASE_FILE = process.env.DEVICE_BASE || [path.join(__dirname, 'data', 'real_fp.json'), path.join(LAB, 'ftr_gen', 'ftr_gen', 'real_fp.json')]
  .find((p) => fs.existsSync(p));

const count = Number(process.argv[2] || 200);
const outDir = path.resolve(process.argv[3] || path.join(__dirname, 'profiles', 'devices'));
let seed = Number(process.argv[4] || Date.now()) >>> 0;
function rand() {
  seed = (seed + 0x6D2B79F5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const weighted = (rows) => {
  const total = rows.reduce((s, r) => s + r[r.length - 1], 0);
  let x = rand() * total;
  for (const r of rows) { x -= r[r.length - 1]; if (x <= 0) return r; }
  return rows[rows.length - 1];
};
const pick = (a) => a[Math.floor(rand() * a.length)];

// [型号, PCI 设备号（pci.ids 核对过）, 档次, 权重]
const GPUS = [
  ['RTX 3060', 0x2504, 'mid', 9], ['RTX 3060', 0x2503, 'mid', 3], ['RTX 4060', 0x2882, 'mid', 7],
  ['RTX 4060 Ti', 0x2803, 'mid', 5], ['RTX 3060 Ti', 0x2489, 'mid', 4], ['RTX 3060 Ti', 0x2486, 'mid', 2],
  ['GTX 1650', 0x1F82, 'low', 5], ['GTX 1660 SUPER', 0x21C4, 'low', 4], ['GTX 1660 Ti', 0x2182, 'low', 1.5],
  ['GTX 1660', 0x2184, 'low', 1.5], ['GTX 1060 6GB', 0x1C03, 'low', 2], ['RTX 3050', 0x2507, 'low', 3],
  ['RTX 2060', 0x1F08, 'mid', 4], ['RTX 2060 SUPER', 0x1F06, 'mid', 1.5], ['RTX 2070 SUPER', 0x1E84, 'mid', 1.5],
  ['RTX 3070', 0x2488, 'high', 3], ['RTX 3070', 0x2484, 'high', 1.5], ['RTX 3080', 0x2216, 'high', 1.5],
  ['RTX 3080', 0x2206, 'high', 1], ['RTX 4070', 0x2786, 'high', 4], ['RTX 4070 SUPER', 0x2783, 'high', 3],
  ['RTX 4070 Ti', 0x2782, 'high', 2], ['RTX 4080 SUPER', 0x2702, 'high', 1.5], ['RTX 4090', 0x2684, 'high', 1],
  ['RTX 5070', 0x2F04, 'high', 1.5], ['RTX 5060 Ti', 0x2D04, 'mid', 1], ['RTX 5080', 0x2C02, 'high', 0.7],
];
const THREADS = {
  low: [[4, 1], [6, 2], [8, 3], [12, 3], [16, 1]],
  mid: [[8, 2], [12, 4], [16, 4], [20, 1], [24, 1]],
  high: [[12, 2], [16, 4], [20, 2], [24, 2], [32, 2]],
};
// navigator.deviceMemory：Chrome 155 桌面上限 32。
const MEMORY = { low: [[8, 3], [16, 4]], mid: [[16, 6], [32, 3], [8, 1]], high: [[32, 6], [16, 3]] };
// [物理宽, 物理高, 缩放, 权重]；CSS 尺寸 = 物理 / 缩放。
const SCREENS = [
  [1920, 1080, 1, 52], [2560, 1440, 1, 17], [1920, 1080, 1.25, 6], [3840, 2160, 1.5, 5], [3840, 2160, 2, 2],
  [2560, 1080, 1, 3], [3440, 1440, 1, 4], [1680, 1050, 1, 2], [1600, 900, 1, 2], [1366, 768, 1, 2],
  [1440, 900, 1, 1], [2560, 1440, 1.25, 2], [1920, 1200, 1, 2],
];
// 真机 Chrome 在 api.js 的 65 个探测字体里能测到的：Windows 10/11 自带的 33 个，装了 Office 再多一批。
const FONTS_WINDOWS = ['Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria', 'Cambria Math', 'Comic Sans MS', 'Consolas',
  'Courier', 'Courier New', 'Georgia', 'Helvetica', 'Impact', 'Lucida Console', 'Lucida Sans Unicode', 'Microsoft Sans Serif',
  'MS Gothic', 'MS PGothic', 'MS Sans Serif', 'MS Serif', 'Palatino Linotype', 'Segoe Print', 'Segoe Script', 'Segoe UI',
  'Segoe UI Light', 'Segoe UI Semibold', 'Segoe UI Symbol', 'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Wingdings'];
const FONTS_OFFICE = ['Arial Rounded MT Bold', 'Book Antiqua', 'Bookman Old Style', 'Century', 'Century Gothic', 'Century Schoolbook',
  'Garamond', 'Lucida Bright', 'Lucida Calligraphy', 'Lucida Fax', 'Lucida Handwriting', 'Lucida Sans', 'Lucida Sans Typewriter',
  'Monotype Corsiva', 'MS Outlook', 'MS Reference Sans Serif', 'Wingdings 2', 'Wingdings 3'];
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36';
const CHROME_FULL = '155.0.8059.40';

// 浏览器字段统一成 Chrome 155；任务栏 40 是 Win10 的样子（platformVersion 10.0.0），48 是 Win11（19.0.0）。
function uaFields(taskbar) {
  const brands = [['Google Chrome', '155'], ['Chromium', '155'], ['Not(A:Brand', '24']];
  return {
    userAgent: CHROME_UA,
    appVersion: CHROME_UA.slice('Mozilla/'.length),
    uaData: {
      architecture: 'x86', bitness: '64',
      brands: brands.map(([brand, version]) => ({ brand, version })),
      fullVersionList: brands.map(([brand, v]) => ({ brand, version: brand.startsWith('Not') ? `${v}.0.0.0` : CHROME_FULL })),
      mobile: false, model: '', platform: 'Windows',
      platformVersion: taskbar === 40 ? '10.0.0' : '19.0.0',
      uaFullVersion: CHROME_FULL,
    },
  };
}

// node make_devices.js restamp <dir>：只改已有设备的浏览器字段，别的不动。
if (process.argv[2] === 'restamp') {
  const dir = process.argv[3];
  let n = 0;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const file = path.join(dir, f);
    const d = JSON.parse(fs.readFileSync(file, 'utf8'));
    Object.assign(d, uaFields(d.screen.h - d.screen.ah));
    fs.writeFileSync(file, JSON.stringify(d));
    n++;
  }
  console.log(`restamped ${n} devices -> ${dir}`);
  process.exit(0);
}

function makeDevice(base, n) {
  const [model, pci, tier] = weighted(GPUS);
  const renderer = `ANGLE (NVIDIA, NVIDIA GeForce ${model} (0x${pci.toString(16).toUpperCase().padStart(8, '0')}) Direct3D11 vs_5_0 ps_5_0, D3D11)`;
  const [pw, ph, dpr] = weighted(SCREENS);
  const w = Math.round(pw / dpr), h = Math.round(ph / dpr);
  const taskbar = rand() < 0.75 ? 48 : 40;
  const ah = h - taskbar;
  const fonts = FONTS_WINDOWS.concat(rand() < 0.55 ? FONTS_OFFICE : []).sort((a, b) => a.localeCompare(b));
  let canvas = String(base.canvas);
  const head = 'data:image/png;base64,'.length + 200;
  for (let k = 0; k < 2; k++) {
    const i = head + Math.floor(rand() * (canvas.length - head - 200));
    canvas = canvas.slice(0, i) + pick(B64.replace(canvas[i], '').split('')) + canvas.slice(i + 1);
  }
  const gl1 = Object.assign({}, base.webgl1, { unmaskedVendor: 'Google Inc. (NVIDIA)', unmaskedRenderer: renderer });
  const gl2 = Object.assign({}, base.webgl2, { unmaskedVendor: 'Google Inc. (NVIDIA)', unmaskedRenderer: renderer });
  const id = 'xian_' + n.toString().padStart(4, '0') + '_' + Math.floor(rand() * 0xffffff).toString(16).padStart(6, '0');
  return Object.assign({}, base, uaFields(taskbar), {
    id,
    gpu: model,
    language: 'en-US',
    languages: ['en-US', 'en'],
    tz: 'America/New_York',
    tzOffset: 240,
    hardwareConcurrency: weighted(THREADS[tier])[0],
    deviceMemory: weighted(MEMORY[tier])[0],
    screen: { w, h, aw: w, ah, cd: 24, pd: 24 },
    win: { dpr, ow: w, oh: ah, iw: w, ih: ah - 121, sx: 0, sy: 0 },
    webgl1: gl1,
    webgl2: gl2,
    canvas,
    fonts,
    audioValue: '124.04347776696522',
  });
}

if (!BASE_FILE) throw new Error('找不到 real_fp.json（DEVICE_BASE 或 data/real_fp.json）');
const base = JSON.parse(fs.readFileSync(BASE_FILE, 'utf8'));
fs.mkdirSync(outDir, { recursive: true });
const seen = new Set();
let made = 0;
for (let n = 0; made < count && n < count * 5; n++) {
  const d = makeDevice(base, made);
  const key = [d.gpu, d.hardwareConcurrency, d.deviceMemory, d.screen.w, d.screen.h, d.screen.ah, d.win.dpr, d.fonts.length].join('|');
  if (seen.has(key) && rand() < 0.7) continue;
  seen.add(key);
  fs.writeFileSync(path.join(outDir, d.id + '.json'), JSON.stringify(d));
  made++;
}
console.log(`made ${made} devices -> ${outDir}`);
