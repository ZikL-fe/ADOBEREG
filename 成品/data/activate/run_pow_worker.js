// 在 Node 里跑 Arkose PoW worker —— 用**真 worker**（零语义重写），
// 只把慢的 crypto.subtle.digest 换成 Node 原生 createHash（快 ~1000x）。
//
//   node tools/re/run_pow_worker.js <worker.js> <message.json>
//
// message.json = {"type":"start","data":{type,itimeout,seed,startingNonce,targetHashData}}
const fs = require("fs");
const nodeCrypto = require("crypto");
const { webcrypto } = nodeCrypto;

globalThis.self = globalThis;
globalThis.window = globalThis;
globalThis.performance = globalThis.performance || { now: () => Date.now() };
if (typeof TextEncoder === "undefined") globalThis.TextEncoder = require("util").TextEncoder;

const realSubtle = webcrypto.subtle;

// ---- 快速 digest：worker 只用到 digest('SHA-512', buf) ----
let __calls=0, __t0=Date.now();
function fastDigest(alg, data) {
  __calls++;
  const name = (typeof alg === "string" ? alg : alg.name || "").replace(/-/g, "").toLowerCase();
  const buf = Buffer.isBuffer(data) ? data
            : (data instanceof ArrayBuffer) ? Buffer.from(data)
            : Buffer.from(data.buffer || data);
  const out = nodeCrypto.createHash(name).update(buf).digest();
  // 必须是独立的 ArrayBuffer（worker 会 new Uint8Array(hashBuffer)）
  return Promise.resolve(out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength));
}

globalThis.crypto = Object.create(webcrypto);
globalThis.crypto.subtle = Object.create(realSubtle);
globalThis.crypto.subtle.digest = fastDigest;
globalThis.crypto.getRandomValues = webcrypto.getRandomValues.bind(webcrypto);

globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");

// ---- ★ 源码级加速补丁（语义等价，已逐字节对账 finalTransform）----
// worker 的 hashStandard 每次哈希都做 64 次 toString(16)+padStart+join，
// 比 SHA-512 本身贵 ~10x。换成 Buffer.toString('hex') 后 hashRate 178->324。
globalThis.__hex = (b) => Buffer.from(new Uint8Array(b)).toString("hex");
globalThis.__TE = null;
globalThis.__N = null;   // ★ 并行求出的 nonce 表；命中后 worker 从答案起跳

globalThis.btoa = (s) => {
  const r = Buffer.from(s, "binary").toString("base64");
  // ★ chunk = u(JSON.stringify(m(seed)))，长度远大于 k() 内部的短 btoa
  if (globalThis.__N === null && r.length > 100 && !globalThis.__solving) {
    globalThis.__solving = true;
    try {
      const tg = (msg && msg.data && msg.data.targetHashData || []).map((x) => x.targetHashData);
      if (tg.length) {
        const req = JSON.stringify({ chunk: r, targets: tg,
                                     start: (msg.data.startingNonce | 0), span: 12000000 });
        const out = require("child_process").execSync(
          process.env.POW_SOLVER || "python tools/re/pow_solve.py",
          { input: req, maxBuffer: 1 << 26, cwd: process.env.POW_CWD || "." }).toString();
        const j = JSON.parse(out);
        if (j.ok && j.nonces && j.nonces.length === tg.length) {
          globalThis.__N = j.nonces;
          process.stderr.write("pow_solve: " + JSON.stringify({secs:j.secs,nonces:j.nonces,pool_ms:j.pool_ms,split_ms:j.split_ms,span:j.span,span_used:j.span_used}) + "\n");
        } else {
          process.stderr.write("pow_solve FAILED: " + out.slice(0, 160) + "\n");
        }
      }
    } catch (e) {
      process.stderr.write("pow_solve EXC: " + String((e && e.message) || e).slice(0, 160) + "\n");
    }
  }
  return r;
};

const out = [];
globalThis.postMessage = (m) => { out.push(m); };

const workerPath = process.argv[2];
const msgPath = process.argv[3];
let src = fs.readFileSync(workerPath, "utf8");

// ---- ★ 加速补丁：只替换已知的等价写法，未命中则原样跑 ----
let __patched = [];
const P1 = "const hashArray=Array.from(new Uint8Array(hashBuffer));"
         + "const hashHex=hashArray.map(b=>b.toString(16).padStart(2,'0')).join('');return hashHex;";
if (process.env.POW_NO_PATCH !== "1" && src.includes(P1)) {
  src = src.replace(P1, "return __hex(hashBuffer);");
  __patched.push("hex");
}
const P2 = "const msgBuffer=new TextEncoder().encode(data);";
if (process.env.POW_NO_PATCH !== "1" && src.includes(P2)) {
  src = src.replace(P2, "const msgBuffer=(__TE||(__TE=new TextEncoder())).encode(data);");
  __patched.push("te");
}
// ★ 起跳补丁：把搜索循环的起始 nonce 换成 __N[IDX]（__N 为 null 时恒等）
//    线上 worker 每会话多态，且有两种调用形状：
//      (a) 派发式  ](V,Y,w[M],timer,timeout)        → 起始 = Y
//      (b) 直呼式  D(I,R[M],timer,timeout)          → 起始 = I
//    统一取 ARR[IDX] 前面那个标识符作为起始 nonce。
if (process.env.POW_NO_PATCH !== "1") {
  const P3RE = /([A-Za-z_$][\w$]*),([A-Za-z_$][\w$]*)\[([A-Za-z_$][\w$]*)\],timer,timeout\)/;
  const m3 = P3RE.exec(src);
  if (m3) {
    src = src.replace(P3RE, (all, start, arr, idx) =>
      `(globalThis.__N||[])[${idx}]??${start},${arr}[${idx}],timer,timeout)`);
    __patched.push("jump");
  } else {
    process.stderr.write("JUMP_PATCH_MISS\n");
    try { require("fs").writeFileSync(process.env.POW_SAVE_WORKER || "data/pow/live_reg_worker.js", src); } catch (e) {}
  }
}
const msg = JSON.parse(fs.readFileSync(msgPath, "utf8"));

(0, eval)(src);

(async () => {
  const t0 = Date.now();
  try {
    await globalThis.onmessage({ data: msg });
  } catch (e) {
    out.push({ type: "error", data: { message: String((e && e.message) || e) } });
  }
  const done = out.find((m) => m && m.type === "done") || null;
  process.stderr.write("fastDigest calls="+__calls+" in "+(Date.now()-__t0)+"ms patched="+__patched.join(",")+"\n");
  const res = {
    ok: !!done,
    ms: Date.now() - t0,
    patched: __patched,
    done,
    splits: out.filter((m) => m && m.type === "split_done"),
    errors: out.filter((m) => m && m.type === "error"),
    dbg: out.filter((m) => m && String(m.type).startsWith("dbg")),
    all_types: out.map((m) => m && m.type),
  };
  process.stdout.write(JSON.stringify(res));
})();
