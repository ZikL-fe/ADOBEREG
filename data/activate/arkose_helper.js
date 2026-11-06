// Activate-only Arkose helper (lives under data/activate — never arksandbox).
// Split: local PoW (real polymorphic worker) + dapib; YesCaptcha is Classification only (Go side).
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { spawnSync } = require("child_process");

const HERE = __dirname;

function normalizePowRates(data, setup) {
  let hr = Number(data.hashRate || 0);
  let tm = Number(data.time || 0) | 0;
  if (hr > 2000 || tm < 200) {
    const rows = Array.isArray(data.targetHashData) ? data.targetHashData : [];
    const iters = rows.map((x) => Number(x && x.iterations) || 0);
    const start = Number((((setup || {}).work_config) || {}).starting_nonce || 0);
    const dist = iters.length ? Math.max(...iters) - start : 0;
    hr = 130 + Math.random() * 230;
    tm = hr > 0 && dist > 0 ? Math.max(400, Math.floor(dist / hr)) : Math.max(400, tm);
    data.__normalized = { dist, orig_rate: data.hashRate, orig_time: data.time };
  }
  data.hashRate = hr;
  data.time = tm;
  return data;
}

function ensureResult(data) {
  if (!Array.isArray(data.result) || data.result.length === 0) {
    const rows = Array.isArray(data.targetHashData) ? data.targetHashData : [];
    data.result = rows
      .map((x) => ({
        target_hash: x && (x.targetHash || x.target_hash),
        attempt_count: x && (x.iterations != null ? x.iterations : x.attempt_count),
      }))
      .filter((x) => x.target_hash != null && x.attempt_count != null);
  }
  return data;
}

function runPowViaPureWorker(source, setup) {
  const wc = (setup && setup.work_config) || {};
  const targets = (Array.isArray(wc.splits) ? wc.splits : [])
    .map((s) => s && s.target_hash)
    .filter(Boolean);
  const msg = {
    type: "start",
    data: {
      type: setup && setup.work_type,
      itimeout: setup && setup.timeout,
      seed: wc.seed,
      startingNonce: Number(wc.starting_nonce || 0),
      targetHashData: targets.map((h) => ({ targetHashData: h })),
    },
  };
  const workerJs = path.join(HERE, "run_pow_worker.js");
  const powSolve = path.join(HERE, "pow_solve.py");
  if (!fs.existsSync(workerJs) || !fs.existsSync(powSolve)) {
    return null;
  }
  const td = fs.mkdtempSync(path.join(os.tmpdir(), "act-pow-"));
  try {
    const wp = path.join(td, "worker.js");
    const mp = path.join(td, "msg.json");
    fs.writeFileSync(wp, String(source || ""), "utf8");
    fs.writeFileSync(mp, JSON.stringify(msg), "utf8");
    const r = spawnSync("node", [workerJs, wp, mp], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      timeout: 240000,
      env: {
        ...process.env,
        POW_CWD: HERE,
        // Relative so Windows paths don't need nested quotes in execSync.
        POW_SOLVER: "python pow_solve.py",
      },
      cwd: HERE,
    });
    if (r.error) {
      return { ok: false, error: "pow_spawn: " + String(r.error.message || r.error) };
    }
    let j;
    try {
      j = JSON.parse(String(r.stdout || "").trim());
    } catch (e) {
      return {
        ok: false,
        error: "pow_bad_json: " + String(r.stderr || r.stdout || e).slice(0, 180),
      };
    }
    if (!j.ok || !j.done || !j.done.data) {
      return {
        ok: false,
        error: "pow_worker: " + JSON.stringify(j.errors || j).slice(0, 200),
      };
    }
    const data = ensureResult(normalizePowRates({ ...j.done.data }, setup));
    if (!data.finalTransform || !Array.isArray(data.result) || data.result.length === 0) {
      return { ok: false, error: "pow_incomplete" };
    }
    return { ok: true, result: data };
  } finally {
    try {
      fs.rmSync(td, { recursive: true, force: true });
    } catch (_) {}
  }
}

// Fallback in-process vm runner (kept if pure worker scripts are missing).
function splitChunk(chunk, n) {
  if (n <= 0) return [];
  const size = Math.ceil(chunk.length / n);
  const s = chunk.slice(0, size * n);
  const out = [];
  for (let i = 0; i < n; i++) out.push(s.slice(i * size, (i + 1) * size));
  return out;
}

function findNonces(chunk, targets, start) {
  const crypto = require("crypto");
  const parts = splitChunk(chunk, targets.length);
  let nonce = start | 0;
  const found = [];
  const span = 50000000;
  for (let j = 0; j < targets.length; j++) {
    const pb = Buffer.from(parts[j], "latin1");
    const target = targets[j];
    let got = -1;
    for (let win = 0; win < 4 && got < 0; win++) {
      const lo = nonce + win * span;
      const hi = lo + span;
      for (let i = lo; i < hi; i++) {
        if (crypto.createHash("sha512").update(pb).update(String(i)).digest("hex") === target) {
          got = i;
          break;
        }
      }
    }
    if (got < 0) throw new Error("pow_search miss split=" + j + " from=" + nonce);
    found.push(got);
    nonce = got;
  }
  return found;
}

async function runPowVm(source, setup) {
  const crypto = require("crypto");
  const { webcrypto } = crypto;
  const { TextEncoder, TextDecoder } = require("util");
  const wc = (setup && setup.work_config) || {};
  const targets = (Array.isArray(wc.splits) ? wc.splits : [])
    .map((s) => s && s.target_hash)
    .filter(Boolean);
  const msg = {
    type: "start",
    data: {
      type: setup && setup.work_type,
      itimeout: setup && setup.timeout,
      seed: wc.seed,
      startingNonce: Number(wc.starting_nonce || 0),
      targetHashData: targets.map((h) => ({ targetHashData: h })),
    },
  };
  let src = String(source || "");
  const slowHex =
    "const hashArray=Array.from(new Uint8Array(hashBuffer));const hashHex=hashArray.map(b=>b.toString(16).padStart(2,'0')).join('');return hashHex;";
  if (src.includes(slowHex)) {
    src = src.replace(slowHex, "return Buffer.from(new Uint8Array(hashBuffer)).toString('hex');");
  }
  const jump = /([A-Za-z_$][\w$]*),([A-Za-z_$][\w$]*)\[([A-Za-z_$][\w$]*)\],timer,timeout\)/;
  if (!jump.test(src)) return { ok: false, error: "pow_worker_shape" };
  src = src.replace(
    jump,
    (all, start, arr, idx) => `(__N||[])[${idx}]??${start},${arr}[${idx}],timer,timeout)`
  );

  const posted = [];
  let nonceCount = -1;
  const sandbox = {
    Buffer,
    Uint8Array,
    Array,
    Object,
    JSON,
    Math,
    Date,
    Promise,
    TextEncoder,
    TextDecoder,
    setTimeout,
    clearTimeout,
    console: { log() {}, warn() {}, error() {} },
    __N: null,
    onmessage: null,
    postMessage: (m) => {
      posted.push(m);
    },
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => {
      const r = Buffer.from(s, "binary").toString("base64");
      if (!sandbox.__N && r.length > 100 && targets.length) {
        try {
          sandbox.__N = findNonces(r, targets, msg.data.startingNonce | 0);
          nonceCount = sandbox.__N.length;
        } catch (e) {
          nonceCount = -2;
          sandbox.__powSearchErr = String(e && e.message ? e.message : e).slice(0, 120);
        }
      }
      return r;
    },
    crypto: {
      getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
      subtle: {
        digest: (alg, data) => {
          const name = (typeof alg === "string" ? alg : (alg && alg.name) || "")
            .replace(/-/g, "")
            .toLowerCase();
          const buf = Buffer.isBuffer(data) ? data : Buffer.from(data.buffer || data);
          const out = crypto.createHash(name).update(buf).digest();
          return Promise.resolve(out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength));
        },
      },
    },
  };
  sandbox.self = sandbox;
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  try {
    vm.runInContext(src, ctx, { timeout: 180000 });
    if (typeof sandbox.onmessage !== "function") return { ok: false, error: "pow_no_handler" };
    await Promise.race([
      Promise.resolve(sandbox.onmessage({ data: msg })),
      new Promise((_, reject) => setTimeout(() => reject(new Error("pow_timeout")), 180000)),
    ]);
  } finally {
    sandbox.__N = null;
  }
  const done = posted.find((m) => m && m.type === "done");
  if (!done || !done.data) {
    return {
      ok: false,
      error:
        "pow_no_result nonces=" +
        nonceCount +
        (sandbox.__powSearchErr ? " detail=" + sandbox.__powSearchErr : ""),
    };
  }
  const data = ensureResult(normalizePowRates({ ...done.data }, setup));
  if (!data.finalTransform || !Array.isArray(data.result) || data.result.length === 0) {
    return { ok: false, error: "pow_incomplete" };
  }
  return { ok: true, result: data };
}

async function runPow(source, setup) {
  const via = runPowViaPureWorker(source, setup);
  if (via) return via;
  return runPowVm(source, setup);
}

function runDapib(source, answer) {
  // Match adobe_pure_protocol/tools/re/run_dapib.js exactly:
  // never expose process/require, or dapib appends random A-Z suffixes and CA returns "not answered".
  let result = null;
  const sandbox = {
    console,
    Math,
    JSON,
    Object,
    String,
    Number,
    Array,
    Error,
    Promise,
    Date,
    RegExp,
    setTimeout,
    clearTimeout,
    window: null,
    document: {
      hidden: false,
      visibilityState: "visible",
      activeElement: {},
      createElement: () => ({ setAttribute() {}, style: {}, appendChild() {} }),
      body: { appendChild() {} },
    },
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.parent = sandbox;
  sandbox.ae = {
    answer,
    dapibReceive(r) {
      result = r;
    },
  };
  vm.createContext(sandbox);
  try {
    vm.runInContext(String(source || ""), sandbox, { timeout: 20000 });
  } catch (e) {
    if (result === null) {
      return { ok: false, error: "dapib_exc: " + String((e && e.message) || e).slice(0, 120) };
    }
  }
  if (!result || result.tanswer == null) return { ok: false, error: "dapib_no_answer" };
  return { ok: true, tanswer: result.tanswer };
}

(async () => {
  try {
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    if (input.mode === "dapib") {
      let answer = input.payload.answer;
      if (typeof answer === "string") {
        try {
          answer = JSON.parse(answer);
        } catch {}
      }
      process.stdout.write(JSON.stringify(runDapib(input.payload.source, answer)));
      return;
    }
    if (input.mode === "pow") {
      let setup = input.payload.setup;
      if (typeof setup === "string") setup = JSON.parse(setup);
      const out = await runPow(input.payload.source, setup);
      process.stdout.write(JSON.stringify(out));
      return;
    }
    process.stdout.write(JSON.stringify({ ok: false, error: "unknown_mode" }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String((e && e.message) || e) }));
  }
})();
