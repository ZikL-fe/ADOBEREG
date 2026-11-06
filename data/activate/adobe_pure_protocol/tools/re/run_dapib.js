// 在 Node vm 里跑**真实的 dapib 脚本**（Arkose tguess transform）。
// 用法: node run_dapib.js <dapib.js 路径> <input JSON 路径>
// 输出: stdout = JSON.stringify(tanswer)
//
// 要点：必须屏蔽 `process`，否则脚本会走 headless 分支给每个值**追加随机后缀**
// （0x41 + random*26，即 A-Z），服务端就会拒。
const fs = require('fs');
const vm = require('vm');

const srcPath = process.argv[2];
const inPath = process.argv[3];
const src = fs.readFileSync(srcPath, 'utf8');
const input = JSON.parse(fs.readFileSync(inPath, 'utf8'));

let result = null;
const sandbox = {
  // 关键：不要暴露 process / require
  console,
  Math, JSON, Object, String, Number, Array, Error, Promise, Date, RegExp,
  setTimeout, clearTimeout,
  window: null,
  document: {
    hidden: false,
    visibilityState: 'visible',
    activeElement: {},            // instanceof Object -> true
    createElement: () => ({ setAttribute() {}, style: {}, appendChild() {} }),
    body: { appendChild() {} },
  },
};
sandbox.window = sandbox;
sandbox.self = sandbox;
sandbox.parent = sandbox;         // dapib 读 window.parent.ae
sandbox.ae = {
  answer: input,
  dapibReceive: (r) => { result = r; },
};

vm.createContext(sandbox);
try {
  vm.runInContext(src, sandbox, { timeout: 20000 });
} catch (e) {
  // dapib 内部 try/catch 会把异常当 tanswer 回传；这里兜底
  if (result === null) { console.error('ERR ' + e.message); process.exit(1); }
}
process.stdout.write(JSON.stringify(result ? result.tanswer : null));
