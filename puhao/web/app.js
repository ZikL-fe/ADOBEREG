const COUNTRIES = ["SG", "JP", "US", "DE", "GB", "CA", "AU", "FR", "NL", "KR", "TW", "HK", "IN", "PH", "ID", "MY", "TH", "VN", "BR"];
const STATUS = { pending: "待注册", running: "注册中", activated: "已注册", failed: "失败" };
const $ = (id) => document.getElementById(id);
const sel = new Set();
let settingsReady = false;
let page = 1;
let pageSizeReady = false;
let lastState = null;

$("country").innerHTML = COUNTRIES.map((c) => `<option value="${c}">${c}</option>`).join("");

async function api(path, opt) {
  const res = await fetch(path, opt);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "请求失败");
  return data;
}

function fillSettings(s) {
  if (settingsReady) return;
  $("key").value = s.captchaKey || "";
  $("proxies").value = s.proxies || "";
  $("country").value = COUNTRIES.includes(s.country) ? s.country : "US";
  $("count").value = s.count || 0;
  $("conc").value = s.concurrency || 1;
  settingsReady = true;
}

function readSettings() {
  return {
    captchaKey: $("key").value.trim(),
    proxies: $("proxies").value,
    country: $("country").value,
    count: Number($("count").value) || 0,
    concurrency: Number($("conc").value) || 1,
    intervalSec: 0,
  };
}

async function saveSettings() {
  await api("/api/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(readSettings()) });
  $("saveMsg").textContent = "已保存";
}

function pageSize() {
  const n = Number($("pageSize").value);
  if (!Number.isFinite(n) || n < 10) return 10;
  if (n > 500) return 500;
  return Math.floor(n);
}

function render(state) {
  lastState = state;
  fillSettings(state.settings || {});
  if (!pageSizeReady) {
    const saved = Number(localStorage.getItem("puhao.pageSize"));
    $("pageSize").value = saved >= 10 && saved <= 500 ? saved : 50;
    pageSizeReady = true;
  }
  const sum = state.sum || {};
  $("sum").innerHTML = [
    ["邮箱", sum.total || 0, ""],
    ["已注册", sum.activated || 0, "ok"],
    ["待注册", sum.pending || 0, ""],
    ["注册中", sum.running || 0, "run"],
    ["失败", sum.failed || 0, "bad"],
  ].map(([n, v, c]) => `<span class="chip ${c}">${n} ${v}</span>`).join("");
  const accounts = state.accounts || [];
  const size = pageSize();
  const pages = Math.max(1, Math.ceil(accounts.length / size));
  if (page > pages) page = pages;
  if (page < 1) page = 1;
  const slice = accounts.slice((page - 1) * size, page * size);
  const pageIds = slice.map((a) => a.id);
  $("pageAll").checked = pageIds.length > 0 && pageIds.every((id) => sel.has(id));
  $("pageAll").indeterminate = pageIds.some((id) => sel.has(id)) && !$("pageAll").checked;
  $("rows").innerHTML = slice.map((a) => `<tr class="${sel.has(a.id) ? "on" : ""}">
    <td><input type="checkbox" data-id="${a.id}" ${sel.has(a.id) ? "checked" : ""} /></td>
    <td>${esc(a.email)}${a.ready ? "" : " · 凭据不完整"}</td>
    <td class="st-${a.status}">${STATUS[a.status] || a.status}</td>
    <td>${esc(a.country || "")}</td>
    <td>${a.tries || 0}</td>
    <td>${esc(a.message || "")}${a.hasCookie ? " · 可导出" : ""}</td>
  </tr>`).join("");
  const picked = accounts.filter((a) => sel.has(a.id)).length;
  $("pageInfo").textContent = accounts.length ? `${page} / ${pages}　已选 ${picked}` : "0 / 1";
  $("log").innerHTML = (state.logs || []).slice(-80).map((l) => {
    const t = new Date(l.t).toLocaleTimeString();
    return `<span class="lv-${l.level}">${t} ${esc(l.msg)}</span>`;
  }).join("\n");
  $("log").scrollTop = $("log").scrollHeight;
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

async function refresh() {
  try {
    render(await api("/api/state"));
    if (!envSettled) await loadEnv();
  } catch (err) {
    $("saveMsg").textContent = err.message;
  }
}

let envSettled = false;
async function loadEnv() {
  const env = await api("/api/env");
  let text = "环境未就绪";
  let cls = "bad";
  if (env.checking) {
    text = "正在检查环境";
    cls = "";
  } else if (env.ready && env.protocol) {
    text = "协议已就绪";
    cls = "ok";
    envSettled = true;
  } else {
    envSettled = true;
  }
  $("env").innerHTML = `<span class="chip ${cls}">${text}</span>`;
}

$("rows").addEventListener("change", (ev) => {
  const id = ev.target.getAttribute("data-id");
  if (!id) return;
  if (ev.target.checked) sel.add(id);
  else sel.delete(id);
  if (lastState) render(lastState);
});

$("save").onclick = () => saveSettings().catch((e) => { $("saveMsg").textContent = e.message; });
$("initEnv").onclick = async () => {
  $("saveMsg").textContent = "正在初始化环境";
  try {
    const r = await api("/api/env/init", { method: "POST" });
    $("saveMsg").textContent = r.ok ? "环境已就绪" : "环境还没齐";
    await loadEnv();
    await refresh();
  } catch (e) { $("saveMsg").textContent = e.message; }
};
$("doImport").onclick = async () => {
  try {
    await saveSettings();
    const r = await api("/api/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: $("import").value }) });
    $("import").value = "";
    $("saveMsg").textContent = `新增 ${r.added}，更新 ${r.updated}`;
    await refresh();
  } catch (e) { $("saveMsg").textContent = e.message; }
};
$("startLocal").onclick = () => start({ all: true });
$("startSel").onclick = () => start({ ids: [...sel] });
async function start(body) {
  try {
    await saveSettings();
    const r = await api("/api/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    $("saveMsg").textContent = `已开始 ${r.count} 个`;
    await refresh();
  } catch (e) { $("saveMsg").textContent = e.message; }
}
$("stop").onclick = () => api("/api/stop", { method: "POST" }).then(refresh).catch((e) => { $("saveMsg").textContent = e.message; });
$("del").onclick = () => api("/api/delete", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids: [...sel] }) }).then(() => { sel.clear(); return refresh(); });
$("pageSize").addEventListener("change", () => {
  const n = pageSize();
  $("pageSize").value = n;
  localStorage.setItem("puhao.pageSize", String(n));
  page = 1;
  if (lastState) render(lastState);
});
$("prev").onclick = () => { if (page > 1) { page--; if (lastState) render(lastState); } };
$("next").onclick = () => {
  const total = (lastState && lastState.accounts || []).length;
  const pages = Math.max(1, Math.ceil(total / pageSize()));
  if (page < pages) { page++; if (lastState) render(lastState); }
};
$("pageAll").addEventListener("change", () => {
  document.querySelectorAll("#rows input[data-id]").forEach((el) => {
    const id = el.getAttribute("data-id");
    if ($("pageAll").checked) sel.add(id);
    else sel.delete(id);
  });
  if (lastState) render(lastState);
});
async function downloadExport(ids) {
  const opt = ids
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids }) }
    : undefined;
  const res = await fetch("/api/export", opt);
  const kind = res.headers.get("content-type") || "";
  if (!res.ok || kind.includes("application/json")) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || "导出失败");
  }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cookies.txt";
  a.click();
  URL.revokeObjectURL(a.href);
}
$("expAll").onclick = () => downloadExport().catch((e) => { $("saveMsg").textContent = e.message; });
$("expSel").onclick = () => {
  if (sel.size === 0) { $("saveMsg").textContent = "先勾选要导出的邮箱"; return; }
  downloadExport([...sel]).catch((e) => { $("saveMsg").textContent = e.message; });
};
function win(action) {
  fetch("/api/window/" + action, { method: "POST" }).catch(() => {});
}
function openLink(url) {
  fetch("/api/open", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) }).catch(() => {});
}
$("buy").onclick = () => openLink("https://cookieauto.com/register?invite=RUS99UJJ");
$("repo").onclick = () => openLink("https://github.com/lichao199208/ADOBEREG");
$("min").onclick = () => win("minimize");
$("close").onclick = () => win("close");
$("drag").addEventListener("mousedown", (ev) => {
  if (ev.button === 0) win("drag");
});

loadEnv();
refresh();
setInterval(refresh, 1500);
