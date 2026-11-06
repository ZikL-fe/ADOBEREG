# 把普号注册打成可拷走的桌面目录：exe + 协议 + Node + Python + 设备指纹。
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $here
$out = Join-Path $here "dist"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null

Push-Location $repo
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-H windowsgui -s -w" -o (Join-Path $out "普号注册.exe") ./puhao
Pop-Location

function Copy-Tree($src, $dst, $extra) {
  if (-not (Test-Path $src)) { throw "缺少 $src" }
  New-Item -ItemType Directory -Path $dst -Force | Out-Null
  $rc = @($src, $dst, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/nc", "/ns", "/np", "/XD", "__pycache__", ".git") + $extra
  & robocopy @rc | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "复制失败 $src -> $dst ($LASTEXITCODE)" }
}

Copy-Tree (Join-Path $repo "data\activate") (Join-Path $out "data\activate") @("/XF", "last_*.json", "grab_fresh.json")
Copy-Tree (Join-Path $repo "data\arksandbox") (Join-Path $out "data\arksandbox") @()
$profiles = Join-Path $repo "dist\data\arksandbox\profiles"
if (Test-Path $profiles) {
  Copy-Tree $profiles (Join-Path $out "data\arksandbox\profiles") @()
}
Copy-Tree (Join-Path $repo "dist\runtime") (Join-Path $out "runtime") @()

Write-Host "完成: $out"
Write-Host "双击 普号注册.exe 打开界面。整个 dist 目录可以拷到别的 Windows 机器。"
