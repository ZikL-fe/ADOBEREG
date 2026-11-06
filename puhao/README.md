# 普号注册

独立桌面程序。注册流程用的是主项目里的普号建号（`activate.RunPlain`），界面、邮箱列表和结果都在这个目录里。

这个目录属于主模块 `firefly-go`，这样才能直接调用普号建号代码。开发时在仓库根目录执行：

```
go run ./puhao --no-open
```

然后打开 http://127.0.0.1:17620/ 。不加 `--no-open` 会打开 1100×720 的无边框窗口。

打包：

```
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

产物在 `dist\`：

- `普号注册.exe`
- `data\activate` 协议和认图脚本
- `data\arksandbox` 设备指纹
- `runtime\node`、`runtime\python` 配套环境

把整个 `dist` 拷走即可，双击 exe。邮箱和设置写在 exe 同级的 `puhao.db`，Cookie 从界面导出。

导入格式与补号相同：`主邮箱----密码----ClientID----RefreshToken----辅助邮箱----辅助密码`。
