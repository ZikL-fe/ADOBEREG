# 普号注册

纯协议的 Adobe 普号注册机。不打开浏览器，直接按接口建号、登录。

交流 QQ 群：727682537

## 成品

`成品` 目录是可以直接运行的完整程序。双击 `成品/普号注册.exe`。

请整目录一起使用。exe 旁边需要 `data` 和 `runtime`，单独把 exe 拷走开不起来。

第一次打开会检查 Node、Python、协议和设备指纹。邮箱和设置写在 exe 旁边的 `puhao.db`，这个库没有放进仓库。

## 打码

建号时 Adobe 会要求认图。程序把认图交给 YesCaptcha 自动提交，使用前要在界面里填写自己的打码密钥。没有密钥不能开始注册，这一步不是免打码。

代理按行填写。每次注册会换成新的 8 位 SID。

## 导入邮箱

一行一个：

```
邮箱----密码----ClientID----RefreshToken----辅助邮箱----辅助密码
```

也可以直接导 ReMail 取件邮箱（只有取件凭证，没有 OAuth）：

```
邮箱----remail----st_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## ReMail 取码邮箱

界面右侧「ReMail 取码邮箱」卡片对接 <https://remail.aishop6.com/docs> 的开放 API：

- 填 `rk-` 开头的 API Key，保存后点「检测密钥 / 项目」，会回显余额和当前可下单的项目。
- 项目编号填 0 时自动挑第一个「已上架且该购买方式有货」的项目；后缀填 `outlook` / `outlook.com` / `domain` 等，留空由服务端随机。
- 「拉号入库」按「本地注册数量」买邮箱，下单返回的 `deliveryEmail` 直接进邮箱池，`serviceToken` 存成 `remail----<token>`。
- 勾上「开始前自动补号」，点「开始注册」时会先把缺的数量补齐再开跑。

接口对应关系：

| 用途 | 接口 | 鉴权 |
| --- | --- | --- |
| 查密钥余额 | `GET /v1/open/apikey/profile` | 需要 API Key |
| 查项目/库存 | `GET /v1/open/projects` | 需要 API Key |
| 下单买邮箱 | `POST /v1/open/orders?serviceMode=code\|purchase` | 需要 API Key + `Idempotency-Key` |
| 读邮件列表 | `GET /v1/pickup?email=&token=` | 只要邮箱 + serviceToken |
| 读单封正文 | `GET /v1/pickup/messages/{id}?email=&token=` | 只要邮箱 + serviceToken |

注册流程里的验证码就是走 pickup 读出来的：`internal/mail` 的 `Session` 按凭据前缀路由到 ReMail 通道，`waitCode` 会遵守接口返回的 `fetch.nextFetchAllowedAt` 再轮询，不会空转刷接口。

自建/镜像地址可以用 `REMAIL_BASE` 环境变量或界面里的「接口地址」覆盖。

## 从源码构建

需要 Go 1.24，在仓库根目录执行：

```
go build -trimpath -ldflags "-H windowsgui -s -w" -o 成品/普号注册.exe ./puhao
```

开发时可以：

```
go run ./puhao --no-open
```

然后打开 http://127.0.0.1:17620/

界面标题栏可以打开积分号购买和本仓库。
