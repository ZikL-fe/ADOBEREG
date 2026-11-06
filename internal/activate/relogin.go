package activate

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Relogin signs an already-activated sub back in and returns a pool cookie
// line. It does not create the Adobe account again.
func Relogin(ctx context.Context, in Input) (Result, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" {
		return Result{}, errRelogin("缺邮箱")
	}
	if strings.TrimSpace(in.Proxy) == "" {
		return Result{}, errRelogin("没有代理")
	}
	if in.Pool == nil {
		return Result{}, errRelogin("没有出站连接池")
	}
	ua := strings.TrimSpace(in.UA)
	devicePath := strings.TrimSpace(in.DevicePath)
	if devicePath == "" && in.Profile != nil {
		devicePath = in.Profile.File
	}
	if dUA := deviceUA(devicePath); dUA != "" {
		ua = dUA
	}
	sess := openSession(in.Pool, in.Proxy, ua)
	note(in, "Cookie 失效了，用原密码重新登录")
	tr := tracker{}
	line, err := loginLine(ctx, sess, &tr, email, in.Secret, uuid.NewString(), "", in.Log)
	if err != nil {
		fallback := cookiePoolLine(ctx, email, sess)
		if strings.Contains(fallback, "ims_sid=") {
			note(in, "登录凭证已经拿到")
			return Result{OK: true, Touched: true, Message: "重新登录成功", Line: fallback}, nil
		}
		return Result{Touched: true, Message: err.Error()}, err
	}
	if !strings.Contains(line, "ims_sid=") {
		return Result{Touched: true, Message: "重新登录没拿到会话"}, errRelogin("重新登录没拿到会话")
	}
	note(in, "新的登录凭证到手")
	return Result{OK: true, Touched: true, Message: "重新登录成功", Line: line}, nil
}

type reloginErr string

func (e reloginErr) Error() string { return string(e) }

func errRelogin(msg string) error { return reloginErr(msg) }
