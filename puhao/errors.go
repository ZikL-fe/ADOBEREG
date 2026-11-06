package main

import "errors"

var (
	errBusy    = errors.New("已有注册任务在跑")
	errNoKey   = errors.New("先填写 YesCaptcha 密钥")
	errNoProxy = errors.New("先填写代理")
	errNone    = errors.New("没有可注册的邮箱")
)
