//go:build !windows

package main

import "os/exec"

func hideCmd(cmd *exec.Cmd) {}

func runWindow(string) { select {} }

func focusExisting() {}

func postWindow(uint32) {}

func openBrowser(string) {}
