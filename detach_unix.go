//go:build !windows

package main

import "syscall"

// detachSysProcAttr starts the agent in its own session (setsid) so it survives
// the launching shell and detaches from the controlling terminal.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
