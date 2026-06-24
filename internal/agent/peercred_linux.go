//go:build linux

package agent

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// peerExecutableImpl identifies the connecting process via SO_PEERCRED and reads
// its executable through /proc/<pid>/exe.
func peerExecutableImpl(conn *net.UnixConn) (string, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return "", err
	}
	if credErr != nil {
		return "", credErr
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", cred.Pid))
}
