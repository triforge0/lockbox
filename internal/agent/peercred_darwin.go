//go:build darwin

package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// Constants not exported by the standard syscall package on darwin.
const (
	sysSOLLocal     = 0     // SOL_LOCAL
	sysLocalPeerPID = 0x002 // LOCAL_PEERPID
	sysCTLKern      = 1     // CTL_KERN
	sysKernArgmax   = 8     // KERN_ARGMAX
	sysKernProcArgs = 49    // KERN_PROCARGS2
)

// peerExecutableImpl identifies the connecting process via LOCAL_PEERPID and
// resolves its executable path through the KERN_PROCARGS2 sysctl. macOS has no
// /proc, so the path comes from the process argument area, whose layout is:
// [int32 argc][executable path \0...][argv strings].
func peerExecutableImpl(conn *net.UnixConn) (string, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var pid int
	var pidErr error
	if err := rc.Control(func(fd uintptr) {
		pid, pidErr = syscall.GetsockoptInt(int(fd), sysSOLLocal, sysLocalPeerPID)
	}); err != nil {
		return "", err
	}
	if pidErr != nil {
		return "", pidErr
	}
	return pidPath(pid)
}

func pidPath(pid int) (string, error) {
	size, err := sysctlUint32([]int32{sysCTLKern, sysKernArgmax})
	if err != nil || size == 0 {
		size = 1 << 18 // 256 KiB fallback if KERN_ARGMAX is unavailable
	}
	buf := make([]byte, size)
	n, err := sysctlRaw([]int32{sysCTLKern, sysKernProcArgs, int32(pid)}, buf)
	if err != nil {
		return "", err
	}
	if n < 4 {
		return "", errors.New("procargs2 response too short")
	}
	// Skip the leading argc (int32); the executable path follows as a C string.
	path := buf[4:n]
	if i := bytes.IndexByte(path, 0); i >= 0 {
		path = path[:i]
	}
	if len(path) == 0 {
		return "", errors.New("empty executable path")
	}
	return string(path), nil
}

func sysctlRaw(mib []int32, out []byte) (int, error) {
	n := uintptr(len(out))
	var p unsafe.Pointer
	if len(out) > 0 {
		p = unsafe.Pointer(&out[0])
	}
	if _, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(p), uintptr(unsafe.Pointer(&n)),
		0, 0,
	); errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func sysctlUint32(mib []int32) (uint32, error) {
	out := make([]byte, 4)
	n, err := sysctlRaw(mib, out)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, errors.New("short sysctl response")
	}
	return binary.LittleEndian.Uint32(out), nil
}
