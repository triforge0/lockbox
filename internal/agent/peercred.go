package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// errPeerCheckUnsupported is returned by the platform peer-credential probe on
// systems where we cannot identify the connecting process. On those platforms
// authorize fails open (preserving behaviour) rather than locking the user out.
var errPeerCheckUnsupported = errors.New("peer credential check unsupported on this platform")

// peerExecutable resolves the executable path of the process on the other end of
// a Unix-domain connection. It is a package var so tests can substitute a stub.
// The real implementation is platform specific (see peercred_*.go).
var peerExecutable = peerExecutableImpl

// authorize reports whether the peer of conn is allowed to use the session. Only
// a process running the *same binary* as this agent is permitted, so that no
// other local process — even one running as the same user — can drive the key.
//
// Non-Unix connections (e.g. the net.Pipe used in unit tests) and platforms
// without peer-credential support are allowed: the check is a hardening layer on
// top of the socket's 0600 permissions, not the only line of defence.
func (a *agent) authorize(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	peer, err := peerExecutable(uc)
	if errors.Is(err, errPeerCheckUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("identify peer: %w", err)
	}
	if !sameFile(peer, a.selfExe) {
		return fmt.Errorf("peer executable %q is not this binary", peer)
	}
	return nil
}

// sameFile reports whether two paths refer to the same on-disk file. Comparing
// by device+inode (via os.SameFile) is robust to symlinks and to the different
// path spellings a launcher might use (e.g. a Homebrew symlink vs the real
// Cellar path).
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}
