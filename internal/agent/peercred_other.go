//go:build !linux && !darwin

package agent

import "net"

// peerExecutableImpl is a stub for platforms without a supported
// peer-credential mechanism (e.g. Windows). authorize treats
// errPeerCheckUnsupported as "allow", preserving the prior behaviour where the
// socket's file permissions are the only access control.
func peerExecutableImpl(*net.UnixConn) (string, error) {
	return "", errPeerCheckUnsupported
}
