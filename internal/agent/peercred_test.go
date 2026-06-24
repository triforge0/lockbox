package agent

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// unixConnPair returns a connected pair of *net.UnixConn over a short-named
// socket (macOS limits socket paths to ~104 bytes, so we avoid t.TempDir which
// can be long). The server side mirrors what agent.Run authorizes. Peer
// credentials are not part of the model on Windows (peercred_other.go fails
// open), so the unix-socket tests skip there.
func unixConnPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix-domain peer credentials are not used on Windows")
	}
	dir, err := os.MkdirTemp(shortTempBase(), "lbpc")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	ln, err := net.Listen("unix", filepath.Join(dir, "s.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { r.c.Close() })
	return r.c.(*net.UnixConn), c.(*net.UnixConn)
}

// shortTempBase returns a short base directory for the test socket. /tmp keeps
// the socket path under the ~104-byte limit on macOS/BSD; os.TempDir is the
// portable fallback when /tmp is absent.
func shortTempBase() string {
	if _, err := os.Stat("/tmp"); err == nil {
		return "/tmp"
	}
	return os.TempDir()
}

// TestAuthorizeAllowsSameBinary exercises the real platform peer-credential
// probe: the connecting peer is this very test process, so its executable
// matches the agent's selfExe and the connection is authorized.
func TestAuthorizeAllowsSameBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable: %v", err)
	}
	server, _ := unixConnPair(t)
	a := &agent{selfExe: exe}

	if err := a.authorize(server); err != nil {
		// On a platform without peer-cred support this still passes (authorize
		// fails open), which is the documented behaviour.
		t.Errorf("authorize rejected the same binary: %v", err)
	}
}

// TestAuthorizeRejectsForeignBinary simulates a different process (e.g. the PoC
// attacker) connecting to the socket: its executable differs from the agent's,
// so authorize must reject it.
func TestAuthorizeRejectsForeignBinary(t *testing.T) {
	// A real, distinct file standing in for the attacker's executable.
	foreign := filepath.Join(t.TempDir(), "attacker")
	if err := os.WriteFile(foreign, []byte("x"), 0o755); err != nil {
		t.Fatalf("write foreign: %v", err)
	}

	orig := peerExecutable
	peerExecutable = func(*net.UnixConn) (string, error) { return foreign, nil }
	t.Cleanup(func() { peerExecutable = orig })

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable: %v", err)
	}
	server, _ := unixConnPair(t)
	a := &agent{selfExe: exe}

	if err := a.authorize(server); err == nil {
		t.Error("authorize accepted a foreign executable; the socket is not protected")
	}
}

// TestAuthorizeAllowsNonUnixConn ensures the in-memory net.Pipe used by other
// unit tests (and any non-Unix transport) is not blocked by the check.
func TestAuthorizeAllowsNonUnixConn(t *testing.T) {
	c, _ := net.Pipe()
	t.Cleanup(func() { c.Close() })
	a := &agent{selfExe: "/does/not/matter"}
	if err := a.authorize(c); err != nil {
		t.Errorf("authorize rejected a non-unix conn: %v", err)
	}
}
