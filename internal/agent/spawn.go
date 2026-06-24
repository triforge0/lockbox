package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// agentSubcommand is the hidden subcommand the binary re-execs as to become the
// background daemon. The CLI dispatch must route this to Run.
const agentSubcommand = "__agent"

// Spawn launches a detached agent process for the named vault and hands it the
// derived key and salt over a stdin pipe. It returns once the agent's socket is
// responsive.
func Spawn(name string, key, salt []byte) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}

	// Detach stdout/stderr from the terminal so the agent keeps running after
	// the launching shell exits and prints nothing.
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devnull.Close()

	cmd := exec.Command(self, agentSubcommand)
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = detachSysProcAttr()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("create stdin pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	hs := handshake{
		Vault: name,
		Key:   base64.StdEncoding.EncodeToString(key),
		Salt:  base64.StdEncoding.EncodeToString(salt),
	}
	if err := json.NewEncoder(stdin).Encode(hs); err != nil {
		stdin.Close()
		return fmt.Errorf("send handshake: %w", err)
	}
	stdin.Close()

	// Let the detached process run independently of this one.
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release agent: %w", err)
	}

	// Wait for the agent to start listening (bounded).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if Alive(name) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("agent did not become ready")
}

// IsAgentInvocation reports whether the given CLI args mean "run as the daemon".
// main/cli use this to route to Run.
func IsAgentInvocation(command string) bool {
	return command == agentSubcommand
}
