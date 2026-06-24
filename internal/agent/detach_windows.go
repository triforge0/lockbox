//go:build windows

package agent

import "syscall"

// Windows process creation flags (not all are exported by the syscall package).
const (
	detachedProcess       = 0x00000008 // DETACHED_PROCESS
	createNewProcessGroup = 0x00000200 // CREATE_NEW_PROCESS_GROUP
)

// detachSysProcAttr starts the agent detached from the console so it keeps
// running after the launching command window closes, with no visible window.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup,
		HideWindow:    true,
	}
}
