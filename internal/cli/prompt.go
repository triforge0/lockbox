package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// stdin is a single shared buffered reader. Using one reader for the whole
// program avoids losing input: a fresh bufio.Reader per call would buffer and
// discard any bytes past the first line, which breaks piped/scripted input.
var stdin = bufio.NewReader(os.Stdin)

// readLine reads a single trimmed line of visible input from stdin.
func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := stdin.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readSecret reads a line of input without echoing it to the terminal. When
// stdin is not a terminal (e.g. piped input in scripts/tests) it falls back to
// a normal line read so the tool remains usable in automation.
func readSecret(prompt string) (string, error) {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return readLine("")
	}
	b, err := term.ReadPassword(fd)
	fmt.Println() // ReadPassword swallows the newline; restore it
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readMasterPassword prompts once for an existing vault's master password.
func readMasterPassword() (string, error) {
	pw, err := readSecret("Master password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errors.New("master password cannot be empty")
	}
	return pw, nil
}

// readNewMasterPassword prompts twice and requires the entries to match. Used
// when creating a vault so a typo can't lock the user out.
func readNewMasterPassword() (string, error) {
	pw, err := readSecret("Choose a master password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errors.New("master password cannot be empty")
	}
	confirm, err := readSecret("Confirm master password: ")
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", errors.New("passwords do not match")
	}
	return pw, nil
}
