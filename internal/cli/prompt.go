package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// readPassword prompts on stderr and reads without echo so the value never
// reaches the terminal scrollback.
func readPassword() ([]byte, error) {
	fmt.Fprint(os.Stderr, "value: ")
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return value, nil
}
