// Command ezstore is an encrypted, versioned secret store with multi-agent
// scopes, an HTTP API and an MCP server.
package main

import (
	"os"

	"ezstore/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
