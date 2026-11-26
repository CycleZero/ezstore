package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"ezstore/internal/crypto"
	"ezstore/internal/domain"
	"ezstore/internal/repository/gormstore"
	"ezstore/internal/service"
	"ezstore/internal/transport/mcp"
)

func newServer(t *testing.T, in string, actor domain.Actor) (*bytes.Buffer, error) {
	t.Helper()
	store, err := gormstore.Open("sqlite", filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key, _ := crypto.GenerateKey()
	cipher, _ := crypto.New(key)
	audit := service.NewAuditService(store)

	out := &bytes.Buffer{}
	server := mcp.New(mcp.Options{
		Secrets: service.NewSecretService(store, cipher, audit, 0),
		Tokens:  service.NewTokenService(store),
		Audit:   audit,
		Actor:   actor,
		Version: "test",
		In:      strings.NewReader(in),
		Out:     out,
		Log:     log.New(io.Discard, "", 0),
	})
	return out, server.Run(context.Background())
}

func decodeResponses(t *testing.T, out *bytes.Buffer) []map[string]any {
	t.Helper()
	var messages []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		messages = append(messages, msg)
	}
	return messages
}

func TestMCPToolFlow(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secret_put","arguments":{"name":"team/x","value":"v1"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"secret_get","arguments":{"name":"team/x"}}}`,
	}, "\n") + "\n"

	out, err := newServer(t, input, domain.SystemActor())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	messages := decodeResponses(t, out)
	if len(messages) != 4 {
		t.Fatalf("got %d responses, want 4 (notifications must be silent)", len(messages))
	}

	initResult, _ := messages[0]["result"].(map[string]any)
	if initResult["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion = %v", initResult["protocolVersion"])
	}
	serverInfo, _ := initResult["serverInfo"].(map[string]any)
	if serverInfo["name"] != "ezstore" {
		t.Fatalf("serverInfo = %v", serverInfo)
	}

	listResult, _ := messages[1]["result"].(map[string]any)
	tools, _ := listResult["tools"].([]any)
	if len(tools) != 6 {
		t.Fatalf("tool count = %d, want 6", len(tools))
	}

	putResult, _ := messages[2]["result"].(map[string]any)
	putText := firstText(t, putResult)
	if !strings.Contains(putText, `"version":1`) {
		t.Fatalf("put result = %s", putText)
	}

	getResult, _ := messages[3]["result"].(map[string]any)
	getText := firstText(t, getResult)
	if !strings.Contains(getText, `"value":"v1"`) {
		t.Fatalf("get result = %s", getText)
	}
}

func TestMCPPermissionErrorIsToolError(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secret_get","arguments":{"name":"team/x"}}}` + "\n"
	actor := domain.Actor{ID: "limited", Scopes: []string{"other/**"}, Perms: []string{"read"}}

	out, err := newServer(t, input, actor)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	messages := decodeResponses(t, out)
	if len(messages) != 1 {
		t.Fatalf("got %d responses", len(messages))
	}
	result, _ := messages[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("expected isError result, got %v", result)
	}
	if messages[0]["error"] != nil {
		t.Fatalf("domain errors must not become JSON-RPC errors: %v", messages[0]["error"])
	}
}

func TestMCPUnknownToolIsProtocolError(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}` + "\n"
	out, err := newServer(t, input, domain.SystemActor())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	messages := decodeResponses(t, out)
	rpcErr, _ := messages[0]["error"].(map[string]any)
	if rpcErr == nil {
		t.Fatalf("expected a JSON-RPC error, got %v", messages[0])
	}
	if code, _ := rpcErr["code"].(float64); int(code) != -32602 {
		t.Fatalf("error code = %v, want -32602", rpcErr["code"])
	}
}

func firstText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("empty content: %v", result)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}
