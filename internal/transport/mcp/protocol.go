// Package mcp implements a Model Context Protocol server over stdio.
//
// It speaks newline-delimited JSON-RPC 2.0 and exposes exactly one kind of
// capability: secret CRUD. There is no tool that returns anything but what the
// caller explicitly asked for, and every call is bound to the actor resolved
// from EZSTORE_TOKEN at start-up.
package mcp

import (
	"encoding/json"
)

const (
	jsonRPCVersion = "2.0"

	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// request is one JSON-RPC message read from stdin.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// response is one JSON-RPC reply written to stdout.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// tool is an MCP tool descriptor.
type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// callResult is the MCP tools/call payload.
type callResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textContent(text string) callResult {
	return callResult{Content: []content{{Type: "text", Text: text}}}
}

func errorContent(text string) callResult {
	return callResult{Content: []content{{Type: "text", Text: text}}, IsError: true}
}

// callParams is the tools/call argument envelope.
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// initParams is the subset of initialize params this server uses.
type initParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}
