package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"ezstore/internal/domain"
	"ezstore/internal/service"
)

// Server is a stdio MCP endpoint bound to one authenticated actor.
type Server struct {
	secrets *service.SecretService
	tokens  *service.TokenService
	audit   *service.AuditService
	actor   domain.Actor
	version string

	in  io.Reader
	out io.Writer
	log *log.Logger
}

// Options configures a Server.
type Options struct {
	Secrets *service.SecretService
	Tokens  *service.TokenService
	Audit   *service.AuditService
	Actor   domain.Actor
	Version string
	In      io.Reader
	Out     io.Writer
	Log     *log.Logger
}

// New builds a Server.
func New(opts Options) *Server {
	return &Server{
		secrets: opts.Secrets,
		tokens:  opts.Tokens,
		audit:   opts.Audit,
		actor:   opts.Actor,
		version: opts.Version,
		in:      opts.In,
		out:     opts.Out,
		log:     opts.Log,
	}
}

// Run reads newline-delimited JSON-RPC messages until stdin closes.
func (s *Server) Run(ctx context.Context) error {
	reader := bufio.NewReaderSize(s.in, 64*1024)
	writer := bufio.NewWriterSize(s.out, 64*1024)
	defer writer.Flush()

	for {
		line, err := reader.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			s.handle(ctx, writer, trimmed)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (s *Server) handle(ctx context.Context, w *bufio.Writer, line []byte) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		s.write(w, response{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeParseError, Message: "parse error"}})
		return
	}
	// Notifications carry no id and must never be answered.
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		s.write(w, response{JSONRPC: jsonRPCVersion, ID: req.ID, Result: s.initialize(req.Params)})
	case "notifications/initialized", "notifications/cancelled":
		return
	case "ping":
		s.write(w, response{JSONRPC: jsonRPCVersion, ID: req.ID, Result: map[string]any{}})
	case "tools/list":
		s.write(w, response{JSONRPC: jsonRPCVersion, ID: req.ID, Result: map[string]any{"tools": toolDefinitions()}})
	case "tools/call":
		result, rpcErr := s.callTool(ctx, req.Params)
		if rpcErr != nil {
			s.write(w, response{JSONRPC: jsonRPCVersion, ID: req.ID, Error: rpcErr})
			return
		}
		s.write(w, response{JSONRPC: jsonRPCVersion, ID: req.ID, Result: result})
	default:
		if !isNotification {
			s.write(w, response{JSONRPC: jsonRPCVersion, ID: req.ID,
				Error: &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}})
		}
	}
}

func (s *Server) write(w *bufio.Writer, resp response) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		s.log.Printf("mcp: write response: %v", err)
		return
	}
	if err := w.Flush(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		s.log.Printf("mcp: flush: %v", err)
	}
}

func (s *Server) initialize(raw json.RawMessage) map[string]any {
	version := "2025-06-18"
	var params initParams
	if len(raw) > 0 && json.Unmarshal(raw, &params) == nil {
		switch params.ProtocolVersion {
		case "2024-11-05", "2025-03-26", "2025-06-18":
			version = params.ProtocolVersion
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "ezstore", "version": s.version},
	}
}

// callTool dispatches one tools/call. Protocol level problems become JSON-RPC
// errors; domain problems become tool results with isError set so the model
// sees the message and can correct itself.
func (s *Server) callTool(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
	var params callParams
	if len(raw) == 0 {
		return nil, &rpcError{Code: codeInvalidParams, Message: "missing params"}
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
	}

	handler, ok := s.toolHandlers()[params.Name]
	if !ok {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool: " + params.Name}
	}
	result, err := handler(ctx, params.Arguments)
	if err != nil {
		return errorContent(err.Error()), nil
	}
	return result, nil
}

func (s *Server) toolHandlers() map[string]func(context.Context, json.RawMessage) (callResult, error) {
	return map[string]func(context.Context, json.RawMessage) (callResult, error){
		"secret_get":      s.toolGet,
		"secret_put":      s.toolPut,
		"secret_list":     s.toolList,
		"secret_delete":   s.toolDelete,
		"secret_history":  s.toolHistory,
		"secret_rollback": s.toolRollback,
	}
}

// encode renders a tool payload as one compact JSON text block.
func encode(v any) (callResult, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return callResult{}, fmt.Errorf("encode result: %w", err)
	}
	return textContent(string(buf)), nil
}
