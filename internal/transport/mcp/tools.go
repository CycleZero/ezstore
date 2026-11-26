package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

func decodeArguments(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	return json.Unmarshal(raw, v)
}

// --- tool schemas ---

func toolDefinitions() []tool {
	return []tool{
		{
			Name: "secret_get",
			Description: "Read one secret value. Returns the plaintext secret plus its version. " +
				"Every read is written to the audit log.",
			InputSchema: objectSchema(map[string]any{
				"name":    stringProp("Slash separated secret name, for example team/stripe-key"),
				"version": integerProp("Exact version to read; omit for the current version"),
			}, "name"),
		},
		{
			Name: "secret_put",
			Description: "Create a new version of a secret. Returns the new version number. " +
				"Tags are merged with the existing ones.",
			InputSchema: objectSchema(map[string]any{
				"name":  stringProp("Slash separated secret name"),
				"value": stringProp("Secret value in plain text"),
				"tags": map[string]any{
					"type":                 "object",
					"description":          "Optional string tags used for grouping and lookup",
					"additionalProperties": map[string]any{"type": "string"},
				},
			}, "name", "value"),
		},
		{
			Name: "secret_list",
			Description: "List secret names and metadata under a prefix. Never returns values; " +
				"call secret_get for a value.",
			InputSchema: objectSchema(map[string]any{
				"prefix": stringProp("Only return names under this prefix, for example team/"),
				"tag":    stringProp("Filter by tag: \"key\" for presence or \"key=value\" for a match"),
				"limit":  integerProp("Maximum number of names to return"),
			}),
		},
		{
			Name: "secret_delete",
			Description: "Delete a secret. By default the name is soft deleted and its history is kept; " +
				"purge removes every version permanently.",
			InputSchema: objectSchema(map[string]any{
				"name":  stringProp("Slash separated secret name"),
				"purge": booleanProp("Permanently remove the secret and all versions"),
			}, "name"),
		},
		{
			Name:        "secret_history",
			Description: "List version metadata for a secret, newest first. Values are not returned.",
			InputSchema: objectSchema(map[string]any{
				"name":  stringProp("Slash separated secret name"),
				"limit": integerProp("Maximum number of versions to return"),
			}, "name"),
		},
		{
			Name: "secret_rollback",
			Description: "Copy an older version into a new version. History is never rewritten, " +
				"so a rollback can itself be rolled back.",
			InputSchema: objectSchema(map[string]any{
				"name":    stringProp("Slash separated secret name"),
				"version": integerProp("Version to restore"),
			}, "name", "version"),
		},
	}
}

func objectSchema(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func stringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func integerProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func booleanProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

// --- tool implementations ---

type getArgs struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
}

type getPayload struct {
	Name      string            `json:"name"`
	Value     string            `json:"value"`
	Version   int64             `json:"version"`
	Tags      map[string]string `json:"tags,omitempty"`
	CreatedAt string            `json:"created_at"`
}

func (s *Server) toolGet(ctx context.Context, raw json.RawMessage) (callResult, error) {
	var args getArgs
	if err := decodeArguments(raw, &args); err != nil {
		return callResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	v, err := s.secrets.Get(ctx, s.actor, args.Name, args.Version)
	if err != nil {
		return callResult{}, err
	}
	return encode(getPayload{
		Name:      v.Name,
		Value:     string(v.Value),
		Version:   v.Version,
		Tags:      v.Tags,
		CreatedAt: v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}

type putArgs struct {
	Name  string            `json:"name"`
	Value string            `json:"value"`
	Tags  map[string]string `json:"tags"`
}

type putPayload struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
}

func (s *Server) toolPut(ctx context.Context, raw json.RawMessage) (callResult, error) {
	var args putArgs
	if err := decodeArguments(raw, &args); err != nil {
		return callResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	version, err := s.secrets.Put(ctx, s.actor, args.Name, []byte(args.Value), args.Tags)
	if err != nil {
		return callResult{}, err
	}
	return encode(putPayload{Name: args.Name, Version: version})
}

type listArgs struct {
	Prefix string `json:"prefix"`
	Tag    string `json:"tag"`
	Limit  int    `json:"limit"`
}

type listItem struct {
	Name           string            `json:"name"`
	Tags           map[string]string `json:"tags,omitempty"`
	CurrentVersion int64             `json:"current_version"`
	UpdatedAt      string            `json:"updated_at"`
}

func (s *Server) toolList(ctx context.Context, raw json.RawMessage) (callResult, error) {
	var args listArgs
	if err := decodeArguments(raw, &args); err != nil {
		return callResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	items, err := s.secrets.List(ctx, s.actor, args.Prefix, args.Tag, args.Limit)
	if err != nil {
		return callResult{}, err
	}
	out := make([]listItem, 0, len(items))
	for _, item := range items {
		out = append(out, listItem{
			Name:           item.Name,
			Tags:           item.Tags,
			CurrentVersion: item.CurrentVersion,
			UpdatedAt:      item.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return encode(map[string]any{"secrets": out, "count": len(out)})
}

type deleteArgs struct {
	Name  string `json:"name"`
	Purge bool   `json:"purge"`
}

func (s *Server) toolDelete(ctx context.Context, raw json.RawMessage) (callResult, error) {
	var args deleteArgs
	if err := decodeArguments(raw, &args); err != nil {
		return callResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	if err := s.secrets.Delete(ctx, s.actor, args.Name, args.Purge); err != nil {
		return callResult{}, err
	}
	return encode(map[string]bool{"deleted": true, "purged": args.Purge})
}

type historyArgs struct {
	Name  string `json:"name"`
	Limit int    `json:"limit"`
}

type historyItem struct {
	Version   int64  `json:"version"`
	Checksum  string `json:"checksum"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

func (s *Server) toolHistory(ctx context.Context, raw json.RawMessage) (callResult, error) {
	var args historyArgs
	if err := decodeArguments(raw, &args); err != nil {
		return callResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	items, err := s.secrets.History(ctx, s.actor, args.Name, args.Limit)
	if err != nil {
		return callResult{}, err
	}
	out := make([]historyItem, 0, len(items))
	for _, item := range items {
		out = append(out, historyItem{
			Version:   item.Version,
			Checksum:  item.Checksum,
			CreatedAt: item.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			CreatedBy: item.CreatedBy,
		})
	}
	return encode(map[string]any{"versions": out, "count": len(out)})
}

type rollbackArgs struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
}

func (s *Server) toolRollback(ctx context.Context, raw json.RawMessage) (callResult, error) {
	var args rollbackArgs
	if err := decodeArguments(raw, &args); err != nil {
		return callResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	version, err := s.secrets.Rollback(ctx, s.actor, args.Name, args.Version)
	if err != nil {
		return callResult{}, err
	}
	return encode(putPayload{Name: args.Name, Version: version})
}
