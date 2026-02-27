package mcp

import "encoding/json"

// JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeServerError    = -32000
	CodePolicyDenied   = -32001
	CodeUnauthorized   = -32002
	CodeRateLimited    = -32003
)

// NullID is a JSON null value used when the request id cannot be determined.
var NullID = json.RawMessage("null")

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type ToolsCallRequest struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type ToolsCallResult struct {
	Content []Content `json:"content"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ---- initialize types ---------------------------------------------------

// InitializeRequest holds the params sent by the client in the initialize call.
type InitializeRequest struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo,omitempty"`
}

// ClientCapabilities are the capabilities the client advertises (accepted, not enforced).
type ClientCapabilities struct{}

// ClientInfo is the client's self-identification.
type ClientInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// InitializeResult is the gateway's response to the initialize request.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// ServerCapabilities declares which MCP capabilities the gateway supports.
type ServerCapabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability signals support for tools/list and tools/call.
type ToolsCapability struct{}

// ServerInfo identifies the gateway to clients.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
