package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/haze518/mcpshield/internal/mcp"
)

const defaultMaxResponseBytes = 4 << 20 // 4 MiB

// UpstreamMetrics is satisfied by observability.Registry.
// Defining the interface here avoids an import cycle between transport and observability.
type UpstreamMetrics interface {
	IncUpstreamProtocolError(upstreamID string)
	IncUpstreamResponseTooLarge(upstreamID string)
}

// MCPHTTPClient makes JSON-RPC 2.0 calls to a single upstream MCP server
// over HTTP POST to a single endpoint.
type MCPHTTPClient struct {
	upstreamID       string
	baseURL          string
	headers          map[string]string
	httpClient       *http.Client
	nextID           atomic.Int64
	maxResponseBytes int64
	metrics          UpstreamMetrics
}

func NewMCPHTTPClient(upstreamID, baseURL string, headers map[string]string) *MCPHTTPClient {
	return &MCPHTTPClient{
		upstreamID:       upstreamID,
		baseURL:          baseURL,
		headers:          headers,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		maxResponseBytes: defaultMaxResponseBytes,
	}
}

// SetMetrics wires optional upstream metrics into the client.
func (c *MCPHTTPClient) SetMetrics(m UpstreamMetrics) { c.metrics = m }

func (c *MCPHTTPClient) ToolsList(ctx context.Context) ([]mcp.Tool, error) {
	var result mcp.ToolsListResult
	if err := c.call(ctx, "tools/list", nil, &result); err != nil {
		return nil, err
	}
	return result.Tools, nil
}

func (c *MCPHTTPClient) ToolsCall(ctx context.Context, req *mcp.ToolsCallRequest) (*mcp.ToolsCallResult, error) {
	params, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	var result mcp.ToolsCallResult
	if err := c.call(ctx, "tools/call", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// byteCountReader wraps a reader and accumulates the total bytes read.
// Used to detect oversized upstream responses without buffering the full body.
type byteCountReader struct {
	r io.Reader
	n int64
}

func (c *byteCountReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// rpcEnvelope is the JSON-RPC 2.0 request sent to upstream.
type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcReply is the JSON-RPC 2.0 response received from upstream.
type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *mcp.Error      `json:"error"`
}

func (c *MCPHTTPClient) call(ctx context.Context, method string, params json.RawMessage, out any) error {
	id := c.nextID.Add(1)

	body, err := json.Marshal(rpcEnvelope{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer httpResp.Body.Close()

	// Validate HTTP status code.
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("upstream returned HTTP %d", httpResp.StatusCode)
	}

	// Stream-decode the response through a size-tracking reader.
	// This avoids buffering the full body before parsing and halves peak
	// memory per request compared to io.ReadAll + json.Unmarshal.
	// LimitReader(body, maxResponseBytes+1) caps total bytes read; if the
	// counter exceeds maxResponseBytes after (or during) decoding, reject.
	cr := &byteCountReader{r: io.LimitReader(httpResp.Body, c.maxResponseBytes+1)}
	var reply rpcReply
	dec := json.NewDecoder(cr)
	decodeErr := dec.Decode(&reply)
	if cr.n > c.maxResponseBytes {
		if c.metrics != nil {
			c.metrics.IncUpstreamResponseTooLarge(c.upstreamID)
		}
		return fmt.Errorf("upstream response exceeded %d bytes", c.maxResponseBytes)
	}
	if decodeErr != nil {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("decode response: %w", decodeErr)
	}
	// Reject trailing data after the JSON object.
	if _, trailErr := dec.Token(); trailErr != io.EOF {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("upstream: trailing data after JSON object")
	}

	// Validate JSON-RPC version.
	if reply.JSONRPC != "2.0" {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("upstream: unexpected jsonrpc version %q", reply.JSONRPC)
	}

	// Validate that response ID matches sent ID.
	var receivedID int64
	if err := json.Unmarshal(reply.ID, &receivedID); err != nil || receivedID != id {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("upstream: response ID mismatch (sent %d, got %s)", id, reply.ID)
	}

	// Require exactly one of result or error (not both, not neither).
	if reply.Error != nil && reply.Result != nil {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("upstream: response has both result and error")
	}
	if reply.Error == nil && reply.Result == nil {
		if c.metrics != nil {
			c.metrics.IncUpstreamProtocolError(c.upstreamID)
		}
		return fmt.Errorf("upstream: response has neither result nor error")
	}

	if reply.Error != nil {
		return fmt.Errorf("upstream rpc error %d: %s", reply.Error.Code, reply.Error.Message)
	}
	if err := json.Unmarshal(reply.Result, out); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	return nil
}
