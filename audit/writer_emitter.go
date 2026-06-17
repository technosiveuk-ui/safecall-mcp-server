package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
)

// WriterEmitter writes JSON-serialized audit events to an arbitrary io.Writer.
// It is safe for concurrent use.
//
// IMPORTANT for stdio MCP servers: the MCP transport speaks JSON-RPC over
// stdin/stdout, so stdout IS the protocol channel. Emitting audit lines to
// os.Stdout injects non-protocol data into the stream and corrupts/desyncs the
// client connection. On a stdio server always use NewStderrEmitter (or a
// file-backed emitter) — never NewStdoutEmitter.
type WriterEmitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewWriterEmitter creates an emitter that writes to the given writer. Useful
// for testing and for routing audit output to any sink (file, ring buffer,
// network, etc.).
func NewWriterEmitter(w io.Writer) *WriterEmitter {
	return &WriterEmitter{enc: json.NewEncoder(w)}
}

// NewStderrEmitter creates an emitter that writes to os.Stderr. This is the
// correct default for a stdio MCP server, where stdout is reserved for the
// JSON-RPC protocol and must stay clean.
func NewStderrEmitter() *WriterEmitter {
	return &WriterEmitter{enc: json.NewEncoder(os.Stderr)}
}

// NewStdoutEmitter creates an emitter that writes to os.Stdout.
//
// WARNING: do NOT use this on an MCP stdio server — stdout carries the
// JSON-RPC protocol and any non-protocol line will corrupt the client stream.
// It is provided only for non-stdio deployments (e.g. an HTTP/SSE MCP server,
// or a standalone CLI tool). Prefer NewStderrEmitter.
func NewStdoutEmitter() *WriterEmitter {
	return &WriterEmitter{enc: json.NewEncoder(os.Stdout)}
}

// Emit JSON-encodes the event and writes it as a single line.
func (e *WriterEmitter) Emit(_ context.Context, event AuditEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(event)
}
