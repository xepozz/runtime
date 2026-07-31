// SPDX-License-Identifier: MPL-2.0

// Package coresock gives core wasm modules an outbound TCP capability.
//
// WASI Preview 1 has no outbound socket and no resolver, so a guest built against it
// cannot connect however it is linked. wasi:sockets answers this for components, but
// a core module cannot import it. This host is the core-module equivalent: the host
// owns the connection and the guest moves bytes through its own memory.
//
// TCP rather than HTTP on purpose. With a byte stream the guest keeps its own TLS and
// its own protocol code, so an interpreter's standard library works unmodified
// instead of every HTTP client needing a special case.
//
// Integer-only signatures, because that is all a core import can express:
//
//	connect(host_ptr, host_len, port, timeout_ms) -> i64   status<<32 | handle
//	send(handle, buf_ptr, buf_len)                -> i64   status<<32 | written
//	recv(handle, out_ptr, out_cap)                -> i64   status<<32 | read (0=EOF)
//	close(handle)                                 -> i32   status
package coresock

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"

	"github.com/wippyai/runtime/runtime/security"
)

// Namespace is the import module name a core guest declares.
const Namespace = "wippy:sock/tcp"

// Status codes returned in the high half of the i64 result.
const (
	StatusOK            uint32 = 0
	StatusBadRequest    uint32 = 1
	StatusDenied        uint32 = 2
	StatusTransport     uint32 = 3
	StatusUnknownHandle uint32 = 4
	StatusTooMany       uint32 = 5
)

const (
	maxHostLen     = 253
	maxChunkBytes  = 1 << 20
	maxConnections = 16
	defaultTimeout = 30 * time.Second
	// connectAction gates every dial, so a guest that was not granted it cannot
	// reach the network even though the host can.
	connectAction = "wippy.sock.connect"
)

// Host serves TCP calls for core modules.
type Host struct {
	log   *zap.Logger
	conns map[uint32]net.Conn
	mu    sync.Mutex
	next  uint32
}

// New builds a TCP host.
func New(log *zap.Logger) *Host {
	return &Host{log: log, conns: make(map[uint32]net.Conn)}
}

func pack(status, value uint32) uint64 {
	return uint64(status)<<32 | uint64(value)
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// checkTarget mirrors the Lua http_client policy: a private address needs its own
// permission, so a guest cannot use the host as a way into the local network.
func checkTarget(ctx context.Context, host string) error {
	if host == "" || len(host) > maxHostLen {
		return fmt.Errorf("host is empty or too long")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) && !security.IsAllowed(ctx, "http_client.private_ip", host, nil) {
			return fmt.Errorf("not allowed: private IP %s", host)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s", host)
	}
	for _, ip := range ips {
		if isPrivateIP(ip) && !security.IsAllowed(ctx, "http_client.private_ip", ip.String(), nil) {
			return fmt.Errorf("not allowed: private IP %s", ip.String())
		}
	}
	return nil
}

// Connect dials a TCP connection and retains it behind a handle.
func (h *Host) Connect(ctx context.Context, mod api.Module, stack []uint64) {
	hostPtr, hostLen := uint32(stack[0]), uint32(stack[1])
	port, timeoutMS := uint32(stack[2]), uint32(stack[3])

	if hostLen == 0 || hostLen > maxHostLen || port == 0 || port > 65535 {
		stack[0] = pack(StatusBadRequest, 0)
		return
	}
	raw, ok := mod.Memory().Read(hostPtr, hostLen)
	if !ok {
		stack[0] = pack(StatusBadRequest, 0)
		return
	}
	host := string(raw)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if !security.IsAllowed(ctx, connectAction, target, nil) {
		stack[0] = pack(StatusDenied, 0)
		return
	}
	if err := checkTarget(ctx, host); err != nil {
		if h.log != nil {
			h.log.Debug("core socket connect denied", zap.String("target", target), zap.Error(err))
		}
		stack[0] = pack(StatusDenied, 0)
		return
	}

	h.mu.Lock()
	live := len(h.conns)
	h.mu.Unlock()
	if live >= maxConnections {
		stack[0] = pack(StatusTooMany, 0)
		return
	}

	timeout := defaultTimeout
	if timeoutMS > 0 {
		timeout = time.Duration(timeoutMS) * time.Millisecond
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if h.log != nil {
			h.log.Debug("core socket connect failed", zap.String("target", target), zap.Error(err))
		}
		stack[0] = pack(StatusTransport, 0)
		return
	}

	h.mu.Lock()
	h.next++
	if h.next == 0 {
		h.next = 1
	}
	handle := h.next
	h.conns[handle] = conn
	h.mu.Unlock()

	stack[0] = pack(StatusOK, handle)
}

func (h *Host) conn(handle uint32) (net.Conn, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.conns[handle]
	return c, ok
}

// Send writes one chunk from guest memory.
func (h *Host) Send(_ context.Context, mod api.Module, stack []uint64) {
	handle, bufPtr, bufLen := uint32(stack[0]), uint32(stack[1]), uint32(stack[2])

	conn, ok := h.conn(handle)
	if !ok {
		stack[0] = pack(StatusUnknownHandle, 0)
		return
	}
	if bufLen > maxChunkBytes {
		stack[0] = pack(StatusBadRequest, 0)
		return
	}
	payload, ok := mod.Memory().Read(bufPtr, bufLen)
	if !ok {
		stack[0] = pack(StatusBadRequest, 0)
		return
	}

	written, err := conn.Write(payload)
	if err != nil {
		stack[0] = pack(StatusTransport, uint32(written))
		return
	}
	stack[0] = pack(StatusOK, uint32(written))
}

// Recv reads one chunk into guest memory. A read of zero means the peer closed.
func (h *Host) Recv(_ context.Context, mod api.Module, stack []uint64) {
	handle, outPtr, outCap := uint32(stack[0]), uint32(stack[1]), uint32(stack[2])

	conn, ok := h.conn(handle)
	if !ok {
		stack[0] = pack(StatusUnknownHandle, 0)
		return
	}
	if outCap == 0 || outCap > maxChunkBytes {
		stack[0] = pack(StatusBadRequest, 0)
		return
	}

	buf := make([]byte, outCap)
	n, err := conn.Read(buf)
	if n > 0 {
		if !mod.Memory().Write(outPtr, buf[:n]) {
			stack[0] = pack(StatusBadRequest, 0)
			return
		}
	}
	if err != nil && n == 0 {
		// EOF is not a transport failure: it is how the peer says it is done.
		stack[0] = pack(StatusOK, 0)
		return
	}
	stack[0] = pack(StatusOK, uint32(n))
}

// Close releases a connection.
func (h *Host) Close(_ context.Context, _ api.Module, stack []uint64) {
	handle := uint32(stack[0])

	h.mu.Lock()
	conn, ok := h.conns[handle]
	delete(h.conns, handle)
	h.mu.Unlock()

	if !ok {
		stack[0] = uint64(StatusUnknownHandle)
		return
	}
	_ = conn.Close()
	stack[0] = uint64(StatusOK)
}

// CloseAll drops every retained connection; called when an instance goes away.
func (h *Host) CloseAll() {
	h.mu.Lock()
	conns := h.conns
	h.conns = make(map[uint32]net.Conn)
	h.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// LiveConnections reports retained connections, for tests and diagnostics.
func (h *Host) LiveConnections() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}
