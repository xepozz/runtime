// SPDX-License-Identifier: MPL-2.0

package coresock

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	ctxapi "github.com/wippyai/runtime/api/context"
	netapi "github.com/wippyai/runtime/api/net"
	"github.com/wippyai/runtime/api/registry"
	securityapi "github.com/wippyai/runtime/api/security"
)

// overlayContext selects an overlay network the way the runtime does: the effective
// ID lives on the FrameContext, written there by the executor from per-call options,
// per-entry meta.options.network, or the app default.
func overlayContext(t *testing.T, networkID string, permitted bool) context.Context {
	t.Helper()
	ctx := ctxapi.NewRootContext()
	// Strict mode denies when the security context is incomplete, which is the
	// behavior a guest sees by default. Relaxing it stands in for a grant.
	ctx = securityapi.SetStrictMode(ctx, !permitted)
	ctx, fc := ctxapi.OpenFrameContext(ctx)
	t.Cleanup(func() { ctxapi.ReleaseFrameContext(fc) })
	if err := fc.SetMultiple(netapi.DefaultNetworkPair(networkID)); err != nil {
		t.Fatalf("select overlay network: %v", err)
	}
	return ctx
}

var errNotUsed = errors.New("not used by these tests")

type stubRegistry struct {
	svc netapi.Service
	err error
}

func (s stubRegistry) GetNetwork(registry.ID) (netapi.Service, error) { return s.svc, s.err }
func (s stubRegistry) HasNetwork(registry.ID) bool                    { return s.svc != nil }
func (s stubRegistry) NetworkKind(registry.ID) string                 { return "net.overlay" }

type stubService struct {
	dialed chan string
}

// Only DialContext matters here; the rest of netapi.Service exists so the stub
// satisfies the interface the registry hands back.
func (s stubService) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, errNotUsed
}

func (s stubService) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errNotUsed
}

func (s stubService) LookupHost(context.Context, string) ([]string, error) {
	return nil, errNotUsed
}

func (s stubService) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	select {
	case s.dialed <- address:
	default:
	}
	client, server := net.Pipe()
	go func() { _ = server.Close() }()
	return client, nil
}

// A guest must be routed by the network the application selected, exactly as
// host-side code is. Dialing clearnet instead would leak DNS and the target address.
func TestOverlayNetworkIsUsedWhenSelected(t *testing.T) {
	dialed := make(chan string, 1)
	ctx := netapi.WithNetworkRegistry(
		overlayContext(t, "network:tor", true), stubRegistry{svc: stubService{dialed: dialed}})

	host := New(nil)
	conn, err := host.dial(ctx, "example.com", "example.com:443", 5*time.Second)
	if err != nil {
		t.Fatalf("dial through the overlay failed: %v", err)
	}
	defer conn.Close()

	select {
	case address := <-dialed:
		if address != "example.com:443" {
			t.Errorf("overlay dialed %q, want example.com:443", address)
		}
	case <-time.After(time.Second):
		t.Fatal("the overlay dialer was never called, so the guest bypassed it")
	}
}

// Falling back to clearnet when an overlay was asked for would defeat the overlay
// silently, which is worse than refusing.
func TestOverlayRequestedWithoutRegistryIsRefused(t *testing.T) {
	ctx := overlayContext(t, "network:tor", true)

	host := New(nil)
	conn, err := host.dial(ctx, "example.com", "example.com:443", time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("an overlay request with no registry must be refused, not dialed over clearnet")
	}
	t.Logf("refused: %v", err)
}

func TestPrivateAddressNeedsPermission(t *testing.T) {
	host := New(nil)
	_, err := host.dial(context.Background(), "127.0.0.1", "127.0.0.1:9", time.Second)
	if err == nil {
		t.Fatal("a loopback address must require the private-IP permission")
	}
	t.Logf("refused: %v", err)
}

// network.select is what gates overlay use for Lua, and it gates the guest the same
// way: without the permission the dial is refused rather than downgraded.
func TestOverlaySelectionNeedsPermission(t *testing.T) {
	dialed := make(chan string, 1)
	ctx := netapi.WithNetworkRegistry(
		overlayContext(t, "network:tor", false), stubRegistry{svc: stubService{dialed: dialed}})

	host := New(nil)
	conn, err := host.dial(ctx, "example.com", "example.com:443", time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("network.select was not granted, so the dial must be refused")
	}
	if len(dialed) != 0 {
		t.Fatal("the overlay was dialed despite the permission being denied")
	}
	t.Logf("refused: %v", err)
}
