// SPDX-License-Identifier: MPL-2.0

package wasm

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wippyai/runtime/api/registry"
	wasmcomponent "github.com/wippyai/runtime/runtime/wasm/component"
	wasmrt "github.com/wippyai/wasm-runtime/runtime"
	"go.uber.org/zap"
)

func TestWASISocketsProbeReallyConnects(t *testing.T) {
	path := os.Getenv("WASM_SOCKETS_PROBE")
	target := os.Getenv("WASM_SOCKETS_TARGET")
	if path == "" || target == "" {
		t.Skip("set WASM_SOCKETS_PROBE and WASM_SOCKETS_TARGET")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read probe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rt, err := wasmrt.New(ctx)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	defer func() { _ = rt.Close(ctx) }()

	hosts := wasmcomponent.NewHostRegistry()
	if err := hosts.RegisterProfiles(DefaultHostProfiles(zap.NewNop(), nil)...); err != nil {
		t.Fatalf("register profiles: %v", err)
	}
	imports := []registry.ID{
		registry.ParseID("wasi:io"),
		registry.ParseID("wasi:cli"),
		registry.ParseID("wasi:clocks"),
		registry.ParseID("wasi:filesystem"),
		registry.ParseID("wasi:random"),
		registry.ParseID("wasi:sockets"),
	}
	if err := hosts.EnsureImports(ctx, rt, imports, true); err != nil {
		t.Fatalf("bind hosts: %v", err)
	}

	module, err := rt.LoadComponent(ctx, data)
	if err != nil {
		t.Fatalf("load component: %v", err)
	}
	if err := module.Compile(ctx); err != nil {
		t.Fatalf("compile component: %v", err)
	}

	instance, err := module.Instantiate(ctx)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	defer func() { _ = instance.Close(ctx) }()

	out, err := instance.Call(ctx, "probe", target)
	if err != nil {
		t.Fatalf("call probe: %v", err)
	}
	t.Logf("PROBE ANSWER for %s: %#v", target, out)

	line, ok := out.(string)
	if !ok || line == "" {
		t.Fatalf("probe returned nothing usable: %#v", out)
	}
	if len(line) > 3 && line[:3] == "ERR" {
		t.Fatalf("probe failed inside the guest: %s", line)
	}
}
