// SPDX-License-Identifier: MPL-2.0

package wasm

import (
	"context"

	"github.com/tetratelabs/wazero/api"

	"github.com/wippyai/runtime/api/dispatcher"
	runtimewasm "github.com/wippyai/runtime/runtime/wasm"
	wasmcomponent "github.com/wippyai/runtime/runtime/wasm/component"
	"github.com/wippyai/runtime/runtime/wasm/host/wippy/hosts/coresock"
	wasmrt "github.com/wippyai/wasm-runtime/runtime"
	"github.com/wippyai/wasm-runtime/wasi/preview2"
	"go.uber.org/zap"
)

// hostFactory creates hosts backed by a shared resource table.
type hostFactory func(resources *preview2.ResourceTable) []wasmrt.Host

// DefaultHostProfiles returns the default WASM host profiles wired by boot.
func DefaultHostProfiles(log *zap.Logger, disp dispatcher.Dispatcher) []wasmcomponent.HostProfile {
	return []wasmcomponent.HostProfile{
		funcsHostProfile(log),
		wasi1HostProfile(),
		wasiIOProfile(log),
		wasiPollProfile(log),
		wasiClocksProfile(log),
		wasiCLIProfile(log),
		wasiFilesystemProfile(log),
		wasiRandomProfile(log),
		wasiSocketsProfile(log),
		wasiHTTPProfile(disp, log),
		coreSockProfile(log),
	}
}

// getSharedResources retrieves or creates the shared ResourceTable from the HostRegistry in context.
func getSharedResources(ctx context.Context) *preview2.ResourceTable {
	reg := wasmcomponent.GetHostRegistry(ctx)
	if reg == nil {
		return preview2.NewResourceTable()
	}
	if res := reg.SharedResources(); res != nil {
		return res.(*preview2.ResourceTable)
	}
	rt := preview2.NewResourceTable()
	reg.SetSharedResources(rt)
	return rt
}

func registerHosts(ctx context.Context, rt *wasmrt.Runtime, factories []hostFactory, log *zap.Logger, profileName string) error {
	resources := getSharedResources(ctx)
	for _, factory := range factories {
		for _, host := range factory(resources) {
			if err := rt.RegisterHost(host); err != nil {
				return runtimewasm.NewRegisterHostError(host.Namespace(), err)
			}
		}
	}
	if log != nil {
		log.Info("wasm host profile registered", zap.String("profile", profileName))
	}
	return nil
}

func wasiIOProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASIIO,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASIIO}, ioAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{ioHosts}, log, wasmcomponent.HostProfileWASIIO)
		},
	}
}

func wasiPollProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASIPoll,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASIPoll}, pollAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{pollHosts}, log, wasmcomponent.HostProfileWASIPoll)
		},
	}
}

func wasiClocksProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASIClocks,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASIClocks}, clocksAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{clocksHosts}, log, wasmcomponent.HostProfileWASIClocks)
		},
	}
}

func wasiCLIProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASICLI,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASICLI}, cliAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{cliHosts}, log, wasmcomponent.HostProfileWASICLI)
		},
	}
}

func wasiFilesystemProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASIFilesystem,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASIFilesystem}, filesystemAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{filesystemHosts}, log, wasmcomponent.HostProfileWASIFilesystem)
		},
	}
}

func wasiRandomProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASIRandom,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASIRandom}, randomAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{randomHosts}, log, wasmcomponent.HostProfileWASIRandom)
		},
	}
}

func wasiSocketsProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASISockets,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASISockets}, socketsAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			return registerHosts(ctx, rt, []hostFactory{socketsHosts}, log, wasmcomponent.HostProfileWASISockets)
		},
	}
}

func wasiHTTPProfile(d dispatcher.Dispatcher, log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:          wasmcomponent.HostProfileWASIHTTP,
		ComponentOnly: true,
		Aliases:       append([]string{wasmcomponent.HostProfileWASIHTTP}, httpAliases...),
		Register: func(ctx context.Context, rt *wasmrt.Runtime) error {
			if d == nil {
				return runtimewasm.ErrDispatcherNotFound
			}
			return registerHosts(ctx, rt, []hostFactory{httpHosts}, log, wasmcomponent.HostProfileWASIHTTP)
		},
	}
}

// coreSockProfile exposes outbound TCP to core modules.
//
// Deliberately not ComponentOnly: wasi:sockets and wasi:http both are, so a core
// module has no way to reach the network at all. The signatures are raw integers
// because that is what a core import can express, and the calls are async so the
// guest yields while the host waits on the connection.
func coreSockProfile(log *zap.Logger) wasmcomponent.HostProfile {
	return wasmcomponent.HostProfile{
		Name:    coresock.Namespace,
		Aliases: []string{coresock.Namespace, "wippy:sock"},
		Register: func(_ context.Context, rt *wasmrt.Runtime) error {
			host := coresock.New(log)
			i32, i64 := api.ValueTypeI32, api.ValueTypeI64

			// Registered synchronous on purpose. Declaring them async makes the
			// engine asyncify-transform the whole guest, and instrumenting a 10 MB
			// interpreter pushes wazero's compile past the runtime's 30s entry-load
			// timeout. The guest call is synchronous anyway, so the host blocking on
			// the socket is exactly the required behavior.
			register := func(name string, params, results []api.ValueType, fn api.GoModuleFunc) error {
				if err := rt.RegisterCoreFunc(coresock.Namespace, name, params, results, fn, false); err != nil {
					return runtimewasm.NewRegisterHostError(coresock.Namespace, err)
				}
				return nil
			}

			if err := register("connect",
				[]api.ValueType{i32, i32, i32, i32}, []api.ValueType{i64}, host.Connect); err != nil {
				return err
			}
			if err := register("send",
				[]api.ValueType{i32, i32, i32}, []api.ValueType{i64}, host.Send); err != nil {
				return err
			}
			if err := register("recv",
				[]api.ValueType{i32, i32, i32}, []api.ValueType{i64}, host.Recv); err != nil {
				return err
			}
			if err := register("close",
				[]api.ValueType{i32}, []api.ValueType{i32}, host.Close); err != nil {
				return err
			}

			log.Info("wasm host profile registered", zap.String("profile", coresock.Namespace))
			return nil
		},
	}
}
