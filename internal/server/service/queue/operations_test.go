package queue

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/logkit"
)

func TestRoutePolicyInventory(t *testing.T) {
	generated := make(map[string]struct{}, len(v1.PlainQService_ServiceDesc.Methods))
	for _, method := range v1.PlainQService_ServiceDesc.Methods {
		fullMethod := fmt.Sprintf("/%s/%s", v1.PlainQService_ServiceDesc.ServiceName, method.MethodName)
		generated[fullMethod] = struct{}{}
		action, ok := legacyGRPCActionInventory[fullMethod]
		if !ok || !authz.ValidAction(action) {
			t.Errorf("generated RPC %q lacks a valid policy action", fullMethod)
		}
	}
	if len(generated) != len(legacyGRPCActionInventory) {
		t.Fatalf("gRPC policy inventory has %d entries, descriptor has %d", len(legacyGRPCActionInventory), len(generated))
	}

	service := NewService(&config.Config{AuthEnable: false}, logkit.NewNop(), &mockStorage{})
	routes := make(map[string]struct{})
	if err := chi.Walk(service.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes[method+" "+route] = struct{}{}

		return nil
	}); err != nil {
		t.Fatalf("walk HTTP routes: %v", err)
	}
	for route := range routes {
		action, ok := legacyHTTPActionInventory[route]
		if !ok || !authz.ValidAction(action) {
			t.Errorf("HTTP route %q lacks a valid policy action", route)
		}
	}
	if len(routes) != len(legacyHTTPActionInventory) {
		t.Fatalf("HTTP policy inventory has %d entries, router has %d", len(legacyHTTPActionInventory), len(routes))
	}
}
