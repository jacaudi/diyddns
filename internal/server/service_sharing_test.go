package server

import "testing"

// TestBuildMux_SharesServiceInstancesWithWebUI proves api.Build and
// webui.New receive the IDENTICAL *service.XxxService pointers for Devices,
// Enroll, Admin, and Grants — not merely identically-configured ones. All
// four services are stateless wrappers over *store.Store with no
// instance-local mutable cache, so two separately-constructed instances
// given the same arguments would behave identically at runtime; pointer
// identity is the only property that can ever catch a regression back to
// per-adapter construction (see webui.Deps's doc comment in webui.go and
// buildMux's "One construction site per service" comment in server.go).
func TestBuildMux_SharesServiceInstancesWithWebUI(t *testing.T) {
	// Deliberately not t.Parallel(): store.Migrate (internal/store/migrate.go)
	// calls goose's package-level SetBaseFS/SetDialect with no synchronization,
	// which races under -race against other tests that open a store — see
	// TestWebUIPatternsAreReachable in routes_test.go.
	_, _, apiDeps, webDeps, err := buildMux(routesTestConfig(t), openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	if apiDeps.Devices == nil || webDeps.Devices == nil {
		t.Fatal("expected non-nil DeviceService on both sides")
	}
	if apiDeps.Devices != webDeps.Devices {
		t.Error("api.Build and webui.New received different *service.DeviceService instances")
	}

	if apiDeps.Enroll == nil || webDeps.Enroll == nil {
		t.Fatal("expected non-nil EnrollmentService on both sides")
	}
	if apiDeps.Enroll != webDeps.Enroll {
		t.Error("api.Build and webui.New received different *service.EnrollmentService instances")
	}

	if apiDeps.Admin == nil || webDeps.Admin == nil {
		t.Fatal("expected non-nil AdminService on both sides")
	}
	if apiDeps.Admin != webDeps.Admin {
		t.Error("api.Build and webui.New received different *service.AdminService instances")
	}

	if apiDeps.Grants == nil || webDeps.Grants == nil {
		t.Fatal("expected non-nil GrantService on both sides")
	}
	if apiDeps.Grants != webDeps.Grants {
		t.Error("api.Build and webui.New received different *service.GrantService instances")
	}
}
