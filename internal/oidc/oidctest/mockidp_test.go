package oidctest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func TestMockIdP_DiscoveryAdvertisesDeviceOnlyWhenEnabled(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	resp, err := http.Get(idp.Issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc["issuer"] != idp.Issuer {
		t.Fatalf("issuer mismatch: %v != %v", doc["issuer"], idp.Issuer)
	}
	if _, ok := doc["device_authorization_endpoint"]; !ok {
		t.Fatal("expected device endpoint advertised")
	}
}
