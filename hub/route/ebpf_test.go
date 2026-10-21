//go:build with_ebpf && (linux || android)

package route

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestEBPFDiagnosticsControllerAuthentication(t *testing.T) {
	handler := router(false, "diagnostic-secret", "", Cors{})
	for _, test := range []struct {
		token  string
		status int
	}{{"", http.StatusUnauthorized}, {"Bearer wrong", http.StatusUnauthorized}, {"Bearer diagnostic-secret", http.StatusOK}} {
		request := httptest.NewRequest(http.MethodGet, "/ebpf", nil)
		request.Header.Set("Authorization", test.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("token %q: status %d, want %d", test.token, response.Code, test.status)
		}
		if test.status == http.StatusOK {
			var result struct {
				Inbounds []json.RawMessage `json:"inbounds"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Inbounds == nil {
				t.Fatal("empty active inbounds must be an array")
			}
		}
	}
}
