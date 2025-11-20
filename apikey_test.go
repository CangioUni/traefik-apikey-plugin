package traefik_apikey_plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	cfg := CreateConfig()
	cfg.HeaderName = "X-Custom-Key"
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "test-key",
			Subdomains: []string{"*"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	if handler == nil {
		t.Fatal("Handler should not be nil")
	}
}

func TestDefaultHeaderName(t *testing.T) {
	cfg := CreateConfig()
	cfg.HeaderName = ""

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	apiKeyAuth := handler.(*APIKeyAuth)
	if apiKeyAuth.headerName != "X-API-Key" {
		t.Errorf("Expected default header name 'X-API-Key', got '%s'", apiKeyAuth.headerName)
	}
}

func TestServeHTTP_MissingAPIKey(t *testing.T) {
	cfg := CreateConfig()
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "valid-key",
			Subdomains: []string{"*"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(ctx, next, cfg, "test-plugin")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestServeHTTP_ValidAPIKey(t *testing.T) {
	cfg := CreateConfig()
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "valid-key",
			Subdomains: []string{"*"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(ctx, next, cfg, "test-plugin")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-API-Key", "valid-key")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestServeHTTP_InvalidAPIKey(t *testing.T) {
	cfg := CreateConfig()
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "valid-key",
			Subdomains: []string{"*"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(ctx, next, cfg, "test-plugin")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestServeHTTP_CustomHeaderName(t *testing.T) {
	cfg := CreateConfig()
	cfg.HeaderName = "X-Custom-API-Key"
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "custom-key",
			Subdomains: []string{"*"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(ctx, next, cfg, "test-plugin")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-Custom-API-Key", "custom-key")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestMatchSubdomain_Wildcard(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	tests := []struct {
		host       string
		subdomains []string
		expected   bool
	}{
		{"example.com", []string{"*"}, true},
		{"api.example.com", []string{"*"}, true},
		{"test.example.com", []string{"*"}, true},
	}

	for _, tt := range tests {
		result := apiKeyAuth.matchSubdomain(tt.host, tt.subdomains)
		if result != tt.expected {
			t.Errorf("matchSubdomain(%s, %v) = %v, expected %v", tt.host, tt.subdomains, result, tt.expected)
		}
	}
}

func TestMatchSubdomain_Exact(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	tests := []struct {
		host       string
		subdomains []string
		expected   bool
	}{
		{"api.example.com", []string{"api.example.com"}, true},
		{"api.example.com", []string{"web.example.com"}, false},
		{"example.com", []string{"example.com", "api.example.com"}, true},
		{"test.example.com", []string{"api.example.com", "web.example.com"}, false},
	}

	for _, tt := range tests {
		result := apiKeyAuth.matchSubdomain(tt.host, tt.subdomains)
		if result != tt.expected {
			t.Errorf("matchSubdomain(%s, %v) = %v, expected %v", tt.host, tt.subdomains, result, tt.expected)
		}
	}
}

func TestMatchSubdomain_WildcardPrefix(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	tests := []struct {
		host       string
		subdomains []string
		expected   bool
	}{
		{"api.example.com", []string{"*.example.com"}, true},
		{"web.example.com", []string{"*.example.com"}, true},
		{"example.com", []string{"*.example.com"}, true},
		{"api.test.com", []string{"*.example.com"}, false},
	}

	for _, tt := range tests {
		result := apiKeyAuth.matchSubdomain(tt.host, tt.subdomains)
		if result != tt.expected {
			t.Errorf("matchSubdomain(%s, %v) = %v, expected %v", tt.host, tt.subdomains, result, tt.expected)
		}
	}
}

func TestMatchSubdomain_WithPort(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	tests := []struct {
		host       string
		subdomains []string
		expected   bool
	}{
		{"api.example.com:8080", []string{"api.example.com"}, true},
		{"example.com:443", []string{"example.com"}, true},
		{"test.example.com:3000", []string{"*.example.com"}, true},
	}

	for _, tt := range tests {
		result := apiKeyAuth.matchSubdomain(tt.host, tt.subdomains)
		if result != tt.expected {
			t.Errorf("matchSubdomain(%s, %v) = %v, expected %v", tt.host, tt.subdomains, result, tt.expected)
		}
	}
}

func TestMatchIP_DirectMatch(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	tests := []struct {
		clientIP   string
		allowedIPs []string
		expected   bool
	}{
		{"192.168.1.100", []string{"192.168.1.100"}, true},
		{"192.168.1.101", []string{"192.168.1.100"}, false},
		{"10.0.0.5", []string{"192.168.1.100", "10.0.0.5"}, true},
	}

	for _, tt := range tests {
		result := apiKeyAuth.matchIP(tt.clientIP, tt.allowedIPs)
		if result != tt.expected {
			t.Errorf("matchIP(%s, %v) = %v, expected %v", tt.clientIP, tt.allowedIPs, result, tt.expected)
		}
	}
}

func TestMatchIP_CIDR(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	tests := []struct {
		clientIP   string
		allowedIPs []string
		expected   bool
	}{
		{"192.168.1.100", []string{"192.168.1.0/24"}, true},
		{"192.168.1.1", []string{"192.168.1.0/24"}, true},
		{"192.168.2.1", []string{"192.168.1.0/24"}, false},
		{"10.0.0.50", []string{"10.0.0.0/16"}, true},
	}

	for _, tt := range tests {
		result := apiKeyAuth.matchIP(tt.clientIP, tt.allowedIPs)
		if result != tt.expected {
			t.Errorf("matchIP(%s, %v) = %v, expected %v", tt.clientIP, tt.allowedIPs, result, tt.expected)
		}
	}
}

func TestServeHTTP_SubdomainRestriction(t *testing.T) {
	cfg := CreateConfig()
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "api-key",
			Subdomains: []string{"api.example.com"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(ctx, next, cfg, "test-plugin")

	// Test with correct subdomain
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/test", nil)
	req.Header.Set("X-API-Key", "api-key")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d for correct subdomain, got %d", http.StatusOK, recorder.Code)
	}

	// Test with wrong subdomain
	req = httptest.NewRequest(http.MethodGet, "http://web.example.com/test", nil)
	req.Header.Set("X-API-Key", "api-key")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d for wrong subdomain, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestServeHTTP_IPRestriction(t *testing.T) {
	cfg := CreateConfig()
	cfg.AuthorizedKeys = []AuthorizedKey{
		{
			Key:        "api-key",
			Subdomains: []string{"*"},
			AllowedIPs: []string{"192.168.1.100"},
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(ctx, next, cfg, "test-plugin")

	// Test with allowed IP
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-API-Key", "api-key")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d for allowed IP, got %d", http.StatusOK, recorder.Code)
	}

	// Test with different IP
	req = httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-API-Key", "api-key")
	req.Header.Set("X-Forwarded-For", "192.168.1.200")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d for unauthorized IP, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"

	ip := getClientIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", ip)
	}
}

func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.50")
	req.RemoteAddr = "127.0.0.1:12345"

	ip := getClientIP(req)
	if ip != "192.168.1.50" {
		t.Errorf("Expected IP '192.168.1.50', got '%s'", ip)
	}
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.RemoteAddr = "192.168.1.75:54321"

	ip := getClientIP(req)
	if ip != "192.168.1.75" {
		t.Errorf("Expected IP '192.168.1.75', got '%s'", ip)
	}
}

func TestDenyAccess_HTMLResponse(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, _ := New(ctx, next, cfg, "test-plugin")
	apiKeyAuth := handler.(*APIKeyAuth)

	recorder := httptest.NewRecorder()
	apiKeyAuth.denyAccess(recorder, "Test error message")

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type 'text/html; charset=utf-8', got '%s'", contentType)
	}

	body := recorder.Body.String()
	if !contains(body, "Access Denied") {
		t.Error("Expected HTML body to contain 'Access Denied'")
	}
	if !contains(body, "Test error message") {
		t.Error("Expected HTML body to contain the error message")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
