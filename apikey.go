// Package traefik_apikey_plugin implements a Traefik middleware plugin for API key authentication
package traefik_apikey_plugin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Config holds the plugin configuration
type Config struct {
	HeaderName     string          `json:"headerName,omitempty"`
	AuthorizedKeys []AuthorizedKey `json:"authorizedKeys,omitempty"`
}

// AuthorizedKey represents an API key with its access rules
type AuthorizedKey struct {
	Key        string   `json:"key,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
	AllowedIPs []string `json:"allowedIPs,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		HeaderName:     "X-API-Key",
		AuthorizedKeys: []AuthorizedKey{},
	}
}

// APIKeyAuth is the plugin struct
type APIKeyAuth struct {
	next       http.Handler
	name       string
	config     *Config
	headerName string
}

// New creates a new APIKeyAuth plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.HeaderName == "" {
		config.HeaderName = "X-API-Key"
	}

	return &APIKeyAuth{
		next:       next,
		name:       name,
		config:     config,
		headerName: config.HeaderName,
	}, nil
}

func (a *APIKeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	apiKey := req.Header.Get(a.headerName)

	if apiKey == "" {
		a.denyAccess(rw, "Missing API Key")
		return
	}

	// Get client IP
	clientIP := getClientIP(req)
	host := req.Host

	// Check if API key is authorized
	authorized := false
	for _, authKey := range a.config.AuthorizedKeys {
		if authKey.Key == apiKey {
			// Check subdomain match
			if !a.matchSubdomain(host, authKey.Subdomains) {
				continue
			}

			// Check IP address if specified
			if len(authKey.AllowedIPs) > 0 && !a.matchIP(clientIP, authKey.AllowedIPs) {
				continue
			}

			authorized = true
			break
		}
	}

	if !authorized {
		a.denyAccess(rw, "Unauthorized API Key")
		return
	}

	a.next.ServeHTTP(rw, req)
}

// matchSubdomain checks if the host matches any of the allowed subdomains
func (a *APIKeyAuth) matchSubdomain(host string, subdomains []string) bool {
	if len(subdomains) == 0 {
		return true
	}

	// Remove port from host if present
	hostWithoutPort := host
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		hostWithoutPort = host[:colonIndex]
	}

	for _, subdomain := range subdomains {
		if subdomain == "*" {
			return true
		}
		if subdomain == hostWithoutPort {
			return true
		}
		// Support wildcard at the beginning (e.g., *.example.com)
		if strings.HasPrefix(subdomain, "*.") {
			domain := subdomain[2:]
			if strings.HasSuffix(hostWithoutPort, domain) {
				return true
			}
		}
	}

	return false
}

// matchIP checks if the client IP matches any of the allowed IPs
func (a *APIKeyAuth) matchIP(clientIP string, allowedIPs []string) bool {
	for _, allowedIP := range allowedIPs {
		// Check if allowedIP is a CIDR range
		if strings.Contains(allowedIP, "/") {
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err != nil {
				continue
			}
			ip := net.ParseIP(clientIP)
			if ip != nil && ipNet.Contains(ip) {
				return true
			}
		} else if clientIP == allowedIP {
			// Direct IP match
			return true
		}
	}
	return false
}

// getClientIP extracts the client IP from the request
func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header first
	forwarded := req.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the list
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	realIP := req.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// denyAccess sends an HTML response denying access
func (a *APIKeyAuth) denyAccess(rw http.ResponseWriter, message string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusUnauthorized)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a1a 0%%, #2d2d2d 100%%);
            color: #ffffff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: #222222;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            padding: 60px 40px;
            max-width: 600px;
            text-align: center;
            border: 1px solid #333333;
        }
        .icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: #ff3b3b;
            border-radius: 50%%;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 40px;
            box-shadow: 0 5px 20px rgba(255, 59, 59, 0.3);
        }
        h1 {
            font-size: 32px;
            margin-bottom: 20px;
            color: #ffffff;
            font-weight: 600;
        }
        .message {
            font-size: 18px;
            color: #b0b0b0;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        .error-code {
            display: inline-block;
            background: #333333;
            padding: 10px 20px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #ff3b3b;
            margin-top: 20px;
            border: 1px solid #444444;
        }
        .footer {
            margin-top: 40px;
            font-size: 14px;
            color: #666666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔒</div>
        <h1>Access Denied</h1>
        <div class="message">
            %s
            <br><br>
            You do not have permission to access this resource. Please ensure you have a valid API key and proper authorization.
        </div>
        <div class="error-code">HTTP 401 - Unauthorized</div>
        <div class="footer">Protected by Traefik API Key Authentication</div>
    </div>
</body>
</html>`, message)

	_, _ = rw.Write([]byte(html))
}
