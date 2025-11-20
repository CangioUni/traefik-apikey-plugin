# Traefik API Key Authentication Plugin

A Traefik middleware plugin that provides API key-based authentication with advanced filtering capabilities including subdomain matching and IP address restrictions.

## Features

- ✅ **Header-based API Key Authentication** - Authenticate requests using API keys in HTTP headers
- ✅ **Customizable Header Name** - Use any header name (default: `X-API-Key`)
- ✅ **Subdomain Filtering** - Restrict API keys to specific subdomains
- ✅ **Wildcard Support** - Use `*` to allow all subdomains or `*.example.com` for pattern matching
- ✅ **IP Address Filtering** - Bind API keys to specific IP addresses or CIDR ranges
- ✅ **Beautiful Denial Page** - Display a professional, dark-themed HTML page for unauthorized access
- ✅ **Multiple API Keys** - Support for multiple API keys with different access rules

## Installation

To use this plugin with Traefik, you need to add it to your Traefik static configuration:

### Static Configuration (YAML)

```yaml
experimental:
  plugins:
    apikey:
      moduleName: github.com/CangioUni/traefik-apikey-plugin
      version: v1.0.0
```

### Static Configuration (TOML)

```toml
[experimental.plugins.apikey]
  moduleName = "github.com/CangioUni/traefik-apikey-plugin"
  version = "v1.0.0"
```

## Configuration

### Basic Configuration

Here's a minimal configuration example:

```yaml
http:
  middlewares:
    my-apikey-auth:
      plugin:
        apikey:
          headerName: X-API-Key
          authorizedKeys:
            - key: "secret-api-key-1"
              subdomains:
                - "*"
```

### Advanced Configuration

Full configuration with all features:

```yaml
http:
  middlewares:
    my-apikey-auth:
      plugin:
        apikey:
          # Custom header name (optional, default: X-API-Key)
          headerName: X-Custom-API-Key
          
          # List of authorized API keys with their access rules
          authorizedKeys:
            # API key with wildcard subdomain access
            - key: "global-api-key"
              subdomains:
                - "*"
            
            # API key restricted to specific subdomain
            - key: "api-subdomain-key"
              subdomains:
                - "api.example.com"
            
            # API key with wildcard subdomain pattern
            - key: "wildcard-pattern-key"
              subdomains:
                - "*.internal.example.com"
            
            # API key restricted to specific subdomain and IP address
            - key: "restricted-key"
              subdomains:
                - "admin.example.com"
              allowedIPs:
                - "192.168.1.100"
                - "10.0.0.0/24"
            
            # API key with multiple subdomains and IPs
            - key: "multi-access-key"
              subdomains:
                - "api.example.com"
                - "beta.example.com"
              allowedIPs:
                - "203.0.113.0/24"
                - "198.51.100.50"
```

### Docker Compose Example

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--experimental.plugins.apikey.modulename=github.com/CangioUni/traefik-apikey-plugin"
      - "--experimental.plugins.apikey.version=v1.0.0"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./traefik.yml:/traefik.yml
  
  myapp:
    image: my-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.myapp.rule=Host(`api.example.com`)"
      - "traefik.http.routers.myapp.middlewares=api-auth@file"
      - "traefik.http.middlewares.api-auth.plugin.apikey.headerName=X-API-Key"
      - "traefik.http.middlewares.api-auth.plugin.apikey.authorizedKeys[0].key=my-secret-key"
      - "traefik.http.middlewares.api-auth.plugin.apikey.authorizedKeys[0].subdomains[0]=*"
```

## Configuration Options

### Root Level

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `headerName` | string | No | `X-API-Key` | The HTTP header name to check for the API key |
| `authorizedKeys` | array | Yes | `[]` | List of authorized API keys with their access rules |

### AuthorizedKey Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `key` | string | Yes | - | The API key value |
| `subdomains` | array | No | `[]` | List of allowed subdomains. Empty means all subdomains are allowed |
| `allowedIPs` | array | No | `[]` | List of allowed IP addresses or CIDR ranges. Empty means all IPs are allowed |

## Usage Examples

### Example 1: Simple API Key Authentication

Allow access with a specific API key from any subdomain:

```yaml
http:
  middlewares:
    simple-auth:
      plugin:
        apikey:
          authorizedKeys:
            - key: "my-secret-key"
              subdomains:
                - "*"
```

**Request:**
```bash
curl -H "X-API-Key: my-secret-key" https://api.example.com/endpoint
```

### Example 2: Subdomain-Specific API Keys

Different API keys for different subdomains:

```yaml
http:
  middlewares:
    subdomain-auth:
      plugin:
        apikey:
          authorizedKeys:
            - key: "api-key-1"
              subdomains:
                - "api.example.com"
            - key: "api-key-2"
              subdomains:
                - "admin.example.com"
```

### Example 3: IP-Restricted API Key

Restrict API key to specific IP addresses:

```yaml
http:
  middlewares:
    ip-restricted-auth:
      plugin:
        apikey:
          authorizedKeys:
            - key: "internal-key"
              subdomains:
                - "*"
              allowedIPs:
                - "192.168.1.0/24"
                - "10.0.0.50"
```

### Example 4: Custom Header Name

Use a custom header name instead of the default:

```yaml
http:
  middlewares:
    custom-header-auth:
      plugin:
        apikey:
          headerName: Authorization
          authorizedKeys:
            - key: "Bearer my-token"
              subdomains:
                - "*"
```

**Request:**
```bash
curl -H "Authorization: Bearer my-token" https://api.example.com/endpoint
```

### Example 5: Wildcard Subdomain Patterns

Allow access to all subdomains under a specific domain:

```yaml
http:
  middlewares:
    wildcard-auth:
      plugin:
        apikey:
          authorizedKeys:
            - key: "internal-services-key"
              subdomains:
                - "*.internal.example.com"
```

This will match:
- ✅ `service1.internal.example.com`
- ✅ `api.internal.example.com`
- ❌ `external.example.com`
- ❌ `example.com`

## Unauthorized Access Page

When a request is denied (missing or invalid API key), the plugin returns a beautifully designed HTML page with:

- 🎨 Modern dark theme
- 🔒 Clear access denied message
- 💡 Helpful information about the error
- 📱 Responsive design

The page displays:
- HTTP 401 - Unauthorized status
- Reason for denial (missing API key or unauthorized)
- Professional branding

## How It Works

1. **Request Received**: Traefik receives an HTTP request
2. **Header Check**: Plugin checks for the API key in the specified header
3. **Key Validation**: Validates if the API key exists in the authorized keys list
4. **Subdomain Match**: If subdomains are specified, checks if the request host matches
5. **IP Validation**: If IPs are specified, checks if the client IP matches
6. **Decision**:
   - ✅ **Authorized**: Request passes to the backend service
   - ❌ **Unauthorized**: Returns 401 with HTML denial page

## Client IP Detection

The plugin detects client IP addresses in the following order:

1. `X-Forwarded-For` header (takes the first IP)
2. `X-Real-IP` header
3. Direct connection `RemoteAddr`

This ensures accurate IP filtering even when behind proxies or load balancers.

## Security Considerations

- 🔐 **Always use HTTPS** in production to protect API keys in transit
- 🔑 **Use strong, random API keys** (minimum 32 characters recommended)
- 🔒 **Rotate API keys regularly** to minimize security risks
- 🚫 **Don't commit API keys** to version control
- 📝 **Audit access logs** regularly
- 🛡️ **Combine with rate limiting** for additional protection

## Testing

The plugin includes comprehensive tests. To run them:

```bash
go test -v
```

## License

This plugin is open source. Please check the repository for license details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/CangioUni/traefik-apikey-plugin).