# Apache Setup Guide for Quiz Server

This guide explains how to run the Quiz Server behind Apache using HTTP/HTTPS reverse proxy.

## Overview

The Quiz Server uses HTTP/HTTPS protocol with REST API endpoints and Server-Sent Events (SSE) for real-time updates. Apache handles SSL/TLS termination, while the Python server runs on localhost without SSL.

## Prerequisites

1. Apache 2.4+ with the following modules enabled:
   - `mod_ssl` (for HTTPS)
   - `mod_proxy` (for reverse proxy)
   - `mod_proxy_http` (for HTTP proxy support)
   - `mod_headers` (for setting headers)
   - `mod_rewrite` (for HTTP to HTTPS redirect)

2. Python dependencies installed:
   ```bash
   pip install -r requirements.txt
   ```

## Apache Configuration

1. **Enable Required Modules**

   Edit your Apache configuration file (usually `httpd.conf` or in `/etc/apache2/mods-available/`) and ensure these modules are loaded:

   ```apache
   LoadModule ssl_module modules/mod_ssl.so
   LoadModule proxy_module modules/mod_proxy.so
   LoadModule proxy_http_module modules/mod_proxy_http.so
   LoadModule headers_module modules/mod_headers.so
   LoadModule rewrite_module modules/mod_rewrite.so
   ```

2. **Configure Virtual Host**

   Copy or include the `apache_ssl.conf` file in your Apache configuration. Update the following:

   - **ServerName**: Change `quiz.example.com` to your domain or IP
   - **SSL Certificate Paths**: Update paths to your SSL certificate files
   - **Port**: Ensure port 443 is available (or change to your preferred port)

3. **SSL Certificate Setup**

   You have two options:

   **Option A: Use Existing Certificates**
   - Place your SSL certificate at the path specified in `SSLCertificateFile`
   - Place your private key at the path specified in `SSLCertificateKeyFile`

   **Option B: Generate Self-Signed Certificate (Development Only)**
   ```bash
   # The server can auto-generate certificates, or use:
   openssl req -x509 -newkey rsa:2048 -keyout ssl/server.key -out ssl/server.crt -days 365 -nodes
   ```

## Running the Server

1. **Start the Python HTTP Server**

   ```bash
   cd Live-Quiz-Server
   python server.py
   ```

   The server will start on `http://127.0.0.1:8080` (without SSL, since Apache handles it).

2. **Start/Restart Apache**

   ```bash
   # On Linux
   sudo systemctl restart apache2
   # or
   sudo service apache2 restart
   
   # On Windows
   # Restart Apache service from Services panel
   ```

3. **Verify Configuration**

   Check Apache error logs for any issues:
   ```bash
   tail -f /var/log/apache2/error.log
   # or
   tail -f logs/quiz_ssl_error.log
   ```

## Client Configuration

When connecting through Apache, update the client configuration:

1. **For HTTPS connections through Apache:**

   Edit `client.py`:
   ```python
   HOST = 'your-domain.com'  # or Apache server IP
   PORT = 443  # or your Apache HTTPS port
   BASE_URL = f'https://{HOST}:{PORT}'  # Use https:// for secure connection
   ```

2. **For direct connection (bypassing Apache):**

   ```python
   HOST = '127.0.0.1'
   PORT = 8080
   BASE_URL = f'http://{HOST}:{PORT}'  # Direct connection without SSL
   ```

## API Endpoints

The server provides the following REST API endpoints:

- `POST /api/auth` - Authenticate user (returns session ID)
- `GET /api/quiz/start` - Start quiz session (requires X-Session-ID header)
- `GET /api/quiz/question` - Get current question (requires X-Session-ID header)
- `POST /api/quiz/answer` - Submit answer (requires X-Session-ID header)
- `GET /api/quiz/leaderboard` - Get current leaderboard
- `GET /api/quiz/stream` - Server-Sent Events stream for real-time updates (requires X-Session-ID header)
- `GET /api/health` - Health check endpoint

## Testing

1. **Test HTTP Connection**

   You can test the HTTP connection using `curl`:
   ```bash
   curl -k https://your-domain.com/api/health
   ```

2. **Test Authentication**

   ```bash
   curl -k -X POST https://your-domain.com/api/auth \
     -H "Content-Type: application/json" \
     -d '{"username":"fady","password":"fady123"}'
   ```

3. **Test with Client**

   Run the Python client:
   ```bash
   python client.py
   ```

## Troubleshooting

### HTTP Connection Fails

1. **Check Apache Modules**: Ensure required modules are enabled
   ```bash
   apache2ctl -M | grep proxy
   apache2ctl -M | grep ssl
   ```

2. **Check Proxy Configuration**: Verify ProxyPass directives are correct
   - Ensure the Python server is running on port 8080
   - Check that ProxyPass and ProxyPassReverse are configured

3. **Check Firewall**: Ensure ports 443 (HTTPS) and 8080 (internal) are open

### SSL Certificate Issues

1. **Certificate Not Found**: Ensure certificate paths in Apache config are correct
2. **Permission Denied**: Ensure Apache has read access to certificate files
3. **Self-Signed Certificate**: Browser/client may show warnings - this is normal for development

### Connection Timeout

1. **Server Not Running**: Ensure Python server is running on port 8080
2. **Wrong Port**: Verify Apache is proxying to correct port (8080)
3. **Network Issues**: Check if localhost connections work: `curl http://127.0.0.1:8080/api/health`

### 502 Bad Gateway

1. **Backend Not Running**: Ensure Python server is running and accessible
2. **Wrong Backend URL**: Verify ProxyPass points to correct address (http://127.0.0.1:8080)
3. **Backend Error**: Check Python server logs for errors

## Architecture

```
Client (https://) 
    ↓
Apache (HTTPS/443) 
    ↓ (HTTP Reverse Proxy)
Python Server (http://127.0.0.1:8080)
```

- **External**: Clients connect via `https://your-domain.com:443`
- **Internal**: Apache proxies to `http://127.0.0.1:8080`
- **SSL**: Handled by Apache, Python server runs without SSL
- **Protocol**: HTTP/HTTPS with REST API endpoints

## Security Considerations

1. **Firewall**: Only expose port 443 (HTTPS) to the internet, keep 8080 internal
2. **SSL/TLS**: Use valid SSL certificates in production (not self-signed)
3. **Authentication**: The quiz server handles user authentication via session IDs
4. **Rate Limiting**: Consider adding Apache rate limiting for production
5. **Headers**: Security headers are set in Apache configuration

## Production Recommendations

1. Use a process manager (systemd, supervisor) to keep the Python server running
2. Set up log rotation for Apache and Python server logs
3. Monitor server resources and connection counts
4. Use a reverse proxy cache if needed
5. Implement proper SSL certificate management (Let's Encrypt, etc.)
6. Consider using Gunicorn or similar WSGI/ASGI server for better performance
7. Enable HTTP/2 in Apache for better performance
8. Set up monitoring and alerting for server health

## Differences from WebSocket Version

- **Protocol**: HTTP/HTTPS instead of WebSocket
- **Communication**: REST API with polling/SSE instead of persistent WebSocket connection
- **Apache Config**: HTTP reverse proxy instead of WebSocket proxy
- **Client**: Uses HTTP requests instead of WebSocket messages
- **Real-time Updates**: Server-Sent Events (SSE) available for streaming updates
