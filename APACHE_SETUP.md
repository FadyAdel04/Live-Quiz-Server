# Apache Setup Guide for Quiz Server

This guide explains how to run the Quiz Server behind Apache using WebSocket proxying.

## Overview

The Quiz Server has been converted to use WebSocket protocol, which allows it to be proxied through Apache. Apache handles SSL/TLS termination, while the Python server runs on localhost without SSL.

## Prerequisites

1. Apache 2.4+ with the following modules enabled:
   - `mod_ssl` (for HTTPS)
   - `mod_proxy` (for reverse proxy)
   - `mod_proxy_wstunnel` (for WebSocket support)
   - `mod_rewrite` (for WebSocket detection)

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
   LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
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

1. **Start the Python WebSocket Server**

   ```bash
   cd Live-Quiz-Server
   python server.py
   ```

   The server will start on `ws://127.0.0.1:8080` (without SSL, since Apache handles it).

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

1. **For HTTPS/WSS connections through Apache:**

   Edit `client.py`:
   ```python
   HOST = 'your-domain.com'  # or Apache server IP
   PORT = 443  # or your Apache HTTPS port
   WS_URL = f'wss://{HOST}:{PORT}'  # Use wss:// for secure WebSocket
   ```

2. **For direct connection (bypassing Apache):**

   ```python
   HOST = '127.0.0.1'
   PORT = 8080
   WS_URL = f'ws://{HOST}:{PORT}'  # Direct connection without SSL
   ```

## Testing

1. **Test WebSocket Connection**

   You can test the WebSocket connection using a tool like `wscat`:
   ```bash
   npm install -g wscat
   wscat -c wss://your-domain.com
   ```

2. **Test with Client**

   Run the Python client:
   ```bash
   python client.py
   ```

## Troubleshooting

### WebSocket Connection Fails

1. **Check Apache Modules**: Ensure `mod_proxy_wstunnel` is enabled
   ```bash
   apache2ctl -M | grep proxy_wstunnel
   ```

2. **Check Rewrite Rules**: The WebSocket upgrade detection must work
   - Verify `RewriteEngine on` is set
   - Check that `RewriteCond` rules match WebSocket upgrade headers

3. **Check Firewall**: Ensure ports 443 (HTTPS) and 8080 (internal) are open

### SSL Certificate Issues

1. **Certificate Not Found**: Ensure certificate paths in Apache config are correct
2. **Permission Denied**: Ensure Apache has read access to certificate files
3. **Self-Signed Certificate**: Browser/client may show warnings - this is normal for development

### Connection Timeout

1. **Server Not Running**: Ensure Python server is running on port 8080
2. **Wrong Port**: Verify Apache is proxying to correct port (8080)
3. **Network Issues**: Check if localhost connections work: `telnet 127.0.0.1 8080`

## Architecture

```
Client (wss://) 
    ↓
Apache (HTTPS/443) 
    ↓ (WebSocket Proxy)
Python Server (ws://127.0.0.1:8080)
```

- **External**: Clients connect via `wss://your-domain.com:443`
- **Internal**: Apache proxies to `ws://127.0.0.1:8080`
- **SSL**: Handled by Apache, Python server runs without SSL

## Security Considerations

1. **Firewall**: Only expose port 443 (HTTPS) to the internet, keep 8080 internal
2. **SSL/TLS**: Use valid SSL certificates in production (not self-signed)
3. **Authentication**: The quiz server handles user authentication
4. **Rate Limiting**: Consider adding Apache rate limiting for production

## Production Recommendations

1. Use a process manager (systemd, supervisor) to keep the Python server running
2. Set up log rotation for Apache and Python server logs
3. Monitor server resources and connection counts
4. Use a reverse proxy cache if needed
5. Implement proper SSL certificate management (Let's Encrypt, etc.)

