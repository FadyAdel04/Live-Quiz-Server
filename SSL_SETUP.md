# SSL Certificate Setup Guide for Quiz Server

This guide explains how to set up SSL/TLS certificates for the Quiz Server using Apache and Python's built-in SSL support.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Start with Python SSL](#quick-start-with-python-ssl)
3. [Apache SSL Configuration](#apache-ssl-configuration)
4. [Certificate Generation](#certificate-generation)
5. [Production Deployment](#production-deployment)

## 🔍 Overview

The Quiz Server now supports SSL/TLS encryption in two ways:

1. **Direct Python SSL**: The server and client can communicate directly using SSL/TLS
2. **Apache Reverse Proxy**: Apache handles SSL termination and proxies to the Python server

## ⚡ Quick Start with Python SSL

### Step 1: Generate SSL Certificate

**Windows:**
```bash
# Run the batch script
generate_ssl_cert.bat
```

**Linux/macOS:**
```bash
# Make script executable
chmod +x generate_ssl_cert.sh

# Run the script
./generate_ssl_cert.sh
```

**Manual (using OpenSSL):**
```bash
# Create ssl directory
mkdir ssl

# Generate private key
openssl genrsa -out ssl/server.key 2048

# Generate certificate
openssl req -new -x509 -key ssl/server.key -out ssl/server.crt -days 365 -subj "/CN=localhost"
```

### Step 2: Install Python Dependencies

For automatic certificate generation (optional):
```bash
pip install cryptography
```

### Step 3: Run the Server

```bash
python server.py
```

The server will:
- Automatically detect SSL certificate files
- Generate self-signed certificate if files don't exist (requires cryptography library)
- Start with SSL enabled

### Step 4: Run the Client

```bash
python client.py
```

The client will automatically connect using SSL.

## 🌐 Apache SSL Configuration

### Step 1: Install Apache with SSL Module

**Windows:**
- Download Apache from https://httpd.apache.org/
- Ensure mod_ssl is enabled

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install apache2
sudo a2enmod ssl
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo systemctl restart apache2
```

**macOS:**
```bash
brew install apache2
```

### Step 2: Copy SSL Certificate to Apache Directory

```bash
# Copy certificate files
sudo cp ssl/server.crt /etc/ssl/certs/quiz_server.crt
sudo cp ssl/server.key /etc/ssl/private/quiz_server.key
sudo chmod 600 /etc/ssl/private/quiz_server.key
```

### Step 3: Configure Apache

1. Copy the `apache_ssl.conf` configuration
2. Update the certificate paths in the configuration
3. Update `ServerName` to your domain or IP
4. Include the configuration in Apache:

**Linux/macOS:**
```bash
sudo cp apache_ssl.conf /etc/apache2/sites-available/quiz-ssl.conf
sudo a2ensite quiz-ssl
sudo systemctl reload apache2
```

**Windows:**
- Edit `httpd.conf` and include the configuration
- Or create a separate configuration file and include it

### Step 4: Update Python Server Configuration

If using Apache as reverse proxy, you may want to:
- Set `USE_SSL = False` in `server.py` (SSL is handled by Apache)
- Change `HOST = '127.0.0.1'` to only listen on localhost (Apache will proxy)
- Keep port 8080 for Apache to proxy to

## 🔐 Certificate Generation

### Self-Signed Certificate (Development)

The provided scripts generate self-signed certificates suitable for development:

**Windows:**
```bash
generate_ssl_cert.bat
```

**Linux/macOS:**
```bash
chmod +x generate_ssl_cert.sh
./generate_ssl_cert.sh
```

### Certificate Authority (CA) Certificate (Production)

For production, use certificates from a trusted CA:

1. **Let's Encrypt (Free):**
   ```bash
   # Install certbot
   sudo apt-get install certbot python3-certbot-apache
   
   # Generate certificate
   sudo certbot --apache -d yourdomain.com
   ```

2. **Commercial CA:**
   - Purchase certificate from providers like DigiCert, GlobalSign, etc.
   - Follow their instructions for certificate installation

## 🚀 Production Deployment

### Security Best Practices

1. **Use Strong Certificates:**
   - Use 2048-bit or higher RSA keys
   - Or use ECDSA keys for better performance

2. **Enable Certificate Verification:**
   - Update client to verify certificates in production
   - Set `ssl_context.check_hostname = True` in client.py

3. **Apache Configuration:**
   - Enable HSTS (HTTP Strict Transport Security)
   - Disable weak SSL/TLS protocols
   - Use strong cipher suites only

4. **Firewall:**
   - Only allow necessary ports (443 for HTTPS)
   - Block direct access to port 8080 from internet

### Example Production Apache Config

```apache
<VirtualHost *:443>
    ServerName quiz.yourdomain.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/quiz.yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/quiz.yourdomain.com/privkey.pem
    
    # Strong SSL Configuration
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    
    # Proxy Configuration
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

## 🔧 Troubleshooting

### Issue: Certificate Verification Errors

**Solution:** For development, the client accepts self-signed certificates. For production, ensure proper certificate chain.

### Issue: Apache Can't Find Certificate

**Solution:** Check certificate file paths in Apache configuration. Ensure Apache has read permissions.

### Issue: Connection Refused

**Solution:**
- Verify Python server is running on correct port
- Check firewall settings
- Verify Apache proxy configuration

### Issue: SSL Handshake Failed

**Solution:**
- Check certificate validity
- Verify certificate and key match
- Check SSL protocol compatibility

## 📚 Additional Resources

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Apache SSL/TLS Configuration](https://httpd.apache.org/docs/2.4/ssl/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

## ⚠️ Important Notes

- Self-signed certificates are for **development/testing only**
- Production environments should use certificates from trusted CAs
- Always keep private keys secure and never commit them to version control
- Regularly update and renew certificates before expiration

