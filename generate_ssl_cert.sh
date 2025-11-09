#!/bin/bash
# SSL Certificate Generation Script for Quiz Server
# This script generates a self-signed SSL certificate for development/testing

echo "🔐 Generating SSL Certificate for Quiz Server..."

# Create ssl directory if it doesn't exist
mkdir -p ssl

# Generate private key
echo "📝 Generating private key..."
openssl genrsa -out ssl/server.key 2048

# Generate certificate signing request
echo "📝 Generating certificate signing request..."
openssl req -new -key ssl/server.key -out ssl/server.csr -subj "/C=US/ST=State/L=City/O=Quiz Server/CN=localhost"

# Generate self-signed certificate (valid for 365 days)
echo "📝 Generating self-signed certificate..."
openssl x509 -req -days 365 -in ssl/server.csr -signkey ssl/server.key -out ssl/server.crt

# Set appropriate permissions
chmod 600 ssl/server.key
chmod 644 ssl/server.crt

# Clean up CSR file (not needed after certificate is generated)
rm -f ssl/server.csr

echo "✅ SSL certificate generated successfully!"
echo "📜 Certificate: ssl/server.crt"
echo "🔑 Private Key: ssl/server.key"
echo ""
echo "⚠️  Note: This is a self-signed certificate for development/testing only."
echo "   For production, use a certificate from a trusted Certificate Authority (CA)."

