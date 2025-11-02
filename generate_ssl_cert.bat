@echo off
REM SSL Certificate Generation Script for Quiz Server (Windows)
REM This script generates a self-signed SSL certificate for development/testing

echo 🔐 Generating SSL Certificate for Quiz Server...

REM Create ssl directory if it doesn't exist
if not exist ssl mkdir ssl

REM Check if OpenSSL is available
where openssl >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ⚠️  OpenSSL not found in PATH.
    echo    Please install OpenSSL or use Git Bash which includes OpenSSL.
    echo    Download OpenSSL from: https://slproweb.com/products/Win32OpenSSL.html
    pause
    exit /b 1
)

REM Generate private key
echo 📝 Generating private key...
openssl genrsa -out ssl\server.key 2048

REM Generate certificate signing request
echo 📝 Generating certificate signing request...
openssl req -new -key ssl\server.key -out ssl\server.csr -subj "/C=US/ST=State/L=City/O=Quiz Server/CN=localhost"

REM Generate self-signed certificate (valid for 365 days)
echo 📝 Generating self-signed certificate...
openssl x509 -req -days 365 -in ssl\server.csr -signkey ssl\server.key -out ssl\server.crt

REM Clean up CSR file (not needed after certificate is generated)
del /f ssl\server.csr 2>nul

echo.
echo ✅ SSL certificate generated successfully!
echo 📜 Certificate: ssl\server.crt
echo 🔑 Private Key: ssl\server.key
echo.
echo ⚠️  Note: This is a self-signed certificate for development/testing only.
echo    For production, use a certificate from a trusted Certificate Authority (CA).
echo.
pause

