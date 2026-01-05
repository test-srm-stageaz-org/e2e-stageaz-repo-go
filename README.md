# Vulnerable Go Application - Testing Purpose Only

⚠️ **WARNING: This application contains intentional security vulnerabilities for testing purposes only. DO NOT deploy to production!**

## Overview

This Go application contains various security vulnerabilities for testing CodeQL and dependency scanning tools.

## Included Vulnerabilities

### CodeQL Vulnerabilities (CWE)

1. **CWE-89**: SQL Injection - Multiple variations in `main.go` and `db.go`
2. **CWE-78**: OS Command Injection - In `main.go`
3. **CWE-22**: Path Traversal - In `main.go` and `file_handler.go`
4. **CWE-79**: Cross-Site Scripting (XSS) - In `main.go`
5. **CWE-798**: Hard-coded Credentials - In `main.go`
6. **CWE-327**: Weak Cryptographic Algorithm - In `main.go`
7. **CWE-502**: Deserialization of Untrusted Data - In `main.go`
8. **CWE-306**: Missing Authentication - In `main.go`
9. **CWE-209**: Information Exposure - In `main.go`
10. **CWE-190**: Integer Overflow - In `main.go`
11. **CWE-338**: Weak PRNG - In `utils.go`
12. **CWE-326**: Inadequate Encryption - In `utils.go`
13. **CWE-20**: Improper Input Validation - In `utils.go`
14. **CWE-434**: Unrestricted File Upload - In `file_handler.go`
15. **CWE-409**: Zip Bomb - In `file_handler.go`

### Dependency Vulnerabilities (CVE)

The `go.mod` file includes vulnerable dependencies with known CVEs:

1. **github.com/gin-gonic/gin v1.7.0**
   - CVE-2020-28483: Path traversal vulnerability

2. **github.com/gorilla/websocket v1.4.0**
   - CVE-2020-27813: Integer overflow vulnerability

3. **github.com/dgrijalva/jwt-go v3.2.0**
   - CVE-2020-26160: JWT token validation bypass

4. **gopkg.in/yaml.v2 v2.2.2**
   - CVE-2019-11254: Denial of Service vulnerability

5. **golang.org/x/crypto (old version)**
   - Multiple CVEs in outdated crypto library

## Files Structure

- `main.go` - Main application with HTTP handlers and various CWE vulnerabilities
- `db.go` - Database operations with SQL injection vulnerabilities
- `utils.go` - Utility functions with cryptographic and validation vulnerabilities
- `file_handler.go` - File operations with path traversal and file handling vulnerabilities
- `go.mod` - Dependency file with vulnerable packages

## Testing

This code is designed to trigger alerts in:
- GitHub CodeQL scanning
- Dependency scanning tools (Dependabot, Snyk, etc.)
- SAST (Static Application Security Testing) tools
- Security code reviews

## Disclaimer

**DO NOT USE THIS CODE IN PRODUCTION**

This repository is for educational and testing purposes only. All vulnerabilities are intentional and should never be deployed in a real application.
