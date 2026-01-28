# Express Backend - User Management System

A production-ready, secure Express.js backend with PostgreSQL, Redis, JWT authentication, and comprehensive role-based access control (RBAC).

## 🚀 Features

### Security
- ✅ JWT-based authentication with access and refresh tokens
- ✅ Redis session management
- ✅ Bcrypt password hashing (12 rounds)
- ✅ Account lockout after failed login attempts
- ✅ Multi-tier rate limiting (API-wide, auth-specific, and sensitive operations)
- ✅ Helmet.js security headers with CSP
- ✅ CORS protection with dynamic origin validation
- ✅ SQL injection prevention
- ✅ NoSQL injection prevention
- ✅ Path traversal attack prevention
- ✅ HTTP Parameter Pollution (HPP) prevention
- ✅ Bot and automated tool detection
- ✅ Input sanitization and validation
- ✅ Request size limiting
- ✅ File upload protection
- ✅ Cookie security (httpOnly, secure, sameSite)
- ✅ Comprehensive security logging

### Architecture
- ✅ MVC pattern with service layer
- ✅ Centralized error handling
- ✅ Custom exception classes
- ✅ Standardized API responses
- ✅ Request validation using Joi
- ✅ Async/await error handling
- ✅ Database connection pooling
- ✅ Redis caching layer

### User Management
- ✅ User registration and login
- ✅ Profile management
- ✅ Password change
- ✅ Multi-device session management
- ✅ Logout from all devices
- ✅ Role-based access control (User, Moderator, Admin)
- ✅ User activation/deactivation
- ✅ Soft delete functionality

### Additional Features
- ✅ Pagination support
- ✅ Search and filtering
- ✅ User statistics (admin only)
- ✅ Comprehensive logging with request IDs
- ✅ Health check endpoint
- ✅ Graceful shutdown
- ✅ Database migrations
- ✅ Database seeding

## 🔐 Advanced Security Features

### 1. **Multi-Tier Rate Limiting**

**API Rate Limiter**
- 100 requests per 15 minutes per IP
- Applies to all `/api/*` routes
- Uses client IP for tracking
- Prevents DoS attacks

**Authentication Rate Limiter**
- 3 attempts per 5 minutes per IP
- Applies to login and registration endpoints
- Prevents brute force attacks
- Warns on rate limit exceeded

**Sensitive Operation Limiter**
- 3 attempts per hour per IP
- For password changes, role updates, etc.
- Skips successful requests
- Extra protection for critical operations

### 2. **SQL Injection Prevention**

Detects and blocks common SQL injection patterns:
- SQL keywords (SELECT, INSERT, UPDATE, DELETE, DROP, UNION, etc.)
- SQL comments (`--`, `/*`, `*/`)
- Time-based attacks (WAITFOR, DELAY, SLEEP, BENCHMARK)
- Command execution attempts (xp_cmdshell, sp_configure)
- Checks request body, query parameters, and URL params

**Example blocked patterns:**
```
' OR '1'='1
SELECT * FROM users--
UNION SELECT password FROM admin
```

### 3. **NoSQL Injection Prevention**

Protects against MongoDB-style injection attacks:
- Blocks operator keywords (`$ne`, `$gt`, `$in`, `$or`, `$where`, etc.)
- Prevents object-based attacks
- Validates critical fields (email, password, username)
- Ensures authentication fields are strings only
- Checks nested objects recursively

**Example blocked attacks:**
```json
{ "email": { "$ne": null } }
{ "password": { "$gt": "" } }
{ "$where": "this.password == '123'" }
```

### 4. **Path Traversal Protection**

Prevents directory traversal attacks:
- Blocks `../` patterns and encoded variants
- Prevents access to system files (`/etc/`, `.env`, `.git/`, `.ssh/`)
- Blocks Windows system paths (`system32`)
- Checks body, query, and params
- Recursively validates nested objects

**Example blocked patterns:**
```
../../etc/passwd
%2e%2e%2f%2e%2e%2f
..\..\windows\system32
/.env
```

### 5. **Bot Detection**

Identifies and blocks malicious bots and automated tools:

**Malicious Tools Blocked:**
- Security scanners: sqlmap, nikto, nmap, nessus, openvas
- Web app scanners: acunetix, burp, wpscan, nuclei
- Exploitation tools: metasploit, havij
- Directory brute forcers: dirbuster, gobuster

**Suspicious Tools Monitored:**
- Command-line tools: wget, curl
- HTTP clients: python-requests, go-http-client
- Headless browsers: phantomjs, puppeteer
- Web scrapers: scrapy

**Special rules:**
- Blocks malicious bots entirely
- Blocks automated tools on authentication endpoints only
- Logs all suspicious activity with IP addresses

### 6. **Input Sanitization**

**Automatic Cleaning:**
- Trims whitespace
- Removes null bytes (`\0`)
- Collapses multiple spaces
- Limits input length to 10,000 characters
- Recursively sanitizes nested objects

**Applied to:**
- Request body
- Query parameters
- Prevents buffer overflow attacks

### 7. **Security Headers**

**Helmet.js Configuration:**
```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

**Custom Headers:**
- `X-Request-ID`: Unique request tracking
- `X-DNS-Prefetch-Control`: off
- `X-Download-Options`: noopen
- `X-Permitted-Cross-Domain-Policies`: none
- Removes `X-Powered-By` header

### 8. **CORS Protection**

**Dynamic Origin Validation:**
- Configurable allowed origins via environment variable
- Supports multiple origins (comma-separated)
- Credentials support enabled
- Exposes rate limit headers
- 24-hour preflight cache

**Configuration:**
```javascript
CORS_ORIGINS=http://localhost:3000,https://myapp.com,https://www.myapp.com
```

### 9. **File Upload Protection**

**Validation:**
- Whitelist of allowed MIME types (JPEG, PNG, GIF, PDF)
- Maximum file size enforcement (10MB for images)
- Prevents malicious file uploads
- Type checking before processing

### 10. **Request Logging & Monitoring**

**Comprehensive Logging:**
- Request ID for request tracing
- Method, URL, status code
- Response time tracking
- Client IP address
- User agent tracking
- User identification (authenticated/anonymous)
- Referrer tracking

**Security Event Logging:**
- Failed authentication attempts (401, 403)
- Rate limit violations
- SQL injection attempts
- NoSQL injection attempts
- Path traversal attempts
- Bot detection events
- Invalid IP formats

**Log Format:**
- Development: Human-readable format
- Production: JSON format for log aggregation

### 11. **IP Validation**

**Features:**
- Extracts real IP from proxy headers
- Validates IPv4 and IPv6 formats
- Detects spoofed or invalid IPs
- Falls back to 'unknown' for invalid IPs
- Uses for rate limiting and security logging

**Priority Order:**
1. `X-Forwarded-For` header (first IP)
2. `X-Real-IP` header
3. Connection remote address
4. Socket remote address
5. Express req.ip

### 12. **Account Security**

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)

**Brute Force Protection:**
- Tracks failed login attempts per account
- Locks account after 5 failed attempts
- 15-minute lockout period
- Resets counter on successful login

**Session Management:**
- Redis-based session storage
- Session activity tracking
- Multi-device session support
- Logout from specific device
- Logout from all devices
- Session expiration

### 13. **JWT Security**

**Token Configuration:**
- Access token: 15 minutes (short-lived)
- Refresh token: 7 days (long-lived)
- Issuer and audience verification
- Secure cookie storage (httpOnly, secure, sameSite)

**Token Rotation:**
- New refresh token on every refresh
- Old refresh token invalidation
- Prevents token replay attacks

## 🛡️ Security Best Practices Implemented

### Defense in Depth
Multiple layers of security controls protect against various attack vectors.

### Principle of Least Privilege
Users have minimum necessary permissions. Role-based access control enforces this.

### Fail Secure
System fails in a secure state. Invalid requests are rejected, not processed.

### Security Logging
All security events are logged with contextual information for incident response.

### Input Validation
All user input is validated and sanitized before processing.

### Secure Configuration
Security headers, rate limiting, and encryption enabled by default.

## 📊 Security Monitoring

### What Gets Logged

**Normal Operations:**
- All API requests with response times
- User authentication events
- Session creation/destruction

**Security Events:**
- Failed login attempts
- Rate limit violations
- SQL/NoSQL injection attempts
- Path traversal attempts
- Bot detection events
- Invalid IP addresses
- Suspicious user agents

### Log Analysis

Logs include:
- Timestamp (ISO 8601 format)
- Request ID (for tracing)
- HTTP method and URL
- Response status code
- Response time
- Client IP address
- User agent
- User ID (if authenticated)
- Severity level (INFO, WARNING, ERROR)
- Security event type (if applicable)

## 🔧 Security Configuration

### Environment Variables
```bash
# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000           # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100           # Max requests per window

# CORS
CORS_ORIGINS=http://localhost:3000,https://myapp.com

# Request Size
MAX_REQUEST_SIZE=10mb                  # Maximum request body size

# Account Security
MAX_LOGIN_ATTEMPTS=5                   # Failed attempts before lockout
LOCK_TIME=15                          # Lockout duration in minutes

# Password Hashing
BCRYPT_ROUNDS=12                      # Bcrypt hashing rounds
```

## 🚨 Security Incident Response

### If You Detect an Attack:

1. **Check Logs**: Review security event logs for pattern
2. **Identify Source**: Extract attacker IP from logs
3. **Block IP**: Add to firewall/reverse proxy blacklist
4. **Review Impact**: Check if any data was accessed
5. **Patch Vulnerability**: If new attack vector discovered
6. **Update Rate Limits**: Adjust if needed

### Common Attack Responses:

**SQL Injection Attempt:**
```
NoSQL injection pattern detected in email from IP: 192.168.1.100
```
→ IP automatically blocked, request rejected with 400 error

**Rate Limit Exceeded:**
```
Rate limit exceeded for authentication from IP: 192.168.1.100
```
→ IP temporarily blocked, returns 429 error

**Bot Detection:**
```
Malicious bot detected: sqlmap from IP: 192.168.1.100
```
→ Request blocked with 403 error

## 📋 Security Checklist for Production

- [ ] Change all default passwords
- [ ] Generate strong JWT secrets (64+ characters)
- [ ] Enable HTTPS only
- [ ] Configure CORS with production domains
- [ ] Set up database backups
- [ ] Enable Redis persistence
- [ ] Configure log aggregation (ELK, Splunk, etc.)
- [ ] Set up monitoring and alerts
- [ ] Configure WAF (Web Application Firewall)
- [ ] Set up DDoS protection (Cloudflare, AWS Shield)
- [ ] Regular security audits
- [ ] Dependency vulnerability scanning
- [ ] Rate limit tuning based on traffic
- [ ] IP whitelist for admin endpoints
- [ ] Two-factor authentication (future enhancement)

## 🔍 Security Testing

### Test SQL Injection Protection:
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"' OR '1'='1"}'
```
Expected: 400 Bad Request - "Invalid request data"

### Test NoSQL Injection Protection:
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":{"$ne":null},"password":"test"}'
```
Expected: 400 Bad Request - "Invalid request data"

### Test Rate Limiting:
```bash
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
done
```
Expected: 429 Too Many Requests after 3 attempts

### Test Path Traversal Protection:
```bash
curl -X GET http://localhost:3000/api/v1/users?file=../../etc/passwd
```
Expected: 403 Forbidden - "Invalid request data"

## 📞 Support

For security issues, please email security@example.com

For general issues and questions, please open an issue on GitHub.

---

**Built with ❤️ and 🔒 using Express.js, PostgreSQL, and Redis**