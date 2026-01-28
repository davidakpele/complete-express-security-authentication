# API Documentation

## Base URL
```
http://localhost:5000/api/v1
```

## Authentication

All protected endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Alternatively, tokens can be sent via cookies.

## Response Format

### Success Response
```json
{
  "success": true,
  "message": "Success message",
  "data": { ... },
  "timestamp": "2024-01-27T10:00:00.000Z"
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error message",
  "errors": [...],
  "timestamp": "2024-01-27T10:00:00.000Z"
}
```

### Paginated Response
```json
{
  "success": true,
  "message": "Success message",
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 100,
    "totalPages": 10,
    "hasNext": true,
    "hasPrev": false
  },
  "timestamp": "2024-01-27T10:00:00.000Z"
}
```

## Endpoints

### Authentication

#### Register User
```http
POST /auth/register
```

Request Body:
```json
{
  "email": "user@example.com",
  "password": "SecurePass@123",
  "firstName": "John",
  "lastName": "Doe"
}
```

Password Requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)

Response (201):
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role": "user",
      "is_active": true,
      "is_verified": false
    },
    "tokens": {
      "accessToken": "jwt_token",
      "refreshToken": "jwt_token"
    }
  }
}
```

#### Login
```http
POST /auth/login
```

Request Body:
```json
{
  "email": "user@example.com",
  "password": "SecurePass@123"
}
```

Response (200):
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { ... },
    "tokens": { ... }
  }
}
```

Errors:
- 401: Invalid credentials
- 429: Too many login attempts (account locked)

#### Refresh Token
```http
POST /auth/refresh
```

Request Body:
```json
{
  "refreshToken": "jwt_refresh_token"
}
```

Response (200):
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "tokens": {
      "accessToken": "new_jwt_token",
      "refreshToken": "new_refresh_token"
    }
  }
}
```

#### Logout
```http
POST /auth/logout
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Response (200):
```json
{
  "success": true,
  "message": "Logout successful",
  "data": null
}
```

#### Logout from All Devices
```http
POST /auth/logout-all
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Response (200):
```json
{
  "success": true,
  "message": "Logged out from all devices",
  "data": null
}
```

#### Get Profile
```http
GET /auth/me
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Response (200):
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "is_active": true,
    "is_verified": false,
    "last_login": "2024-01-27T10:00:00.000Z",
    "created_at": "2024-01-20T10:00:00.000Z",
    "updated_at": "2024-01-27T10:00:00.000Z"
  }
}
```

#### Update Profile
```http
PUT /auth/profile
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Request Body:
```json
{
  "firstName": "Jane",
  "lastName": "Smith"
}
```

Response (200):
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": { ... }
}
```

#### Change Password
```http
POST /auth/change-password
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Request Body:
```json
{
  "currentPassword": "OldPass@123",
  "newPassword": "NewPass@456"
}
```

Response (200):
```json
{
  "success": true,
  "message": "Password changed successfully. Please login again.",
  "data": null
}
```

Note: All active sessions are terminated after password change.

#### Get Active Sessions
```http
GET /auth/sessions
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Response (200):
```json
{
  "success": true,
  "message": "Sessions retrieved successfully",
  "data": [
    {
      "sessionId": "session:uuid:timestamp",
      "userId": "uuid",
      "email": "user@example.com",
      "role": "user",
      "ipAddress": "192.168.1.1",
      "userAgent": "Mozilla/5.0...",
      "lastActivity": "2024-01-27T10:00:00.000Z",
      "createdAt": "2024-01-27T09:00:00.000Z"
    }
  ]
}
```

### User Management

#### Get All Users
```http
GET /users?page=1&limit=10&search=john&role=user&isActive=true
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin, Moderator

Query Parameters:
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10, max: 100)
- `search` (optional): Search by email, first name, or last name
- `role` (optional): Filter by role (user, moderator, admin)
- `isActive` (optional): Filter by active status (true, false)

Response (200):
```json
{
  "success": true,
  "message": "Users retrieved successfully",
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 45,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  }
}
```

#### Get User by ID
```http
GET /users/:userId
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin, Moderator, Owner

Response (200):
```json
{
  "success": true,
  "message": "User retrieved successfully",
  "data": { ... }
}
```

#### Update User
```http
PUT /users/:userId
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin, Owner

Request Body:
```json
{
  "firstName": "Updated",
  "lastName": "Name"
}
```

Note: Only admins can update role, is_active, and is_verified fields.

Response (200):
```json
{
  "success": true,
  "message": "User updated successfully",
  "data": { ... }
}
```

#### Delete User
```http
DELETE /users/:userId
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin, Owner

Response (204): No Content

Note: This is a soft delete. The user is marked as deleted but not removed from the database.

#### Update User Role
```http
PATCH /users/:userId/role
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin only

Request Body:
```json
{
  "role": "moderator"
}
```

Valid roles: user, moderator, admin

Response (200):
```json
{
  "success": true,
  "message": "User role updated successfully",
  "data": { ... }
}
```

#### Toggle User Status
```http
PATCH /users/:userId/status
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin only

Request Body:
```json
{
  "isActive": false
}
```

Response (200):
```json
{
  "success": true,
  "message": "User status updated successfully",
  "data": { ... }
}
```

#### Search Users
```http
GET /users/search?q=john&page=1&limit=10
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin, Moderator

Query Parameters:
- `q` (required): Search query
- `page` (optional): Page number
- `limit` (optional): Items per page

Response (200):
```json
{
  "success": true,
  "message": "Search results retrieved successfully",
  "data": [...],
  "pagination": { ... }
}
```

#### Get User Statistics
```http
GET /users/stats
```

Headers:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Access: Admin only

Response (200):
```json
{
  "success": true,
  "message": "User statistics retrieved successfully",
  "data": {
    "total": 150,
    "active": 140,
    "inactive": 10,
    "admins": 3
  }
}
```

### Health Check

#### Server Health
```http
GET /health
```

Access: Public

Response (200):
```json
{
  "success": true,
  "message": "Server is running",
  "timestamp": "2024-01-27T10:00:00.000Z",
  "uptime": 3600,
  "environment": "development"
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid or missing token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 422 | Validation Error - Invalid data format |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

## Rate Limiting

- General API: 100 requests per 15 minutes
- Authentication endpoints: 5 requests per 15 minutes

When rate limited, you'll receive:
```json
{
  "success": false,
  "message": "Too many requests from this IP, please try again later",
  "timestamp": "2024-01-27T10:00:00.000Z"
}
```

## Security Headers

All responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

## Postman Collection

Import this base configuration into Postman:

```json
{
  "info": {
    "name": "User Management API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:5000/api/v1"
    },
    {
      "key": "accessToken",
      "value": ""
    }
  ]
}
```