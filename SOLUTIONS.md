# CTF Solutions & Secure Code Examples

## BOLA Vulnerability - Secure Implementation

```javascript
const jwt = require('jsonwebtoken');

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.userId = user.id;
    req.username = user.username;
    next();
  });
};

// Secure BOLA implementation
app.get('/user/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // FIX: Check if the requesting user owns this resource
    if (req.userId !== parseInt(id)) {
      return res.status(403).json({ error: 'Forbidden: You can only access your own profile' });
    }
    
    // Also filter out sensitive fields
    const result = await pool.query(
      'SELECT id, username, email, role, isAdmin, created_at FROM users WHERE id = $1',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

## Alternative: Role-Based Access

If admins should be able to view all profiles:

```javascript
app.get('/user/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get requesting user's role
    const requestingUser = await pool.query(
      'SELECT isAdmin FROM users WHERE id = $1',
      [req.userId]
    );
    
    const isAdmin = requestingUser.rows[0]?.isAdmin;
    
    // Check authorization: user can access their own profile OR user is admin
    if (req.userId !== parseInt(id) && !isAdmin) {
      return res.status(403).json({ error: 'Forbidden: Access denied' });
    }
    
    const result = await pool.query(
      'SELECT id, username, email, role, isAdmin, created_at FROM users WHERE id = $1',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

## Additional Security Best Practices for Authentication

1. **Use helmet.js** for security headers
2. **Implement proper JWT refresh tokens** for better security
3. **Add request validation** (express-validator, joi)
4. **Enable CORS properly** with specific origins
5. **Log security events** for monitoring
6. **Use HTTPS** in production
7. **Keep dependencies updated** (npm audit)
8. **Implement proper error handling** without exposing stack traces
9. **Add rate limiting** to prevent brute force attacks
10. **Store JWT secret in environment variables** never in code
