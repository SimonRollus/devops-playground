const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const pino = require('pino');
const { pinoHttp } = require('pino-http');
const ecsFormat = require('@elastic/ecs-pino-format')();

const app = express();
app.use(bodyParser.json());

// Logging setup
const logPath = path.join(__dirname, 'logs', 'access.log');
const transport = pino.transport({
  target: 'pino/file',
  options: { destination: logPath }
});

const logger = pino(ecsFormat, transport);
app.use(pinoHttp({ logger: logger }));

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'ctf_secret_key_change_in_production';

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'ctf_user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'ctf_lab',
  password: process.env.DB_PASSWORD || 'ctf_password',
  port: process.env.DB_PORT || 5432,
});

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

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

// ============================================================================
// AUTHENTICATION ENDPOINTS
// ============================================================================

// Register new user
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Insert new user
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, isAdmin) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role, created_at',
      [username, email, password_hash, 'user', false]
    );

    const newUser = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login user
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, username, email, password_hash, role, isAdmin FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// VULNERABILITY: BOLA (Broken Object Level Authorization)
// ============================================================================
app.get('/user/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // VULNERABILITY FOUND HERE: No check if req.userId === parseInt(id)
    // Any authenticated user can access any other user's profile
    // This is a BOLA vulnerability - the endpoint doesn't verify if the
    // authenticated user has permission to access this specific user's data
    
    const result = await pool.query(
      'SELECT id, username, email, role, isAdmin, secret_token, created_at FROM users WHERE id = $1',
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

// ============================================================================
// Server startup
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚠️  VULNERABLE CTF API running on port ${PORT}`);
  console.log(`⚠️  FOR EDUCATIONAL PURPOSES ONLY - DO NOT EXPOSE TO INTERNET`);
  console.log(`\nEndpoints:`);
  console.log(`  POST /register - Register new user`);
  console.log(`  POST /login - Login and get JWT token`);
  console.log(`  GET /user/:id - Get user profile (BOLA vulnerable)`);
});
