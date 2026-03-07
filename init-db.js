const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER || 'ctf_user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'ctf_lab',
  password: process.env.DB_PASSWORD || 'ctf_password',
  port: process.env.DB_PORT || 5432,
});

async function initDatabase() {
  try {
    console.log('Initializing CTF database...');
    
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        secret_token VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        isAdmin BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create logs table for DoS demonstration
    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        action VARCHAR(255),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details TEXT
      )
    `);
    
    // Insert sample users with bcrypt hashed passwords (password: "password123")
    const bcrypt = require('bcrypt');
    const hashedPassword = await bcrypt.hash('password123', 10);
    
    await pool.query(`
      INSERT INTO users (username, email, password_hash, secret_token, role, isAdmin)
      VALUES 
        ('alice', 'alice@example.com', $1, 'FLAG{alice_secret_token_a1b2c3}', 'user', false),
        ('bob', 'bob@example.com', $1, 'FLAG{bob_secret_token_d4e5f6}', 'user', false),
        ('admin', 'admin@example.com', $1, 'FLAG{admin_secret_token_g7h8i9}', 'admin', true)
      ON CONFLICT (username) DO NOTHING
    `, [hashedPassword]);
    
    // Insert sample logs (for DoS endpoint)
    for (let i = 0; i < 1000; i++) {
      await pool.query(`
        INSERT INTO logs (user_id, action, details)
        VALUES ($1, $2, $3)
      `, [Math.floor(Math.random() * 3) + 1, 'sample_action', `Log entry ${i}`]);
    }
    
    console.log('✅ Database initialized successfully');
    console.log('Sample users created (password: "password123"):');
    console.log('  - alice (ID: 1, role: user)');
    console.log('  - bob (ID: 2, role: user)');
    console.log('  - admin (ID: 3, role: admin)');
    console.log('\nAll users have the same password: password123');
    
    process.exit(0);
  } catch (err) {
    console.error('Error initializing database:', err);
    process.exit(1);
  }
}

initDatabase();
