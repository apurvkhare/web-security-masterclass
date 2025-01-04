// server.js
const express = require('express');
const sqlite3 = require('sqlite3');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const db = new sqlite3.Database(':memory:');

// Database initialization
db.serialize(async () => {
  // Users table with sensitive information
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    is_admin BOOLEAN DEFAULT 0,
    credit_card TEXT,
    api_key TEXT
  )`);

  // Blog posts table
  db.run(`CREATE TABLE blog_posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    title TEXT,
    content TEXT,
    is_private BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Insert sample data
  db.run(`INSERT INTO users (username, password, email, is_admin, credit_card, api_key) VALUES 
    ('admin', 'admin123', 'admin@blog.com', 1, '4532-xxxx-xxxx-9876', 'sk_live_admin_123456'),
    ('tony', 'tony123', 'tony@blog.com', 0, '4532-xxxx-xxxx-5678', 'sk_live_user_123456')`);

  db.run(`INSERT INTO blog_posts (user_id, title, content, is_private) VALUES
    (1, 'Welcome Post', 'Welcome to our blog!', 0),
    (1, 'Private Admin Notes', 'Secret admin information...', 1),
    (2, 'Tony Public Post', 'Hello everyone!', 0)`);
});


// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname)));

// Vulnerable Routes

// 1. Login - Vulnerable to "always true" attack
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Vulnerable: Direct string concatenation
  const query = `
    SELECT id, username, is_admin, email 
    FROM users 
    WHERE username = '${username}' 
    AND password = '${password}'
  `;
  
  db.get(query, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(user);
  });
});

// 2. Search Posts - Vulnerable to query stacking
app.get('/api/posts/search', (req, res) => {
  const { keyword } = req.query;
  
  // Vulnerable: Allows multiple queries
  const query = `
    SELECT id, title, content 
    FROM blog_posts 
    WHERE content LIKE 'test'; DROP TABLE blog_posts; --';
  `;

  db.all(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results || []);
  });

  db.exec(query, (err) => {
    if (err) return res.status(500).json({ error: err.message });
  });
});

// 3. User Profile - Vulnerable to data exfiltration
app.get('/api/users/profile', (req, res) => {
  const { username } = req.query;
  
  // Vulnerable: Allows UNION-based attacks
  const query = `
    SELECT username, email 
    FROM users 
    WHERE username = 'admin' UNION SELECT credit_card, api_key FROM users WHERE '1'='1'
  `;
  
  db.get(query, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

//secure route
app.post('/api/secure/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password || 
      typeof username !== 'string' || 
      typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  try {
    // Use parameterized query
    const query = `
      SELECT id, username, is_admin, email, password
      FROM users 
      WHERE username = ?
    `;
    
    db.get(query, [username], async (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      if (password !== user.password) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Don't send sensitive data
      delete user.password;
      res.json(user);
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(3000, () => {
  console.log('Vulnerable server running on port 3000');
});