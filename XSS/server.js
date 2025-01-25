// server.js
const express = require('express');
const sqlite3 = require('sqlite3');
const path = require('path');
const escape = require('escape-html');
const sanitizeHtml = require('sanitize-html');

const app = express();
const db = new sqlite3.Database(':memory:');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// Database setup
db.serialize(() => {
  // Create tables
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT,
    profile_bio TEXT
  )`);
  
  db.run(`CREATE TABLE blog_posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    title TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  
  db.run(`CREATE TABLE comments (
    id INTEGER PRIMARY KEY,
    post_id INTEGER,
    user_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES blog_posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Add sample data
  db.run(`INSERT INTO users (username, email, profile_bio) VALUES 
    ('admin', 'admin@example.com', 'Site Administrator'),
    ('john_doe', 'john@example.com', 'Regular blogger')`);
    
  db.run(`INSERT INTO blog_posts (user_id, title, content) VALUES 
    (1, 'Welcome to our blog!', 'This is our first post. Feel free to comment!')`);

  db.run(`INSERT INTO comments (post_id, user_id, content) VALUES
    (1, 2, "<img src=\'/fake.jpg\' onerror=\'document.body.innerHTML=\'HACKED\'\'>")`);
});

// Vulnerable Routes
// 1. Search - Reflected XSS
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.q;
  // Vulnerable: Search term reflected without sanitization
  db.all(`
    SELECT blog_posts.*, users.username 
    FROM blog_posts 
    JOIN users ON blog_posts.user_id = users.id 
    WHERE title LIKE ?`, 
    [`%${searchTerm}%`], 
    (err, posts) => {
      if (err) return res.status(500).json({ error: err.message });
      res.send(`
        <h2>Search Results for: ${searchTerm}</h2>
        <div>${posts.map(post => 
          `<div>
            <h3>${post.title}</h3>
            <p>By: ${post.username}</p>
          </div>`
        ).join('')}</div>
      `);
    });
});

// 2. Comment submission - Stored XSS
app.post('/api/posts/:postId/comments', (req, res) => {
  const { userId, content } = req.body;
  const postId = req.params.postId;
  // Vulnerable: No sanitization of comment content
  db.run('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
    [postId, userId, content], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/posts/:id', (req, res) => {
  const postId = req.params.id;
  db.get('SELECT * FROM blog_posts WHERE id = ?', [postId], (err, post) => {
    if (err) return res.status(500).json({ error: err.message });
    db.all('SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ?', 
      [postId], 
      (err, comments) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ post, comments });
      });
  });
});

// Safe Routes
// 1. Search - Protected from Reflected XSS
app.get('/api/safe/search', (req, res) => {
    const searchTerm = req.query.q;
    
    db.all(`
      SELECT blog_posts.*, users.username 
      FROM blog_posts 
      JOIN users ON blog_posts.user_id = users.id 
      WHERE title LIKE ?`, 
      [`%${searchTerm}%`], 
      (err, posts) => {
        if (err) return res.status(500).json({ error: err.message });
        
        console.log(escape(searchTerm));
        // Escape all user-provided data before inserting into HTML
        const safeHtml = `
          <h2>Search Results for: ${escape(searchTerm)}</h2>
          <div>${posts.map(post => `
            <div>
              <h3>${escape(post.title)}</h3>
              <p>By: ${escape(post.username)}</p>
            </div>
          `).join('')}</div>
        `;
        res.send(safeHtml);
    });
});

// 2. Comment submission - Protected from Stored XSS
app.post('/api/safe/posts/:postId/comments', (req, res) => {
    const { userId, content } = req.body;
    const postId = req.params.postId;
    
    // Sanitize the comment content
    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: ['b', 'i', 'em', 'strong'],
      allowedAttributes: []
    });
    
    console.log(sanitizedContent);
    db.run('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
      [postId, userId, sanitizedContent], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
});

app.get('/api/safe/posts/:id', (req, res) => {
    const postId = req.params.id;
    
    db.get('SELECT * FROM blog_posts WHERE id = ?', [postId], (err, post) => {
      if (err) return res.status(500).json({ error: err.message });
      
      db.all(`
        SELECT comments.*, users.username 
        FROM comments 
        JOIN users ON comments.user_id = users.id 
        WHERE post_id = ?`, 
        [postId], 
        (err, comments) => {
          if (err) return res.status(500).json({ error: err.message });
          
          // Sanitize post and comment content before sending
          const sanitizedPost = {
            ...post,
            title: escape(post.title),
            content: sanitizeHtml(post.content)
          };
          
          const sanitizedComments = comments.map(comment => ({
            ...comment,
            username: escape(comment.username),
            content: sanitizeHtml(comment.content)
          }));
          
          res.json({
            post: sanitizedPost,
            comments: sanitizedComments
          });
        });
    });
  });

app.listen(3000, () => {
  console.log('Server running on port 3000');
});