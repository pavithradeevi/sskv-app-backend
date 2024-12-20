const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const cors = require('cors');



// Load environment variables
dotenv.config();

// Initialize the Express app
const app = express();
app.use(bodyParser.json());
app.use(cors());  // This will allow all origins to access your server

// Create SQLite database
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Database connected');
  }
});

// Create users table if not exists
db.run(
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    phone TEXT UNIQUE,
    password TEXT
  )`
);

// Login route
app.post('/login', (req, res) => {
  const { userId, password } = req.body;
  const query = 'SELECT * FROM users WHERE email = ? OR phone = ?';
  db.get(query, [userId, userId], async (err, user) => {
    if (err) return res.status(500).json({ msg: 'Internal error' });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) return res.status(401).json({ msg: 'Incorrect password' });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ msg: 'Login successful', token });
  });
});

// Register route
app.post('/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
  
    const hashedPassword = await bcrypt.hash(password, 10);
  
    const query = 'INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)';
    db.run(query, [name, email, phone, hashedPassword], function (err) {
      if (err) {
        console.error('Error inserting user:', err.message); // Add detailed log
        if (err.message.includes('UNIQUE')) {
          return res.status(409).json({ msg: 'Email or phone already registered' });
        }
        return res.status(500).json({ msg: 'Registration failed', error: err.message }); // Send error details
      }
      res.status(201).json({ msg: 'User registered successfully' });
    });
  });
  
  const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'Access denied' });
  
    try {
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      req.user = verified; // Attach user details to the request object
      next();
    } catch (err) {
      res.status(403).json({ msg: 'Invalid token' });
    }
  };
  
  // Protect the user route
  app.get('/user/:id', authenticate, (req, res) => {
    const { id } = req.params;
    if (req.user.id !== parseInt(id)) {
      return res.status(403).json({ msg: 'Access denied' });
    }
    const query = 'SELECT id, name, email, phone FROM users WHERE id = ?';
  
    db.get(query, [id], (err, user) => {
      if (err) return res.status(500).json({ msg: 'Internal error' });
      if (!user) return res.status(404).json({ msg: 'User not found' });
      res.status(200).json(user);
    });
  });
  // Get all registered users
app.get('/users', authenticate, (req, res) => {
  const query = 'SELECT id, name, email, phone FROM users'; // Exclude the password field
  
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ msg: 'Internal error' });
    }
    res.status(200).json(rows); // Return the list of users
  });
});


// Start server
const PORT = process.env.PORT || 5001;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
