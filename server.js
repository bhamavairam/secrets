require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const URL = process.env.URL;

app.use(express.json());
app.use(cors());

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});



// User registration
app.post(URL+"/register", async (req, res) => {
    const { username, email, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    db.query(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        [username, email, passwordHash],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "User registered successfully" });
        }
    );
});

// User login
app.post(URL+"/login", (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ error: "Invalid credentials" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    });
});

// Store encrypted password
app.post(URL+"/save-password", (req, res) => {
    const { token, site, username, encryptedPassword } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        db.query(
            "INSERT INTO passwords (user_id, site, username, encrypted_password) VALUES (?, ?, ?, ?)",
            [decoded.userId, site, username, encryptedPassword],
            (err, result) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: "Password saved" });
            }
        );
    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
});


// Fetch all users with sites
app.get(URL+'/get-users-sites', (req, res) => {
    const query = `
      SELECT users.id, users.email, passwords.site
      FROM users
      LEFT JOIN passwords ON users.id = passwords.user_id
      ORDER BY users.email;
    `;
  
    db.query(query, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    });
  });
  
  // Retrieve stored passwords
  app.get(URL+'/get-passwords', (req, res) => {
    const userId = req.user.id;
  
    db.query('SELECT site, username, encryptedPassword FROM passwords WHERE user_id = ?', 
      [userId], 
      (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
      }
    );
  });
  
// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
