const express = require('express');
const pool = require("./database");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const port = 4000;

app.get('/', (req, res) => res.send('Hello World!'));
app.get('/test', (req, res) => res.send('Test URL!'));

// Token authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Get token from header
    if (!token) return res.sendStatus(401); // No token, send status 401
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token, send status 403
        req.user = user; // Save user info to req
        next(); // Continue
    });
};

// Get user account info
app.get('/account', authenticateToken, async (req, res) => {
    try {
        const userid = req.user.id;
        const [results] = await pool.query("SELECT email, name, picture FROM users WHERE id = ?", [userid]);
        if (results.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json(results);
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "Server error" });
    }
});

// User registration
app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const [result] = await pool.query('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', [email, hashedPassword, name]);
        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).send('Error registering user');
    }
});

// Add new employee
app.post('/addnew', async (req, res) => {
    const { fname, lname } = req.body;
    try {
        const [result] = await pool.query('INSERT INTO employees (fname, lname) VALUES (?, ?)', [fname, lname]);
        res.status(201).send('Employee added successfully');
    } catch (error) {
        res.status(500).send('Error adding employee');
    }
});

// User login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = results[0];
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    if (await bcrypt.compare(password, user.password)) {
        const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20h' });
        return res.json({ token: accessToken });
    } else {
        return res.status(401).json({ message: 'Incorrect password' });
    }
});

// Setup storage for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });
app.use('/uploads', express.static('uploads')); // Serve files from 'uploads'

// Update user account info
app.put('/update-account', authenticateToken, upload.single('picture'), async (req, res) => {
    const { name, email } = req.body;
    const picturePath = req.file ? `uploads/${req.file.filename}` : null;
    try {
        const userid = req.user.id;
        let query = 'UPDATE users SET name=?, email=?';
        let params = [name, email];
        if (picturePath) {
            query += ', picture=?';
            params.push(picturePath);
        }
        query += ' WHERE id=?';
        params.push(userid);
        const [results] = await pool.query(query, params);
        if (results.affectedRows === 0) {
            return res.status(400).json({ error: "User not found" });
        }
        res.json({ message: "User info updated successfully" });
    } catch (err) {
        console.log("Error", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Create a new blog post
app.post('/create-post', authenticateToken, async (req, res) => {
    const { title, detail, category } = req.body;
    try {
        const userid = req.user.id; // Use user id from JWT
        const [result] = await pool.query('INSERT INTO blog (userid, title, detail, category) VALUES (?, ?, ?, ?)', [userid, title, detail, category]);
        res.status(201).json({ message: "Post created successfully", postId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: "Unable to create post" });
    }
});

// Get all posts by user
app.get('/read-post/', authenticateToken, async (req, res) => {
    try {
        const userid = req.user.id;
        const [results] = await pool.query('SELECT * FROM blog WHERE userid = ?', [userid]);
        if (results.length === 0) {
            return res.status(404).json({ error: "No posts found" });
        }
        res.json(results);
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "Unable to retrieve posts" });
    }
});

// Get blog post by ID
app.get('/post/:blogid', async (req, res) => {
    const { blogid } = req.params; // Get blogid from URL parameters
    try {
        const [result] = await pool.query('SELECT * FROM blog WHERE blogid = ?', [blogid]);
        if (result.length === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        return res.json(result[0]);
    } catch (err) {
        console.error("Error fetching blog data: ", err);
        return res.status(500).json({ message: 'Error fetching blog data', error: err });
    }
});

// Delete blog post
app.delete('/post/:blogid', async (req, res) => {
    const { blogid } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM blog WHERE blogid = ?', [blogid]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        return res.json({ message: 'Blog deleted successfully' });
    } catch (err) {
        console.error("Error executing SQL: ", err);
        return res.status(500).json({ message: 'Error deleting the blog', error: err });
    }
});

// Update blog post
app.put('/post/:blogid', async (req, res) => {
    const { blogid } = req.params;
    const { title, detail, category } = req.body;
    try {
        const [result] = await pool.query('UPDATE blog SET title = ?, detail = ?, category = ? WHERE blogid = ?', [title, detail, category, blogid]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        return res.json({ message: 'Blog updated successfully' });
    } catch (err) {
        console.error("Error updating SQL: ", err);
        return res.status(500).json({ message: 'Error updating the blog', error: err });
    }
});

// Start server
app.listen(port, () => console.log(`Example app listening on port ${port}!`));
