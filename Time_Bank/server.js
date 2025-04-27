const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

pool.connect((err) => {
    if (err) {
        console.error('Database connection error:', err);
        process.exit(1);
    }
    console.log('Connected to PostgreSQL');
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Serve static pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/profile', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/community', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'community.html')));
app.get('/dashboard', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// Admin Registration
app.post('/admin/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields required' });
    const admin_id = uuidv4().substring(0, 255);
    const pass = await bcrypt.hash(password, 10);
    try {
        await pool.query('INSERT INTO Admin (admin_id, username, pass) VALUES ($1, $2, $3)', [admin_id, username, pass]);
        res.status(201).json({ admin_id });
    } catch (err) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Admin Login
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM Admin WHERE username = $1', [username]);
        if (result.rows.length && await bcrypt.compare(password, result.rows[0].pass)) {
            const token = jwt.sign({ admin_id: result.rows[0].admin_id }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// User Registration
app.post('/register', async (req, res) => {
    const { name, email, password, location, phone_no } = req.body;
    if (!name || !email || !password || !location || !phone_no) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    const user_id = uuidv4().substring(0, 255);
    const transaction_id = uuidv4().substring(0, 255);
    const provider_id = user_id;
    const passwordHash = await bcrypt.hash(password, 10);
    const time_credits = 0;
    try {
        await pool.query(
            'INSERT INTO Users (user_id, transaction_id, provider_id, name, email, password, location, phone_no, time_credits) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [user_id, transaction_id, provider_id, name, email, passwordHash, location, phone_no, time_credits]
        );
        res.status(201).json({ user_id });
    } catch (err) {
        if (err.code === '23505') {
            res.status(409).json({ error: 'Email already registered' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

// User Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    try {
        const result = await pool.query('SELECT * FROM Users WHERE email = $1', [email]);
        if (result.rows.length && await bcrypt.compare(password, result.rows[0].password)) {
            const token = jwt.sign({ user_id: result.rows[0].user_id }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ user_id: result.rows[0].user_id, token, name: result.rows[0].name });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get Skills
app.get('/skills', async (req, res) => {
    try {
        const result = await pool.query('SELECT s.*, u.name FROM Skills s JOIN Users u ON s.user_id = u.user_id WHERE s.is_active = TRUE');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error fetching skills' });
    }
});

// Add Skill
app.post('/skills', authenticateToken, async (req, res) => {
    const { user_id, skill_name, hourly_rate, description, availability } = req.body;
    if (!user_id || !skill_name || !hourly_rate || !description || !availability) {
        return res.status(400).json({ error: 'All fields required' });
    }
    if (req.user.user_id !== user_id) return res.status(403).json({ error: 'Unauthorized' });
    const skill_id = uuidv4().substring(0, 255);
    try {
        await pool.query(
            'INSERT INTO Skills (skill_id, user_id, skill_name, hourly_rate, description, availability, is_active) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [skill_id, user_id, skill_name, hourly_rate, description, availability, true]
        );
        await pool.query('INSERT INTO Offers (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [user_id]);
        res.status(201).json({ skill_id });
    } catch (err) {
        res.status(500).json({ error: 'Error adding skill: ' + err.message });
    }
});

// Update Skill
app.put('/skills/:id', authenticateToken, async (req, res) => {
    const skillId = req.params.id;
    const { skill_name, hourly_rate, description, availability } = req.body;
    console.log('Update request for skillId:', skillId, 'with data:', req.body);
    if (!skill_name || !hourly_rate || !description || !availability) {
        return res.status(400).json({ error: 'All fields (skill_name, hourly_rate, description, availability) are required' });
    }
    try {
        const result = await pool.query(
            'UPDATE Skills SET skill_name = $1, hourly_rate = $2, description = $3, availability = $4 WHERE skill_id = $5 AND user_id = $6 RETURNING *',
            [skill_name, hourly_rate, description, availability, skillId, req.user.user_id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Skill not found or unauthorized' });
        }
        res.json({ message: 'Skill updated successfully' });
    } catch (err) {
        console.error('Update skill error:', err);
        res.status(500).json({ error: 'Error updating skill: ' + err.message });
    }
});

// Archive Skill (Instead of Delete)
app.delete('/skills/:id', authenticateToken, async (req, res) => {
    const skillId = req.params.id;
    console.log('Archive request for skillId:', skillId, 'by user:', req.user.user_id);
    try {
        const result = await pool.query(
            'UPDATE Skills SET is_active = FALSE WHERE skill_id = $1 AND user_id = $2 RETURNING *',
            [skillId, req.user.user_id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Skill not found or unauthorized' });
        }
        res.json({ message: 'Skill archived successfully' });
    } catch (err) {
        console.error('Archive skill error:', err);
        res.status(500).json({ error: 'Error archiving skill: ' + err.message });
    }
});

// Create Transaction
app.post('/transactions', authenticateToken, async (req, res) => {
    const { provider_id, receiver_id, skill_id, hours_transferred, status = 'Pending' } = req.body;
    if (!provider_id || !receiver_id || !skill_id || !hours_transferred) {
        return res.status(400).json({ error: 'All fields required' });
    }
    if (req.user.user_id !== receiver_id) return res.status(403).json({ error: 'Unauthorized' });
    const transaction_id = uuidv4().substring(0, 255);
    try {
        // Check if skill is active
        const skillCheck = await pool.query('SELECT is_active FROM Skills WHERE skill_id = $1', [skill_id]);
        if (skillCheck.rows.length === 0 || !skillCheck.rows[0].is_active) {
            return res.status(404).json({ error: 'Skill not found or inactive' });
        }

        await pool.query(
            'INSERT INTO Transactions (transaction_id, provider_id, receiver_id, skill_id, hours_transferred, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [transaction_id, provider_id, receiver_id, skill_id, hours_transferred, status]
        );
        await pool.query('INSERT INTO Initiates (user_id, transaction_id) VALUES ($1, $2)', [receiver_id, transaction_id]);

        // Create notification for the provider
        const skill = await pool.query('SELECT skill_name, user_id FROM Skills WHERE skill_id = $1', [skill_id]);
        const providerName = await pool.query('SELECT name FROM Users WHERE user_id = $1', [provider_id]);
        const message = `${req.user.name} requested ${skill.rows[0].skill_name} from you for ${hours_transferred} hour(s)`;
        const notification_id = uuidv4().substring(0, 255);
        await pool.query(
            'INSERT INTO Notifications (notification_id, user_id, transaction_id, message, is_read) VALUES ($1, $2, $3, $4, $5)',
            [notification_id, provider_id, transaction_id, message, false]
        );

        res.status(201).json({ transaction_id });
    } catch (err) {
        res.status(500).json({ error: 'Error creating transaction: ' + err.message });
    }
});

// Update Transaction
app.put('/transactions/:id', authenticateToken, async (req, res) => {
    const transactionId = req.params.id;
    const { status } = req.body;
    if (!status) return res.status(400).json({ error: 'Status is required' });
    try {
        const result = await pool.query(
            'UPDATE Transactions SET status = $1 WHERE transaction_id = $2 RETURNING *',
            [status, transactionId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Transaction not found' });
        }
        res.json({ message: 'Transaction updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Error updating transaction' });
    }
});

// Add Review
app.post('/reviews', authenticateToken, async (req, res) => {
    const { user_id, transaction_id, comments, rating } = req.body;
    if (!user_id || !transaction_id || !comments || !rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Invalid review data' });
    }
    if (req.user.user_id !== user_id) return res.status(403).json({ error: 'Unauthorized' });
    const review_id = uuidv4().substring(0, 255);
    try {
        await pool.query(
            'INSERT INTO Reviews (review_id, transaction_id, comments, rating) VALUES ($1, $2, $3, $4)',
            [review_id, transaction_id, comments, rating]
        );
        await pool.query('INSERT INTO Has (transaction_id, review_id) VALUES ($1, $2)', [transaction_id, review_id]);
        await pool.query('INSERT INTO Gives (user_id, review_id) VALUES ($1, $2)', [user_id, review_id]);
        res.status(201).json({ review_id });
    } catch (err) {
        res.status(500).json({ error: 'Error adding review' });
    }
});

// Get User Data
app.get('/user/:id', authenticateToken, async (req, res) => {
    const userId = req.params.id;
    if (req.user.user_id !== userId) return res.status(403).json({ error: 'Unauthorized' });
    try {
        const user = await pool.query('SELECT * FROM Users WHERE user_id = $1', [userId]);
        const skills = await pool.query('SELECT * FROM Skills WHERE user_id = $1 AND is_active = TRUE', [userId]);
        const transactions = await pool.query(
            `SELECT t.*, r.comments, r.rating, r.review_id, up.name as provider_name, ur.name as receiver_name, s.skill_name
             FROM Transactions t
             LEFT JOIN Has h ON t.transaction_id = h.transaction_id
             LEFT JOIN Reviews r ON h.review_id = r.review_id
             LEFT JOIN Users up ON t.provider_id = up.user_id
             LEFT JOIN Users ur ON t.receiver_id = ur.user_id
             LEFT JOIN Skills s ON t.skill_id = s.skill_id
             WHERE t.provider_id = $1 OR t.receiver_id = $1`,
            [userId]
        );
        res.json({
            ...user.rows[0],
            skills: skills.rows,
            transactions: transactions.rows
        });
    } catch (err) {
        res.status(500).json({ error: 'Error fetching user data' });
    }
});

// Update User Profile
app.put('/user/:id', authenticateToken, async (req, res) => {
    const userId = req.params.id;
    const { name, email, location, phone_no, password } = req.body;
    if (req.user.user_id !== userId) return res.status(403).json({ error: 'Unauthorized' });
    try {
        let passwordHash = null;
        if (password) {
            passwordHash = await bcrypt.hash(password, 10);
        }
        const updateFields = [];
        const values = [];
        let index = 1;

        if (name) { updateFields.push(`name = $${index++}`); values.push(name); }
        if (email) { updateFields.push(`email = $${index++}`); values.push(email); }
        if (location) { updateFields.push(`location = $${index++}`); values.push(location); }
        if (phone_no) { updateFields.push(`phone_no = $${index++}`); values.push(phone_no); }
        if (passwordHash) { updateFields.push(`password = $${index++}`); values.push(passwordHash); }

        if (updateFields.length > 0) {
            values.push(userId);
            await pool.query(
                `UPDATE Users SET ${updateFields.join(', ')} WHERE user_id = $${index}`,
                values
            );
        }
        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Error updating profile' });
    }
});

// Match Skills
app.post('/match-skills', authenticateToken, async (req, res) => {
    const { user_id, skill_needed, preferred_location } = req.body;
    if (!user_id || !skill_needed || !preferred_location) {
        return res.status(400).json({ error: 'All fields required' });
    }
    if (req.user.user_id !== user_id) return res.status(403).json({ error: 'Unauthorized' });
    try {
        const result = await pool.query(
            `SELECT s.*, u.name as provider_name 
             FROM Skills s 
             JOIN Users u ON s.user_id = u.user_id 
             WHERE s.skill_name ILIKE $1 
             AND u.location ILIKE $2 
             AND s.user_id != $3 
             AND s.is_active = TRUE`,
            [`%${skill_needed}%`, `%${preferred_location}%`, user_id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error matching skills' });
    }
});

// Community Stats
app.get('/community/stats', async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM Users');
        const totalTransactions = await pool.query('SELECT COUNT(*) FROM Transactions');
        const topContributors = await pool.query(
            `SELECT u.name, COUNT(t.transaction_id) as transactions 
             FROM Users u 
             LEFT JOIN Transactions t ON u.user_id = t.provider_id 
             GROUP BY u.user_id, u.name 
             ORDER BY transactions DESC 
             LIMIT 5`
        );
        const recentTransactions = await pool.query(
            `SELECT t.*, up.name as provider_name, ur.name as receiver_name, s.skill_name 
             FROM Transactions t 
             JOIN Users up ON t.provider_id = up.user_id 
             JOIN Users ur ON t.receiver_id = ur.user_id 
             JOIN Skills s ON t.skill_id = s.skill_id 
             ORDER BY t.transaction_id DESC 
             LIMIT 10`
        );
        res.json({
            totalUsers: totalUsers.rows[0].count,
            totalTransactions: totalTransactions.rows[0].count,
            topContributors: topContributors.rows,
            recentTransactions: recentTransactions.rows
        });
    } catch (err) {
        res.status(500).json({ error: 'Error fetching community stats' });
    }
});

// Get Notifications
app.get('/notifications', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM Notifications WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.user_id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error fetching notifications: ' + err.message });
    }
});

// Mark Notification as Read
app.put('/notifications/:id', authenticateToken, async (req, res) => {
    const notificationId = req.params.id;
    try {
        const result = await pool.query(
            'UPDATE Notifications SET is_read = TRUE WHERE notification_id = $1 AND user_id = $2 RETURNING *',
            [notificationId, req.user.user_id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Notification not found or unauthorized' });
        }
        res.json({ message: 'Notification marked as read' });
    } catch (err) {
        res.status(500).json({ error: 'Error updating notification: ' + err.message });
    }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));