const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authenticateToken = require('./middleware/auth');

dotenv.config();

const app = express();

// ✅ SINGLE CORS CONFIGURATION
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://sridineshinteriros.shop',
    'https://www.sridineshinteriros.shop'
],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// ✅ Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: process.env.DB_HOST.includes("amazonaws.com")
        ? { rejectUnauthorized: false }
        : false
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Error connecting to database:', err.stack);
    } else {
        console.log('✅ Connected to PostgreSQL database');
        release();
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// Signup Route
// Signup Route - Modified to NOT return token
app.post('/api/signup', async (req, res) => {
    try {
        console.log('📝 Signup request received:', { email: req.body.email });
        
        const { name, email, password } = req.body;

        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if user exists
        const userExists = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (userExists.rows.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        const newUser = await pool.query(
            'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
            [name, email, hashedPassword]
        );

        console.log('✅ User created successfully:', email);

        // ✅ REMOVED: No token creation here
        // ✅ Just return success message without token
        
        res.status(201).json({
            success: true,
            message: 'User created successfully. Please login.',
            user: {
                id: newUser.rows[0].id,
                name: newUser.rows[0].name,
                email: newUser.rows[0].email
            }
            // ❌ No token field
        });

    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});
// Login Route
app.post('/api/login', async (req, res) => {
    try {
        console.log('🔐 Login request received:', { email: req.body.email });
        
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Check if user exists
        const user = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (user.rows.length === 0) {
            console.log('❌ User not found:', email);
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Compare password
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            console.log('❌ Invalid password for:', email);
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Create JWT token
        const token = jwt.sign(
            { id: user.rows[0].id, email: user.rows[0].email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE }
        );

        console.log('✅ Login successful for:', email);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user.rows[0].id,
                name: user.rows[0].name,
                email: user.rows[0].email,
                created_at: user.rows[0].created_at
            }
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// Get Profile (Protected Route)
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        console.log('👤 Profile request for user ID:', req.user.id);
        
        const user = await pool.query(
            'SELECT id, name, email, created_at FROM users WHERE id = $1',
            [req.user.id]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            success: true,
            user: user.rows[0]
        });
    } catch (error) {
        console.error('❌ Profile error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// ✅ FIXED: 404 handler - Use a middleware function instead of route pattern
app.use((req, res) => {
    console.log('❌ 404 - Route not found:', req.method, req.originalUrl);
    res.status(404).json({ 
        success: false,
        message: 'Route not found',
        path: req.originalUrl
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 Test endpoint: http://localhost:${PORT}/api/health`);
    console.log(`📍 Login endpoint: http://localhost:${PORT}/api/login`);
    console.log(`📍 Signup endpoint: http://localhost:${PORT}/api/signup`);
});