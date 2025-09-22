const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

// Ensure database directory exists
const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'shelflife.db');

// Create database connection
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Error opening database:', err.message);
    } else {
        console.log('✅ Connected to SQLite database');
        initializeTables();
    }
});

// Initialize database tables
function initializeTables() {
    console.log('🔧 Initializing database tables...');

    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('❌ Error creating users table:', err.message);
        else console.log('✅ Users table ready');
    });

    // Food items table
    db.run(`
        CREATE TABLE IF NOT EXISTS food_items (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            purchase_date DATE NOT NULL,
            expiry_date DATE NOT NULL,
            barcode TEXT,
            notes TEXT,
            status TEXT DEFAULT 'fresh',
            shared BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `, (err) => {
        if (err) console.error('❌ Error creating food_items table:', err.message);
        else console.log('✅ Food items table ready');
    });
}

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

// Auth middleware
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Access token missing' });
    }

    const token = authHeader.substring(7);
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = { userId: decoded.userId, email: decoded.email };
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Sign up
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }

        // Check if user exists
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            if (row) {
                return res.status(409).json({ success: false, message: 'User already exists' });
            }

            // Create user
            const passwordHash = await bcrypt.hash(password, 12);
            const userId = uuidv4();
            const now = new Date().toISOString();

            db.run(
                'INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
                [userId, name, email, passwordHash, now],
                function(err) {
                    if (err) {
                        return res.status(500).json({ success: false, message: 'Failed to create user' });
                    }

                    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
                    res.status(201).json({
                        success: true,
                        user: { id: userId, name, email, createdAt: now },
                        token
                    });
                }
            );
        });
    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Sign in
app.post('/api/auth/signin', (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }

        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }
            if (!user) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            const isValid = await bcrypt.compare(password, user.password_hash);
            if (!isValid) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
            res.json({
                success: true,
                user: { id: user.id, name: user.name, email: user.email, createdAt: user.created_at },
                token
            });
        });
    } catch (error) {
        console.error('❌ Signin error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
    db.get('SELECT id, name, email, created_at FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({ success: true, user });
    });
});

// Get food items
app.get('/api/items', authMiddleware, (req, res) => {
    const { status, category } = req.query;
    let sql = 'SELECT * FROM food_items WHERE user_id = ?';
    const params = [req.user.userId];

    if (status) {
        sql += ' AND status = ?';
        params.push(status);
    }
    if (category) {
        sql += ' AND category = ?';
        params.push(category);
    }

    sql += ' ORDER BY expiry_date ASC';

    db.all(sql, params, (err, items) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        res.json({ success: true, items: items || [] });
    });
});

// Create food item
app.post('/api/items', authMiddleware, (req, res) => {
    const { name, category, quantity, purchaseDate, expiryDate, barcode, notes } = req.body;

    if (!name || !category || !purchaseDate || !expiryDate) {
        return res.status(400).json({ success: false, message: 'Required fields missing' });
    }

    // Calculate status
    const daysUntilExpiry = Math.ceil((new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
    let status = 'fresh';
    if (daysUntilExpiry < 0) status = 'expired';
    else if (daysUntilExpiry <= 3) status = 'expiring';

    const itemId = uuidv4();
    const now = new Date().toISOString();

    db.run(`
        INSERT INTO food_items (
            id, user_id, name, category, quantity, purchase_date,
            expiry_date, barcode, notes, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        itemId, req.user.userId, name, category, quantity || 1,
        purchaseDate, expiryDate, barcode, notes, status, now
    ], function(err) {
        if (err) {
            return res.status(500).json({ success: false, message: 'Failed to create item' });
        }

        db.get('SELECT * FROM food_items WHERE id = ?', [itemId], (err, item) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Failed to retrieve item' });
            }
            res.status(201).json({ success: true, item });
        });
    });
});

// Get user stats
app.get('/api/users/stats', authMiddleware, (req, res) => {
    db.get(`
        SELECT
            COUNT(*) as total_items,
            SUM(CASE WHEN status = 'fresh' THEN 1 ELSE 0 END) as fresh_items,
            SUM(CASE WHEN status = 'expiring' THEN 1 ELSE 0 END) as expiring_items,
            SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired_items
        FROM food_items WHERE user_id = ?
    `, [req.user.userId], (err, stats) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        res.json({
            success: true,
            stats: {
                total: stats.total_items || 0,
                fresh: stats.fresh_items || 0,
                expiring: stats.expiring_items || 0,
                expired: stats.expired_items || 0
            }
        });
    });
});

// Categories
app.get('/api/items/categories/list', (req, res) => {
    const categories = [
        { name: 'Fruits', icon: '🍎', color: '#FF6B6B' },
        { name: 'Vegetables', icon: '🥕', color: '#4ECDC4' },
        { name: 'Dairy', icon: '🥛', color: '#45B7D1' },
        { name: 'Meat', icon: '🥩', color: '#96CEB4' },
        { name: 'Fish', icon: '🐟', color: '#FFEAA7' },
        { name: 'Bread', icon: '🍞', color: '#DDA0DD' },
        { name: 'Pantry', icon: '🥫', color: '#98D8C8' },
        { name: 'Frozen', icon: '🧊', color: '#A8E6CF' },
        { name: 'Beverages', icon: '🥤', color: '#FFB6C1' },
        { name: 'Snacks', icon: '🍿', color: '#F7DC6F' }
    ];
    res.json({ success: true, categories });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 ShelfLife Backend Server Started');
    console.log(`📍 Server running on http://localhost:${PORT}`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
    console.log(`📚 API base URL: http://localhost:${PORT}/api`);
    console.log('🔐 Features enabled:');
    console.log('   ✅ JWT Authentication');
    console.log('   ✅ SQLite Database');
    console.log('   ✅ CORS Protection');
    console.log('   ✅ Rate Limiting');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 Shutting down gracefully...');
    db.close(() => {
        console.log('✅ Database connection closed');
        process.exit(0);
    });
});

module.exports = app;