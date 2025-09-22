const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const sharp = require('sharp');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Database setup - PostgreSQL for production, SQLite for development
let db;
if (NODE_ENV === 'production') {
    // PostgreSQL setup for production
    const { Pool } = require('pg');
    const DATABASE_URL = process.env.DATABASE_URL;

    if (!DATABASE_URL) {
        console.error('❌ DATABASE_URL environment variable is required in production');
        process.exit(1);
    }

    db = new Pool({
        connectionString: DATABASE_URL,
        ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    console.log('🐘 Using PostgreSQL database for production');
} else {
    // SQLite setup for development
    const sqlite3 = require('sqlite3').verbose();
    db = new sqlite3.Database('./data/shelflife.db');
    console.log('📁 Using SQLite database for development');
}

// Comprehensive food database with expiry days
const FOOD_DATABASE = {
    "fruits": {
        "apple": { days: 30, category: "Fruits", storage: "refrigerator" },
        "banana": { days: 7, category: "Fruits", storage: "counter" },
        "orange": { days: 21, category: "Fruits", storage: "refrigerator" },
        "grapes": { days: 7, category: "Fruits", storage: "refrigerator" },
        "strawberry": { days: 5, category: "Fruits", storage: "refrigerator" },
        "blueberry": { days: 10, category: "Fruits", storage: "refrigerator" },
        "avocado": { days: 7, category: "Fruits", storage: "counter" },
        "lemon": { days: 28, category: "Fruits", storage: "refrigerator" },
        "lime": { days: 21, category: "Fruits", storage: "refrigerator" },
        "pear": { days: 14, category: "Fruits", storage: "refrigerator" }
    },
    "vegetables": {
        "carrot": { days: 21, category: "Vegetables", storage: "refrigerator" },
        "broccoli": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "spinach": { days: 5, category: "Vegetables", storage: "refrigerator" },
        "lettuce": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "tomato": { days: 7, category: "Vegetables", storage: "counter" },
        "cucumber": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "bell pepper": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "onion": { days: 30, category: "Vegetables", storage: "pantry" },
        "garlic": { days: 90, category: "Vegetables", storage: "pantry" },
        "potato": { days: 14, category: "Vegetables", storage: "pantry" }
    },
    "dairy": {
        "milk": { days: 7, category: "Dairy", storage: "refrigerator" },
        "cheese": { days: 21, category: "Dairy", storage: "refrigerator" },
        "yogurt": { days: 14, category: "Dairy", storage: "refrigerator" },
        "butter": { days: 30, category: "Dairy", storage: "refrigerator" },
        "cream": { days: 7, category: "Dairy", storage: "refrigerator" }
    },
    "meat": {
        "chicken": { days: 2, category: "Meat", storage: "refrigerator" },
        "beef": { days: 3, category: "Meat", storage: "refrigerator" },
        "pork": { days: 3, category: "Meat", storage: "refrigerator" },
        "fish": { days: 2, category: "Meat", storage: "refrigerator" },
        "salmon": { days: 2, category: "Meat", storage: "refrigerator" }
    }
};

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
}));

// CORS configuration
const corsOptions = {
    origin: NODE_ENV === 'production'
        ? [process.env.CORS_ORIGIN, 'https://shelflife-app.onrender.com']
        : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: { error: 'Too many requests, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// Logging
if (NODE_ENV === 'production') {
    app.use(morgan('combined'));
} else {
    app.use(morgan('dev'));
}

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

// Initialize database tables
async function initializeDatabase() {
    console.log('🔧 Initializing database tables...');

    if (NODE_ENV === 'production') {
        // PostgreSQL table creation
        const createTables = [
            `CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS food_items (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1,
                unit VARCHAR(50) NOT NULL DEFAULT 'pieces',
                purchase_date DATE,
                expiry_date DATE,
                auto_calculated BOOLEAN DEFAULT false,
                storage_location VARCHAR(100) DEFAULT 'refrigerator',
                barcode VARCHAR(255),
                image_url TEXT,
                nutritional_info JSONB,
                recipe_suggestions JSONB,
                status VARCHAR(50) DEFAULT 'fresh',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS notifications (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                food_item_id UUID REFERENCES food_items(id) ON DELETE CASCADE,
                type VARCHAR(50) NOT NULL,
                message TEXT NOT NULL,
                sent_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`
        ];

        for (const query of createTables) {
            await db.query(query);
        }
    } else {
        // SQLite table creation
        const createTables = [
            `CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS food_items (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1,
                unit TEXT NOT NULL DEFAULT 'pieces',
                purchase_date TEXT,
                expiry_date TEXT,
                auto_calculated INTEGER DEFAULT 0,
                storage_location TEXT DEFAULT 'refrigerator',
                barcode TEXT,
                image_url TEXT,
                nutritional_info TEXT,
                recipe_suggestions TEXT,
                status TEXT DEFAULT 'fresh',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )`,
            `CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                food_item_id TEXT,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                sent_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (food_item_id) REFERENCES food_items (id)
            )`
        ];

        for (const query of createTables) {
            await new Promise((resolve, reject) => {
                db.run(query, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }
    }

    console.log('✅ All database tables initialized');
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Utility functions
function calculateExpiryDate(foodName, purchaseDate = new Date()) {
    const lowerName = foodName.toLowerCase();
    let defaultDays = 7; // Default 7 days

    // Search through food database
    for (const category of Object.values(FOOD_DATABASE)) {
        for (const [name, data] of Object.entries(category)) {
            if (lowerName.includes(name) || name.includes(lowerName)) {
                defaultDays = data.days;
                break;
            }
        }
    }

    const expiryDate = new Date(purchaseDate);
    expiryDate.setDate(expiryDate.getDate() + defaultDays);
    return expiryDate;
}

function calculateDaysUntilExpiry(expiryDate) {
    const today = new Date();
    const expiry = new Date(expiryDate);
    const diffTime = expiry - today;
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}

function determineStatus(daysUntilExpiry) {
    if (daysUntilExpiry < 0) return 'expired';
    if (daysUntilExpiry <= 3) return 'expiring';
    return 'fresh';
}

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: NODE_ENV,
        features: {
            camera_scanning: true,
            auto_expiry: true,
            notifications: true,
            comprehensive_database: true
        }
    });
});

// Auth endpoints
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and password are required'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const userId = uuidv4();

        if (NODE_ENV === 'production') {
            // PostgreSQL
            const result = await db.query(
                'INSERT INTO users (id, name, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, name, email, created_at',
                [userId, name, email, hashedPassword]
            );
            const user = result.rows[0];

            const token = jwt.sign(
                { userId: user.id, email: user.email },
                JWT_SECRET,
                { expiresIn: '30d' }
            );

            res.status(201).json({
                success: true,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    createdAt: user.created_at
                },
                token
            });
        } else {
            // SQLite
            await new Promise((resolve, reject) => {
                db.run(
                    'INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)',
                    [userId, name, email, hashedPassword],
                    function(err) {
                        if (err) {
                            if (err.message.includes('UNIQUE constraint failed')) {
                                reject(new Error('Email already exists'));
                            } else {
                                reject(err);
                            }
                        } else {
                            resolve();
                        }
                    }
                );
            });

            const token = jwt.sign(
                { userId, email },
                JWT_SECRET,
                { expiresIn: '30d' }
            );

            res.status(201).json({
                success: true,
                user: {
                    id: userId,
                    name,
                    email,
                    createdAt: new Date().toISOString()
                },
                token
            });
        }
    } catch (error) {
        console.error('Signup error:', error);
        if (error.message === 'Email already exists') {
            res.status(409).json({ success: false, message: 'Email already exists' });
        } else {
            res.status(500).json({ success: false, message: 'Server error during signup' });
        }
    }
});

app.post('/api/auth/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        let user;
        if (NODE_ENV === 'production') {
            // PostgreSQL
            const result = await db.query(
                'SELECT id, name, email, password_hash, created_at FROM users WHERE email = $1',
                [email]
            );
            user = result.rows[0];
        } else {
            // SQLite
            user = await new Promise((resolve, reject) => {
                db.get(
                    'SELECT id, name, email, password_hash, created_at FROM users WHERE email = ?',
                    [email],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    }
                );
            });
        }

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                createdAt: user.created_at
            },
            token
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ success: false, message: 'Server error during signin' });
    }
});

// Get user profile
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        let user;
        if (NODE_ENV === 'production') {
            const result = await db.query(
                'SELECT id, name, email, created_at FROM users WHERE id = $1',
                [req.user.userId]
            );
            user = result.rows[0];
        } else {
            user = await new Promise((resolve, reject) => {
                db.get(
                    'SELECT id, name, email, created_at FROM users WHERE id = ?',
                    [req.user.userId],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    }
                );
            });
        }

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                createdAt: user.created_at
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Food items endpoints
app.get('/api/items', authenticateToken, async (req, res) => {
    try {
        let items;
        if (NODE_ENV === 'production') {
            const result = await db.query(
                `SELECT * FROM food_items WHERE user_id = $1 ORDER BY created_at DESC`,
                [req.user.userId]
            );
            items = result.rows;
        } else {
            items = await new Promise((resolve, reject) => {
                db.all(
                    'SELECT * FROM food_items WHERE user_id = ? ORDER BY created_at DESC',
                    [req.user.userId],
                    (err, rows) => {
                        if (err) reject(err);
                        else resolve(rows);
                    }
                );
            });
        }

        // Calculate dynamic fields
        const enrichedItems = items.map(item => {
            const daysUntilExpiry = calculateDaysUntilExpiry(item.expiry_date);
            const status = determineStatus(daysUntilExpiry);

            return {
                ...item,
                daysUntilExpiry,
                status,
                daysInStorage: Math.ceil((new Date() - new Date(item.purchase_date)) / (1000 * 60 * 60 * 24))
            };
        });

        res.json({ success: true, items: enrichedItems });
    } catch (error) {
        console.error('Get items error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/items', authenticateToken, async (req, res) => {
    try {
        const {
            name,
            category,
            quantity = 1,
            unit = 'pieces',
            purchaseDate,
            expiryDate,
            storageLocation = 'refrigerator',
            barcode
        } = req.body;

        if (!name || !category) {
            return res.status(400).json({
                success: false,
                message: 'Name and category are required'
            });
        }

        const itemId = uuidv4();
        const purchase = purchaseDate ? new Date(purchaseDate) : new Date();
        let expiry;
        let autoCalculated = false;

        if (expiryDate) {
            expiry = new Date(expiryDate);
        } else {
            expiry = calculateExpiryDate(name, purchase);
            autoCalculated = true;
        }

        const daysUntilExpiry = calculateDaysUntilExpiry(expiry);
        const status = determineStatus(daysUntilExpiry);

        if (NODE_ENV === 'production') {
            const result = await db.query(
                `INSERT INTO food_items
                (id, user_id, name, category, quantity, unit, purchase_date, expiry_date,
                 auto_calculated, storage_location, barcode, status)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                RETURNING *`,
                [itemId, req.user.userId, name, category, quantity, unit,
                 purchase.toISOString().split('T')[0], expiry.toISOString().split('T')[0],
                 autoCalculated, storageLocation, barcode, status]
            );

            const item = result.rows[0];
            res.status(201).json({
                success: true,
                item: {
                    ...item,
                    daysUntilExpiry,
                    daysInStorage: Math.ceil((new Date() - purchase) / (1000 * 60 * 60 * 24))
                }
            });
        } else {
            await new Promise((resolve, reject) => {
                db.run(
                    `INSERT INTO food_items
                    (id, user_id, name, category, quantity, unit, purchase_date, expiry_date,
                     auto_calculated, storage_location, barcode, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [itemId, req.user.userId, name, category, quantity, unit,
                     purchase.toISOString().split('T')[0], expiry.toISOString().split('T')[0],
                     autoCalculated ? 1 : 0, storageLocation, barcode, status],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });

            res.status(201).json({
                success: true,
                item: {
                    id: itemId,
                    user_id: req.user.userId,
                    name,
                    category,
                    quantity,
                    unit,
                    purchase_date: purchase.toISOString().split('T')[0],
                    expiry_date: expiry.toISOString().split('T')[0],
                    auto_calculated: autoCalculated,
                    storage_location: storageLocation,
                    barcode,
                    status,
                    daysUntilExpiry,
                    daysInStorage: Math.ceil((new Date() - purchase) / (1000 * 60 * 60 * 24)),
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }
            });
        }
    } catch (error) {
        console.error('Create item error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// User stats
app.get('/api/users/stats', authenticateToken, async (req, res) => {
    try {
        let items;
        if (NODE_ENV === 'production') {
            const result = await db.query(
                'SELECT * FROM food_items WHERE user_id = $1',
                [req.user.userId]
            );
            items = result.rows;
        } else {
            items = await new Promise((resolve, reject) => {
                db.all(
                    'SELECT * FROM food_items WHERE user_id = ?',
                    [req.user.userId],
                    (err, rows) => {
                        if (err) reject(err);
                        else resolve(rows || []);
                    }
                );
            });
        }

        // Calculate stats
        let fresh = 0, expiring = 0, expired = 0;
        const categories = {};
        const recentActivity = [];
        const upcomingExpiry = [];

        items.forEach(item => {
            const daysUntilExpiry = calculateDaysUntilExpiry(item.expiry_date);
            const status = determineStatus(daysUntilExpiry);

            // Count by status
            if (status === 'fresh') fresh++;
            else if (status === 'expiring') expiring++;
            else if (status === 'expired') expired++;

            // Count by category
            if (!categories[item.category]) {
                categories[item.category] = 0;
            }
            categories[item.category]++;

            // Recent activity (last 7 days)
            const createdDate = new Date(item.created_at);
            const daysSinceCreated = Math.ceil((new Date() - createdDate) / (1000 * 60 * 60 * 24));
            if (daysSinceCreated <= 7) {
                recentActivity.push({
                    name: item.name,
                    category: item.category,
                    created_at: item.created_at,
                    expiry_date: item.expiry_date
                });
            }

            // Upcoming expiry (next 7 days)
            if (daysUntilExpiry >= 0 && daysUntilExpiry <= 7) {
                upcomingExpiry.push({
                    name: item.name,
                    category: item.category,
                    expiry_date: item.expiry_date,
                    days_until_expiry: daysUntilExpiry
                });
            }
        });

        const categoryStats = Object.entries(categories).map(([category, count]) => ({
            category,
            count,
            storage_location: 'mixed'
        }));

        res.json({
            success: true,
            stats: {
                total: items.length,
                fresh,
                expiring,
                expired,
                categories: categoryStats,
                recentActivity: recentActivity.slice(0, 5),
                upcomingExpiry: upcomingExpiry.slice(0, 5),
                lastUpdated: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Food database search
app.get('/api/food-database/search/:query', (req, res) => {
    const query = req.params.query.toLowerCase();
    const results = [];

    for (const [categoryName, foods] of Object.entries(FOOD_DATABASE)) {
        for (const [foodName, data] of Object.entries(foods)) {
            if (foodName.includes(query) || query.includes(foodName)) {
                results.push({
                    name: foodName,
                    ...data,
                    category: data.category
                });
            }
        }
    }

    res.json({ success: true, results: results.slice(0, 10) });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Global error handler:', error);

    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'File too large. Maximum size is 10MB.' });
        }
    }

    res.status(500).json({
        success: false,
        message: NODE_ENV === 'production' ? 'Internal server error' : error.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'API endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    if (NODE_ENV !== 'production' && db && db.close) {
        db.close();
    }
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    if (NODE_ENV !== 'production' && db && db.close) {
        db.close();
    }
    process.exit(0);
});

// Start server
async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, '0.0.0.0', () => {
            console.log('🚀 ShelfLife Backend Server Started');
            console.log(`📍 Server running on http://localhost:${PORT}`);
            console.log(`🏥 Health check: http://localhost:${PORT}/health`);
            console.log(`📚 API base URL: http://localhost:${PORT}/api`);
            console.log(`🌍 Environment: ${NODE_ENV}`);
            console.log('🔐 Enhanced features enabled:');
            console.log('   ✅ Auto Expiry Calculation');
            console.log('   ✅ Comprehensive Food Database');
            console.log('   ✅ User Authentication');
            console.log('   ✅ Advanced Analytics');

            if (NODE_ENV === 'production') {
                console.log('🐘 Connected to PostgreSQL database');
            } else {
                console.log('📁 Connected to SQLite database');
            }
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();