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
const multer = require('multer');
const sharp = require('sharp');
const { createWorker } = require('tesseract.js');
const axios = require('axios');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

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
        "pear": { days: 14, category: "Fruits", storage: "refrigerator" },
        "peach": { days: 5, category: "Fruits", storage: "refrigerator" },
        "plum": { days: 7, category: "Fruits", storage: "refrigerator" },
        "kiwi": { days: 14, category: "Fruits", storage: "refrigerator" },
        "mango": { days: 7, category: "Fruits", storage: "refrigerator" },
        "pineapple": { days: 5, category: "Fruits", storage: "refrigerator" },
        "watermelon": { days: 7, category: "Fruits", storage: "refrigerator" },
        "cantaloupe": { days: 5, category: "Fruits", storage: "refrigerator" },
        "honeydew": { days: 7, category: "Fruits", storage: "refrigerator" }
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
        "potato": { days: 14, category: "Vegetables", storage: "pantry" },
        "sweet potato": { days: 14, category: "Vegetables", storage: "pantry" },
        "celery": { days: 14, category: "Vegetables", storage: "refrigerator" },
        "asparagus": { days: 3, category: "Vegetables", storage: "refrigerator" },
        "green beans": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "corn": { days: 3, category: "Vegetables", storage: "refrigerator" },
        "zucchini": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "mushroom": { days: 7, category: "Vegetables", storage: "refrigerator" },
        "cabbage": { days: 14, category: "Vegetables", storage: "refrigerator" }
    },
    "dairy": {
        "milk": { days: 7, category: "Dairy", storage: "refrigerator" },
        "cheese": { days: 21, category: "Dairy", storage: "refrigerator" },
        "yogurt": { days: 14, category: "Dairy", storage: "refrigerator" },
        "butter": { days: 30, category: "Dairy", storage: "refrigerator" },
        "cream": { days: 7, category: "Dairy", storage: "refrigerator" },
        "sour cream": { days: 14, category: "Dairy", storage: "refrigerator" },
        "cottage cheese": { days: 7, category: "Dairy", storage: "refrigerator" },
        "cream cheese": { days: 14, category: "Dairy", storage: "refrigerator" }
    },
    "meat": {
        "chicken": { days: 2, category: "Meat", storage: "refrigerator" },
        "beef": { days: 3, category: "Meat", storage: "refrigerator" },
        "pork": { days: 3, category: "Meat", storage: "refrigerator" },
        "fish": { days: 2, category: "Meat", storage: "refrigerator" },
        "salmon": { days: 2, category: "Meat", storage: "refrigerator" },
        "turkey": { days: 2, category: "Meat", storage: "refrigerator" },
        "bacon": { days: 7, category: "Meat", storage: "refrigerator" },
        "ham": { days: 5, category: "Meat", storage: "refrigerator" },
        "sausage": { days: 3, category: "Meat", storage: "refrigerator" }
    },
    "pantry": {
        "bread": { days: 7, category: "Pantry", storage: "pantry" },
        "rice": { days: 365, category: "Pantry", storage: "pantry" },
        "pasta": { days: 730, category: "Pantry", storage: "pantry" },
        "flour": { days: 365, category: "Pantry", storage: "pantry" },
        "sugar": { days: 730, category: "Pantry", storage: "pantry" },
        "olive oil": { days: 730, category: "Pantry", storage: "pantry" },
        "vegetable oil": { days: 365, category: "Pantry", storage: "pantry" },
        "vinegar": { days: 1095, category: "Pantry", storage: "pantry" },
        "honey": { days: 1095, category: "Pantry", storage: "pantry" },
        "salt": { days: 1825, category: "Pantry", storage: "pantry" },
        "black pepper": { days: 1095, category: "Pantry", storage: "pantry" },
        "canned tomatoes": { days: 730, category: "Pantry", storage: "pantry" },
        "beans": { days: 730, category: "Pantry", storage: "pantry" }
    },
    "frozen": {
        "frozen vegetables": { days: 365, category: "Frozen", storage: "freezer" },
        "frozen fruit": { days: 365, category: "Frozen", storage: "freezer" },
        "ice cream": { days: 60, category: "Frozen", storage: "freezer" },
        "frozen pizza": { days: 90, category: "Frozen", storage: "freezer" },
        "frozen chicken": { days: 365, category: "Frozen", storage: "freezer" },
        "frozen beef": { days: 365, category: "Frozen", storage: "freezer" },
        "frozen fish": { days: 180, category: "Frozen", storage: "freezer" }
    }
};

// Ensure directories exist
const dbDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
[dbDir, uploadsDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
        cb(null, `${uuidv4()}-${Date.now()}.${file.originalname.split('.').pop()}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

const dbPath = path.join(dbDir, 'shelflife.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Error opening database:', err.message);
    } else {
        console.log('✅ Connected to SQLite database');
        initializeTables();
    }
});

// Enhanced database initialization
function initializeTables() {
    console.log('🔧 Initializing enhanced database tables...');

    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            preferences TEXT DEFAULT '{}',
            notification_settings TEXT DEFAULT '{}',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('❌ Error creating users table:', err.message);
        else console.log('✅ Users table ready');
    });

    // Enhanced food items table
    db.run(`
        CREATE TABLE IF NOT EXISTS food_items (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            unit TEXT DEFAULT 'pieces',
            purchase_date DATE,
            expiry_date DATE NOT NULL,
            auto_calculated BOOLEAN DEFAULT FALSE,
            storage_location TEXT,
            barcode TEXT,
            image_url TEXT,
            nutritional_info TEXT,
            recipe_suggestions TEXT,
            status TEXT DEFAULT 'fresh',
            days_in_storage INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `, (err) => {
        if (err) console.error('❌ Error creating food_items table:', err.message);
        else console.log('✅ Enhanced food items table ready');
    });

    // Receipts table
    db.run(`
        CREATE TABLE IF NOT EXISTS receipts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            store_name TEXT,
            purchase_date DATE,
            total_amount DECIMAL(10,2),
            image_url TEXT,
            ocr_text TEXT,
            parsed_items TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `, (err) => {
        if (err) console.error('❌ Error creating receipts table:', err.message);
        else console.log('✅ Receipts table ready');
    });

    // Notifications table
    db.run(`
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            item_id TEXT,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            scheduled_for DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (item_id) REFERENCES food_items (id)
        )
    `, (err) => {
        if (err) console.error('❌ Error creating notifications table:', err.message);
        else console.log('✅ Notifications table ready');
    });

    // Analytics table
    db.run(`
        CREATE TABLE IF NOT EXISTS analytics (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `, (err) => {
        if (err) console.error('❌ Error creating analytics table:', err.message);
        else console.log('✅ Analytics table ready');
    });

    // Food database table
    db.run(`
        CREATE TABLE IF NOT EXISTS food_database (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            expiry_days INTEGER NOT NULL,
            storage_location TEXT NOT NULL,
            nutritional_info TEXT,
            search_keywords TEXT
        )
    `, (err) => {
        if (err) console.error('❌ Error creating food_database table:', err.message);
        else {
            console.log('✅ Food database table ready');
            seedFoodDatabase();
        }
    });

    console.log('✅ All enhanced tables initialized');
}

// Seed comprehensive food database
function seedFoodDatabase() {
    db.get('SELECT COUNT(*) as count FROM food_database', (err, row) => {
        if (err) {
            console.error('❌ Error checking food database:', err.message);
            return;
        }

        if (row.count === 0) {
            console.log('🌱 Seeding comprehensive food database...');

            const insertStmt = db.prepare(`
                INSERT OR IGNORE INTO food_database (name, category, expiry_days, storage_location, search_keywords)
                VALUES (?, ?, ?, ?, ?)
            `);

            Object.keys(FOOD_DATABASE).forEach(categoryKey => {
                const items = FOOD_DATABASE[categoryKey];
                Object.keys(items).forEach(itemName => {
                    const item = items[itemName];
                    const keywords = `${itemName} ${item.category} ${item.storage}`.toLowerCase();
                    insertStmt.run(itemName, item.category, item.days, item.storage, keywords);
                });
            });

            insertStmt.finalize((err) => {
                if (err) {
                    console.error('❌ Error seeding food database:', err.message);
                } else {
                    console.log('✅ Food database seeded successfully');
                }
            });
        }
    });
}

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Serve uploaded files
app.use('/uploads', express.static(uploadsDir));

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// OCR Helper Functions
async function performOCR(imagePath) {
    try {
        const worker = await createWorker();
        await worker.loadLanguage('eng');
        await worker.initialize('eng');

        const { data: { text } } = await worker.recognize(imagePath);
        await worker.terminate();

        return text;
    } catch (error) {
        console.error('❌ OCR Error:', error);
        throw error;
    }
}

// Receipt parsing function
function parseReceiptText(ocrText) {
    const lines = ocrText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    const items = [];
    let storeName = '';
    let totalAmount = 0;
    let purchaseDate = null;

    // Enhanced parsing logic
    const itemPatterns = [
        /^(.+?)\s+(\d+\.?\d*)\s*$/,  // Item name + price
        /^(.+?)\s+\$(\d+\.?\d*)$/,   // Item name + $price
        /^(\d+)\s+(.+?)\s+(\d+\.?\d*)$/  // Quantity + item + price
    ];

    const datePattern = /(\d{1,2}\/\d{1,2}\/\d{2,4}|\d{1,2}-\d{1,2}-\d{2,4})/;
    const totalPattern = /total\s*:?\s*\$?(\d+\.?\d*)/i;
    const storePatterns = [
        /walmart/i, /target/i, /kroger/i, /safeway/i, /whole foods/i,
        /trader joe/i, /costco/i, /publix/i, /albertsons/i
    ];

    lines.forEach((line, index) => {
        // Extract store name
        if (index < 5 && !storeName) {
            storePatterns.forEach(pattern => {
                if (pattern.test(line)) {
                    storeName = line;
                }
            });
        }

        // Extract date
        const dateMatch = line.match(datePattern);
        if (dateMatch && !purchaseDate) {
            purchaseDate = new Date(dateMatch[1]);
        }

        // Extract total
        const totalMatch = line.match(totalPattern);
        if (totalMatch) {
            totalAmount = parseFloat(totalMatch[1]);
        }

        // Extract items
        itemPatterns.forEach(pattern => {
            const match = line.match(pattern);
            if (match && !line.toLowerCase().includes('total') && !line.toLowerCase().includes('tax')) {
                let itemName, price, quantity = 1;

                if (match.length === 3) {
                    [, itemName, price] = match;
                } else if (match.length === 4) {
                    [, quantity, itemName, price] = match;
                }

                if (itemName && price) {
                    // Clean up item name
                    itemName = itemName.replace(/[^a-zA-Z\s]/g, '').trim().toLowerCase();

                    // Skip if too short or contains common non-food words
                    if (itemName.length < 3 ||
                        ['tax', 'fee', 'bag', 'total', 'cash', 'change', 'card'].some(word => itemName.includes(word))) {
                        return;
                    }

                    items.push({
                        name: itemName,
                        quantity: parseInt(quantity) || 1,
                        price: parseFloat(price),
                        category: 'Unknown' // Will be determined later
                    });
                }
            }
        });
    });

    return {
        storeName: storeName || 'Unknown Store',
        purchaseDate: purchaseDate || new Date(),
        totalAmount,
        items
    };
}

// Smart food categorization
function categorizeFoodItem(itemName) {
    const name = itemName.toLowerCase();

    // Search in food database first
    return new Promise((resolve) => {
        db.get(
            'SELECT * FROM food_database WHERE search_keywords LIKE ? OR name LIKE ? LIMIT 1',
            [`%${name}%`, `%${name}%`],
            (err, row) => {
                if (!err && row) {
                    resolve({
                        category: row.category,
                        expiryDays: row.expiry_days,
                        storage: row.storage_location,
                        autoCalculated: true
                    });
                } else {
                    // Fallback to keyword matching
                    const fruitKeywords = ['apple', 'banana', 'orange', 'berry', 'grape', 'fruit'];
                    const vegKeywords = ['carrot', 'broccoli', 'lettuce', 'tomato', 'vegetable', 'pepper'];
                    const dairyKeywords = ['milk', 'cheese', 'yogurt', 'butter', 'dairy'];
                    const meatKeywords = ['chicken', 'beef', 'pork', 'fish', 'meat', 'salmon'];

                    let category = 'Other';
                    let expiryDays = 7;

                    if (fruitKeywords.some(keyword => name.includes(keyword))) {
                        category = 'Fruits';
                        expiryDays = 14;
                    } else if (vegKeywords.some(keyword => name.includes(keyword))) {
                        category = 'Vegetables';
                        expiryDays = 7;
                    } else if (dairyKeywords.some(keyword => name.includes(keyword))) {
                        category = 'Dairy';
                        expiryDays = 10;
                    } else if (meatKeywords.some(keyword => name.includes(keyword))) {
                        category = 'Meat';
                        expiryDays = 3;
                    }

                    resolve({
                        category,
                        expiryDays,
                        storage: 'refrigerator',
                        autoCalculated: true
                    });
                }
            }
        );
    });
}

// Enhanced Routes

// Simple web interface
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🍎 ShelfLife Backend</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; }
                .status { background: #e8f5e8; padding: 20px; border-radius: 8px; margin: 20px 0; }
                .endpoint { background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 4px; }
                .success { color: #28a745; }
                h1 { color: #2c3e50; }
            </style>
        </head>
        <body>
            <h1>🍎 ShelfLife Backend Server</h1>
            <div class="status">
                <h2 class="success">✅ Server Running Successfully!</h2>
                <p>Your ShelfLife backend is running on port 3000</p>
            </div>

            <h3>📚 Available API Endpoints:</h3>
            <div class="endpoint"><strong>GET</strong> /health - Server health check</div>
            <div class="endpoint"><strong>POST</strong> /api/auth/signup - User registration</div>
            <div class="endpoint"><strong>POST</strong> /api/auth/signin - User login</div>
            <div class="endpoint"><strong>GET</strong> /api/auth/me - Get current user</div>
            <div class="endpoint"><strong>GET</strong> /api/items - Get food items</div>
            <div class="endpoint"><strong>POST</strong> /api/items - Create food item</div>
            <div class="endpoint"><strong>GET</strong> /api/users/stats - User statistics</div>

            <h3>📱 iOS App Connection:</h3>
            <p>Your iOS app is configured to connect to: <code>http://127.0.0.1:3000/api</code></p>
            <p>Run your app in the iOS Simulator and it will connect automatically!</p>

            <h3>🧪 Quick Test:</h3>
            <p><a href="/health" target="_blank">Test Health Endpoint</a></p>
        </body>
        </html>
    `);
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        features: {
            camera_scanning: true,
            receipt_ocr: true,
            auto_expiry: true,
            notifications: true,
            comprehensive_database: true
        }
    });
});

// Authentication routes (existing)
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }

        // Password validation
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();

        db.run(
            'INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)',
            [userId, name, email, hashedPassword],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ success: false, message: 'Email already exists' });
                    }
                    return res.status(500).json({ success: false, message: 'Signup error' });
                }

                const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });

                res.status(201).json({
                    success: true,
                    user: { id: userId, name, email, createdAt: new Date().toISOString() },
                    token
                });
            }
        );
    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

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

            const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '30d' });

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
        });
    } catch (error) {
        console.error('❌ Signin error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get current user profile
app.get('/api/auth/me', authenticateToken, (req, res) => {
    try {
        db.get('SELECT id, name, email, created_at FROM users WHERE id = ?', [req.user.userId], (err, user) => {
            if (err) {
                console.error('❌ Get user error:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
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
        });
    } catch (error) {
        console.error('❌ Get user profile error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Enhanced food items routes
app.get('/api/items', authenticateToken, (req, res) => {
    const { category, status, storage } = req.query;
    let query = 'SELECT * FROM food_items WHERE user_id = ?';
    const params = [req.user.userId];

    if (category) {
        query += ' AND category = ?';
        params.push(category);
    }
    if (status) {
        query += ' AND status = ?';
        params.push(status);
    }
    if (storage) {
        query += ' AND storage_location = ?';
        params.push(storage);
    }

    query += ' ORDER BY expiry_date ASC';

    db.all(query, params, (err, items) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        // Update status based on expiry date and days in storage
        const updatedItems = items.map(item => {
            const expiryDate = new Date(item.expiry_date);
            const today = new Date();
            const daysUntilExpiry = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));

            // Update days in storage
            const purchaseDate = new Date(item.purchase_date || item.created_at);
            const daysInStorage = Math.floor((today - purchaseDate) / (1000 * 60 * 60 * 24));

            let status = 'fresh';
            if (daysUntilExpiry <= 0) {
                status = 'expired';
            } else if (daysUntilExpiry <= 3) {
                status = 'expiring';
            }

            return {
                ...item,
                status,
                daysInStorage,
                daysUntilExpiry
            };
        });

        res.json({ success: true, items: updatedItems });
    });
});

// Enhanced add item route
app.post('/api/items', authenticateToken, async (req, res) => {
    try {
        const { name, category, quantity, purchaseDate, expiryDate, unit, storageLocation, barcode } = req.body;

        if (!name) {
            return res.status(400).json({ success: false, message: 'Item name required' });
        }

        const itemId = uuidv4();
        let finalExpiryDate = expiryDate;
        let autoCalculated = false;

        // Auto-calculate expiry if not provided
        if (!expiryDate) {
            const foodInfo = await categorizeFoodItem(name);
            const purchase = new Date(purchaseDate || Date.now());
            finalExpiryDate = new Date(purchase.getTime() + (foodInfo.expiryDays * 24 * 60 * 60 * 1000));
            autoCalculated = true;
        }

        db.run(`
            INSERT INTO food_items (
                id, user_id, name, category, quantity, unit, purchase_date,
                expiry_date, auto_calculated, storage_location, barcode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            itemId, req.user.userId, name, category || 'Other',
            quantity || 1, unit || 'pieces', purchaseDate || new Date().toISOString(),
            finalExpiryDate, autoCalculated, storageLocation || 'refrigerator', barcode
        ], function(err) {
            if (err) {
                console.error('❌ Add item error:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            res.status(201).json({
                success: true,
                item: {
                    id: itemId,
                    name,
                    category: category || 'Other',
                    quantity: quantity || 1,
                    unit: unit || 'pieces',
                    purchaseDate: purchaseDate || new Date().toISOString(),
                    expiryDate: finalExpiryDate,
                    autoCalculated,
                    storageLocation: storageLocation || 'refrigerator',
                    barcode
                }
            });
        });
    } catch (error) {
        console.error('❌ Add item error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Receipt scanning route
app.post('/api/scan-receipt', authenticateToken, upload.single('receipt'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Receipt image required' });
        }

        const receiptId = uuidv4();
        const imagePath = req.file.path;
        const imageUrl = `/uploads/${req.file.filename}`;

        // Perform OCR
        console.log('🔍 Performing OCR on receipt...');
        const ocrText = await performOCR(imagePath);

        // Parse receipt
        console.log('📝 Parsing receipt text...');
        const parsedData = parseReceiptText(ocrText);

        // Categorize and calculate expiry for each item
        console.log('🏷️ Categorizing food items...');
        const enhancedItems = await Promise.all(
            parsedData.items.map(async (item) => {
                const foodInfo = await categorizeFoodItem(item.name);
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + foodInfo.expiryDays);

                return {
                    ...item,
                    category: foodInfo.category,
                    expiryDate: expiryDate.toISOString(),
                    storageLocation: foodInfo.storage,
                    autoCalculated: true
                };
            })
        );

        // Save receipt to database
        db.run(`
            INSERT INTO receipts (
                id, user_id, store_name, purchase_date, total_amount,
                image_url, ocr_text, parsed_items
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            receiptId, req.user.userId, parsedData.storeName,
            parsedData.purchaseDate.toISOString(), parsedData.totalAmount,
            imageUrl, ocrText, JSON.stringify(enhancedItems)
        ], (err) => {
            if (err) {
                console.error('❌ Save receipt error:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            res.json({
                success: true,
                receipt: {
                    id: receiptId,
                    storeName: parsedData.storeName,
                    purchaseDate: parsedData.purchaseDate,
                    totalAmount: parsedData.totalAmount,
                    items: enhancedItems,
                    imageUrl
                }
            });
        });

    } catch (error) {
        console.error('❌ Receipt scanning error:', error);
        res.status(500).json({ success: false, message: 'Receipt scanning failed' });
    }
});

// Bulk add items from receipt
app.post('/api/items/bulk-add', authenticateToken, async (req, res) => {
    try {
        const { items, receiptId } = req.body;

        if (!items || !Array.isArray(items)) {
            return res.status(400).json({ success: false, message: 'Items array required' });
        }

        const addedItems = [];
        const stmt = db.prepare(`
            INSERT INTO food_items (
                id, user_id, name, category, quantity, purchase_date,
                expiry_date, auto_calculated, storage_location
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const item of items) {
            const itemId = uuidv4();
            stmt.run([
                itemId, req.user.userId, item.name, item.category,
                item.quantity, item.purchaseDate || new Date().toISOString(),
                item.expiryDate, item.autoCalculated || false, item.storageLocation
            ]);

            addedItems.push({
                id: itemId,
                ...item
            });
        }

        stmt.finalize((err) => {
            if (err) {
                console.error('❌ Bulk add error:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            res.json({
                success: true,
                message: `${addedItems.length} items added successfully`,
                items: addedItems
            });
        });

    } catch (error) {
        console.error('❌ Bulk add error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Food database search
app.get('/api/food-database/search', authenticateToken, (req, res) => {
    const { q } = req.query;

    if (!q) {
        return res.status(400).json({ success: false, message: 'Search query required' });
    }

    db.all(
        'SELECT * FROM food_database WHERE search_keywords LIKE ? OR name LIKE ? LIMIT 20',
        [`%${q.toLowerCase()}%`, `%${q.toLowerCase()}%`],
        (err, results) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            res.json({ success: true, results });
        }
    );
});

// Enhanced analytics
app.get('/api/users/stats', authenticateToken, (req, res) => {
    const queries = {
        total: 'SELECT COUNT(*) as count FROM food_items WHERE user_id = ?',
        fresh: 'SELECT COUNT(*) as count FROM food_items WHERE user_id = ? AND status = "fresh"',
        expiring: 'SELECT COUNT(*) as count FROM food_items WHERE user_id = ? AND status = "expiring"',
        expired: 'SELECT COUNT(*) as count FROM food_items WHERE user_id = ? AND status = "expired"',
        categories: `
            SELECT category, COUNT(*) as count, storage_location
            FROM food_items
            WHERE user_id = ?
            GROUP BY category, storage_location
        `,
        recentActivity: `
            SELECT name, category, created_at, expiry_date
            FROM food_items
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 10
        `,
        upcomingExpiry: `
            SELECT name, category, expiry_date,
                   CAST((julianday(expiry_date) - julianday('now')) AS INTEGER) as days_until_expiry
            FROM food_items
            WHERE user_id = ? AND days_until_expiry <= 7 AND days_until_expiry >= 0
            ORDER BY expiry_date ASC
        `
    };

    const stats = {};
    let completed = 0;
    const total = Object.keys(queries).length;

    Object.keys(queries).forEach(key => {
        db.all(queries[key], [req.user.userId], (err, result) => {
            if (err) {
                console.error(`❌ Stats error for ${key}:`, err);
                stats[key] = key === 'categories' || key === 'recentActivity' || key === 'upcomingExpiry' ? [] : 0;
            } else {
                if (key === 'categories' || key === 'recentActivity' || key === 'upcomingExpiry') {
                    stats[key] = result;
                } else {
                    stats[key] = result[0]?.count || 0;
                }
            }

            completed++;
            if (completed === total) {
                res.json({
                    success: true,
                    stats: {
                        ...stats,
                        lastUpdated: new Date().toISOString()
                    }
                });
            }
        });
    });
});

// Notification system
app.get('/api/notifications', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
        [req.user.userId],
        (err, notifications) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            res.json({ success: true, notifications });
        }
    );
});

// Daily notification job
cron.schedule('0 9 * * *', async () => {
    console.log('🔔 Running daily expiry notifications...');

    // Find items expiring soon
    db.all(`
        SELECT fi.*, u.email, u.name as user_name
        FROM food_items fi
        JOIN users u ON fi.user_id = u.id
        WHERE CAST((julianday(fi.expiry_date) - julianday('now')) AS INTEGER) IN (0, 1, 3)
    `, (err, items) => {
        if (err) {
            console.error('❌ Notification job error:', err);
            return;
        }

        items.forEach(item => {
            const daysUntilExpiry = Math.ceil((new Date(item.expiry_date) - new Date()) / (1000 * 60 * 60 * 24));
            let title, message;

            if (daysUntilExpiry <= 0) {
                title = '⚠️ Item Expired';
                message = `${item.name} has expired. Consider removing it from your inventory.`;
            } else if (daysUntilExpiry === 1) {
                title = '🚨 Expires Tomorrow';
                message = `${item.name} expires tomorrow. Use it soon!`;
            } else {
                title = '📅 Expiring Soon';
                message = `${item.name} expires in ${daysUntilExpiry} days.`;
            }

            // Save notification
            db.run(`
                INSERT INTO notifications (id, user_id, item_id, type, title, message)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [uuidv4(), item.user_id, item.id, 'expiry_warning', title, message]);
        });

        console.log(`✅ Created ${items.length} expiry notifications`);
    });
});

// Additional enhanced endpoints
const additionalRoutes = require('./additional-endpoints');
app.use('/api', additionalRoutes);

// Start server
app.listen(PORT, () => {
    console.log('🚀 Enhanced ShelfLife Backend Server Started');
    console.log(`📍 Server running on http://localhost:${PORT}`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
    console.log(`📚 API base URL: http://localhost:${PORT}/api`);
    console.log('🔐 Enhanced features enabled:');
    console.log('   ✅ Camera & Receipt Scanning');
    console.log('   ✅ Auto Expiry Calculation');
    console.log('   ✅ Comprehensive Food Database');
    console.log('   ✅ Smart Notifications');
    console.log('   ✅ Advanced Analytics');
    console.log('   ✅ Image Processing');
    console.log('   ✅ Recipe Suggestions & Meal Planning');
    console.log('   ✅ Smart Shopping Lists');
    console.log('   ✅ Gamification & Achievements');
    console.log('   ✅ Social Food Sharing Network');
    console.log('   ✅ Environmental Impact Tracking');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down server gracefully...');
    db.close((err) => {
        if (err) {
            console.error('❌ Error closing database:', err.message);
        } else {
            console.log('✅ Database connection closed');
        }
        process.exit(0);
    });
});