// Additional API endpoints for the enhanced ShelfLife app

const express = require('express');
const router = express.Router();

// MARK: - Recipe and Meal Planning Endpoints

// Get recipe suggestions based on ingredients
router.get('/recipes/suggestions', (req, res) => {
    const { ingredients } = req.query;

    // Mock recipe suggestions
    const recipes = [
        {
            id: '1',
            name: 'Quick Vegetable Stir Fry',
            description: 'A healthy and quick meal using fresh vegetables',
            ingredients: ['spinach', 'carrots', 'garlic', 'soy sauce'],
            instructions: [
                'Heat oil in a large pan',
                'Add garlic and cook for 30 seconds',
                'Add vegetables and stir fry for 5 minutes',
                'Season with soy sauce and serve'
            ],
            prepTime: 15,
            cookTime: 10,
            servings: 4,
            difficulty: 'easy',
            cuisineType: 'Asian',
            dietaryTags: ['vegetarian', 'vegan', 'quick'],
            rating: 4.5
        },
        {
            id: '2',
            name: 'Banana Smoothie Bowl',
            description: 'Perfect breakfast using ripe bananas',
            ingredients: ['bananas', 'greek yogurt', 'granola', 'honey'],
            instructions: [
                'Blend bananas with yogurt until smooth',
                'Pour into bowl',
                'Top with granola and drizzle honey'
            ],
            prepTime: 5,
            cookTime: 0,
            servings: 1,
            difficulty: 'easy',
            cuisineType: 'American',
            dietaryTags: ['vegetarian', 'healthy', 'breakfast'],
            rating: 4.8
        }
    ];

    res.json({
        success: true,
        suggestions: recipes
    });
});

// Get meal plans
router.get('/meal-plans', (req, res) => {
    const { date } = req.query;

    const mealPlans = [
        {
            id: '1',
            date: date || new Date().toISOString().split('T')[0],
            mealType: 'breakfast',
            recipeName: 'Banana Smoothie Bowl',
            ingredients: [
                { name: 'banana', quantity: 1, unit: 'piece' },
                { name: 'greek yogurt', quantity: 0.5, unit: 'cup' }
            ],
            servings: 1,
            notes: 'Use ripe bananas for best flavor'
        }
    ];

    res.json({
        success: true,
        mealPlans
    });
});

// MARK: - Shopping Lists Endpoints

// Get shopping lists
router.get('/shopping-lists', (req, res) => {
    const lists = [
        {
            id: '1',
            name: 'Weekly Groceries',
            createdDate: new Date().toISOString(),
            totalBudget: 150.00,
            spentAmount: 89.50,
            itemCount: 12,
            purchasedCount: 7
        },
        {
            id: '2',
            name: 'Party Supplies',
            createdDate: new Date(Date.now() - 86400000).toISOString(),
            totalBudget: 75.00,
            spentAmount: 45.25,
            itemCount: 8,
            purchasedCount: 5
        }
    ];

    res.json({
        success: true,
        lists
    });
});

// Get shopping suggestions
router.get('/shopping-suggestions', (req, res) => {
    const suggestions = [
        {
            name: 'Milk',
            category: 'Dairy',
            reason: 'Running low based on usage pattern',
            priority: 1,
            estimatedPrice: 3.99
        },
        {
            name: 'Bananas',
            category: 'Fruits',
            reason: 'Frequently purchased item',
            priority: 2,
            estimatedPrice: 2.50
        },
        {
            name: 'Bread',
            category: 'Pantry',
            reason: 'Will expire soon, replacement needed',
            priority: 3,
            estimatedPrice: 2.99
        }
    ];

    res.json({
        success: true,
        suggestions
    });
});

// MARK: - Analytics Endpoints

// Waste analytics
router.get('/waste/analytics', (req, res) => {
    const analytics = {
        summary: {
            totalWastedItems: 5,
            totalCostImpact: '$23.45',
            totalCO2Impact: '12.5 kg',
            co2Equivalent: 'Driving 31 miles'
        },
        breakdown: [
            {
                wastedItems: 2,
                totalCost: 8.99,
                totalCO2: 4.5,
                wasteReason: 'expired',
                category: 'Vegetables'
            },
            {
                wastedItems: 3,
                totalCost: 14.46,
                totalCO2: 8.0,
                wasteReason: 'spoiled',
                category: 'Fruits'
            }
        ],
        insights: [
            'You waste 15% less food than the average household',
            'Vegetables are your most wasted category',
            'Consider buying smaller quantities of fresh produce'
        ]
    };

    res.json({
        success: true,
        analytics
    });
});

// Environmental impact
router.get('/environmental-impact', (req, res) => {
    const impact = {
        monthlyCO2Footprint: '45.2 kg',
        equivalents: {
            milesInCar: '112 miles',
            treesNeeded: 2
        },
        recommendations: [
            'Buy local produce to reduce transportation emissions',
            'Use all parts of vegetables when cooking',
            'Compost food scraps instead of throwing away'
        ],
        score: 8.5
    };

    res.json({
        success: true,
        impact
    });
});

// Budget analysis
router.get('/budget/analysis', (req, res) => {
    const { period } = req.query;

    const analysis = {
        period: period || 'month',
        analysis: {
            totalSpent: '$342.67',
            categories: [
                { category: 'Fruits', totalSpent: 89.50, itemCount: 25 },
                { category: 'Vegetables', totalSpent: 76.25, itemCount: 18 },
                { category: 'Dairy', totalSpent: 65.40, itemCount: 12 },
                { category: 'Meat', totalSpent: 111.52, itemCount: 8 }
            ],
            insights: {
                topCategory: 'Meat',
                avgItemCost: '$9.52'
            }
        }
    };

    res.json({
        success: true,
        ...analysis
    });
});

// MARK: - Smart Features Endpoints

// Restocking suggestions
router.get('/restocking/suggestions', (req, res) => {
    const suggestions = [
        {
            name: 'Milk',
            category: 'Dairy',
            shouldRestock: true,
            urgency: 'high',
            suggestedQuantity: 1,
            daysSinceLastPurchase: 8,
            reason: 'You typically buy milk every 7 days'
        },
        {
            name: 'Eggs',
            category: 'Dairy',
            shouldRestock: true,
            urgency: 'medium',
            suggestedQuantity: 1,
            daysSinceLastPurchase: 12,
            reason: 'Low stock based on usage pattern'
        },
        {
            name: 'Chicken Breast',
            category: 'Meat',
            shouldRestock: false,
            urgency: 'low',
            suggestedQuantity: 2,
            daysSinceLastPurchase: 3,
            reason: 'Recently purchased, still have stock'
        }
    ];

    res.json({
        success: true,
        suggestions
    });
});

// Food database search with barcode
router.get('/food-database/barcode/:barcode', (req, res) => {
    const { barcode } = req.params;

    // Mock barcode lookup
    const foodDatabase = {
        '123456789': {
            name: 'Organic Milk',
            category: 'Dairy',
            nutrition: {
                calories: 150,
                protein: 8.0,
                carbs: 12.0,
                fiber: 0.0
            },
            avgPrice: 4.99,
            expiryDays: 7,
            storage: 'refrigerator'
        },
        '987654321': {
            name: 'Whole Wheat Bread',
            category: 'Pantry',
            nutrition: {
                calories: 80,
                protein: 4.0,
                carbs: 14.0,
                fiber: 2.0
            },
            avgPrice: 2.99,
            expiryDays: 7,
            storage: 'pantry'
        }
    };

    const food = foodDatabase[barcode];

    if (food) {
        res.json({
            success: true,
            food
        });
    } else {
        res.status(404).json({
            success: false,
            message: 'Product not found in database'
        });
    }
});

// MARK: - Gamification Endpoints

// Get user achievements
router.get('/achievements', (req, res) => {
    const achievements = [
        {
            id: '1',
            title: 'Waste Warrior',
            description: 'Prevented 50+ lbs of food waste',
            icon: 'shield.fill',
            dateEarned: new Date().toISOString(),
            xpReward: 100,
            category: 'environmental'
        },
        {
            id: '2',
            title: 'Recipe Explorer',
            description: 'Tried 10 different AI-suggested recipes',
            icon: 'book.fill',
            dateEarned: new Date(Date.now() - 86400000 * 3).toISOString(),
            xpReward: 75,
            category: 'cooking'
        }
    ];

    res.json({
        success: true,
        achievements
    });
});

// Get weekly challenges
router.get('/challenges/weekly', (req, res) => {
    const challenge = {
        id: '1',
        title: 'Zero Waste Week',
        description: 'Don\'t let any food expire this week',
        progress: 5,
        target: 7,
        reward: '250 XP + Special Badge',
        startDate: new Date(Date.now() - 86400000 * 5).toISOString(),
        endDate: new Date(Date.now() + 86400000 * 2).toISOString(),
        type: 'waste_reduction'
    };

    res.json({
        success: true,
        challenge
    });
});

// MARK: - Notification Endpoints

// Get user notifications
router.get('/notifications', (req, res) => {
    const notifications = [
        {
            id: '1',
            type: 'expiry_warning',
            title: 'Items Expiring Soon',
            message: 'Greek yogurt and spinach expire in 2 days',
            data: { itemIds: ['item1', 'item2'] },
            readStatus: false,
            createdAt: new Date().toISOString()
        },
        {
            id: '2',
            type: 'restocking',
            title: 'Restocking Suggestion',
            message: 'You\'re running low on milk',
            data: { itemName: 'milk' },
            readStatus: false,
            createdAt: new Date(Date.now() - 3600000).toISOString()
        },
        {
            id: '3',
            type: 'recipe',
            title: 'Recipe Suggestion',
            message: 'New recipe using your expiring bananas',
            data: { recipeId: 'recipe2' },
            readStatus: true,
            createdAt: new Date(Date.now() - 86400000).toISOString()
        }
    ];

    res.json({
        success: true,
        notifications
    });
});

// Mark notification as read
router.patch('/notifications/:id/read', (req, res) => {
    const { id } = req.params;

    res.json({
        success: true,
        message: `Notification ${id} marked as read`
    });
});

// MARK: - Social Features (Food Sharing)

// Get nearby food shares
router.get('/food-shares/nearby', (req, res) => {
    const { lat, lng, radius } = req.query;

    const shares = [
        {
            id: '1',
            userName: 'Sarah M.',
            distance: '0.3 miles',
            items: ['Organic Apples (5 lbs)', 'Fresh Bread', 'Greek Yogurt'],
            message: 'Moving tomorrow, can\'t take these!',
            timePosted: '2 hours ago',
            userRating: 4.9,
            location: { lat: 37.7749, lng: -122.4194 }
        },
        {
            id: '2',
            userName: 'Mike K.',
            distance: '0.7 miles',
            items: ['Bananas (bunch)', 'Bell Peppers', 'Milk'],
            message: 'Bought too much at Costco 😅',
            timePosted: '4 hours ago',
            userRating: 4.7,
            location: { lat: 37.7849, lng: -122.4094 }
        }
    ];

    res.json({
        success: true,
        shares
    });
});

// Get user's food shares
router.get('/food-shares/mine', (req, res) => {
    const shares = [
        {
            id: '1',
            items: ['Spinach', 'Carrots'],
            message: 'Fresh vegetables, expiring tomorrow',
            timePosted: '1 day ago',
            status: 'Claimed by Jessica R.',
            claimedAt: new Date(Date.now() - 3600000).toISOString()
        }
    ];

    res.json({
        success: true,
        shares
    });
});

// Create new food share
router.post('/food-shares', (req, res) => {
    const { items, message, location } = req.body;

    const share = {
        id: Date.now().toString(),
        items,
        message,
        location,
        timePosted: new Date().toISOString(),
        status: 'active'
    };

    res.status(201).json({
        success: true,
        share,
        message: 'Food share created successfully'
    });
});

module.exports = router;