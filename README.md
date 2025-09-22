# ShelfLife Backend

Node.js/Express backend for the ShelfLife food management iOS application.

## Features

- User authentication with JWT
- Food item CRUD operations
- Automatic expiry date calculation
- Image upload and OCR text extraction
- User statistics and analytics
- PostgreSQL (production) and SQLite (development) support

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://username:password@hostname:port/database_name
JWT_SECRET=your-secure-jwt-secret
CLOUDINARY_CLOUD_NAME=your-cloudinary-cloud-name
CLOUDINARY_API_KEY=your-cloudinary-api-key
CLOUDINARY_API_SECRET=your-cloudinary-api-secret
```

## Local Development

```bash
npm install
npm start
```

## Production Deployment

Configured for Render.com deployment with `render.yaml`.

## API Endpoints

- `POST /api/auth/signup` - User registration
- `POST /api/auth/signin` - User login
- `GET /api/auth/me` - Get current user
- `GET /api/items` - Get user's food items
- `POST /api/items` - Create food item
- `GET /api/users/stats` - Get user statistics
- `GET /health` - Health check