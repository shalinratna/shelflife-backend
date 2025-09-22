# ShelfLife Backend Deployment Guide

## Automatic Deployment on Render.com

### 1. Repository Setup ✅
- GitHub repository: https://github.com/shalinratna/shelflife-backend
- All files committed and pushed

### 2. Render Configuration ✅
- `render.yaml` configured for automatic deployment
- PostgreSQL database will be auto-provisioned
- Environment variables configured

### 3. Manual Deployment Steps

1. Go to [render.com](https://render.com)
2. Sign in with GitHub account
3. Click "New" → "Web Service"
4. Connect repository: `shalinratna/shelflife-backend`
5. Render will automatically detect `render.yaml`
6. Click "Deploy Web Service"

### 4. Environment Variables (Auto-configured)
- `NODE_ENV`: production
- `JWT_SECRET`: auto-generated
- `DATABASE_URL`: auto-configured from PostgreSQL service

### 5. Expected Deployment URL
Format: `https://shelflife-backend-[random].onrender.com`

### 6. Health Check
Once deployed, test: `GET /health`

### 7. API Endpoints
- `POST /api/auth/signup` - User registration
- `POST /api/auth/signin` - User login
- `GET /api/auth/me` - Get current user
- `GET /api/items` - Get user's food items
- `POST /api/items` - Create food item
- `GET /api/users/stats` - Get user statistics

## Next Steps After Deployment
1. Update iOS app baseURL to production URL
2. Test authentication flow
3. Test food item management
4. Configure Cloudinary for image uploads