// src/routes/authRoutes.js

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/authMiddleware');
const { validate, schemas } = require('../middleware/validationMiddleware');
const { authLimiter } = require('../middleware/securityMiddleware');

router.post('/register', authLimiter, validate(schemas.register), authController.register);
router.post('/login', authLimiter, validate(schemas.login), authController.login);
router.post('/refresh', validate(schemas.refreshToken), authController.refreshToken);

// Protected routes
router.post('/logout', authenticate, authController.logout);
router.post('/logout-all', authenticate, authController.logoutAll);
router.get('/me', authenticate, authController.getProfile);
router.put('/profile', authenticate, validate(schemas.updateProfile), authController.updateProfile);
router.post('/change-password', authenticate, validate(schemas.changePassword), authController.changePassword);
router.get('/sessions', authenticate, authController.getSessions);

module.exports = router;