// src/routes/userRoutes.js

const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authenticate, authorize, authorizeOwnerOrAdmin } = require('../middleware/authMiddleware');
const { validate, schemas } = require('../middleware/validationMiddleware');

router.get('/stats', authenticate, authorize('admin'), userController.getUserStats);

router.get('/search', authenticate, authorize('admin', 'moderator'), userController.searchUsers);
router.get('/', authenticate, authorize('admin', 'moderator'), validate(schemas.pagination), userController.getAllUsers);
router.get('/:userId', authenticate, authorizeOwnerOrAdmin('userId'), validate(schemas.userId), userController.getUserById);
router.put('/:userId', authenticate, authorizeOwnerOrAdmin('userId'), validate(schemas.userId), userController.updateUser);
router.delete('/:userId', authenticate, authorizeOwnerOrAdmin('userId'), validate(schemas.userId), userController.deleteUser);

// Admin-only routes
router.patch('/:userId/role', authenticate, authorize('admin'), validate(schemas.updateRole), userController.updateUserRole);
router.patch('/:userId/status', authenticate, authorize('admin'), validate(schemas.toggleStatus), userController.toggleUserStatus);

module.exports = router;