// src/controllers/userController.js

const userService = require('../services/userService');
const { successResponse, paginatedResponse, noContentResponse } = require('../responses/apiResponses');
const { asyncHandler } = require('../middleware/errorMiddleware');

/**
 * Get all users
 * @route GET /api/v1/users
 * @access Private (Admin, Moderator)
 */
const getAllUsers = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search, role, isActive } = req.query;

  const filters = {};
  if (role) filters.role = role;
  if (isActive !== undefined) filters.isActive = isActive === 'true';
  if (search) filters.search = search;

  const { users, total } = await userService.getAllUsers(
    parseInt(page),
    parseInt(limit),
    filters
  );

  paginatedResponse(
    res,
    users,
    {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
    },
    'Users retrieved successfully'
  );
});

/**
 * Get user by ID
 * @route GET /api/v1/users/:userId
 * @access Private (Admin, Moderator, Owner)
 */
const getUserById = asyncHandler(async (req, res) => {
  const user = await userService.getUserById(req.params.userId);

  successResponse(res, user, 'User retrieved successfully');
});

/**
 * Update user
 * @route PUT /api/v1/users/:userId
 * @access Private (Admin, Owner)
 */
const updateUser = asyncHandler(async (req, res) => {
  const user = await userService.updateUser(
    req.params.userId,
    req.body,
    req.user.id,
    req.user.role
  );

  successResponse(res, user, 'User updated successfully');
});

/**
 * Delete user
 * @route DELETE /api/v1/users/:userId
 * @access Private (Admin, Owner)
 */
const deleteUser = asyncHandler(async (req, res) => {
  await userService.deleteUser(
    req.params.userId,
    req.user.id,
    req.user.role
  );

  noContentResponse(res);
});

/**
 * Update user role
 * @route PATCH /api/v1/users/:userId/role
 * @access Private (Admin only)
 */
const updateUserRole = asyncHandler(async (req, res) => {
  const user = await userService.updateUserRole(
    req.params.userId,
    req.body.role,
    req.user.role
  );

  successResponse(res, user, 'User role updated successfully');
});

/**
 * Toggle user active status
 * @route PATCH /api/v1/users/:userId/status
 * @access Private (Admin only)
 */
const toggleUserStatus = asyncHandler(async (req, res) => {
  const user = await userService.toggleUserStatus(
    req.params.userId,
    req.body.isActive,
    req.user.role
  );

  successResponse(res, user, 'User status updated successfully');
});

/**
 * Search users
 * @route GET /api/v1/users/search
 * @access Private (Admin, Moderator)
 */
const searchUsers = asyncHandler(async (req, res) => {
  const { q, page = 1, limit = 10 } = req.query;

  const { users, total } = await userService.searchUsers(
    q,
    parseInt(page),
    parseInt(limit)
  );

  paginatedResponse(
    res,
    users,
    {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
    },
    'Search results retrieved successfully'
  );
});

/**
 * Get user statistics
 * @route GET /api/v1/users/stats
 * @access Private (Admin only)
 */
const getUserStats = asyncHandler(async (req, res) => {
  const stats = await userService.getUserStats(req.user.role);

  successResponse(res, stats, 'User statistics retrieved successfully');
});

module.exports = {
  getAllUsers,
  getUserById,
  updateUser,
  deleteUser,
  updateUserRole,
  toggleUserStatus,
  searchUsers,
  getUserStats,
};