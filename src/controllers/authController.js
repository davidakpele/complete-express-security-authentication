// src/controllers/authController.js

const authService = require('../services/authService');
const { successResponse, createdResponse } = require('../responses/apiResponses');
const { asyncHandler } = require('../middleware/errorMiddleware');

/**
 * Register a new user
 * @route POST /api/v1/auth/register
 * @access Public
 */
const register = asyncHandler(async (req, res) => {
  const result = await authService.register(req.body);

  // Set tokens in cookies
  res.cookie('accessToken', result.tokens.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000, 
  });

  res.cookie('refreshToken', result.tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, 
  });

  res.cookie('sessionId', result.sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, 
  });

  createdResponse(res, {
    user: result.user,
    tokens: result.tokens,
  }, 'User registered successfully');
});

/**
 * Login user
 * @route POST /api/v1/auth/login
 * @access Public
 */
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const ipAddress = req.clientIP;
  const userAgent = req.headers['user-agent'];

  const result = await authService.login(email, password, ipAddress, userAgent);

  // Set tokens in cookies
  res.cookie('accessToken', result.tokens.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000, 
  });

  res.cookie('refreshToken', result.tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.cookie('sessionId', result.sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, 
  });

  successResponse(res, {
    user: result.user,
    tokens: result.tokens,
  }, 'Login successful');
});

/**
 * Logout user
 * @route POST /api/v1/auth/logout
 * @access Private
 */
const logout = asyncHandler(async (req, res) => {
  await authService.logout(req.user.id, req.sessionId);

  // Clear cookies
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.clearCookie('sessionId');

  successResponse(res, null, 'Logout successful');
});

/**
 * Logout from all devices
 * @route POST /api/v1/auth/logout-all
 * @access Private
 */
const logoutAll = asyncHandler(async (req, res) => {
  await authService.logoutAll(req.user.id);

  // Clear cookies
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.clearCookie('sessionId');

  successResponse(res, null, 'Logged out from all devices');
});

/**
 * Refresh access token
 * @route POST /api/v1/auth/refresh
 * @access Public
 */
const refreshToken = asyncHandler(async (req, res) => {
  const refreshToken = req.body.refreshToken || req.cookies.refreshToken;

  const result = await authService.refreshToken(refreshToken);

  // Set new tokens in cookies
  res.cookie('accessToken', result.tokens.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000, 
  });

  res.cookie('refreshToken', result.tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, 
  });

  successResponse(res, {
    tokens: result.tokens,
  }, 'Token refreshed successfully');
});

/**
 * Get current user profile
 * @route GET /api/v1/auth/me
 * @access Private
 */
const getProfile = asyncHandler(async (req, res) => {
  const user = await authService.getProfile(req.user.id);

  successResponse(res, user, 'Profile retrieved successfully');
});

/**
 * Update user profile
 * @route PUT /api/v1/auth/profile
 * @access Private
 */
const updateProfile = asyncHandler(async (req, res) => {
  const user = await authService.updateProfile(req.user.id, req.body);

  successResponse(res, user, 'Profile updated successfully');
});

/**
 * Change password
 * @route POST /api/v1/auth/change-password
 * @access Private
 */
const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  await authService.changePassword(req.user.id, currentPassword, newPassword);

  // Clear cookies after password change
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.clearCookie('sessionId');

  successResponse(res, null, 'Password changed successfully. Please login again.');
});

/**
 * Get active sessions
 * @route GET /api/v1/auth/sessions
 * @access Private
 */
const getSessions = asyncHandler(async (req, res) => {
  const sessions = await authService.getActiveSessions(req.user.id);

  successResponse(res, sessions, 'Sessions retrieved successfully');
});

module.exports = {
  register,
  login,
  logout,
  logoutAll,
  refreshToken,
  getProfile,
  updateProfile,
  changePassword,
  getSessions,
};