// src/services/authService.js

const UserModel = require('../models/UserModel');
const SessionModel = require('../models/SessionModel');
const RefreshTokenModel = require('../models/RefreshTokenModel');
const { generateTokens, verifyRefreshToken } = require('../config/jwt');
const { UnauthorizedError, BadRequestError, TooManyRequestsError } = require('../exceptions/customExceptions');

class AuthService {
  /**
   * Register a new user
   */
  async register(userData) {
    const existingUser = await UserModel.findByEmail(userData.email);

    if (existingUser) {
      throw new BadRequestError('Email already registered');
    }

    const user = await UserModel.create(userData);
    const tokens = generateTokens(user);

    // Store refresh token
    await RefreshTokenModel.create(user.id, tokens.refreshToken);

    // Create session
    const sessionId = await SessionModel.create(user.id, {
      email: user.email,
      role: user.role,
      lastActivity: new Date().toISOString(),
    });

    return {
      user: this.sanitizeUser(user),
      tokens,
      sessionId,
    };
  }

  /**
   * Login user
   */
  async login(email, password, ipAddress, userAgent) {
    // Check if account is locked
    const isLocked = await UserModel.isAccountLocked(email);
    if (isLocked) {
      throw new TooManyRequestsError('Account is temporarily locked due to multiple failed login attempts');
    }

    const user = await UserModel.findByEmail(email);

    if (!user) {
      throw new UnauthorizedError('Invalid credentials');
    }

    if (!user.is_active) {
      throw new UnauthorizedError('Account is deactivated');
    }

    const isPasswordValid = await UserModel.comparePassword(password, user.password);

    if (!isPasswordValid) {
      await UserModel.incrementFailedLoginAttempts(email);
      throw new UnauthorizedError('Invalid credentials');
    }

    // Reset failed login attempts on successful login
    await UserModel.resetFailedLoginAttempts(email);

    const tokens = generateTokens(user);

    // Store refresh token
    await RefreshTokenModel.create(user.id, tokens.refreshToken);

    // Create session
    const sessionId = await SessionModel.create(user.id, {
      email: user.email,
      role: user.role,
      ipAddress,
      userAgent,
      lastActivity: new Date().toISOString(),
    });

    return {
      user: this.sanitizeUser(user),
      tokens,
      sessionId,
    };
  }

  /**
   * Logout user
   */
  async logout(userId, sessionId) {
    await SessionModel.delete(sessionId);
    return true;
  }

  /**
   * Logout from all devices
   */
  async logoutAll(userId) {
    await Promise.all([
      SessionModel.deleteAllUserSessions(userId),
      RefreshTokenModel.deleteAllUserTokens(userId),
    ]);
    return true;
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken) {
    try {
      const decoded = verifyRefreshToken(refreshToken);
      
      // Verify token exists in database
      const tokenData = await RefreshTokenModel.verify(decoded.id, refreshToken);
      
      if (!tokenData) {
        throw new UnauthorizedError('Invalid refresh token');
      }

      const user = await UserModel.findById(decoded.id);

      if (!user || !user.is_active) {
        throw new UnauthorizedError('User not found or inactive');
      }

      const tokens = generateTokens(user);

      // Delete old refresh token and store new one
      await RefreshTokenModel.delete(user.id, tokenData.tokenId);
      await RefreshTokenModel.create(user.id, tokens.refreshToken);

      return {
        user: this.sanitizeUser(user),
        tokens,
      };
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired refresh token');
    }
  }

  /**
   * Get user profile
   */
  async getProfile(userId) {
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    return this.sanitizeUser(user);
  }

  /**
   * Update user profile
   */
  async updateProfile(userId, updateData) {
    const user = await UserModel.update(userId, updateData);

    if (!user) {
      throw new BadRequestError('Unable to update profile');
    }

    return this.sanitizeUser(user);
  }

  /**
   * Change password
   */
  async changePassword(userId, currentPassword, newPassword) {
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    // Get user with password for verification
    const userWithPassword = await UserModel.findByEmail(user.email);
    const isPasswordValid = await UserModel.comparePassword(currentPassword, userWithPassword.password);

    if (!isPasswordValid) {
      throw new UnauthorizedError('Current password is incorrect');
    }

    await UserModel.updatePassword(userId, newPassword);

    // Logout from all devices after password change
    await this.logoutAll(userId);

    return true;
  }

  /**
   * Get active sessions
   */
  async getActiveSessions(userId) {
    return await SessionModel.getUserSessions(userId);
  }

  /**
   * Remove password from user object
   */
  sanitizeUser(user) {
    const { password, failed_login_attempts, account_locked_until, ...sanitized } = user;
    return sanitized;
  }
}

module.exports = new AuthService();