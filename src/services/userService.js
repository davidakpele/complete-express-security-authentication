// src/services/userService.js

const UserModel = require('../models/UserModel');
const { NotFoundError, BadRequestError, ForbiddenError } = require('../exceptions/customExceptions');

class UserService {
  /**
   * Get all users with pagination and filters
   */
  async getAllUsers(page, limit, filters) {
    return await UserModel.findAll(page, limit, filters);
  }

  /**
   * Get user by ID
   */
  async getUserById(userId) {
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new NotFoundError('User not found');
    }

    return user;
  }

  /**
   * Update user
   */
  async updateUser(userId, updateData, requestingUserId, requestingUserRole) {
    // Check if user exists
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Permission check: users can only update themselves unless they're admin
    if (userId !== requestingUserId && requestingUserRole !== 'admin') {
      throw new ForbiddenError('You do not have permission to update this user');
    }

    // Prevent non-admins from changing certain fields
    if (requestingUserRole !== 'admin') {
      delete updateData.role;
      delete updateData.is_active;
      delete updateData.is_verified;
    }

    const updatedUser = await UserModel.update(userId, updateData);

    if (!updatedUser) {
      throw new BadRequestError('Unable to update user');
    }

    return updatedUser;
  }

  /**
   * Delete user (soft delete)
   */
  async deleteUser(userId, requestingUserId, requestingUserRole) {
    // Check if user exists
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Permission check: users can only delete themselves unless they're admin
    if (userId !== requestingUserId && requestingUserRole !== 'admin') {
      throw new ForbiddenError('You do not have permission to delete this user');
    }

    // Prevent users from deleting themselves if they're the only admin
    if (user.role === 'admin') {
      const { users } = await UserModel.findAll(1, 100, { role: 'admin' });
      if (users.length === 1) {
        throw new BadRequestError('Cannot delete the only admin user');
      }
    }

    const deleted = await UserModel.delete(userId);

    if (!deleted) {
      throw new BadRequestError('Unable to delete user');
    }

    return true;
  }

  /**
   * Update user role (admin only)
   */
  async updateUserRole(userId, newRole, requestingUserRole) {
    if (requestingUserRole !== 'admin') {
      throw new ForbiddenError('Only admins can change user roles');
    }

    const validRoles = ['user', 'moderator', 'admin'];
    if (!validRoles.includes(newRole)) {
      throw new BadRequestError('Invalid role');
    }

    const user = await UserModel.findById(userId);

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Prevent downgrading the only admin
    if (user.role === 'admin' && newRole !== 'admin') {
      const { users } = await UserModel.findAll(1, 100, { role: 'admin' });
      if (users.length === 1) {
        throw new BadRequestError('Cannot change role of the only admin user');
      }
    }

    const updatedUser = await UserModel.update(userId, { role: newRole });
    return updatedUser;
  }

  /**
   * Activate/Deactivate user (admin only)
   */
  async toggleUserStatus(userId, isActive, requestingUserRole) {
    if (requestingUserRole !== 'admin') {
      throw new ForbiddenError('Only admins can activate/deactivate users');
    }

    const user = await UserModel.findById(userId);

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Prevent deactivating the only admin
    if (user.role === 'admin' && !isActive) {
      const { users } = await UserModel.findAll(1, 100, { role: 'admin', isActive: true });
      if (users.length === 1) {
        throw new BadRequestError('Cannot deactivate the only active admin user');
      }
    }

    const updatedUser = await UserModel.update(userId, { is_active: isActive });
    return updatedUser;
  }

  /**
   * Search users
   */
  async searchUsers(searchTerm, page, limit) {
    return await UserModel.findAll(page, limit, { search: searchTerm });
  }

  /**
   * Get user statistics (admin only)
   */
  async getUserStats(requestingUserRole) {
    if (requestingUserRole !== 'admin') {
      throw new ForbiddenError('Only admins can view user statistics');
    }

    const [totalUsers, activeUsers, adminUsers] = await Promise.all([
      UserModel.findAll(1, 1, {}),
      UserModel.findAll(1, 1, { isActive: true }),
      UserModel.findAll(1, 1, { role: 'admin' }),
    ]);

    return {
      total: totalUsers.total,
      active: activeUsers.total,
      inactive: totalUsers.total - activeUsers.total,
      admins: adminUsers.total,
    };
  }
}

module.exports = new UserService();