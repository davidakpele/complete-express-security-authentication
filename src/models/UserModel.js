//src/models/UserModel.js
const { query, transaction } = require('../config/database');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

class User {
  /**
   * Create a new user
   */
  static async create(userData) {
    const { email, password, firstName, lastName, role = 'user' } = userData;
    
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    const id = uuidv4();

    const text = `
      INSERT INTO users (id, email, password, first_name, last_name, role, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
      RETURNING id, email, first_name, last_name, role, is_active, is_verified, created_at, updated_at
    `;
    
    const values = [id, email.toLowerCase(), hashedPassword, firstName, lastName, role];
    const result = await query(text, values);
    
    return result.rows[0];
  }

  /**
   * Find user by ID
   */
  static async findById(id) {
    const text = `
      SELECT id, email, first_name, last_name, role, is_active, is_verified, 
             failed_login_attempts, account_locked_until, last_login, created_at, updated_at
      FROM users
      WHERE id = $1 AND deleted_at IS NULL
    `;
    
    const result = await query(text, [id]);
    return result.rows[0] || null;
  }

  /**
   * Find user by email
   */
  static async findByEmail(email) {
    const text = `
      SELECT id, email, password, first_name, last_name, role, is_active, is_verified,
             failed_login_attempts, account_locked_until, last_login, created_at, updated_at
      FROM users
      WHERE email = $1 AND deleted_at IS NULL
    `;
    
    const result = await query(text, [email.toLowerCase()]);
    return result.rows[0] || null;
  }

  /**
   * Find all users with pagination
   */
  static async findAll(page = 1, limit = 10, filters = {}) {
    const offset = (page - 1) * limit;
    let whereClause = 'WHERE deleted_at IS NULL';
    const values = [];
    let paramCount = 0;

    if (filters.role) {
      paramCount++;
      whereClause += ` AND role = $${paramCount}`;
      values.push(filters.role);
    }

    if (filters.isActive !== undefined) {
      paramCount++;
      whereClause += ` AND is_active = $${paramCount}`;
      values.push(filters.isActive);
    }

    if (filters.search) {
      paramCount++;
      whereClause += ` AND (email ILIKE $${paramCount} OR first_name ILIKE $${paramCount} OR last_name ILIKE $${paramCount})`;
      values.push(`%${filters.search}%`);
    }

    paramCount++;
    const limitParam = paramCount;
    paramCount++;
    const offsetParam = paramCount;

    const text = `
      SELECT id, email, first_name, last_name, role, is_active, is_verified, 
             last_login, created_at, updated_at
      FROM users
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${limitParam} OFFSET $${offsetParam}
    `;

    const countText = `SELECT COUNT(*) FROM users ${whereClause}`;

    values.push(limit, offset);

    const [dataResult, countResult] = await Promise.all([
      query(text, values),
      query(countText, values.slice(0, -2)),
    ]);

    return {
      users: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
    };
  }

  /**
   * Update user
   */
  static async update(id, updateData) {
    const allowedFields = ['first_name', 'last_name', 'is_active', 'is_verified'];
    const updates = [];
    const values = [];
    let paramCount = 0;

    Object.keys(updateData).forEach((key) => {
      if (allowedFields.includes(key)) {
        paramCount++;
        updates.push(`${key} = $${paramCount}`);
        values.push(updateData[key]);
      }
    });

    if (updates.length === 0) {
      return null;
    }

    paramCount++;
    updates.push(`updated_at = NOW()`);
    values.push(id);

    const text = `
      UPDATE users
      SET ${updates.join(', ')}
      WHERE id = $${paramCount} AND deleted_at IS NULL
      RETURNING id, email, first_name, last_name, role, is_active, is_verified, updated_at
    `;

    const result = await query(text, values);
    return result.rows[0] || null;
  }

  /**
   * Update password
   */
  static async updatePassword(id, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);

    const text = `
      UPDATE users
      SET password = $1, updated_at = NOW()
      WHERE id = $2 AND deleted_at IS NULL
      RETURNING id
    `;

    const result = await query(text, [hashedPassword, id]);
    return result.rows[0] || null;
  }

  /**
   * Soft delete user
   */
  static async delete(id) {
    const text = `
      UPDATE users
      SET deleted_at = NOW(), is_active = false
      WHERE id = $1 AND deleted_at IS NULL
      RETURNING id
    `;

    const result = await query(text, [id]);
    return result.rows[0] || null;
  }

  /**
   * Compare password
   */
  static async comparePassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }

  /**
   * Increment failed login attempts
   */
  static async incrementFailedLoginAttempts(email) {
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
    const lockTimeMinutes = parseInt(process.env.LOCK_TIME) || 15;

    const text = `
      UPDATE users
      SET failed_login_attempts = failed_login_attempts + 1,
          account_locked_until = CASE
            WHEN failed_login_attempts + 1 >= $1 
            THEN NOW() + INTERVAL '${lockTimeMinutes} minutes'
            ELSE account_locked_until
          END,
          updated_at = NOW()
      WHERE email = $2 AND deleted_at IS NULL
      RETURNING failed_login_attempts, account_locked_until
    `;

    const result = await query(text, [maxAttempts, email.toLowerCase()]);
    return result.rows[0] || null;
  }

  /**
   * Reset failed login attempts
   */
  static async resetFailedLoginAttempts(email) {
    const text = `
      UPDATE users
      SET failed_login_attempts = 0,
          account_locked_until = NULL,
          last_login = NOW(),
          updated_at = NOW()
      WHERE email = $1 AND deleted_at IS NULL
    `;

    await query(text, [email.toLowerCase()]);
  }

  /**
   * Check if account is locked
   */
  static async isAccountLocked(email) {
    const text = `
      SELECT account_locked_until
      FROM users
      WHERE email = $1 AND deleted_at IS NULL
    `;

    const result = await query(text, [email.toLowerCase()]);
    
    if (!result.rows[0] || !result.rows[0].account_locked_until) {
      return false;
    }

    const lockExpiry = new Date(result.rows[0].account_locked_until);
    const now = new Date();

    return lockExpiry > now;
  }
}

module.exports = User;