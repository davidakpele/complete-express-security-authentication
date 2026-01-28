// src/models/RefreshTokenModel.js

const redis = require('../config/redis');
const { v4: uuidv4 } = require('uuid');

class RefreshToken {
  /**
   * Store refresh token
   */
  static async create(userId, token, expirationInSeconds = 604800) {
    const tokenId = uuidv4();
    const key = `refresh_token:${userId}:${tokenId}`;
    
    const data = {
      tokenId,
      userId,
      token,
      createdAt: new Date().toISOString(),
    };

    await redis.set(key, data, expirationInSeconds);
    return { tokenId, ...data };
  }

  /**
   * Verify and get refresh token
   */
  static async verify(userId, token) {
    const pattern = `refresh_token:${userId}:*`;
    const keys = await redis.redisClient.keys(pattern);

    for (const key of keys) {
      const data = await redis.get(key);
      if (data && data.token === token) {
        return { key, ...data };
      }
    }

    return null;
  }

  /**
   * Delete refresh token
   */
  static async delete(userId, tokenId) {
    const key = `refresh_token:${userId}:${tokenId}`;
    return await redis.del(key);
  }

  /**
   * Delete all refresh tokens for a user
   */
  static async deleteAllUserTokens(userId) {
    const pattern = `refresh_token:${userId}:*`;
    return await redis.deletePattern(pattern);
  }

  /**
   * Get all refresh tokens for a user
   */
  static async getUserTokens(userId) {
    const pattern = `refresh_token:${userId}:*`;
    const keys = await redis.redisClient.keys(pattern);
    
    const tokens = await Promise.all(
      keys.map(async (key) => {
        const data = await redis.get(key);
        return data;
      })
    );

    return tokens.filter(Boolean);
  }
}

module.exports = RefreshToken;