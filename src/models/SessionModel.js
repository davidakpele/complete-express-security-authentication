// src/models/SessionModel.js

const redis = require('../config/redis');

class Session {
  /**
   * Create a new session
   */
  static async create(userId, sessionData, expirationInSeconds = 604800) {
    const sessionId = `session:${userId}:${Date.now()}`;
    const data = {
      userId,
      ...sessionData,
      createdAt: new Date().toISOString(),
    };

    await redis.set(sessionId, data, expirationInSeconds);
    return sessionId;
  }

  /**
   * Get session data
   */
  static async get(sessionId) {
    return await redis.get(sessionId);
  }

  /**
   * Update session data
   */
  static async update(sessionId, updateData) {
    const existingData = await redis.get(sessionId);
    
    if (!existingData) {
      return null;
    }

    const updatedData = {
      ...existingData,
      ...updateData,
      updatedAt: new Date().toISOString(),
    };

    const ttl = await redis.redisClient.ttl(sessionId);
    await redis.set(sessionId, updatedData, ttl > 0 ? ttl : 604800);
    
    return updatedData;
  }

  /**
   * Delete session
   */
  static async delete(sessionId) {
    return await redis.del(sessionId);
  }

  /**
   * Delete all sessions for a user
   */
  static async deleteAllUserSessions(userId) {
    const pattern = `session:${userId}:*`;
    return await redis.deletePattern(pattern);
  }

  /**
   * Get all sessions for a user
   */
  static async getUserSessions(userId) {
    const pattern = `session:${userId}:*`;
    const keys = await redis.redisClient.keys(pattern);
    
    const sessions = await Promise.all(
      keys.map(async (key) => {
        const data = await redis.get(key);
        return { sessionId: key, ...data };
      })
    );

    return sessions;
  }

  /**
   * Refresh session expiration
   */
  static async refresh(sessionId, expirationInSeconds = 604800) {
    const exists = await redis.exists(sessionId);
    
    if (!exists) {
      return false;
    }

    await redis.expire(sessionId, expirationInSeconds);
    return true;
  }

  /**
   * Check if session exists
   */
  static async exists(sessionId) {
    return await redis.exists(sessionId);
  }
}

module.exports = Session;