// src/config/redis.js

const redis = require('redis');
const dotenv = require('dotenv');

dotenv.config();

const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
  password: process.env.REDIS_PASSWORD || undefined,
  database: process.env.REDIS_DB || 0,
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

// Connect to Redis
(async () => {
  await redisClient.connect();
})();

// Redis helper methods
const redisHelpers = {
  async set(key, value, expirationInSeconds = null) {
    try {
      const serialized = JSON.stringify(value);
      if (expirationInSeconds) {
        await redisClient.setEx(key, expirationInSeconds, serialized);
      } else {
        await redisClient.set(key, serialized);
      }
      return true;
    } catch (error) {
      console.error('Redis SET error:', error);
      throw error;
    }
  },

  async get(key) {
    try {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Redis GET error:', error);
      throw error;
    }
  },

  async del(key) {
    try {
      await redisClient.del(key);
      return true;
    } catch (error) {
      console.error('Redis DEL error:', error);
      throw error;
    }
  },

  async exists(key) {
    try {
      const result = await redisClient.exists(key);
      return result === 1;
    } catch (error) {
      console.error('Redis EXISTS error:', error);
      throw error;
    }
  },

  async incr(key) {
    try {
      return await redisClient.incr(key);
    } catch (error) {
      console.error('Redis INCR error:', error);
      throw error;
    }
  },

  async expire(key, seconds) {
    try {
      await redisClient.expire(key, seconds);
      return true;
    } catch (error) {
      console.error('Redis EXPIRE error:', error);
      throw error;
    }
  },

  async deletePattern(pattern) {
    try {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(keys);
      }
      return keys.length;
    } catch (error) {
      console.error('Redis DELETE PATTERN error:', error);
      throw error;
    }
  },
};

module.exports = {
  redisClient,
  ...redisHelpers,
};