// src/server.js

const app = require('./app');
const dotenv = require('dotenv');

dotenv.config();

const { pool } = require('./config/database');
const { redisClient } = require('./config/redis');

const PORT = process.env.PORT || 5000;
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION! Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});

const server = app.listen(PORT, () => {
  console.log('=================================');
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode`);
  console.log(`Server listening on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}/api/${process.env.API_VERSION || 'v1'}`);
  console.log('=================================');
});

const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  server.close(async () => {
    console.log('HTTP server closed');

    try {
      await pool.end();
      console.log('Database connection closed');
      await redisClient.quit();
      console.log('Redis connection closed');

      console.log('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      console.error('Error during shutdown:', error);
      process.exit(1);
    }
  });
  setTimeout(() => {
    console.error('Forced shutdown due to timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = server;