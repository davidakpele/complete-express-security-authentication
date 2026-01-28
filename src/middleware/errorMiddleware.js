// src/middleware/errorMiddleware.js

const { AppError } = require('../exceptions/customExceptions');
const { errorResponse } = require('../responses/apiResponses');

/**
 * Global error handler
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;
  error.stack = err.stack;

  console.error('Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user: req.user?.id,
  });

  // PostgreSQL duplicate key error
  if (err.code === '23505') {
    error = new AppError('Duplicate field value entered', 400);
  }

  // PostgreSQL validation error
  if (err.code === '23502') {
    error = new AppError('Missing required field', 400);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = new AppError('Invalid token', 401);
  }

  if (err.name === 'TokenExpiredError') {
    error = new AppError('Token expired', 401);
  }

  // PostgreSQL connection errors
  if (err.code === 'ECONNREFUSED') {
    error = new AppError('Database connection failed', 503);
  }

  // Redis errors
  if (err.message && err.message.includes('Redis')) {
    error = new AppError('Cache service unavailable', 503);
  }

  // If it's an operational error, send it as is
  if (err instanceof AppError) {
    return errorResponse(
      res,
      err.message,
      err.statusCode,
      err.errors || null
    );
  }

  const message =
    process.env.NODE_ENV === 'development'
      ? err.message
      : 'Something went wrong';

  const statusCode = error.statusCode || 500;

  return errorResponse(res, message, statusCode, process.env.NODE_ENV === 'development' ? { stack: error.stack } : null);
};

/**
 * Handle 404 errors
 */
const notFound = (req, res, next) => {
  const error = new AppError(`Route ${req.originalUrl} not found`, 404);
  next(error);
};

/**
 * Async handler wrapper to catch errors in async route handlers
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  errorHandler,
  notFound,
  asyncHandler,
};