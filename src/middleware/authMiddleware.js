// src/middleware/authMiddleware.js

const { verifyAccessToken } = require('../config/jwt');
const SessionModel = require('../models/SessionModel');
const { UnauthorizedError, ForbiddenError } = require('../exceptions/customExceptions');

/**
 * Verify JWT token and attach user to request
 */
const authenticate = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      throw new UnauthorizedError('Authentication required');
    }
    const decoded = verifyAccessToken(token);

    const sessionId = req.headers['x-session-id'] || req.cookies.sessionId;
    
    if (sessionId) {
      const session = await SessionModel.get(sessionId);
      
      if (!session) {
        throw new UnauthorizedError('Session expired or invalid');
      }
      await SessionModel.update(sessionId, {
        lastActivity: new Date().toISOString(),
      });
    }
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
    };

    req.sessionId = sessionId;

    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new UnauthorizedError('Invalid token'));
    }
    if (error.name === 'TokenExpiredError') {
      return next(new UnauthorizedError('Token expired'));
    }
    next(error);
  }
};


const optionalAuthenticate = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (token) {
      const decoded = verifyAccessToken(token);
      req.user = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
      };
    }

    next();
  } catch (error) {
    next();
  }
};

/**
 * Authorize based on roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    if (!roles.includes(req.user.role)) {
      return next(new ForbiddenError('You do not have permission to access this resource'));
    }

    next();
  };
};

/**
 * Check if user is owner of resource or admin
 */
const authorizeOwnerOrAdmin = (userIdParam = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    const resourceUserId = req.params[userIdParam] || req.body[userIdParam];

    if (req.user.role === 'admin' || req.user.id === resourceUserId) {
      return next();
    }

    return next(new ForbiddenError('You do not have permission to access this resource'));
  };
};

module.exports = {
  authenticate,
  optionalAuthenticate,
  authorize,
  authorizeOwnerOrAdmin,
};