// src/middleware/validationMiddleware.js

const Joi = require('joi');
const { ValidationError } = require('../exceptions/customExceptions');

/**
 * Validate request data against schema
 */
const validate = (schema) => {
  return (req, res, next) => {
    const validationOptions = {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    };

    const { error, value } = schema.validate(
      {
        body: req.body,
        query: req.query,
        params: req.params,
      },
      validationOptions
    );

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return next(new ValidationError('Validation failed', errors));
    }
    req.body = value.body || req.body;
    req.query = value.query || req.query;
    req.params = value.params || req.params;
    next();
  };
};

/**
 * Common validation schemas
 */
const schemas = {
  // Registration schema
  register: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
      }),
      password: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
          'string.min': 'Password must be at least 8 characters long',
          'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
          'any.required': 'Password is required',
        }),
      firstName: Joi.string().min(2).max(50).required().messages({
        'string.min': 'First name must be at least 2 characters long',
        'string.max': 'First name cannot exceed 50 characters',
        'any.required': 'First name is required',
      }),
      lastName: Joi.string().min(2).max(50).required().messages({
        'string.min': 'Last name must be at least 2 characters long',
        'string.max': 'Last name cannot exceed 50 characters',
        'any.required': 'Last name is required',
      }),
    }),
  }),

  login: Joi.object({
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
      }),
      password: Joi.string().required().messages({
        'any.required': 'Password is required',
      }),
    }),
  }),

  refreshToken: Joi.object({
    body: Joi.object({
      refreshToken: Joi.string().required().messages({
        'any.required': 'Refresh token is required',
      }),
    }),
  }),

  updateProfile: Joi.object({
    body: Joi.object({
      firstName: Joi.string().min(2).max(50).messages({
        'string.min': 'First name must be at least 2 characters long',
        'string.max': 'First name cannot exceed 50 characters',
      }),
      lastName: Joi.string().min(2).max(50).messages({
        'string.min': 'Last name must be at least 2 characters long',
        'string.max': 'Last name cannot exceed 50 characters',
      }),
    }),
  }),

  changePassword: Joi.object({
    body: Joi.object({
      currentPassword: Joi.string().required().messages({
        'any.required': 'Current password is required',
      }),
      newPassword: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
          'string.min': 'New password must be at least 8 characters long',
          'string.pattern.base': 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
          'any.required': 'New password is required',
        }),
    }),
  }),

  userId: Joi.object({
    params: Joi.object({
      userId: Joi.string().uuid().required().messages({
        'string.guid': 'Invalid user ID format',
        'any.required': 'User ID is required',
      }),
    }),
  }),

  pagination: Joi.object({
    query: Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(10),
      search: Joi.string().allow('').optional(),
      role: Joi.string().valid('user', 'moderator', 'admin').optional(),
      isActive: Joi.boolean().optional(),
    }),
  }),

  updateRole: Joi.object({
    body: Joi.object({
      role: Joi.string().valid('user', 'moderator', 'admin').required().messages({
        'any.only': 'Role must be one of: user, moderator, admin',
        'any.required': 'Role is required',
      }),
    }),
    params: Joi.object({
      userId: Joi.string().uuid().required(),
    }),
  }),

  toggleStatus: Joi.object({
    body: Joi.object({
      isActive: Joi.boolean().required().messages({
        'any.required': 'isActive field is required',
      }),
    }),
    params: Joi.object({
      userId: Joi.string().uuid().required(),
    }),
  }),
};

module.exports = {
  validate,
  schemas,
};