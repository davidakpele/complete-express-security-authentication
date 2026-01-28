// src/helpers/utilities.js

const crypto = require('crypto');

/**
 * Generate random string
 */
const generateRandomString = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate random number
 */
const generateRandomNumber = (min = 100000, max = 999999) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

/**
 * Hash string using SHA256
 */
const hashString = (str) => {
  return crypto.createHash('sha256').update(str).digest('hex');
};

/**
 * Sleep/delay function
 */
const sleep = (ms) => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};

/**
 * Check if email is valid
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Sanitize user input
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .trim()
    .replace(/[<>]/g, '') 
    .replace(/javascript:/gi, '') 
    .replace(/on\w+=/gi, ''); 
};

/**
 * Format date to readable string
 */
const formatDate = (date, format = 'YYYY-MM-DD HH:mm:ss') => {
  const d = new Date(date);
  
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  const seconds = String(d.getSeconds()).padStart(2, '0');
  
  return format
    .replace('YYYY', year)
    .replace('MM', month)
    .replace('DD', day)
    .replace('HH', hours)
    .replace('mm', minutes)
    .replace('ss', seconds);
};

/**
 * Parse pagination parameters
 */
const parsePagination = (query) => {
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 10));
  const offset = (page - 1) * limit;
  
  return { page, limit, offset };
};

/**
 * Build pagination metadata
 */
const buildPaginationMeta = (total, page, limit) => {
  const totalPages = Math.ceil(total / limit);
  
  return {
    total,
    page,
    limit,
    totalPages,
    hasNext: page < totalPages,
    hasPrev: page > 1,
    nextPage: page < totalPages ? page + 1 : null,
    prevPage: page > 1 ? page - 1 : null,
  };
};

/**
 * Mask email for privacy
 */
const maskEmail = (email) => {
  if (!email || typeof email !== 'string') return '';
  
  const [localPart, domain] = email.split('@');
  
  if (!domain) return email;
  
  const maskedLocal = localPart.length > 2
    ? localPart.charAt(0) + '*'.repeat(localPart.length - 2) + localPart.charAt(localPart.length - 1)
    : localPart;
  
  return `${maskedLocal}@${domain}`;
};

/**
 * Extract error message from error object
 */
const extractErrorMessage = (error) => {
  if (typeof error === 'string') return error;
  
  if (error.message) return error.message;
  
  if (error.errors && Array.isArray(error.errors)) {
    return error.errors.map(e => e.message || e).join(', ');
  }
  
  return 'An unexpected error occurred';
};

/**
 * Check if value is empty
 */
const isEmpty = (value) => {
  if (value === null || value === undefined) return true;
  if (typeof value === 'string') return value.trim().length === 0;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
};

/**
 * Deep clone object
 */
const deepClone = (obj) => {
  return JSON.parse(JSON.stringify(obj));
};

/**
 * Remove undefined and null values from object
 */
const cleanObject = (obj) => {
  const cleaned = {};
  
  Object.keys(obj).forEach(key => {
    if (obj[key] !== undefined && obj[key] !== null) {
      cleaned[key] = obj[key];
    }
  });
  
  return cleaned;
};

module.exports = {
  generateRandomString,
  generateRandomNumber,
  hashString,
  sleep,
  isValidEmail,
  sanitizeInput,
  formatDate,
  parsePagination,
  buildPaginationMeta,
  maskEmail,
  extractErrorMessage,
  isEmpty,
  deepClone,
  cleanObject,
};