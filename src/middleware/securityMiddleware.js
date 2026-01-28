// src/middleware/securityMiddleware.js

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const hpp = require('hpp');
const cors = require('cors');
const crypto = require('crypto');
const { TooManyRequestsError } = require('../exceptions/customExceptions');

const extractClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown';
};

const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return extractClientIP(req);
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many requests from this IP, please try again later',
      timestamp: new Date().toISOString()
    });
  },
});

const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 3, 
  skipSuccessfulRequests: false,
  message: 'Too many authentication attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return extractClientIP(req);
  },
  handler: (req, res) => {
    const clientIP = extractClientIP(req);
    console.warn(`Rate limit exceeded for authentication from IP: ${clientIP}`);
    res.status(429).json({
      success: false,
      message: 'Too many authentication attempts, please try again later',
      timestamp: new Date().toISOString()
    });
  },
});

const sensitiveOperationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return extractClientIP(req);
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many attempts, please try again later',
      timestamp: new Date().toISOString()
    });
  },
});

const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.CORS_ORIGINS 
      ? process.env.CORS_ORIGINS.split(',')
      : ['http://localhost:3000'];
    
    if (!origin) {
      callback(null, true);
    } else if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-ID', 'X-Request-ID'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  maxAge: 86400,
};

const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      formAction: ["'self'"],
    },
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true,
  },
  frameguard: {
    action: 'deny',
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin',
  },
  xssFilter: true,
  noSniff: true,
  ieNoOpen: true,
  hidePoweredBy: true,
});

const pathTraversalProtection = (req, res, next) => {
  const pathTraversalPatterns = [
    /\.\./g,
    /%2e%2e/gi,
    /%252e/gi,
    /\\/g,
    /\0/g,
    /\/etc\//gi,
    /\/\.env/gi,
    /\/\.git/gi,
    /\/\.ssh/gi,
    /windows.*system32/gi,
  ];

  const checkPathTraversal = (value) => {
    if (typeof value === 'string') {
      for (const pattern of pathTraversalPatterns) {
        if (pattern.test(value)) {
          return true;
        }
      }
    }
    return false;
  };

  const checkObject = (obj) => {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (typeof obj[key] === 'string' && checkPathTraversal(obj[key])) {
          return true;
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          if (checkObject(obj[key])) return true;
        }
      }
    }
    return false;
  };

  if ((req.body && checkObject(req.body)) || 
      (req.query && checkObject(req.query)) || 
      (req.params && checkObject(req.params))) {
    console.warn(`Path traversal attempt detected from IP: ${req.clientIP}`);
    return res.status(403).json({
      success: false,
      message: 'Invalid request data',
    });
  }

  next();
};

const noSQLInjectionProtection = (req, res, next) => {
  const nosqlPatterns = [
    /\$ne\b/gi,
    /\$gt\b/gi,
    /\$gte\b/gi,
    /\$lt\b/gi,
    /\$lte\b/gi,
    /\$in\b/gi,
    /\$nin\b/gi,
    /\$or\b/gi,
    /\$and\b/gi,
    /\$not\b/gi,
    /\$nor\b/gi,
    /\$exists\b/gi,
    /\$where\b/gi,
    /\$regex\b/gi,
    /\$text\b/gi,
    /\$search\b/gi,
    /\$slice\b/gi,
    /\$elemMatch\b/gi,
    /\$size\b/gi,
    /\$all\b/gi,
    /\$type\b/gi,
    /\$mod\b/gi,
    /{\s*['"]\$[^'"]+['"]\s*:/gi,
    /['"]\s*,\s*['"]\$\w+['"]\s*:/gi,
  ];

  const checkNoSQLInjection = (obj) => {
    if (obj && typeof obj === 'object') {
      if (Array.isArray(obj)) {
        for (const item of obj) {
          if (checkNoSQLInjection(item)) {
            return true;
          }
        }
        return false;
      }
      
      const keys = Object.keys(obj);
      for (const key of keys) {
        if (key.startsWith('$')) {
          return true;
        }
        
        if (typeof obj[key] === 'string') {
          for (const pattern of nosqlPatterns) {
            if (pattern.test(obj[key])) {
              return true;
            }
          }
        }
        
        if (typeof obj[key] === 'object' && obj[key] !== null) {
          if (checkNoSQLInjection(obj[key])) {
            return true;
          }
        }
      }
    }
    return false;
  };

  if (req.body && typeof req.body === 'object') {
    const criticalFields = ['email', 'password', 'username', 'user', 'id'];
    
    for (const field of criticalFields) {
      if (req.body[field]) {
        if (typeof req.body[field] !== 'string') {
          console.warn(`NoSQL injection: ${field} is not a string from IP: ${req.clientIP}`);
          return res.status(400).json({
            success: false,
            message: 'Invalid request data',
          });
        }
        
        for (const pattern of nosqlPatterns) {
          if (pattern.test(req.body[field])) {
            console.warn(`NoSQL injection pattern detected in ${field} from IP: ${req.clientIP}`);
            return res.status(400).json({
              success: false,
              message: 'Invalid request data',
            });
          }
        }
      }
    }
    
    if (checkNoSQLInjection(req.body)) {
      console.warn(`NoSQL injection in body from IP: ${req.clientIP}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid request data',
      });
    }
  }

  if (req.query && checkNoSQLInjection(req.query)) {
    console.warn(`NoSQL injection in query from IP: ${req.clientIP}`);
    return res.status(400).json({
      success: false,
      message: 'Invalid request parameters',
    });
  }

  next();
};

const sqlInjectionProtection = (req, res, next) => {
  const sqlInjectionPatterns = [
    /(\bSELECT\b.*\bFROM\b)/gi,
    /(\bINSERT\s+INTO\b)/gi,
    /(\bUPDATE\b.*\bSET\b)/gi,
    /(\bDELETE\s+FROM\b)/gi,
    /(\bDROP\s+(TABLE|DATABASE)\b)/gi,
    /(\bUNION\s+(ALL\s+)?SELECT\b)/gi,
    /(\bEXEC(UTE)?\s*\()/gi,
    /(--\s*$|--\s*[;'"])/gm,
    /\/\*.*\*\//gs,
    /['"]\s*OR\s+['"]\d+['"]\s*=\s*['"]\d+/gi,
    /['"]\s*OR\s+\d+\s*=\s*\d+/gi,
    /(\b(WAITFOR|SLEEP|BENCHMARK)\s*\()/gi,
    /(xp_cmdshell|sp_executesql)/gi,
  ];

  const checkForSQLInjection = (value) => {
    if (typeof value === 'string') {
      for (const pattern of sqlInjectionPatterns) {
        if (pattern.test(value)) {
          return true;
        }
      }
    }
    return false;
  };

  const checkObjectFields = (obj, location) => {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (typeof value === 'string' && checkForSQLInjection(value)) {
          console.warn(`Potential SQL injection in ${location}.${key} from IP: ${req.clientIP}`);
          return true;
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          if (checkObjectFields(value, `${location}.${key}`)) {
            return true;
          }
        }
      }
    }
    return false;
  };

  if (req.body && typeof req.body === 'object' && checkObjectFields(req.body, 'body')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid request data',
    });
  }

  if (req.query && typeof req.query === 'object' && checkObjectFields(req.query, 'query')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid request parameters',
    });
  }

  if (req.params && typeof req.params === 'object' && checkObjectFields(req.params, 'params')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid URL parameters',
    });
  }

  next();
};

const inputSanitization = (req, res, next) => {
  const sanitizeInput = (input) => {
    if (typeof input === 'string') {
      input = input.trim();
      input = input.replace(/\0/g, '');
      input = input.replace(/\s+/g, ' ');
      
      if (input.length > 10000) {
        input = input.substring(0, 10000);
      }
    }
    return input;
  };

  if (req.body) {
    sanitizeObject(req.body);
  }

  if (req.query) {
    sanitizeObject(req.query);
  }

  function sanitizeObject(obj) {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (typeof obj[key] === 'string') {
          obj[key] = sanitizeInput(obj[key]);
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      }
    }
  }

  next();
};

const botDetection = (req, res, next) => {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  
  const maliciousBots = [
    'sqlmap',
    'nikto',
    'nmap',
    'masscan',
    'nessus',
    'openvas',
    'acunetix',
    'burp',
    'metasploit',
    'havij',
    'dirbuster',
    'gobuster',
    'wpscan',
    'nuclei',
    'skipfish',
  ];
  
  const suspiciousTools = [
    'wget',
    'curl',
    'python-requests',
    'go-http-client',
    'headlesschrome',
    'phantomjs',
    'scrapy',
    'httpclient',
  ];
  
  for (const bot of maliciousBots) {
    if (userAgent.includes(bot)) {
      console.warn(`Malicious bot detected: ${bot} from IP: ${req.clientIP}`);
      return res.status(403).json({
        success: false,
        message: 'Access denied',
      });
    }
  }
  
  for (const tool of suspiciousTools) {
    if (userAgent.includes(tool)) {
      console.warn(`Suspicious automated tool detected: ${tool} from IP: ${req.clientIP}, User-Agent: ${req.headers['user-agent']}`);
      if (req.path.includes('/auth/') || req.path.includes('/login') || req.path.includes('/register')) {
        return res.status(403).json({
          success: false,
          message: 'Automated requests not allowed on authentication endpoints',
        });
      }
    }
  }
  
  next();
};

const sanitizeRequest = [
  hpp(),
  botDetection,
  noSQLInjectionProtection,
  pathTraversalProtection,
  sqlInjectionProtection,
  inputSanitization,
];

const securityHeaders = (req, res, next) => {
  res.removeHeader('X-Powered-By');
  
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Download-Options', 'noopen');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  
  const requestId = req.headers['x-request-id'] || generateRequestId();
  res.setHeader('X-Request-ID', requestId);
  req.requestId = requestId;
  
  next();
};

const generateRequestId = () => {
  return `req_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
};

const extractIP = (req, res, next) => {
  req.clientIP = 
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown';
  
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/;
  
  if (!ipRegex.test(req.clientIP) && req.clientIP !== 'unknown') {
    console.warn(`Invalid IP format detected: ${req.clientIP}`);
    req.clientIP = 'invalid';
  }
  
  next();
};

const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.clientIP,
      userAgent: req.headers['user-agent'] || 'unknown',
      user: req.user?.id || 'anonymous',
      referrer: req.headers.referer || req.headers.referrer || 'none',
    };
    
    if (res.statusCode >= 400) {
      logEntry.severity = 'WARNING';
    }
    
    if (res.statusCode >= 500) {
      logEntry.severity = 'ERROR';
    }
    
    if (res.statusCode === 403 || res.statusCode === 401) {
      logEntry.securityEvent = 'AUTH_FAILURE';
    }
    
    if (process.env.NODE_ENV === 'production') {
      console.log(JSON.stringify(logEntry));
    } else {
      console.log(`${logEntry.timestamp} ${logEntry.method} ${logEntry.url} ${logEntry.status} ${logEntry.duration} ${logEntry.ip}`);
    }
  });
  
  next();
};

const bodyParserConfig = {
  json: {
    limit: process.env.MAX_REQUEST_SIZE || '10mb',
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf.toString(encoding || 'utf8');
    },
  },
  urlencoded: {
    limit: process.env.MAX_REQUEST_SIZE || '10mb',
    extended: true,
    parameterLimit: 100,
  },
};

const fileUploadProtection = (req, res, next) => {
  if (req.file || req.files) {
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    
    const files = req.files ? Object.values(req.files).flat() : [req.file];
    
    for (const file of files) {
      if (!allowedMimeTypes.includes(file.mimetype)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid file type',
        });
      }
      
      if (file.mimetype.startsWith('image/') && file.size > 10 * 1024 * 1024) {
        return res.status(400).json({
          success: false,
          message: 'File too large',
        });
      }
    }
  }
  
  next();
};

module.exports = {
  apiLimiter,
  authLimiter,
  sensitiveOperationLimiter,
  corsOptions,
  helmetConfig,
  sanitizeRequest,
  securityHeaders,
  extractIP,
  requestLogger,
  bodyParserConfig,
  fileUploadProtection,
  sqlInjectionProtection, 
  inputSanitization,
  pathTraversalProtection,
  noSQLInjectionProtection,
  botDetection,
};