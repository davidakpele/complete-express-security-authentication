//src/app.js

const express = require('express');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const morgan = require('morgan');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import middleware
const { errorHandler, notFound } = require('./middleware/errorMiddleware');
const {
  corsOptions,
  helmetConfig,
  sanitizeRequest,
  securityHeaders,
  extractIP,
  requestLogger,
  apiLimiter,
} = require('./middleware/securityMiddleware');

// Import routes
const routes = require('./routes/mainRouter');

// Create Express app
const app = express();

// Trust proxy 
app.set('trust proxy', 1);

// Security middleware
app.use(helmetConfig);
app.use(securityHeaders);
app.use(extractIP);

// CORS
app.use(cors(corsOptions));

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser
app.use(cookieParser());

// Data sanitization
sanitizeRequest.forEach(middleware => app.use(middleware));

// Compression
app.use(compression());

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Custom request logger
app.use(requestLogger);

// Rate limiting
app.use('/api/', apiLimiter);

// API routes
app.use(`/api/${process.env.API_VERSION || 'v1'}`, routes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'User Management API',
    version: process.env.API_VERSION || 'v1',
    documentation: '/api/v1/health',
  });
});

// Handle 404 errors
app.use(notFound);

// Global error handler
app.use(errorHandler);

module.exports = app;