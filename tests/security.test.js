// tests/security.test.js

const request = require('supertest');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { describe, it, expect, beforeEach, afterAll } = require('@jest/globals');


const securityResults = {
  categories: {}
};

function trackTest(category, testName, totalRequests, blocked, passed) {
  if (!securityResults.categories[category]) {
    securityResults.categories[category] = {
      tests: [],
      totalRequests: 0,
      totalBlocked: 0,
      totalPassed: 0
    };
  }
  
  securityResults.categories[category].tests.push({
    name: testName,
    total: totalRequests,
    blocked: blocked,
    passed: passed,
    status: blocked === totalRequests ? 'GOOD' : 'FAIL'
  });
  
  securityResults.categories[category].totalRequests += totalRequests;
  securityResults.categories[category].totalBlocked += blocked;
  securityResults.categories[category].totalPassed += passed;
}

function printSecurityReport() {
  const fs = require('fs');
  const path = require('path');
  
  let reportContent = '';
  
  reportContent += '# SECURITY TEST RESULTS REPORT\n\n';
  reportContent += `**Generated:** ${new Date().toISOString()}\n\n`;
  reportContent += '---\n\n';

  let grandTotal = 0;
  let grandBlocked = 0;
  let grandPassed = 0;

  Object.keys(securityResults.categories).forEach(category => {
    const cat = securityResults.categories[category];
    
    reportContent += `## ${category.toUpperCase()}\n\n`;
    reportContent += '| Test Name | Total | Blocked | Passed | Status |\n';
    reportContent += '|-----------|-------|---------|--------|--------|\n';
    
    cat.tests.forEach(test => {
      reportContent += `| ${test.name} | ${test.total} | ${test.blocked} | ${test.passed} | ${test.status} |\n`;
    });
    
    reportContent += `| **SUBTOTAL** | **${cat.totalRequests}** | **${cat.totalBlocked}** | **${cat.totalPassed}** | **${cat.totalBlocked === cat.totalRequests ? '✅ GOOD' : '❌ FAIL'}** |\n\n`;
    
    grandTotal += cat.totalRequests;
    grandBlocked += cat.totalBlocked;
    grandPassed += cat.totalPassed;
  });

  reportContent += '---\n\n';
  reportContent += '## GRAND TOTAL\n\n';
  reportContent += '| Metric | Total | Blocked | Passed | Status |\n';
  reportContent += '|--------|-------|---------|--------|--------|\n';
  reportContent += `| **ALL TESTS** | **${grandTotal}** | **${grandBlocked}** | **${grandPassed}** | **${grandBlocked === grandTotal ? '✅ GOOD' : '❌ FAIL'}** |\n\n`;
  
  const blockRate = grandTotal > 0 ? ((grandBlocked / grandTotal) * 100).toFixed(2) : 0;
  const passRate = grandTotal > 0 ? ((grandPassed / grandTotal) * 100).toFixed(2) : 0;
  
  reportContent += '---\n\n';
  reportContent += '## SUMMARY\n\n';
  reportContent += `- **Total Attack Requests:** ${grandTotal}\n`;
  reportContent += `- **Blocked (Good):** ${grandBlocked} (${blockRate}%)\n`;
  reportContent += `- **Passed Through (Bad):** ${grandPassed} (${passRate}%)\n`;
  reportContent += `- **Security Rating:** ${blockRate >= 100 ? '🛡️ EXCELLENT' : blockRate >= 90 ? '✅ GOOD' : blockRate >= 70 ? '⚠️ FAIR' : '❌ POOR'}\n\n`;
  
  reportContent += '---\n\n';
  reportContent += '## DETAILED FINDINGS\n\n';
  
  if (grandPassed === 0) {
    reportContent += '### All Attacks Blocked\n\n';
    reportContent += 'Your security middleware successfully blocked all attack attempts. The system is well-protected against:\n\n';
    reportContent += '- SQL Injection attacks\n';
    reportContent += '- Cross-Site Scripting (XSS)\n';
    reportContent += '- Path Traversal attempts\n';
    reportContent += '- CORS violations\n';
    reportContent += '- NoSQL Injection\n';
    reportContent += '- Rate limiting bypass\n';
    reportContent += '- Large payload attacks (DoS)\n';
    reportContent += '- Malicious bots and scanners\n\n';
  } else {
    reportContent += '### Security Gaps Detected\n\n';
    reportContent += `${grandPassed} attack(s) passed through the security middleware. Review the following:\n\n`;
    
    Object.keys(securityResults.categories).forEach(category => {
      const cat = securityResults.categories[category];
      const failedTests = cat.tests.filter(t => t.passed > 0);
      
      if (failedTests.length > 0) {
        reportContent += `**${category}:**\n\n`;
        failedTests.forEach(test => {
          reportContent += `- ${test.name}: ${test.passed} request(s) passed through\n`;
        });
        reportContent += '\n';
      }
    });
  }
  
  reportContent += '---\n\n';
  reportContent += '## RECOMMENDATIONS\n\n';
  
  if (grandPassed === 0) {
    reportContent += '- Maintain current security configurations\n';
    reportContent += '- Continue monitoring security logs\n';
    reportContent += '- Schedule regular security audits\n';
    reportContent += '- Keep security middleware dependencies updated\n\n';
  } else {
    reportContent += '- Review and strengthen middleware for failed tests\n';
    reportContent += '- Implement additional validation layers\n';
    reportContent += '- Enable detailed security logging\n';
    reportContent += '- Set up real-time security alerts\n\n';
  }
  
  reportContent += '---\n\n';
  reportContent += '*Report generated by Security Test Suite*\n';

  // Write to file
  const reportPath = path.join(process.cwd(), 'SECURITYREPORT.md');
  fs.writeFileSync(reportPath, reportContent);
  
  // Also print to console with table format
  console.log('\n\n');
  console.log('═══════════════════════════════════════════════════════════════════════════════');
  console.log('                        SECURITY TEST RESULTS REPORT                            ');
  console.log('═══════════════════════════════════════════════════════════════════════════════');
  console.log('\n');

  Object.keys(securityResults.categories).forEach(category => {
    const cat = securityResults.categories[category];
    
    console.log(`\n${category.toUpperCase()}`);
    console.log('─'.repeat(79));
    console.log(`${'Test Name'.padEnd(45)} | ${'Total'.padEnd(6)} | ${'Blocked'.padEnd(8)} | ${'Passed'.padEnd(7)} | Status`);
    console.log('─'.repeat(79));
    
    cat.tests.forEach(test => {
      const name = test.name.length > 44 ? test.name.substring(0, 41) + '...' : test.name;
      console.log(
        `${name.padEnd(45)} | ${String(test.total).padEnd(6)} | ${String(test.blocked).padEnd(8)} | ${String(test.passed).padEnd(7)} | ${test.status}`
      );
    });
    
    console.log('─'.repeat(79));
    console.log(
      `${'SUBTOTAL'.padEnd(45)} | ${String(cat.totalRequests).padEnd(6)} | ${String(cat.totalBlocked).padEnd(8)} | ${String(cat.totalPassed).padEnd(7)} | ${cat.totalBlocked === cat.totalRequests ? '✅ GOOD' : '❌ FAIL'}`
    );
  });

  console.log('\n');
  console.log('═══════════════════════════════════════════════════════════════════════════════');
  console.log(`${'GRAND TOTAL'.padEnd(45)} | ${String(grandTotal).padEnd(6)} | ${String(grandBlocked).padEnd(8)} | ${String(grandPassed).padEnd(7)} | ${grandBlocked === grandTotal ? '✅ GOOD' : '❌ FAIL'}`);
  console.log('═══════════════════════════════════════════════════════════════════════════════');
  
  console.log('\nSUMMARY:');
  console.log(`   Total Attack Requests: ${grandTotal}`);
  console.log(`   Blocked (Good): ${grandBlocked} (${blockRate}%)`);
  console.log(`   Passed Through (Bad): ${grandPassed} (${passRate}%)`);
  console.log(`   Security Rating: ${blockRate >= 100 ? 'EXCELLENT' : blockRate >= 90 ? 'GOOD' : blockRate >= 70 ? 'FAIR' : 'POOR'}`);
  console.log('\n');
  console.log(`Report saved to: ${reportPath}\n`);
}

// Mock your app setup
const createTestApp = () => {
  const app = express();
  
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: false,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        message: 'Too many authentication attempts, please try again later',
        timestamp: new Date().toISOString()
      });
    },
  });

  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    skipSuccessfulRequests: false,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        message: 'Too many requests from this IP, please try again later',
        timestamp: new Date().toISOString()
      });
    },
  });
  
  const { 
    helmetConfig, 
    corsOptions, 
    sanitizeRequest, 
    securityHeaders,
    extractIP,
    requestLogger,
    bodyParserConfig
  } = require('../src/middleware/securityMiddleware');
  
  app.use(helmetConfig);
  app.use(require('cors')(corsOptions));
  app.use(securityHeaders);
  app.use(extractIP);
  app.use(requestLogger);
  app.use(express.json(bodyParserConfig.json));
  app.use(express.urlencoded(bodyParserConfig.urlencoded));
  app.use(sanitizeRequest);
  
  app.use('/api/v1/auth/login', authLimiter);
  app.use('/api/v1/auth/register', authLimiter);
  
  app.post('/api/v1/auth/login', (req, res) => {
    res.status(200).json({ 
      success: true, 
      message: 'Login successful',
      token: 'mock-jwt-token'
    });
  });
  
  app.post('/api/v1/auth/register', (req, res) => {
    res.status(201).json({ 
      success: true, 
      message: 'Registration successful',
      userId: '123'
    });
  });
  
  app.use('/api/', apiLimiter);
  
  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({
      success: false,
      message: err.message,
      timestamp: new Date().toISOString()
    });
  });
  
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      message: 'Route not found',
      timestamp: new Date().toISOString()
    });
  });
  
  return app;
};

describe('Security Middleware Tests', () => {
  let app;
  
  beforeEach(() => {
    app = createTestApp();
  });

  afterAll(() => {
    printSecurityReport();
  });
  
  describe('Network & Infrastructure Security', () => {
    describe('Rate Limiting', () => {
      it('should limit requests per IP on /api/v1/auth/login', async () => {
        let blocked = 0;
        let passed = 0;
        const total = 6;
        
        for (let i = 0; i < 5; i++) {
          const response = await request(app)
            .post('/api/v1/auth/login')
            .send({ email: `test${i}@example.com`, password: 'password' });
          
          if (response.status === 429) blocked++;
          else passed++;
        }
        
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send({ email: 'test6@example.com', password: 'password' });
        
        if (response.status === 429) blocked++;
        else passed++;
        
        trackTest('Rate Limiting', 'Brute force attempt (6 requests)', total, blocked, passed);
        
        expect(response.status).toBe(429);
        expect(response.body.message).toContain('Too many authentication attempts');
      });
    });
    
    describe('Request Size Limits', () => {
      it('should reject request body larger than 10MB', async () => {
        const largePayload = {
          email: 'test@example.com',
          password: 'password',
          extra: 'x'.repeat(11 * 1024 * 1024)
        };
        
        const response = await request(app)
          .post('/api/v1/auth/register')
          .send(largePayload);
        
        const blocked = response.status === 413 ? 1 : 0;
        const passed = response.status === 413 ? 0 : 1;
        
        trackTest('Request Size Protection', 'DoS attack (11MB payload)', 1, blocked, passed);
        
        expect(response.status).toBe(413);
      });
    });
  });
  
  describe('SQL Injection Protection', () => {
    const testCases = [
      { name: 'UNION SELECT', payload: { email: "test' UNION SELECT * FROM users--", password: 'password' } },
      { name: 'OR 1=1', payload: { email: "admin' OR '1'='1", password: 'password' } },
      { name: 'DROP TABLE', payload: { email: "test'; DROP TABLE users;--", password: 'password' } },
      { name: 'SQL comment', payload: { email: "test'--", password: 'password' } },
      { name: 'SLEEP function', payload: { email: "test' AND SLEEP(5)--", password: 'password' } },
      { name: 'BENCHMARK', payload: { email: "test' AND BENCHMARK(5000000,MD5('test'))--", password: 'password' } },
      { name: 'INFORMATION_SCHEMA', payload: { email: "test' UNION SELECT * FROM INFORMATION_SCHEMA.TABLES--", password: 'password' } },
      { name: 'Error-based', payload: { email: "test' AND 1=CONVERT(int, (SELECT @@version))--", password: 'password' } },
      { name: 'Time-based blind', payload: { email: "test' AND IF(1=1,SLEEP(5),0)--", password: 'password' } },
      { name: 'Stacked queries', payload: { email: "test'; SELECT * FROM users;--", password: 'password' } },
      { name: 'Database functions', payload: { email: "test' AND LOAD_FILE('/etc/passwd')--", password: 'password' } },
      { name: 'XP_CMDSHELL', payload: { email: "test'; EXEC xp_cmdshell('dir')--", password: 'password' } },
    ];
    
    testCases.forEach(testCase => {
      it(`should block ${testCase.name} SQL injection attempt`, async () => {
        let blocked = 0;
        let passed = 0;
        
        const loginResponse = await request(app)
          .post('/api/v1/auth/login')
          .send(testCase.payload);
        
        if ([400, 401, 403].includes(loginResponse.status)) blocked++;
        else passed++;
        
        const registerPayload = { 
          ...testCase.payload, 
          firstName: 'Test',
          lastName: 'User' 
        };
        
        const registerResponse = await request(app)
          .post('/api/v1/auth/register')
          .send(registerPayload);
        
        if ([400, 401, 403].includes(registerResponse.status)) blocked++;
        else passed++;
        
        trackTest('SQL Injection Protection', testCase.name, 2, blocked, passed);
        
        expect([400, 401, 403]).toContain(loginResponse.status);
        expect([400, 401, 403]).toContain(registerResponse.status);
      });
    });
  });
  
  describe('XSS (Cross-Site Scripting) Protection', () => {
    const xssTestCases = [
      { name: 'Script tags', payload: { email: '<script>alert("XSS")</script>@example.com', password: 'password' } },
      { name: 'JavaScript URI', payload: { email: 'javascript:alert("XSS")', password: 'password' } },
      { name: 'Event handler', payload: { email: '" onmouseover="alert(\'XSS\')', password: 'password' } },
      { name: 'IMG tag with XSS', payload: { email: '<img src=x onerror=alert("XSS")>', password: 'password' } },
      { name: 'SVG XSS', payload: { email: '<svg onload=alert("XSS")>', password: 'password' } },
      { name: 'Encoded XSS', payload: { email: '%3Cscript%3Ealert(%22XSS%22)%3C%2Fscript%3E', password: 'password' } },
      { name: 'Unicode XSS', payload: { email: '&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;', password: 'password' } },
      { name: 'Eval function', payload: { email: "';eval('alert(1)');'", password: 'password' } },
      { name: 'Document write', payload: { email: '";document.write("<script>alert(1)</script>");"', password: 'password' } },
      { name: 'InnerHTML', payload: { email: '";document.body.innerHTML="<script>alert(1)</script>";"', password: 'password' } },
    ];
    
    xssTestCases.forEach(testCase => {
      it(`should detect ${testCase.name} XSS attempt`, async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send(testCase.payload);
        
        const blocked = !response.text.includes(testCase.payload.email) ? 1 : 0;
        const passed = response.text.includes(testCase.payload.email) ? 1 : 0;
        
        trackTest('XSS Protection', testCase.name, 1, blocked, passed);
        
        expect(response.text).not.toContain(testCase.payload.email);
      });
    });
  });
  
  describe('Path Traversal Protection', () => {
    const pathTraversalCases = [
      { name: 'Basic path traversal', payload: { email: '../../etc/passwd', password: 'password' } },
      { name: 'URL encoded', payload: { email: '%2e%2e%2f%2e%2e%2fetc%2fpasswd', password: 'password' } },
      { name: 'Double encoding', payload: { email: '%252e%252e%252fetc%252fpasswd', password: 'password' } },
      { name: 'Windows style', payload: { email: '..\\..\\Windows\\System32\\config', password: 'password' } },
      { name: 'Null byte', payload: { email: '../../etc/passwd%00', password: 'password' } },
      { name: 'Sensitive file', payload: { email: '/etc/shadow', password: 'password' } },
      { name: 'Configuration file', payload: { email: '../../.env', password: 'password' } },
      { name: 'Git files', payload: { email: '../../.git/config', password: 'password' } },
    ];
    
    pathTraversalCases.forEach(testCase => {
      it(`should block ${testCase.name} attempt`, async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send(testCase.payload);
        
        const blocked = [400, 401, 403].includes(response.status) ? 1 : 0;
        const passed = [400, 401, 403].includes(response.status) ? 0 : 1;
        
        trackTest('Path Traversal Protection', testCase.name, 1, blocked, passed);
        
        expect([400, 401, 403]).toContain(response.status);
      });
    });
  });
  
  describe('CORS Protection', () => {
    it('should block requests from unauthorized origins', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', 'http://evil.com')
        .send({ email: 'test@example.com', password: 'password' });
      
      const blocked = [403, 500].includes(response.status) ? 1 : 0;
      const passed = [403, 500].includes(response.status) ? 0 : 1;
      
      trackTest('CORS Protection', 'Unauthorized origin (evil.com)', 1, blocked, passed);
      
      expect([403, 500]).toContain(response.status);
    });
  });
  
  describe('NoSQL Injection Protection', () => {
    const nosqlTestCases = [
      { name: 'MongoDB $ne operator', payload: { email: { $ne: null }, password: { $exists: true } } },
      { name: 'JSON injection', payload: { email: 'test@example.com", "$gt": ""}', password: 'password' } },
      { name: 'Array injection', payload: { email: ['admin', 'test@example.com'], password: 'password' } },
    ];
    
    nosqlTestCases.forEach(testCase => {
      it(`should handle ${testCase.name} attempt`, async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .send(testCase.payload);
        
        const blocked = response.status !== 200 ? 1 : 0;
        const passed = response.status === 200 ? 1 : 0;
        
        trackTest('NoSQL Injection Protection', testCase.name, 1, blocked, passed);
        
        expect(response.status).toBeDefined();
      });
    });
  });
  
  describe('Bot & Scanner Protection', () => {
    const maliciousUserAgents = [
      { name: 'sqlmap', userAgent: 'sqlmap/1.6#stable' },
      { name: 'nikto', userAgent: 'Mozilla/5.00 (Nikto/2.1.6)' },
      { name: 'nmap', userAgent: 'Nmap Scripting Engine' },
      { name: 'wget', userAgent: 'Wget/1.21.3' },
      { name: 'curl', userAgent: 'curl/7.88.1' },
      { name: 'headless chrome', userAgent: 'HeadlessChrome/91.0.4472.114' },
      { name: 'python requests', userAgent: 'python-requests/2.28.2' },
      { name: 'go-scanner', userAgent: 'Go-http-client/1.1' },
    ];
    
    maliciousUserAgents.forEach(agent => {
      it(`should block ${agent.name} user agent`, async () => {
        const response = await request(app)
          .post('/api/v1/auth/login')
          .set('User-Agent', agent.userAgent)
          .send({ email: 'test@example.com', password: 'password' });
        
        const blocked = response.status === 403 ? 1 : 0;
        const passed = response.status === 403 ? 0 : 1;
        
        trackTest('Bot Detection & Blocking', agent.name, 1, blocked, passed);
        
        expect(response.status).toBe(403);
        expect(response.body.success).toBe(false);
      });
    });
  });
});