/**
 * ASTRA Shield Server - Advanced Bot Detection & Verification
 *
 * Features超越 Cloudflare Turnstile + reCAPTCHA v3:
 * 1. Multi-layered fingerprinting (canvas, WebGL, audio, font, TLS)
 * 2. ML-powered behavioral analysis
 * 3. Proof-of-work challenges
 * 4. Global threat intelligence
 * 5. Continuous verification
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';

import { createAPIRoutes } from './routes/api.js';
import { BotDetectionService } from './services/BotDetectionService.js';
import { FingerprintService } from './services/FingerprintService.js';
import { MLAnalysisService } from './services/MLAnalysisService.js';
import { ThreatIntelligenceService } from './services/ThreatIntelligenceService.js';
import { SessionService } from './services/SessionService.js';
import { ChallengeService } from './services/ChallengeService.js';

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '1mb' }));

// Initialize services
const services = {
  botDetection: new BotDetectionService(),
  fingerprint: new FingerprintService(),
  mlAnalysis: new MLAnalysisService(),
  threatIntel: new ThreatIntelligenceService(),
  session: new SessionService({
    redis: null // Will use in-memory storage if Redis not available
  }),
  challenge: new ChallengeService({
    sessionService: null // Will be set after initialization
  })
};

// Set session service reference for challenge service
services.challenge.sessionService = services.session;

// Simple rate limiting (in production, use Redis-based rate limiter)
const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 100;

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimits.get(ip);

  if (!record) {
    rateLimits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + RATE_LIMIT_WINDOW;
    return true;
  }

  if (record.count >= RATE_LIMIT_MAX) {
    return false;
  }

  record.count++;
  return true;
}

// Routes
const apiRoutes = createAPIRoutes(services);
app.use('/api', (req, res, next) => {
  if (!checkRateLimit(req.ip)) {
    return res.status(429).json({
      success: false,
      reason: 'rate_limit_exceeded',
      retryAfter: 60
    });
  }
  next();
});
app.use('/api', apiRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '1.0.0',
    uptime: process.uptime(),
    services: Object.keys(services)
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🛡️  ASTRA Shield Server - Advanced Edition            ║
║                                                          ║
║   Bot Detection Features超越Cloudflare+reCAPTCHA:         ║
║   • Multi-layer fingerprinting                           ║
║   • ML-powered behavioral analysis                       ║
║   • Proof-of-work challenges                             ║
║   • Global threat intelligence                           ║
║   • Continuous verification                              ║
║                                                          ║
║   Running on: http://localhost:${PORT}                    ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
  `);
});

export { app, services };
