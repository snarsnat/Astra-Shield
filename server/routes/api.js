/**
 * API Routes - Main verification and analysis endpoints
 */

import express from 'express';
import crypto from 'crypto';

export function createAPIRoutes(services = {}) {
  const router = express.Router();

  const {
    botDetection,
    fingerprint,
    mlAnalysis,
    threatIntel,
    session,
    challenge
  } = services;

  /**
   * POST /api/verify
   * Main verification endpoint
   */
  router.post('/verify', async (req, res) => {
    try {
      const {
        sessionId,
        token,
        clientData,
        challengeToken,
        challengeSolution,
      } = req.body;

      // Validate token or session
      let sessionData;
      if (token) {
        const tokenResult = await session.validateToken(token);
        if (!tokenResult) {
          return res.status(401).json({
            success: false,
            reason: 'invalid_token',
          });
        }
        sessionData = tokenResult.session;
      } else if (sessionId) {
        sessionData = await session.getSession(sessionId);
        if (!sessionData) {
          return res.status(401).json({
            success: false,
            reason: 'invalid_session',
          });
        }
      } else {
        return res.status(400).json({
          success: false,
          reason: 'missing_credentials',
        });
      }

      // Initialize result
      const result = {
        success: false,
        tier: 0,
        reason: 'pending',
        riskScore: 0,
        details: {},
      };

      // If there's a challenge solution, verify it first
      if (challengeToken && challengeSolution) {
        const challengeResult = await challenge.verifyChallenge(
          challengeToken,
          challengeSolution,
          { sessionId: sessionData.id }
        );

        if (!challengeResult.success) {
          return res.json({
            ...result,
            success: false,
            reason: challengeResult.reason,
            attemptsRemaining: challengeResult.attemptsRemaining,
          });
        }

        result.details.challenge = {
          verified: true,
          verificationLevel: challengeResult.verificationLevel,
        };
      }

      // Analyze client data
      if (clientData) {
        // 1. Bot Detection Analysis
        const botAnalysis = await botDetection.analyze(clientData);
        result.details.botDetection = botAnalysis;

        // 2. Fingerprint Analysis
        const fingerprintAnalysis = await fingerprint.analyze(
          clientData.fingerprints || {},
          clientData.serverObservations || {}
        );
        result.details.fingerprint = fingerprintAnalysis;

        // 3. Threat Intelligence
        const clientIP = req.ip || clientData.ip;
        const threatIntelResult = await threatIntel.getThreatIntelligence(
          clientIP,
          {
            userAgent: req.get('user-agent'),
            timezone: clientData.timezone,
            languages: clientData.languages,
          }
        );
        result.details.threatIntel = threatIntelResult;

        // 4. ML Analysis
        const mlResult = await mlAnalysis.analyze(
          clientData.behavior || {},
          clientData.serverObservations || {}
        );
        result.details.mlAnalysis = mlResult;

        // Calculate composite risk score
        const compositeScore = calculateCompositeScore({
          botScore: botAnalysis.riskScore,
          fingerprintScore: fingerprintAnalysis.riskScore,
          threatScore: threatIntelResult.reputation.score / 100,
          mlScore: mlResult.riskScore,
        });

        result.riskScore = compositeScore;

        // Determine tier based on risk score
        result.tier = determineTier(compositeScore);

        // Update session risk
        await session.updateRiskScore(sessionData.id, { score: compositeScore });

        // Generate recommendations
        const recommendations = generateRecommendations({
          botAnalysis,
          fingerprintAnalysis,
          threatIntel: threatIntelResult,
          mlAnalysis: mlResult,
          compositeScore,
        });

        // Take action based on recommendations
        if (recommendations.action === 'block') {
          result.success = false;
          result.reason = 'blocked';
          result.blockReason = recommendations.reason;
        } else if (recommendations.action === 'challenge') {
          // Need additional verification
          const challengeData = await challenge.selectOptimalChallenge(
            compositeScore,
            clientData.deviceInfo || {},
            { sessionId: sessionData.id }
          );
          result.success = false;
          result.reason = 'challenge_required';
          result.challenge = challengeData;
        } else {
          result.success = true;
          result.reason = 'verified';
        }
      }

      // Store verification result
      const verification = await session.storeVerification(sessionData.id, result);

      // Log action
      await session.addSessionAction(sessionData.id, {
        type: 'verification',
        result: result.success ? 'success' : 'failed',
        riskScore: result.riskScore,
        tier: result.tier,
      });

      res.json({
        ...result,
        verificationId: verification.id,
        sessionId: sessionData.id,
      });
    } catch (error) {
      console.error('Verification error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  });

  /**
   * POST /api/analyze
   * Behavioral analysis endpoint
   */
  router.post('/analyze', async (req, res) => {
    try {
      const { clientData, includeThreatIntel } = req.body;

      if (!clientData) {
        return res.status(400).json({
          success: false,
          reason: 'missing_data',
        });
      }

      const analysis = {
        timestamp: Date.now(),
      };

      // Bot Detection
      analysis.botDetection = await botDetection.analyze(clientData);

      // ML Analysis
      analysis.ml = await mlAnalysis.analyze(
        clientData.behavior || {},
        clientData.serverObservations || {}
      );

      // Fingerprint Analysis
      if (clientData.fingerprints) {
        analysis.fingerprint = await fingerprint.analyze(
          clientData.fingerprints,
          clientData.serverObservations || {}
        );
      }

      // Threat Intelligence (optional)
      if (includeThreatIntel) {
        const clientIP = req.ip || clientData.ip;
        analysis.threatIntel = await threatIntel.getThreatIntelligence(clientIP, {
          userAgent: req.get('user-agent'),
          timezone: clientData.timezone,
          languages: clientData.languages,
        });
      }

      // Calculate overall score
      analysis.overallRisk = calculateCompositeScore({
        botScore: analysis.botDetection.riskScore,
        fingerprintScore: analysis.fingerprint?.riskScore || 0,
        threatScore: analysis.threatIntel?.reputation.score / 100 || 0,
        mlScore: analysis.ml.riskScore,
      });

      res.json({
        success: true,
        analysis,
      });
    } catch (error) {
      console.error('Analysis error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * POST /api/challenge
   * Challenge generation endpoint
   */
  router.post('/challenge', async (req, res) => {
    try {
      const { type, difficulty, sessionId, deviceInfo } = req.body;

      // Validate session
      if (sessionId) {
        const sessionData = await session.getSession(sessionId);
        if (!sessionData) {
          return res.status(401).json({
            success: false,
            reason: 'invalid_session',
          });
        }
      }

      // Generate challenge
      const challengeData = await challenge.generateChallenge(type || 'breath', {
        difficulty: difficulty || 'medium',
        sessionId,
        deviceInfo,
        userAgent: req.get('user-agent'),
        ip: req.ip,
      });

      res.json({
        success: true,
        challenge: challengeData,
      });
    } catch (error) {
      console.error('Challenge generation error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * POST /api/challenge/verify
   * Challenge verification endpoint
   */
  router.post('/challenge/verify', async (req, res) => {
    try {
      const { challengeId, solution, sessionId } = req.body;

      if (!challengeId || !solution) {
        return res.status(400).json({
          success: false,
          reason: 'missing_parameters',
        });
      }

      const result = await challenge.verifyChallenge(challengeId, solution, {
        sessionId,
        ip: req.ip,
      });

      res.json(result);
    } catch (error) {
      console.error('Challenge verification error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * POST /api/threat-intel
   * Threat intelligence lookup
   */
  router.post('/threat-intel', async (req, res) => {
    try {
      const { ip } = req.body;

      if (!ip) {
        return res.status(400).json({
          success: false,
          reason: 'missing_ip',
        });
      }

      const intel = await threatIntel.getThreatIntelligence(ip, {
        userAgent: req.get('user-agent'),
        timezone: req.body.timezone,
        languages: req.body.languages,
      });

      res.json({
        success: true,
        intel,
      });
    } catch (error) {
      console.error('Threat intel error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * POST /api/session/create
   * Create new session
   */
  router.post('/session/create', async (req, res) => {
    try {
      const clientData = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        country: req.body.country,
        deviceType: req.body.deviceType,
        browser: req.body.browser,
        os: req.body.os,
      };

      const sessionResult = await session.createSession(clientData);

      // Create initial token
      const tokenResult = await session.createToken(sessionResult.sessionId, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        sessionId: sessionResult.sessionId,
        token: tokenResult.accessToken,
        refreshToken: tokenResult.refreshToken,
        expires: sessionResult.expires,
      });
    } catch (error) {
      console.error('Session creation error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * POST /api/session/refresh
   * Refresh access token
   */
  router.post('/session/refresh', async (req, res) => {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          reason: 'missing_refresh_token',
        });
      }

      const result = await session.refreshTokens(refreshToken);

      if (!result) {
        return res.status(401).json({
          success: false,
          reason: 'invalid_or_expired_refresh_token',
        });
      }

      res.json({
        success: true,
        token: result.accessToken,
        refreshToken: result.refreshToken,
        expires: result.expires,
      });
    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * POST /api/session/report-threat
   * Report threat activity
   */
  router.post('/session/report-threat', async (req, res) => {
    try {
      const { ip, threatType, details } = req.body;

      if (!ip || !threatType) {
        return res.status(400).json({
          success: false,
          reason: 'missing_parameters',
        });
      }

      await threatIntel.reportThreat(ip, {
        type: threatType,
        ...details,
      });

      res.json({
        success: true,
      });
    } catch (error) {
      console.error('Threat report error:', error);
      res.status(500).json({
        success: false,
        reason: 'server_error',
      });
    }
  });

  /**
   * GET /api/stats
   * Get service statistics
   */
  router.get('/stats', (req, res) => {
    res.json({
      success: true,
      stats: {
        sessions: session.getStats(),
        challenges: challenge.getStats(),
        threatIntel: threatIntel.getThreatStats(),
      },
      uptime: process.uptime(),
      timestamp: Date.now(),
    });
  });

  /**
   * GET /api/health
   * Health check endpoint
   */
  router.get('/health', (req, res) => {
    res.json({
      success: true,
      status: 'healthy',
      timestamp: Date.now(),
    });
  });

  return router;
}

/**
 * Calculate composite risk score
 */
function calculateCompositeScore({ botScore, fingerprintScore, threatScore, mlScore }) {
  const weights = {
    bot: 0.35,
    fingerprint: 0.25,
    threat: 0.20,
    ml: 0.20,
  };

  const score =
    botScore * weights.bot +
    fingerprintScore * weights.fingerprint +
    threatScore * weights.threat +
    mlScore * weights.ml;

  return Math.min(Math.max(score, 0), 1);
}

/**
 * Determine tier based on risk score
 */
function determineTier(riskScore) {
  if (riskScore < 0.15) return 0; // Ghost - no friction
  if (riskScore < 0.30) return 1; // Whisper - minimal friction
  if (riskScore < 0.50) return 2; // Nudge - light challenge
  if (riskScore < 0.70) return 3; // Pause - moderate challenge
  return 4; // Gate - full verification
}

/**
 * Generate recommendations based on analysis
 */
function generateRecommendations({ botAnalysis, fingerprintAnalysis, threatIntel, mlAnalysis, compositeScore }) {
  const reasons = [];

  // Check bot detection flags
  if (botAnalysis.riskScore > 0.6) {
    reasons.push('high_bot_score');
  }

  // Check fingerprint anomalies
  if (fingerprintAnalysis.anomalies?.length > 3) {
    reasons.push('multiple_fingerprint_anomalies');
  }

  // Check threat intel
  if (threatIntel.reputation.score > 60) {
    reasons.push('suspicious_ip_reputation');
  }

  // Check ML anomalies
  if (mlAnalysis.anomalies?.length > 5) {
    reasons.push('multiple_ml_anomalies');
  }

  // High composite score
  if (compositeScore > 0.7) {
    return {
      action: 'block',
      reason: reasons.join(', '),
    };
  }

  if (compositeScore > 0.4) {
    return {
      action: 'challenge',
      reason: reasons.join(', '),
    };
  }

  if (compositeScore > 0.2) {
    return {
      action: 'monitor',
      reason: 'low_risk_with_indicators',
    };
  }

  return {
    action: 'allow',
    reason: 'low_risk',
  };
}
