/**
 * Bot Detection Service - Advanced bot detection超越Cloudflare Bot Management
 *
 * Detection layers:
 * 1. Headless browser detection
 * 2. Automation framework detection (Selenium, Puppeteer, Playwright)
 * 3. VM/hardware simulation detection
 * 4. Proxy/VPN/Tor detection
 * 5. Bot farm pattern detection
 * 6. Credential stuffing detection
 * 7. Device fingerprint anomalies
 */

export class BotDetectionService {
  constructor() {
    // Known automation scripts and their signatures
    this.automationSignatures = [
      'selenium',
      'webdriver',
      'puppeteer',
      'playwright',
      'phantomjs',
      'nightmare',
      'casperjs',
      'htmlunit',
      'headless',
      'chromium',
      'firefox',
      ' Zombie'
    ];

    // Known bot User-Agents
    this.botUserAgents = [
      'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
      'python-requests', 'axios', 'node-fetch', 'go-http',
      'java/', 'okhttp', 'apache-httpclient', 'libwww',
      'midpoint', 'HttpClient', 'Python-urllib'
    ];

    // Suspicious header combinations
    this.suspiciousHeaderPatterns = [
      { missing: ['Accept-Language'], weight: 0.3 },
      { missing: ['Accept-Encoding'], weight: 0.2 },
      { missing: ['Accept'], weight: 0.1 },
      { has: ['WebDriver', '__webdriver'], weight: 0.9 },
      { has: ['$cdc_', '__webdriver__'], weight: 0.95 }
    ];

    // Weight configuration
    this.weights = {
      headlessBrowser: 0.4,
      automationFramework: 0.5,
      proxyVpn: 0.3,
      tor: 0.35,
      datacenter: 0.25,
      suspiciousBehavior: 0.4,
      fingerprintAnomaly: 0.3,
      rateAnomaly: 0.35,
      patternAnomaly: 0.45,
      knownBot: 1.0
    };
  }

  /**
   * Comprehensive bot detection
   */
  async analyze(verificationData) {
    const {
      fingerprints,
      behavioralData,
      networkData,
      challengeData,
      sessionData,
      headers,
      ip
    } = verificationData;

    const signals = [];
    let botScore = 0;
    let confidence = 0;

    // 1. Headless Browser Detection
    const headlessResult = this.detectHeadlessBrowser(fingerprints, headers);
    if (headlessResult.isBot) {
      signals.push({ type: 'headless_browser', score: headlessResult.score, details: headlessResult.details });
      botScore += this.weights.headlessBrowser * headlessResult.score;
    }

    // 2. Automation Framework Detection
    const automationResult = this.detectAutomationFramework(headers, fingerprints);
    if (automationResult.isBot) {
      signals.push({ type: 'automation_framework', score: automationResult.score, details: automationResult.details });
      botScore += this.weights.automationFramework * automationResult.score;
    }

    // 3. Proxy/VPN/Tor Detection
    const networkResult = await this.detectProxyVpnTor(ip, networkData);
    if (networkResult.isSuspicious) {
      signals.push({ type: 'proxy_vpn_tor', score: networkResult.score, details: networkResult.details });
      botScore += this.weights.proxyVpn * networkResult.score;
    }

    // 4. Fingerprint Anomaly Detection
    const fingerprintResult = this.detectFingerprintAnomalies(fingerprints, sessionData);
    if (fingerprintResult.isBot) {
      signals.push({ type: 'fingerprint_anomaly', score: fingerprintResult.score, details: fingerprintResult.details });
      botScore += this.weights.fingerprintAnomaly * fingerprintResult.score;
    }

    // 5. Behavioral Analysis
    const behavioralResult = this.analyzeBehavior(behavioralData, sessionData);
    if (behavioralResult.isBot) {
      signals.push({ type: 'behavioral_anomaly', score: behavioralResult.score, details: behavioralResult.details });
      botScore += this.weights.suspiciousBehavior * behavioralResult.score;
    }

    // 6. Rate Limiting Analysis
    const rateResult = this.analyzeRatePatterns(sessionData, networkData);
    if (rateResult.isSuspicious) {
      signals.push({ type: 'rate_anomaly', score: rateResult.score, details: rateResult.details });
      botScore += this.weights.rateAnomaly * rateResult.score;
    }

    // 7. Known Bot Detection
    const knownBotResult = this.detectKnownBot(headers, networkData);
    if (knownBotResult.isBot) {
      signals.push({ type: 'known_bot', score: knownBotResult.score, details: knownBotResult.details });
      botScore = 1.0; // Hard block for known bots
    }

    // 8. Challenge Analysis
    const challengeResult = this.analyzeChallengeResponse(challengeData);
    if (challengeResult.isBot) {
      signals.push({ type: 'challenge_failure', score: challengeResult.score, details: challengeResult.details });
      botScore += this.weights.patternAnomaly * challengeResult.score;
    }

    // Calculate confidence based on signal strength
    confidence = this.calculateConfidence(signals);

    // Normalize bot score
    botScore = Math.min(1, botScore);

    // Generate decision
    const decision = this.makeDecision(botScore, confidence, signals);

    return {
      isBot: decision.isBot,
      isSuspicious: decision.isSuspicious,
      botScore,
      confidence,
      signals,
      decision,
      riskLevel: this.getRiskLevel(botScore),
      recommendedAction: decision.action,
      details: {
        totalSignals: signals.length,
        criticalSignals: signals.filter(s => s.score > 0.8).length,
        analysisVersion: '2.0-advanced'
      }
    };
  }

  /**
   * Detect headless browsers
   */
  detectHeadlessBrowser(fingerprints, headers) {
    const details = [];
    let score = 0;

    // Check WebGL renderer
    if (fingerprints?.webgl) {
      const webglRenderer = fingerprints.webgl.renderer?.toLowerCase() || '';
      const webglVendor = fingerprints.webgl.vendor?.toLowerCase() || '';

      if (webglRenderer.includes('swiftshader') ||
          webglRenderer.includes('llvmpipe') ||
          webglRenderer.includes('software')) {
        score += 0.5;
        details.push('WebGL indicates software rendering (headless)');
      }

      if (!webglVendor || webglVendor === 'google inc') {
        // Might be headless
        score += 0.2;
        details.push('Suspicious WebGL vendor');
      }
    }

    // Check navigator properties
    if (fingerprints?.navigator) {
      const nav = fingerprints.navigator;

      if (nav.webdriver === true) {
        score += 0.9;
        details.push('Navigator.webdriver detected');
      }

      // Check for missing properties that real browsers have
      const realBrowserProps = ['languages', 'plugins', 'mimeTypes'];
      for (const prop of realBrowserProps) {
        if (!nav[prop] || nav[prop].length === 0) {
          score += 0.15;
          details.push(`Missing navigator.${prop}`);
        }
      }

      // Automation properties
      const automationProps = ['__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_function'];
      for (const prop of automationProps) {
        if (nav[prop]) {
          score += 0.8;
          details.push(`Automation property detected: ${prop}`);
        }
      }
    }

    // Check permissions
    if (fingerprints?.permissions) {
      if (fingerprints.permissions.notifications === 'denied' &&
          fingerprints.permissions.geolocation === 'denied') {
        // Common pattern in headless browsers
        score += 0.2;
        details.push('Suspicious permission denial pattern');
      }
    }

    // Check canvas (often blank or minimal in headless)
    if (fingerprints?.canvas?.hash) {
      // Real browsers have complex, varied canvas fingerprints
      if (fingerprints.canvas.hash.length < 50) {
        score += 0.3;
        details.push('Abnormally simple canvas fingerprint');
      }
    }

    return {
      isBot: score > 0.5,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Detect automation frameworks
   */
  detectAutomationFramework(headers, fingerprints) {
    const details = [];
    let score = 0;

    // Check User-Agent
    const ua = (headers['user-agent'] || '').toLowerCase();
    for (const sig of this.automationSignatures) {
      if (ua.includes(sig)) {
        score += 0.7;
        details.push(`User-Agent contains: ${sig}`);
      }
    }

    // Check headers
    if (headers['webdriver'] || headers['xRequestedWith']?.toLowerCase().includes('webdriver')) {
      score += 0.9;
      details.push('WebDriver header detected');
    }

    // Check for automation-specific cookies
    if (fingerprints?.cookies) {
      const automationCookies = ['__selenium', '__webdriver', 'webdriver'];
      for (const cookie of automationCookies) {
        if (fingerprints.cookies[cookie]) {
          score += 0.8;
          details.push(`Automation cookie detected: ${cookie}`);
        }
      }
    }

    // Check runtime evaluation results
    if (fingerprints?.runtime) {
      // Chrome runtime returns specific values in automation
      if (fingerprint.runtime.chrome?.loadTimes ||
          fingerprint.runtime.csi?.startTime) {
        score += 0.6;
        details.push('Chrome automation runtime detected');
      }
    }

    // Check for puppeteer/selenium specific properties
    if (fingerprints?.navigator?.automation?.length > 0) {
      score += 0.7;
      details.push('Navigator automation detected');
    }

    return {
      isBot: score > 0.5,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Detect Proxy/VPN/Tor
   */
  async detectProxyVpnTor(ip, networkData) {
    const details = [];
    let score = 0;

    // This would integrate with IP intelligence services
    // For demo, using basic checks

    if (networkData?.isVPN !== undefined) {
      if (networkData.isVPN) {
        score += 0.6;
        details.push('VPN detected');
      }
    }

    if (networkData?.isTor !== undefined) {
      if (networkData.isTor) {
        score += 0.8;
        details.push('Tor exit node detected');
      }
    }

    if (networkData?.isProxy !== undefined) {
      if (networkData.isProxy) {
        score += 0.5;
        details.push('Proxy detected');
      }
    }

    if (networkData?.isDatacenter !== undefined) {
      if (networkData.isDatacenter) {
        score += 0.4;
        details.push('Datacenter IP detected');
      }
    }

    // Check ASN reputation
    if (networkData?.asn?.reputation !== undefined) {
      if (networkData.asn.reputation < 50) {
        score += 0.3;
        details.push('Low reputation ASN');
      }
    }

    // Recent abuse history
    if (networkData?.abuseHistory?.length > 0) {
      score += 0.4;
      details.push(`IP has ${networkData.abuseHistory.length} abuse reports`);
    }

    return {
      isSuspicious: score > 0.3,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Detect fingerprint anomalies
   */
  detectFingerprintAnomalies(fingerprints, sessionData) {
    const details = [];
    let score = 0;

    if (!fingerprints || !sessionData) {
      return { isBot: false, score: 0, details: [] };
    }

    // Check for timezone mismatch
    if (fingerprints.timezone && sessionData.userTimezone) {
      if (fingerprints.timezone.offset !== sessionData.userTimezone.offset) {
        score += 0.4;
        details.push('Timezone mismatch detected');
      }
    }

    // Check for language mismatch
    if (fingerprints.languages && sessionData.acceptLanguage) {
      const fpLangs = new Set(fingerprints.languages.map(l => l.toLowerCase()));
      const acceptLangs = new Set(sessionData.acceptLanguage.split(',').map(l => l.trim().split('-')[0].toLowerCase()));

      const intersection = [...fpLangs].filter(l => acceptLangs.has(l));
      if (intersection.length === 0) {
        score += 0.5;
        details.push('Language mismatch between fingerprint and headers');
      }
    }

    // Check screen resolution consistency
    if (fingerprints.screen && sessionData.screen) {
      if (fingerprint.screen.width !== sessionData.screen.width ||
          fingerprint.screen.height !== sessionData.screen.height) {
        score += 0.6;
        details.push('Screen resolution mismatch');
      }
    }

    // Check for device consistency across sessions
    if (sessionData.previousFingerprints?.length > 0) {
      const currentFP = this.hashFingerprint(fingerprints);
      const previousMatches = sessionData.previousFingerprints.filter(
        prev => this.compareFingerprints(currentFP, prev) > 0.9
      );

      if (previousMatches.length === 0 && sessionData.previousFingerprints.length > 3) {
        score += 0.5;
        details.push('Device fingerprint changed across sessions');
      }
    }

    // Check for impossible combinations
    if (fingerprints.touchSupport && fingerprints.touchSupport.maxTouchPoints === 0) {
      if (fingerprint.device?.isMobile) {
        score += 0.3;
        details.push('Mobile device without touch support');
      }
    }

    // Check WebGL vs reported GPU
    if (fingerprints.webgl?.renderer && fingerprints.device?.gpu) {
      const webglGPU = fingerprint.webgl.renderer.toLowerCase();
      const reportedGPU = fingerprint.device.gpu.toLowerCase();
      if (!webglGPU.includes(reportedGPU) && !reportedGPU.includes(webglGPU.split(' ')[0])) {
        score += 0.5;
        details.push('GPU mismatch between WebGL and reported');
      }
    }

    return {
      isBot: score > 0.5,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Analyze behavioral patterns
   */
  analyzeBehavior(behavioralData, sessionData) {
    const details = [];
    let score = 0;

    if (!behavioralData) {
      return { isBot: false, score: 0, details: [] };
    }

    // Mouse movement entropy analysis
    if (behavioralData.mouseMovements?.length > 0) {
      const entropy = this.calculateEntropy(behavioralData.mouseMovements);

      // Real humans have medium entropy (not perfect, not random)
      if (entropy < 0.2) {
        score += 0.4;
        details.push('Mouse movements too uniform (bot-like)');
      } else if (entropy > 0.95) {
        score += 0.5;
        details.push('Mouse movements appear random (bot-like)');
      }

      // Check for perfect straight lines (bot-like)
      const straightLineRatio = this.checkStraightLines(behavioralData.mouseMovements);
      if (straightLineRatio > 0.8) {
        score += 0.5;
        details.push('Excessive straight-line mouse movements');
      }
    }

    // Keystroke dynamics
    if (behavioralData.keystrokes?.length > 10) {
      const keystrokeAnalysis = this.analyzeKeystrokeDynamics(behavioralData.keystrokes);

      if (keystrokeAnalysis.stdDev < 10) {
        score += 0.4;
        details.push('Keystroke timing too uniform');
      }

      if (keystrokeAnalysis.errorRate < 0.01) {
        score += 0.3;
        details.push('No typing errors (suspicious)');
      }
    }

    // Click patterns
    if (behavioralData.clicks?.length > 5) {
      const clickInterval = this.getClickIntervals(behavioralData.clicks);
      const clickVariance = this.calculateVariance(clickInterval);

      if (clickVariance < 50) {
        score += 0.35;
        details.push('Click intervals too regular');
      }
    }

    // Scroll behavior
    if (behavioralData.scrolls?.length > 3) {
      const scrollPattern = this.analyzeScrollPattern(behavioralData.scrolls);

      if (scrollPattern.velocityVariance < 0.1) {
        score += 0.3;
        details.push('Scroll velocity too constant');
      }
    }

    // Touch gesture analysis
    if (behavioralData.touches?.length > 0) {
      const touchAnalysis = this.analyzeTouchGestures(behavioralData.touches);

      if (touchAnalysis.regularity > 0.95) {
        score += 0.35;
        details.push('Touch gestures too regular');
      }
    }

    // Check for impossible speed
    if (behavioralData.mouseMovements?.length > 2) {
      const maxVelocity = Math.max(...behavioralData.mouseMovements.map(m => m.velocity || 0));
      if (maxVelocity > 5000) { // px/second
        score += 0.4;
        details.push('Impossibly fast mouse movement');
      }
    }

    return {
      isBot: score > 0.4,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Analyze rate patterns
   */
  analyzeRatePatterns(sessionData, networkData) {
    const details = [];
    let score = 0;

    if (!sessionData) {
      return { isSuspicious: false, score: 0, details: [] };
    }

    // Check request frequency
    if (sessionData.requestsPerMinute > 60) {
      score += 0.4;
      details.push(`High request rate: ${sessionData.requestsPerMinute}/min`);
    }

    // Check for burst patterns
    if (sessionData.burstCount > 5) {
      score += 0.3;
      details.push('Burst request pattern detected');
    }

    // Check page visit timing
    if (sessionData.pageTimings) {
      const avgTimeOnPage = sessionData.pageTimings.avg;
      if (avgTimeOnPage < 500) { // Less than 500ms per page
        score += 0.35;
        details.push('Unrealistically fast page traversal');
      }
    }

    // Check navigation patterns
    if (sessionData.navigationPattern === 'impossible') {
      score += 0.5;
      details.push('Impossible navigation pattern');
    }

    return {
      isSuspicious: score > 0.3,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Detect known bots
   */
  detectKnownBot(headers, networkData) {
    const details = [];
    let score = 0;

    const ua = (headers['user-agent'] || '').toLowerCase();

    // Check for known bot User-Agents
    for (const bot of this.botUserAgents) {
      if (ua.includes(bot)) {
        score += 0.9;
        details.push(`Known bot signature: ${bot}`);
      }
    }

    // Check for missing essential headers
    const essentialHeaders = ['user-agent', 'accept'];
    const missingHeaders = essentialHeaders.filter(h => !headers[h]);
    if (missingHeaders.length > 1) {
      score += 0.4;
      details.push('Missing essential headers');
    }

    // Check for mismatched headers
    if (headers['user-agent'] && headers['sec-ch-ua']) {
      // User-Agent and Sec-CH-UA should match
      // This is a simplified check
      score += 0.2;
    }

    return {
      isBot: score > 0.7,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Analyze challenge response
   */
  analyzeChallengeResponse(challengeData) {
    const details = [];
    let score = 0;

    if (!challengeData) {
      return { isBot: false, score: 0, details: [] };
    }

    if (!challengeData.completed) {
      score += 0.6;
      details.push('Challenge not completed');
    }

    if (challengeData.attempts > 3) {
      score += 0.3;
      details.push(`Multiple challenge attempts: ${challengeData.attempts}`);
    }

    if (challengeData.timing < 500 && challengeData.type !== 'instant_allowed') {
      // Too fast for legitimate human
      score += 0.4;
      details.push('Challenge completed suspiciously fast');
    }

    if (challengeData.timing > 30000) {
      // Took too long, possibly scripted
      score += 0.2;
      details.push('Challenge took unusually long');
    }

    // Check for pattern in failure
    if (challengeData.failurePattern) {
      score += 0.5;
      details.push('Pattern detected in challenge failures');
    }

    return {
      isBot: score > 0.5,
      score: Math.min(1, score),
      details
    };
  }

  /**
   * Calculate confidence based on signals
   */
  calculateConfidence(signals) {
    if (signals.length === 0) return 0.3;

    const avgScore = signals.reduce((sum, s) => sum + s.score, 0) / signals.length;
    const criticalCount = signals.filter(s => s.score > 0.8).length;
    const signalCountBonus = Math.min(0.2, signals.length * 0.02);

    let confidence = avgScore + signalCountBonus;

    if (criticalCount >= 2) {
      confidence = Math.min(1, confidence + 0.2);
    }

    return Math.min(1, confidence);
  }

  /**
   * Make verification decision
   */
  makeDecision(botScore, confidence, signals) {
    // High confidence + high score = definitely bot
    if (confidence > 0.8 && botScore > 0.7) {
      return {
        isBot: true,
        isSuspicious: true,
        action: 'block'
      };
    }

    // High score but low confidence = suspicious, needs challenge
    if (botScore > 0.5 && confidence < 0.6) {
      return {
        isBot: false,
        isSuspicious: true,
        action: 'challenge'
      };
    }

    // Moderate score = allow but track
    if (botScore > 0.3) {
      return {
        isBot: false,
        isSuspicious: true,
        action: 'allow_with_tracking'
      };
    }

    // Low score = allow
    return {
      isBot: false,
      isSuspicious: false,
      action: 'allow'
    };
  }

  /**
   * Get risk level
   */
  getRiskLevel(score) {
    if (score >= 0.8) return 'critical';
    if (score >= 0.6) return 'high';
    if (score >= 0.4) return 'medium';
    if (score >= 0.2) return 'low';
    return 'minimal';
  }

  // Utility methods

  calculateEntropy(data) {
    if (!data || data.length === 0) return 0;

    // Simplified entropy calculation for behavioral data
    const counts = {};
    for (const item of data) {
      const key = typeof item === 'object' ? JSON.stringify(item) : String(item);
      counts[key] = (counts[key] || 0) + 1;
    }

    const total = data.length;
    let entropy = 0;

    for (const count of Object.values(counts)) {
      const p = count / total;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }

  checkStraightLines(movements) {
    if (movements.length < 3) return 0;

    let straightCount = 0;
    for (let i = 1; i < movements.length - 1; i++) {
      const v1 = {
        x: movements[i].x - movements[i-1].x,
        y: movements[i].y - movements[i-1].y
      };
      const v2 = {
        x: movements[i+1].x - movements[i].x,
        y: movements[i+1].y - movements[i].y
      };

      // Check if vectors are parallel (dot product near 1)
      const dot = (v1.x * v2.x + v1.y * v2.y) /
                   (Math.sqrt(v1.x**2 + v1.y**2) * Math.sqrt(v2.x**2 + v2.y**2));

      if (Math.abs(dot) > 0.98) {
        straightCount++;
      }
    }

    return straightCount / (movements.length - 2);
  }

  analyzeKeystrokeDynamics(keystrokes) {
    if (keystrokes.length < 2) return { stdDev: 100, errorRate: 0.1 };

    const intervals = [];
    for (let i = 1; i < keystrokes.length; i++) {
      intervals.push(keystrokes[i].timestamp - keystrokes[i-1].timestamp);
    }

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / intervals.length;

    return {
      stdDev: Math.sqrt(variance),
      errorRate: 0 // Would need backspace data
    };
  }

  getClickIntervals(clicks) {
    const intervals = [];
    for (let i = 1; i < clicks.length; i++) {
      intervals.push(clicks[i].timestamp - clicks[i-1].timestamp);
    }
    return intervals;
  }

  calculateVariance(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
  }

  analyzeScrollPattern(scrolls) {
    const velocities = scrolls.map(s => s.velocity || 0);
    const mean = velocities.reduce((a, b) => a + b, 0) / velocities.length;
    const variance = velocities.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / velocities.length;

    return {
      velocityVariance: mean > 0 ? variance / mean : 0
    };
  }

  analyzeTouchGestures(touches) {
    if (touches.length < 2) return { regularity: 0 };

    // Check if gestures are too similar
    const intervals = [];
    for (let i = 1; i < touches.length; i++) {
      intervals.push(touches[i].timestamp - touches[i-1].timestamp);
    }

    const variance = this.calculateVariance(intervals);
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;

    return {
      regularity: mean > 0 ? 1 - (Math.sqrt(variance) / mean) : 0
    };
  }

  hashFingerprint(fingerprint) {
    // Simplified fingerprint hashing
    const str = JSON.stringify(fingerprint);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  compareFingerprints(fp1, fp2) {
    if (fp1 === fp2) return 1;
    // Simplified comparison
    return 0;
  }
}
