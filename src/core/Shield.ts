/**
 * ASTRAShield - Main Shield Class
 * The intelligent guardian that knows when to stay invisible.
 */

import {
  ASTRAShield as ISTRAShield,
  ASTRAShieldOptions,
  VerificationResult,
  TierLevel,
  EventType
} from '../types';

import { Session } from './Session';
import { Detector } from './Detector';
import { TierEngine } from '../tiers/TierEngine';
import { ChallengeManager } from '../challenges/ChallengeManager';
import { Mutator } from '../mutation/Mutator';
import { AccessibilityManager } from '../accessibility/AccessibilityManager';
import { HappinessTracker } from '../metrics/HappinessTracker';

export class ASTRAShield implements ISTRAShield {
  private options: Required<ASTRAShieldOptions>;

  // Core modules
  public readonly session: Session;
  public readonly detector: Detector;
  public readonly mutator: Mutator;
  public readonly accessibility: AccessibilityManager;
  public readonly happiness: HappinessTracker;
  public readonly tierEngine: TierEngine;
  public readonly challengeManager: ChallengeManager;

  // Event listeners
  private listeners: Map<EventType, Set<(data: unknown) => void>> = new Map();

  // State
  public readonly isInitialized: boolean = false;
  public isVerifying: boolean = false;
  private currentTier: TierLevel = 0;

  constructor(options: ASTRAShieldOptions = {}) {
    this.options = {
      apiKey: options.apiKey || null,
      endpoint: options.endpoint || '/api/verify',
      debug: options.debug || false,
      theme: options.theme || 'auto',
      storagePrefix: options.storagePrefix || 'astra_',
      sessionDuration: options.sessionDuration || 30 * 60 * 1000,
      mutationInterval: options.mutationInterval || 60 * 60 * 1000,
      onReady: options.onReady || (() => {}),
      onChallenge: options.onChallenge || (() => {}),
      onSuccess: options.onSuccess || (() => {}),
      onBlocked: options.onBlocked || (() => {}),
      onTierChange: options.onTierChange || (() => {}),
      onError: options.onError || (() => {})
    };

    // Initialize core modules
    this.session = new Session({
      storagePrefix: this.options.storagePrefix,
      sessionDuration: this.options.sessionDuration
    });

    this.detector = new Detector();
    this.mutator = new Mutator({
      mutationInterval: this.options.mutationInterval
    });
    this.accessibility = new AccessibilityManager();
    this.happiness = new HappinessTracker();
    this.tierEngine = new TierEngine();
    this.challengeManager = new ChallengeManager(this.options, this.mutator, this.accessibility);

    // Bind methods
    this.protect = this.protect.bind(this);
    this.verify = this.verify.bind(this);
    this.on = this.on.bind(this);
    this.off = this.off.bind(this);
    this.destroy = this.destroy.bind(this);

    // Auto-initialize
    this.init();
  }

  /**
   * Initialize the shield system
   */
  async init(): Promise<void> {
    try {
      // Initialize session
      await this.session.init();

      // Initialize detector with session data
      await this.detector.init(this.session);

      // Initialize mutation system
      await this.mutator.init();

      // Apply accessibility preferences
      await this.accessibility.init();

      // Check OOS score and apply appropriate tier
      await this.tierEngine.init(this.detector, this.session);

      // Inject styles
      this.injectStyles();

      // Start behavioral tracking
      this.startTracking();

      this.log('ASTRA Shield initialized successfully');
      this.options.onReady();

      // Emit ready event
      this.emit('ready', { timestamp: Date.now() });

    } catch (error) {
      this.log('Initialization error:', error);
      this.emit('error', { type: 'init', error });
      this.options.onError({ type: 'init', error: error as Error });
    }
  }

  /**
   * Start behavioral tracking
   */
  private startTracking(): void {
    document.addEventListener('mousemove', this.handleMouseMove.bind(this), { passive: true });
    document.addEventListener('click', this.handleClick.bind(this), { passive: true });
    document.addEventListener('keydown', this.handleKeydown.bind(this), { passive: true });
    document.addEventListener('scroll', this.handleScroll.bind(this), { passive: true });
    document.addEventListener('touchstart', this.handleTouch.bind(this), { passive: true });
    document.addEventListener('touchmove', this.handleTouchMove.bind(this), { passive: true });
  }

  private handleMouseMove(event: MouseEvent): void {
    if (!this.isInitialized) return;
    this.detector.recordMouseMove({
      x: event.clientX,
      y: event.clientY,
      timestamp: Date.now()
    });
  }

  private handleClick(event: MouseEvent): void {
    if (!this.isInitialized) return;
    this.detector.recordClick({
      target: (event.target as HTMLElement).tagName,
      x: event.clientX,
      y: event.clientY,
      timestamp: Date.now()
    });
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (!this.isInitialized) return;
    this.detector.recordKeystroke({
      key: event.key,
      timestamp: Date.now()
    });
  }

  private handleScroll(): void {
    if (!this.isInitialized) return;
    this.detector.recordScroll({
      scrollY: window.scrollY,
      timestamp: Date.now()
    });
  }

  private handleTouch(event: TouchEvent): void {
    if (!this.isInitialized) return;
    const touch = event.touches[0];
    if (touch) {
      this.detector.recordTouch({
        x: touch.clientX,
        y: touch.clientY,
        timestamp: Date.now()
      });
    }
  }

  private handleTouchMove(event: TouchEvent): void {
    if (!this.isInitialized) return;
    const touch = event.touches[0];
    if (touch) {
      this.detector.recordTouchMove({
        x: touch.clientX,
        y: touch.clientY,
        velocity: 0,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Protect a sensitive action
   */
  async protect(action: string, context: Record<string, unknown> = {}): Promise<VerificationResult> {
    const oosScore = await this.detector.getOOSScore();
    const tier = this.tierEngine.getTierForScore(oosScore);

    this.log(`Protecting action: ${action}, OOS: ${oosScore}, Tier: ${tier}`);

    if (tier !== this.currentTier) {
      this.currentTier = tier;
      this.emit('tierChange', { tier, oosScore });
      this.options.onTierChange({ tier, oosScore });
    }

    // If backend endpoint is configured, perform server-side verification
    if (this.options.endpoint && this.options.endpoint !== '/api/verify') {
      const backendResult = await this.performBackendVerification();

      if (backendResult.action === 'block') {
        this.emit('blocked', {
          reason: backendResult.blockReason || 'backend_blocked',
          attempts: 0
        });
        this.options.onBlocked({
          reason: backendResult.blockReason || 'backend_blocked',
          attempts: 0
        });

        return {
          success: false,
          tier: this.currentTier,
          blocked: true,
          reason: backendResult.blockReason || 'backend_blocked'
        };
      }

      if (backendResult.action === 'challenge' && backendResult.challenge) {
        // Backend requires additional challenge
        return await this.showBackendChallenge(backendResult.challenge);
      }
    }

    return await this.tierEngine.handleAction(tier, {
      action,
      context,
      shield: this,
      session: this.session,
      detector: this.detector
    });
  }

  /**
   * Perform backend verification
   */
  private async performBackendVerification(): Promise<{
    action: 'allow' | 'challenge' | 'block';
    challenge?: any;
    blockReason?: string;
  }> {
    try {
      const clientData = await this.detector.getClientData();

      const response = await fetch(this.options.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.options.apiKey || '',
          'X-Client-Version': '1.0.0'
        },
        body: JSON.stringify({
          clientData,
          action: 'protect',
          timestamp: Date.now()
        })
      });

      if (!response.ok) {
        this.log('Backend verification failed:', response.status);
        return { action: 'allow' }; // Fallback to local verification
      }

      const result = await response.json();

      if (result.success) {
        return { action: 'allow' };
      }

      if (result.challenge) {
        return { action: 'challenge', challenge: result.challenge };
      }

      return { action: 'block', blockReason: result.blockReason || 'blocked_by_backend' };
    } catch (error) {
      this.log('Backend verification error:', error);
      return { action: 'allow' }; // Fallback to local verification
    }
  }

  /**
   * Show backend-provided challenge
   */
  private async showBackendChallenge(challengeData: any): Promise<VerificationResult> {
    return new Promise((resolve) => {
      this.emit('challenge', { tier: this.currentTier, type: 'starting', challengeType: challengeData.type });
      this.options.onChallenge({ tier: this.currentTier, type: 'starting', challengeType: challengeData.type });

      // Create challenge UI based on backend challenge data
      const overlay = document.createElement('div');
      overlay.className = 'astra-overlay';
      overlay.id = 'astra-overlay';

      const challengeHtml = this.getBackendChallengeHTML(challengeData);
      overlay.innerHTML = challengeHtml;

      document.body.appendChild(overlay);

      // Animate in
      requestAnimationFrame(() => {
        overlay.classList.add('active');
      });

      // Handle solution submission
      const submitBtn = document.getElementById('astra-submit-btn');
      const skipLink = document.getElementById('astra-skip');

      submitBtn?.addEventListener('click', async () => {
        const solution = this.collectChallengeSolution(challengeData);

        try {
          const response = await fetch(this.options.endpoint + '/verify', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-API-Key': this.options.apiKey || ''
            },
            body: JSON.stringify({
              challengeId: challengeData.id,
              solution
            })
          });

          const result = await response.json();

          overlay.classList.remove('active');
          setTimeout(() => overlay.remove(), 300);

          if (result.success) {
            this.session.increaseTrust();
            resolve({
              success: true,
              tier: this.currentTier,
              type: challengeData.type,
              timestamp: Date.now()
            });
          } else {
            resolve({
              success: false,
              tier: this.currentTier,
              blocked: true,
              reason: result.reason || 'challenge_failed'
            });
          }
        } catch (error) {
          overlay.classList.remove('active');
          setTimeout(() => overlay.remove(), 300);
          resolve({
            success: false,
            tier: this.currentTier,
            blocked: true,
            reason: 'verification_error'
          });
        }
      });

      skipLink?.addEventListener('click', () => {
        overlay.classList.remove('active');
        setTimeout(() => overlay.remove(), 300);
        resolve({
          success: false,
          tier: this.currentTier,
          blocked: true,
          reason: 'skipped'
        });
      });
    });
  }

  /**
   * Get HTML for backend challenge
   */
  private getBackendChallengeHTML(challengeData: any): string {
    const type = challengeData.type || 'breath';

    switch (type) {
      case 'pulse':
        return this.getPulseChallengeHTML(challengeData);
      case 'tilt':
        return this.getTiltChallengeHTML(challengeData);
      case 'flick':
        return this.getFlickChallengeHTML(challengeData);
      case 'breath':
        return this.getBreathChallengeHTML(challengeData);
      case 'proof_of_work':
        return this.getPoWChallengeHTML(challengeData);
      default:
        return this.getBreathChallengeHTML(challengeData);
    }
  }

  private getPulseChallengeHTML(data: any): string {
    return `
      <div class="astra-modal">
        <div class="astra-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M4.5 3h15M12 3v18M3 12h18M12 8l4 4-4 4"/>
          </svg>
        </div>
        <h2 class="astra-title">Pulse Challenge</h2>
        <p class="astra-subtitle">${data.data?.instructions || 'Tap the button in rhythm with the pulses'}</p>
        <div class="astra-challenge-area">
          <div class="astra-pulse-container">
            <div class="astra-pulse-ring" id="pulse-ring-1"></div>
            <div class="astra-pulse-ring" id="pulse-ring-2"></div>
            <div class="astra-pulse-core" id="pulse-core"></div>
          </div>
        </div>
        <button class="astra-btn" id="astra-submit-btn">Tap in Rhythm</button>
        <a href="#" class="astra-btn-secondary" id="astra-skip">Skip (you might be blocked)</a>
      </div>
    `;
  }

  private getTiltChallengeHTML(data: any): string {
    return `
      <div class="astra-modal">
        <div class="astra-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="5" y="2" width="14" height="20" rx="2"/>
            <circle cx="12" cy="18" r="1"/>
          </svg>
        </div>
        <h2 class="astra-title">Tilt Challenge</h2>
        <p class="astra-subtitle">${data.data?.instructions || 'Tilt your device as instructed'}</p>
        <div class="astra-challenge-area">
          <div class="astra-tilt-container">
            <div class="astra-tilt-ball" id="tilt-ball"></div>
            <div class="astra-tilt-target" id="tilt-target"></div>
          </div>
        </div>
        <button class="astra-btn" id="astra-submit-btn">I'm Ready</button>
        <a href="#" class="astra-btn-secondary" id="astra-skip">Skip (you might be blocked)</a>
      </div>
    `;
  }

  private getFlickChallengeHTML(data: any): string {
    return `
      <div class="astra-modal">
        <div class="astra-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M5 12h14M12 5l7 7-7 7"/>
          </svg>
        </div>
        <h2 class="astra-title">Flick Challenge</h2>
        <p class="astra-subtitle">${data.data?.instructions || 'Flick in the correct direction'}</p>
        <div class="astra-challenge-area">
          <div style="width: 150px; height: 150px; border: 3px solid var(--astra-primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; position: relative;">
            <div id="flick-indicator" style="font-size: 24px;">→</div>
          </div>
        </div>
        <button class="astra-btn" id="astra-submit-btn">Flick →</button>
        <a href="#" class="astra-btn-secondary" id="astra-skip">Skip (you might be blocked)</a>
      </div>
    `;
  }

  private getBreathChallengeHTML(data: any): string {
    return `
      <div class="astra-modal">
        <div class="astra-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
          </svg>
        </div>
        <h2 class="astra-title">Breath Challenge</h2>
        <p class="astra-subtitle">${data.data?.instructions || 'Breathe in sync with the pattern'}</p>
        <div class="astra-challenge-area">
          <div class="astra-breath-circle" id="breath-circle"></div>
          <div class="astra-breath-text" id="breath-text">Breathe In</div>
        </div>
        <button class="astra-btn" id="astra-submit-btn">Continue</button>
        <a href="#" class="astra-btn-secondary" id="astra-skip">Skip (you might be blocked)</a>
      </div>
    `;
  }

  private getPoWChallengeHTML(data: any): string {
    return `
      <div class="astra-modal">
        <div class="astra-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="4" y="4" width="16" height="16" rx="2"/>
            <path d="M9 9h6M9 13h6M9 17h4"/>
          </svg>
        </div>
        <h2 class="astra-title">Verifying...</h2>
        <p class="astra-subtitle">Computing proof of work. Please wait.</p>
        <div class="astra-challenge-area">
          <div class="astra-progress">
            <div class="astra-progress-bar" style="width: 100%; animation: loading 2s infinite;"></div>
          </div>
        </div>
        <button class="astra-btn" id="astra-submit-btn" disabled>Verifying...</button>
        <a href="#" class="astra-btn-secondary" id="astra-skip">Skip (you might be blocked)</a>
      </div>
      <style>
        @keyframes loading {
          0% { width: 0%; margin-left: 0; }
          50% { width: 70%; margin-left: 0; }
          100% { width: 0%; margin-left: 100%; }
        }
      </style>
    `;
  }

  /**
   * Collect challenge solution based on type
   */
  private collectChallengeSolution(challengeData: any): any {
    // This would collect actual user input based on challenge type
    return {
      timestamp: Date.now()
    };
  }

  /**
   * Manual verification request
   */
  async verify(): Promise<VerificationResult> {
    if (this.isVerifying) {
      return { success: false, tier: this.currentTier, reason: 'already_verifying' };
    }

    this.isVerifying = true;

    try {
      const oosScore = await this.detector.getOOSScore();
      const tier = this.tierEngine.getTierForScore(oosScore);

      if (tier >= 2) {
        return await this.showChallenge(tier);
      }

      return {
        success: true,
        tier: 0,
        verified: true,
        timestamp: Date.now()
      };

    } finally {
      this.isVerifying = false;
    }
  }

  /**
   * Show a challenge to the user
   */
  async showChallenge(tier: TierLevel): Promise<VerificationResult> {
    this.emit('challenge', { tier, type: 'starting' });
    this.options.onChallenge({ tier, type: 'starting' });

    const challengeStart = Date.now();

    return new Promise((resolve) => {
      this.challengeManager.createChallengeUI(tier, (result) => {
        const completionTime = Date.now() - challengeStart;
        this.happiness.trackChallengeCompletion(result.success, completionTime, result.type as any);

        if (result.success) {
          this.emit('success', {
            tier: result.tier,
            type: result.type,
            duration: completionTime
          });
          this.options.onSuccess({
            tier: result.tier,
            type: result.type as any,
            duration: completionTime
          });
          this.session.increaseTrust();

          resolve({
            success: true,
            tier: result.tier,
            type: result.type,
            duration: completionTime,
            timestamp: Date.now()
          });
        } else {
          this.emit('blocked', {
            reason: result.reason,
            attempts: result.attempts || 1
          });
          this.options.onBlocked({
            reason: result.reason || 'verification_failed',
            attempts: result.attempts || 1
          });

          resolve({
            success: false,
            tier: result.tier,
            blocked: true,
            reason: result.reason,
            attempts: result.attempts
          });
        }
      });
    });
  }

  /**
   * Event emitter methods
   */
  on(event: EventType, callback: (data: unknown) => void): this {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
    return this;
  }

  off(event: EventType, callback: (data: unknown) => void): this {
    this.listeners.get(event)?.delete(callback);
    return this;
  }

  private emit(event: EventType, data: unknown): void {
    this.listeners.get(event)?.forEach(callback => callback(data));
  }

  /**
   * Inject CSS styles
   */
  private injectStyles(): void {
    if (document.getElementById('astra-shield-styles')) return;

    const styles = document.createElement('style');
    styles.id = 'astra-shield-styles';
    styles.textContent = this.getStyles();
    document.head.appendChild(styles);
  }

  /**
   * Get all CSS styles
   */
  private getStyles(): string {
    return `
      :root {
        --astra-primary: #6366F1;
        --astra-secondary: #8B5CF6;
        --astra-success: #10B981;
        --astra-warning: #F59E0B;
        --astra-error: #EF4444;
        --astra-bg: rgba(255, 255, 255, 0.98);
        --astra-text: #1E293B;
        --astra-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
      }

      @media (prefers-color-scheme: dark) {
        :root {
          --astra-bg: rgba(15, 23, 42, 0.98);
          --astra-text: #F8FAFC;
        }
      }

      .astra-overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 2147483647;
        opacity: 0;
        transition: opacity 0.3s ease;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }

      .astra-overlay.active { opacity: 1; }

      .astra-modal {
        background: var(--astra-bg);
        border-radius: 24px;
        padding: 48px;
        max-width: 420px;
        width: 90%;
        text-align: center;
        box-shadow: var(--astra-shadow);
        transform: scale(0.9) translateY(20px);
        transition: transform 0.3s ease;
      }

      .astra-overlay.active .astra-modal { transform: scale(1) translateY(0); }

      .astra-icon {
        width: 80px;
        height: 80px;
        margin: 0 auto 24px;
        background: linear-gradient(135deg, var(--astra-primary), var(--astra-secondary));
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .astra-icon svg { width: 40px; height: 40px; color: white; }

      .astra-title {
        font-size: 24px;
        font-weight: 700;
        color: var(--astra-text);
        margin: 0 0 12px;
      }

      .astra-subtitle {
        font-size: 16px;
        color: #64748B;
        margin: 0 0 32px;
        line-height: 1.5;
      }

      .astra-progress {
        width: 100%;
        height: 4px;
        background: #E2E8F0;
        border-radius: 2px;
        overflow: hidden;
        margin-bottom: 32px;
      }

      .astra-progress-bar {
        height: 100%;
        background: linear-gradient(90deg, var(--astra-primary), var(--astra-success));
        border-radius: 2px;
        transition: width 0.1s linear;
      }

      .astra-challenge-area {
        background: linear-gradient(135deg, #F8FAFC, #F1F5F9);
        border-radius: 16px;
        padding: 32px;
        margin-bottom: 24px;
        min-height: 200px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        position: relative;
      }

      .astra-instruction {
        font-size: 14px;
        color: #64748B;
        margin-bottom: 24px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }

      .astra-btn {
        background: linear-gradient(135deg, var(--astra-primary), var(--astra-secondary));
        color: white;
        border: none;
        padding: 16px 48px;
        border-radius: 12px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
        font-family: inherit;
      }

      .astra-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 40px rgba(99, 102, 241, 0.4);
      }

      .astra-btn-secondary {
        background: transparent;
        color: #64748B;
        font-size: 14px;
        padding: 8px 16px;
        margin-top: 16px;
      }

      /* Pulse Challenge */
      .astra-pulse-container {
        position: relative;
        width: 120px;
        height: 120px;
      }

      .astra-pulse-ring {
        position: absolute;
        inset: 0;
        border: 3px solid var(--astra-primary);
        border-radius: 50%;
        opacity: 0;
      }

      .astra-pulse-ring.animate {
        animation: pulse-ring 1.2s ease-out infinite;
      }

      @keyframes pulse-ring {
        0% { transform: scale(0.8); opacity: 0.8; }
        100% { transform: scale(1.5); opacity: 0; }
      }

      .astra-pulse-core {
        position: absolute;
        inset: 20px;
        background: var(--astra-primary);
        border-radius: 50%;
        transition: transform 0.15s ease;
      }

      .astra-pulse-core.active { transform: scale(1.2); }

      /* Tilt Challenge */
      .astra-tilt-container {
        width: 200px;
        height: 200px;
        background: radial-gradient(circle at 30% 30%, #E2E8F0, #CBD5E1);
        border-radius: 50%;
        position: relative;
        overflow: hidden;
      }

      .astra-tilt-ball {
        width: 40px;
        height: 40px;
        background: var(--astra-primary);
        border-radius: 50%;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        transition: transform 0.1s ease;
        box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
      }

      .astra-tilt-target {
        width: 60px;
        height: 60px;
        border: 3px dashed var(--astra-success);
        border-radius: 50%;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
      }

      /* Breath Challenge */
      .astra-breath-circle {
        width: 120px;
        height: 120px;
        background: linear-gradient(135deg, var(--astra-primary), var(--astra-secondary));
        border-radius: 50%;
        animation: breathe 4s ease-in-out infinite;
      }

      @keyframes breathe {
        0%, 100% { transform: scale(0.8); opacity: 0.6; }
        50% { transform: scale(1.2); opacity: 1; }
      }

      .astra-breath-text {
        font-size: 18px;
        font-weight: 600;
        color: var(--astra-text);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-top: 16px;
      }

      /* Success Animation */
      .astra-success-check { width: 80px; height: 80px; margin: 0 auto; }
      .astra-success-check svg { width: 100%; height: 100%; color: var(--astra-success); }
      .astra-success-check .check-circle {
        stroke-dasharray: 166;
        stroke-dashoffset: 166;
        animation: check-circle 0.6s ease-in-out forwards;
      }
      .astra-success-check .check-check {
        stroke-dasharray: 48;
        stroke-dashoffset: 48;
        animation: check-check 0.3s ease-in-out 0.4s forwards;
      }

      @keyframes check-circle { to { stroke-dashoffset: 0; } }
      @keyframes check-check { to { stroke-dashoffset: 0; } }

      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }
      }

      .astra-sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip: rect(0, 0, 0, 0);
        white-space: nowrap;
        border: 0;
      }
    `;
  }

  private log(...args: unknown[]): void {
    if (this.options.debug) {
      console.log('[ASTRA Shield]', ...args);
    }
  }

  /**
   * Destroy the shield instance
   */
  destroy(): void {
    document.removeEventListener('mousemove', this.handleMouseMove);
    document.removeEventListener('click', this.handleClick);
    document.removeEventListener('keydown', this.handleKeydown);
    document.removeEventListener('scroll', this.handleScroll);
    document.removeEventListener('touchstart', this.handleTouch);
    document.removeEventListener('touchmove', this.handleTouchMove);

    const overlay = document.getElementById('astra-overlay');
    if (overlay) overlay.remove();

    const styles = document.getElementById('astra-shield-styles');
    if (styles) styles.remove();

    (this as any).isInitialized = false;
  }
}

// Auto-attach to window for script tag usage
if (typeof window !== 'undefined') {
  (window as any).ASTRAShield = ASTRAShield;
}

export { ASTRAShield };
