/**
 * Challenge Manager
 */

import { TierLevel, ChallengeType, ASTRAShieldOptions, VerificationResult } from '../types';
import { Mutator } from '../mutation/Mutator';
import { AccessibilityManager } from '../accessibility/AccessibilityManager';

type ChallengeCallback = (result: VerificationResult) => void;

export class ChallengeManager {
  private options: ASTRAShieldOptions;
  private mutator: Mutator;
  private accessibility: AccessibilityManager;
  private activeOverlay: HTMLElement | null = null;
  private currentChallenge: { cleanup?: () => void } | null = null;
  private callback: ChallengeCallback | null = null;

  private challenges: Record<ChallengeType, { name: string; description: string; duration: number; accessibility: boolean }> = {
    pulse: { name: 'Pulse', description: 'Tap along with the rhythm', duration: 3000, accessibility: true },
    tilt: { name: 'Tilt', description: 'Balance the ball on the target', duration: 4000, accessibility: true },
    flick: { name: 'Flick', description: 'Swipe in the indicated direction', duration: 2000, accessibility: true },
    breath: { name: 'Breath', description: 'Follow the breathing rhythm', duration: 5000, accessibility: true }
  };

  constructor(options: ASTRAShieldOptions, mutator: Mutator, accessibility: AccessibilityManager) {
    this.options = options;
    this.mutator = mutator;
    this.accessibility = accessibility;
  }

  createChallengeUI(tier: TierLevel, callback: ChallengeCallback): void {
    this.callback = callback;
    this.removeOverlay();

    const challengeType = this.mutator.getChallengeForTier(tier);

    this.activeOverlay = document.createElement('div');
    this.activeOverlay.id = 'astra-overlay';
    this.activeOverlay.className = 'astra-overlay';
    this.activeOverlay.setAttribute('role', 'dialog');
    this.activeOverlay.setAttribute('aria-modal', 'true');

    this.activeOverlay.innerHTML = this.buildChallengeUI(challengeType, tier);
    document.body.appendChild(this.activeOverlay);

    requestAnimationFrame(() => {
      this.activeOverlay?.classList.add('active');
    });

    this.initChallenge(challengeType, tier);
  }

  private buildChallengeUI(challengeType: ChallengeType, tier: TierLevel): string {
    const challenge = this.challenges[challengeType];
    const durationMod = this.accessibility.getDurationModifier();

    return `
      <div class="astra-modal">
        <div class="astra-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <h2 class="astra-title">Quick Verification</h2>
        <p class="astra-subtitle">${challenge.description}</p>

        <div class="astra-progress">
          <div class="astra-progress-bar" id="astra-progress" style="width: 100%"></div>
        </div>

        <div class="astra-challenge-area">
          ${this.getChallengeContent(challengeType)}
        </div>

        <p class="astra-instruction">${this.getInstruction(challengeType)}</p>
      </div>
    `;
  }

  private getChallengeContent(type: ChallengeType): string {
    switch (type) {
      case 'pulse':
        return `
          <div class="astra-pulse-container" id="pulse-container">
            <div class="astra-pulse-ring"></div>
            <div class="astra-pulse-ring"></div>
            <div class="astra-pulse-ring"></div>
            <div class="astra-pulse-core" id="pulse-core"></div>
          </div>
          <p style="margin-top: 16px; color: #64748B;">Tap 3 times with the rhythm</p>
        `;
      case 'tilt':
        return `
          <div class="astra-tilt-container" id="tilt-container">
            <div class="astra-tilt-target" id="tilt-target"></div>
            <div class="astra-tilt-ball" id="tilt-ball"></div>
          </div>
          <p style="margin-top: 16px; color: #64748B;">Tilt or drag to balance</p>
        `;
      case 'flick':
        return `
          <div class="astra-tilt-container" id="flick-container" style="display: flex; align-items: center; justify-content: center;">
            <svg id="flick-arrow" xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="#6366F1" stroke-width="2">
              <path d="M5 12h14"/>
              <path d="m12 5 7 7-7 7"/>
            </svg>
          </div>
          <p style="margin-top: 16px; color: #64748B;">Swipe in the arrow direction</p>
        `;
      case 'breath':
        return `
          <div class="astra-breath-circle" id="breath-circle"></div>
          <div class="astra-breath-text" id="breath-text">Breathe In</div>
          <p style="margin-top: 16px; color: #64748B;">Click and hold during inhale</p>
        `;
      default:
        return '<p>Loading...</p>';
    }
  }

  private getInstruction(type: ChallengeType): string {
    const instructions: Record<ChallengeType, string> = {
      pulse: 'TAP WITH THE RHYTHM',
      tilt: 'TILT OR DRAG TO BALANCE',
      flick: 'SWIPE THE DIRECTION',
      breath: 'FOLLOW THE BREATHING'
    };
    return instructions[type];
  }

  private initChallenge(type: ChallengeType, tier: TierLevel): void {
    switch (type) {
      case 'pulse': this.initPulseChallenge(tier); break;
      case 'tilt': this.initTiltChallenge(tier); break;
      case 'flick': this.initFlickChallenge(tier); break;
      case 'breath': this.initBreathChallenge(tier); break;
    }
  }

  private initPulseChallenge(tier: TierLevel): void {
    const pulseCount = tier === 2 ? 3 : 5;
    let currentPulse = 0;
    const duration = 3000;
    const startTime = Date.now();
    const progressBar = document.getElementById('astra-progress');
    const core = document.getElementById('pulse-core');
    const rings = document.querySelectorAll('.astra-pulse-ring');

    rings.forEach((ring, i) => setTimeout(() => ring.classList.add('animate'), i * 400));

    const animate = () => {
      const elapsed = Date.now() - startTime;
      if (progressBar) progressBar.style.width = `${Math.max(0, 100 - (elapsed / duration * 100))}%`;
      if (elapsed < duration) requestAnimationFrame(animate);
    };
    animate();

    const handleTap = () => {
      const elapsed = Date.now() - startTime;
      const expectedTimes = Array.from({ length: pulseCount }, (_, i) => (duration / (pulseCount + 1)) * (i + 1));
      const isValid = expectedTimes.some(t => Math.abs(elapsed - t) < 400);

      if (isValid && currentPulse < pulseCount) {
        currentPulse++;
        core?.classList.add('active');
        setTimeout(() => core?.classList.remove('active'), 100);
        if ('vibrate' in navigator) navigator.vibrate(30);

        if (currentPulse >= pulseCount) {
          document.removeEventListener('click', handleTap);
          document.removeEventListener('touchstart', handleTap);
          this.completeChallenge(true, 'pulse', tier);
        }
      }
    };

    document.addEventListener('click', handleTap);
    document.addEventListener('touchstart', handleTap);

    this.currentChallenge = {
      cleanup: () => {
        document.removeEventListener('click', handleTap);
        document.removeEventListener('touchstart', handleTap);
      }
    };

    setTimeout(() => {
      if (currentPulse < pulseCount) {
        (this.currentChallenge as any)?.cleanup?.();
        this.completeChallenge(false, 'pulse', tier);
      }
    }, duration + 500);
  }

  private initTiltChallenge(tier: TierLevel): void {
    const ball = document.getElementById('tilt-ball') as HTMLElement;
    const target = document.getElementById('tilt-target') as HTMLElement;
    const container = document.getElementById('tilt-container') as HTMLElement;
    const progressBar = document.getElementById('astra-progress');
    const duration = 4000;
    const startTime = Date.now();

    let ballX = 80, ballY = 80, targetX = 80, targetY = 80;
    let isBalanced = 0;
    const requiredBalance = tier === 2 ? 15 : 25;
    const tolerance = tier === 2 ? 20 : 15;
    let dragMode = false;

    const animate = () => {
      const elapsed = Date.now() - startTime;
      if (progressBar) progressBar.style.width = `${Math.max(0, 100 - (elapsed / duration * 100))}%`;

      const distance = Math.sqrt(Math.pow(ballX - targetX, 2) + Math.pow(ballY - targetY, 2));
      if (distance < tolerance) isBalanced++;
      else isBalanced = Math.max(0, isBalanced - 2);

      if (ball) {
        ball.style.left = `${ballX}px`;
        ball.style.top = `${ballY}px`;
      }

      if (Math.random() < 0.02 && target) {
        targetX = 60 + Math.random() * 80;
        targetY = 60 + Math.random() * 80;
        target.style.left = `${targetX}px`;
        target.style.top = `${targetY}px`;
      }

      if (isBalanced >= requiredBalance) {
        this.completeChallenge(true, 'tilt', tier);
        return;
      }

      if (elapsed < duration) {
        requestAnimationFrame(animate);
      } else {
        this.completeChallenge(false, 'tilt', tier);
      }
    };

    const handleOrientation = (e: DeviceOrientationEvent) => {
      if (dragMode) return;
      const gamma = (e.gamma || 0) * 0.5;
      const beta = (e.beta || 0) * 0.3;
      ballX = Math.max(20, Math.min(160, ballX - gamma));
      ballY = Math.max(20, Math.min(160, ballY + beta));
    };

    if (window.DeviceOrientationEvent && typeof DeviceOrientationEvent.requestPermission !== 'function') {
      window.addEventListener('deviceorientation', handleOrientation);
    } else {
      dragMode = true;
    }

    const handleDrag = (e: MouseEvent | TouchEvent) => {
      if (!dragMode) return;
      const rect = container.getBoundingClientRect();
      const x = 'clientX' in (e as MouseEvent) ? (e as MouseEvent).clientX : (e as TouchEvent).touches?.[0]?.clientX;
      const y = 'clientY' in (e as MouseEvent) ? (e as MouseEvent).clientY : (e as TouchEvent).touches?.[0]?.clientY;
      if (x !== undefined && y !== undefined) {
        ballX = Math.max(20, Math.min(160, x - rect.left));
        ballY = Math.max(20, Math.min(160, y - rect.top));
      }
    };

    container?.addEventListener('mousedown', () => dragMode = true);
    container?.addEventListener('touchstart', () => dragMode = true);
    document.addEventListener('mousemove', handleDrag);
    document.addEventListener('touchmove', handleDrag);
    document.addEventListener('mouseup', () => dragMode = false);
    document.addEventListener('touchend', () => dragMode = false);

    this.currentChallenge = {
      cleanup: () => {
        window.removeEventListener('deviceorientation', handleOrientation);
        document.removeEventListener('mousemove', handleDrag);
        document.removeEventListener('touchmove', handleDrag);
      }
    };

    animate();
  }

  private initFlickChallenge(tier: TierLevel): void {
    const container = document.getElementById('flick-container');
    const arrow = document.getElementById('flick-arrow') as HTMLElement;
    const progressBar = document.getElementById('astra-progress');
    const duration = 3000;
    const startTime = Date.now();

    const directions = ['right', 'left', 'up', 'down'];
    const targetDir = directions[Math.floor(Math.random() * directions.length)];
    const rotations: Record<string, number> = { right: 0, down: 90, left: 180, up: 270 };

    if (arrow) arrow.style.transform = `rotate(${rotations[targetDir]}deg)`;

    let startX = 0, startY = 0, isTracking = false;

    const handleStart = (e: MouseEvent | TouchEvent) => {
      const evt = e as MouseEvent;
      const touch = (e as TouchEvent).touches?.[0];
      startX = evt.clientX || touch?.clientX || 0;
      startY = evt.clientY || touch?.clientY || 0;
      isTracking = true;
    };

    const handleMove = (e: MouseEvent | TouchEvent) => {
      if (!isTracking) return;
      const evt = e as MouseEvent;
      const touch = (e as TouchEvent).touches?.[0];
      const deltaX = (evt.clientX || touch?.clientX || 0) - startX;
      const deltaY = (evt.clientY || touch?.clientY || 0) - startY;
      const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);

      if (distance > 50) {
        isTracking = false;
        const swipeDir = Math.abs(deltaX) > Math.abs(deltaY)
          ? (deltaX > 0 ? 'right' : 'left')
          : (deltaY > 0 ? 'down' : 'up');

        if (swipeDir === targetDir) {
          if (arrow) arrow.style.transform = `rotate(${rotations[targetDir]}deg) scale(1.3)`;
          if ('vibrate' in navigator) navigator.vibrate(50);
          this.completeChallenge(true, 'flick', tier);
        } else {
          startX = evt.clientX || touch?.clientX || 0;
          startY = evt.clientY || touch?.clientY || 0;
          isTracking = true;
        }
      }
    };

    container?.addEventListener('mousedown', handleStart);
    container?.addEventListener('touchstart', handleStart);
    document.addEventListener('mousemove', handleMove);
    document.addEventListener('touchmove', handleMove);
    document.addEventListener('mouseup', () => isTracking = false);
    document.addEventListener('touchend', () => isTracking = false);

    this.currentChallenge = {
      cleanup: () => {
        document.removeEventListener('mousemove', handleMove);
        document.removeEventListener('touchmove', handleMove);
      }
    };

    const animate = () => {
      const elapsed = Date.now() - startTime;
      if (progressBar) progressBar.style.width = `${Math.max(0, 100 - (elapsed / duration * 100))}%`;
      if (elapsed < duration) requestAnimationFrame(animate);
      else this.completeChallenge(false, 'flick', tier);
    };
    animate();
  }

  private initBreathChallenge(tier: TierLevel): void {
    const circle = document.getElementById('breath-circle') as HTMLElement;
    const text = document.getElementById('breath-text') as HTMLElement;
    const progressBar = document.getElementById('astra-progress');
    const duration = 6000;
    const startTime = Date.now();
    const breathDuration = 4000;
    let totalHoldTime = 0;
    let isPressing = false;

    const handlePressStart = () => { isPressing = true; };
    const handlePressEnd = () => { isPressing = false; };

    document.addEventListener('mousedown', handlePressStart);
    document.addEventListener('touchstart', handlePressStart);
    document.addEventListener('mouseup', handlePressEnd);
    document.addEventListener('touchend', handlePressEnd);

    this.currentChallenge = {
      cleanup: () => {
        document.removeEventListener('mousedown', handlePressStart);
        document.removeEventListener('touchstart', handlePressStart);
        document.removeEventListener('mouseup', handlePressEnd);
        document.removeEventListener('touchend', handlePressEnd);
      }
    };

    const animate = () => {
      const elapsed = Date.now() - startTime;
      if (progressBar) progressBar.style.width = `${Math.max(0, 100 - (elapsed / duration * 100))}%`;

      const cycleTime = elapsed % (breathDuration * 2);
      const breathPhase = cycleTime / breathDuration;

      if (breathPhase < 1) {
        const scale = 0.6 + (breathPhase * 0.6);
        if (circle) circle.style.transform = `scale(${scale})`;
        if (text) text.textContent = 'Breathe In';
        if (circle) circle.style.opacity = String(0.6 + (breathPhase * 0.4));
      } else {
        const scale = 1.2 - ((breathPhase - 1) * 0.6);
        if (circle) circle.style.transform = `scale(${scale})`;
        if (text) text.textContent = 'Breathe Out';
        if (circle) circle.style.opacity = String(1 - ((breathPhase - 1) * 0.4));
      }

      if (breathPhase < 0.5 && isPressing) totalHoldTime += 16;

      if (totalHoldTime >= (tier === 2 ? 2000 : 3000)) {
        if ('vibrate' in navigator) navigator.vibrate([50, 50, 50]);
        this.completeChallenge(true, 'breath', tier);
        return;
      }

      if (elapsed < duration) {
        requestAnimationFrame(animate);
      } else {
        this.completeChallenge(false, 'breath', tier);
      }
    };
    animate();
  }

  completeChallenge(success: boolean, type: ChallengeType, tier: TierLevel): void {
    this.currentChallenge?.cleanup?.();

    if (success) {
      this.showSuccess(() => {
        this.removeOverlay();
        this.callback?.({ success: true, type, tier });
      });
    } else {
      this.callback?.({ success: false, reason: 'timeout', type, tier, attempts: 1 });
    }
  }

  private showSuccess(callback: () => void): void {
    const modal = document.querySelector('.astra-modal');
    if (modal) {
      modal.innerHTML = `
        <div class="astra-success-check">
          <svg viewBox="0 0 52 52">
            <circle class="check-circle" cx="26" cy="26" r="25" fill="none" stroke="#10B981" stroke-width="2"/>
            <path class="check-check" fill="none" stroke="#10B981" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" d="M14 27l7 7 16-16"/>
          </svg>
        </div>
        <h2 class="astra-title" style="color: #10B981;">Verified!</h2>
        <p class="astra-subtitle">You're all set.</p>
      `;
    }
    if ('vibrate' in navigator) navigator.vibrate([50, 100, 50]);
    setTimeout(callback, 1500);
  }

  removeOverlay(): void {
    this.currentChallenge?.cleanup?.();
    const overlay = document.getElementById('astra-overlay');
    if (overlay) {
      overlay.classList.remove('active');
      setTimeout(() => overlay.remove(), 300);
    }
  }
}
