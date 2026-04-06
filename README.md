# ASTRA Shield - Invisible Security System

**The best security is the security you never notice.**

ASTRA Shield is a revolutionary invisible security framework that operates on a 5-tier friction model, where 95% of users experience Tier 0-1 (completely invisible to imperceptible), and only detected threats face higher tiers.

## Features

- **Invisible by Default**: 95% of users experience zero friction
- **5-Tier Friction Model**: From ghost (invisible) to gate (manual verification)
- **Modern Challenges**: Pulse (haptic), Tilt, Flick, Breath - no old CAPTCHA puzzles
- **Hourly Mutation**: Challenges constantly evolve to prevent bot learning
- **Accessibility First**: WCAG 2.1 AA compliant, with multiple alternatives
- **Lightweight**: ~55KB minified, no external dependencies

## Installation

### NPM

```bash
npm install astra-shield
```

### CDN

```html
<script src="https://cdn.example.com/astra-shield.min.js"></script>
```

### Download

Download `astra-shield.min.js` from the `dist/` directory.

## Quick Start

```javascript
import { ASTRAShield } from 'astra-shield';

// Initialize
const shield = new ASTRAShield({
  apiKey: 'your-api-key',
  debug: true
});

// Protect sensitive actions
async function handleLogin() {
  const result = await shield.protect('login', { userId: '123' });

  if (result.success) {
    // Proceed with login
    console.log('Verified! User is human.');
  } else {
    console.log('Verification failed:', result.reason);
  }
}

// Event listeners
shield.on('challenge', (data) => {
  console.log('Challenge started:', data.tier);
});

shield.on('success', (data) => {
  console.log('Verification complete:', data);
});

shield.on('blocked', (data) => {
  console.log('Blocked:', data.reason);
});
```

## The 5-Tier Friction Model

| Tier | Name | OOS Range | Experience |
|------|------|-----------|------------|
| 0 | Ghost | 0.0-1.5 | Nothing - invisible |
| 1 | Whisper | 1.5-2.0 | 200ms micro-delay |
| 2 | Nudge | 2.0-2.5 | Single gesture challenge |
| 3 | Pause | 2.5-3.0 | Multi-step challenge |
| 4 | Gate | 3.0+ | Manual verification |

## Challenge Types

### Pulse Challenge
Tap along with device vibration - 3 pulses, haptic feedback.

### Tilt Challenge
Balance a ball on target using device tilt or drag.

### Flick Challenge
Swipe in the indicated direction with velocity detection.

### Breath Challenge
Follow breathing rhythm - expand/contract circle matching.

All challenges:
- Mutate hourly to prevent bot learning
- Have accessibility alternatives
- Complete in under 5 seconds
- Feel intuitive and engaging

## API Reference

### Constructor

```javascript
const shield = new ASTRAShield({
  apiKey: string,           // API key for backend verification
  endpoint: string,         // Backend endpoint (default: '/api/verify')
  debug: boolean,          // Enable debug logging (default: false)
  theme: 'auto' | 'light' | 'dark',
  storagePrefix: string,    // LocalStorage prefix (default: 'astra_')
  sessionDuration: number, // Session duration in ms (default: 30 min)
  mutationInterval: number // Challenge mutation interval (default: 1 hour)
});
```

### Methods

#### `shield.protect(action, context)`
Protect a sensitive action with appropriate tier.

```javascript
const result = await shield.protect('checkout', { amount: 99.99 });
```

#### `shield.verify()`
Manual verification request.

```javascript
const verified = await shield.verify();
```

#### `shield.on(event, callback)`
Add event listener.

```javascript
shield.on('success', (data) => {
  console.log('Verified:', data.tier);
});
```

#### `shield.off(event, callback)`
Remove event listener.

#### `shield.destroy()`
Clean up and remove all listeners.

### Events

| Event | Description |
|-------|-------------|
| `ready` | Shield initialized successfully |
| `challenge` | Challenge started |
| `success` | Verification successful |
| `blocked` | Verification failed |
| `tierChange` | User moved to different tier |
| `error` | An error occurred |

## Behavioral Analysis

ASTRA Shield passively analyzes:

- Mouse movement patterns (velocity, direction changes)
- Click timing and intervals
- Scroll behavior
- Keystroke rhythms
- Touch gestures
- Session history and trust score

All analysis is performed client-side with optional server-side verification.

## Accessibility

ASTRA Shield is built accessibility-first:

- Screen reader compatible with ARIA labels
- High contrast mode
- Reduced motion support
- Keyboard alternatives for all challenges
- Extended time options
- Audio cues option

Toggle accessibility options using:

```javascript
shield.accessibility.setPreference('reduceMotion', true);
shield.accessibility.setPreference('highContrast', true);
```

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+
- iOS Safari 13+
- Chrome for Android 80+

## License

MIT License - See LICENSE file.

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

---

**Philosophy**: Security should feel like a helpful assistant, not a hostile gatekeeper.
