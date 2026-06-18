// Single source of truth for glassmorphism surfaces (skill: elevation-consistent,
// dark-mode-pairing, token-driven theming). Spread onto MUI sx props.
export const glass = {
  // Standard glass surface — cards, panels.
  surface: {
    background: 'rgba(15, 20, 30, 0.45)',
    backdropFilter: 'blur(20px) saturate(180%)',
    WebkitBackdropFilter: 'blur(20px) saturate(180%)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '16px',
    boxShadow:
      '0 8px 32px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255,255,255,0.05)',
  },
  // Brighter — modals, dialogs, hero content.
  elevated: {
    background: 'rgba(20, 25, 38, 0.65)',
    backdropFilter: 'blur(28px) saturate(200%)',
    WebkitBackdropFilter: 'blur(28px) saturate(200%)',
    border: '1px solid rgba(255, 255, 255, 0.10)',
    borderRadius: '20px',
    boxShadow: '0 12px 48px rgba(0, 0, 0, 0.45)',
  },
  // Subtle — navbars, sticky bars.
  nav: {
    background: 'rgba(10, 12, 20, 0.55)',
    backdropFilter: 'blur(16px) saturate(150%)',
    WebkitBackdropFilter: 'blur(16px) saturate(150%)',
    borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
  },
};

// Neon accent tokens — keep the existing cyber-green identity.
export const neon = {
  green: '#00ff88',
  blue: '#00b4ff',
  violet: '#7850ff',
  glow: (c = '#00ff88') => `0 0 12px ${c}66, 0 0 24px ${c}33`,
};
