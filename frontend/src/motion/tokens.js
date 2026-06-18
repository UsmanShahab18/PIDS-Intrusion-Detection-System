// Shared motion system — single source of truth for the whole app.
// Skill rules: motion-consistency (one rhythm), spring-physics (natural feel),
// exit-faster-than-enter, stagger-sequence, duration-timing (150-300ms),
// transform-performance (only transform/opacity), reduced-motion (respect it).
//
// Import these everywhere instead of redefining transitions per component.

// --- Easing & duration tokens -------------------------------------------
export const EASE_OUT = [0.16, 1, 0.3, 1];   // entering
export const EASE_IN = [0.7, 0, 0.84, 0];     // exiting

export const DURATION = {
  fast: 0.15,
  base: 0.25,
  slow: 0.4,
};

// Spring presets (natural feel). Use for hover/press/layout.
export const SPRING = {
  soft: { type: 'spring', stiffness: 260, damping: 26, mass: 0.9 },
  snappy: { type: 'spring', stiffness: 420, damping: 30 },
  gentle: { type: 'spring', stiffness: 140, damping: 20 },
};

// --- Reusable variants ---------------------------------------------------
// Page-level fade + lift. Exit is shorter than enter (skill rule).
export const pageVariants = {
  initial: { opacity: 0, y: 12 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: DURATION.base, ease: EASE_OUT },
  },
  exit: {
    opacity: 0,
    y: -8,
    transition: { duration: DURATION.fast, ease: EASE_IN },
  },
};

// Container that staggers its children on mount.
export const staggerContainer = (stagger = 0.05, delayChildren = 0.05) => ({
  initial: {},
  animate: {
    transition: { staggerChildren: stagger, delayChildren },
  },
});

// Child item for staggered reveals (cards, list rows, sections).
export const fadeInUp = {
  initial: { opacity: 0, y: 20 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: DURATION.base, ease: EASE_OUT },
  },
};

export const scaleIn = {
  initial: { opacity: 0, scale: 0.96 },
  animate: { opacity: 1, scale: 1, transition: SPRING.soft },
};

// --- Interaction presets (spread onto motion components) -----------------
// Subtle scale on hover/press for cards & buttons (skill scale-feedback).
export const hoverLift = {
  whileHover: { y: -4, scale: 1.02, transition: SPRING.snappy },
  whileTap: { scale: 0.98, transition: SPRING.snappy },
};

export const pressable = {
  whileTap: { scale: 0.97, transition: SPRING.snappy },
};
