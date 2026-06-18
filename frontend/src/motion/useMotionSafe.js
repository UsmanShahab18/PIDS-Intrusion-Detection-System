import { useReducedMotion } from 'framer-motion';

// Returns motion props that collapse to an instant (no-movement) variant
// when the user has prefers-reduced-motion set. Skill rule: reduced-motion.
//
// Usage:
//   const safe = useMotionSafe();
//   <motion.div {...safe(fadeInUp)} />
export default function useMotionSafe() {
  const reduce = useReducedMotion();

  return (variants) => {
    if (!reduce) {
      return { variants, initial: 'initial', animate: 'animate', exit: 'exit' };
    }
    // Reduced motion: keep opacity changes, drop all transform movement.
    return {
      variants: {
        initial: { opacity: 0 },
        animate: { opacity: 1, transition: { duration: 0.01 } },
        exit: { opacity: 0, transition: { duration: 0.01 } },
      },
      initial: 'initial',
      animate: 'animate',
      exit: 'exit',
    };
  };
}
