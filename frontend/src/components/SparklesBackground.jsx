import React from 'react';
import { Box, useMediaQuery } from '@mui/material';
import { SparklesCore } from './SparklesCore';

// Atmospheric particle layer for hero sections.
// Sits at zIndex 0; content above must use position:relative + zIndex >= 2.
// Enforces the perf/a11y rules: density caps, mobile reduction, reduced-motion.
export default function SparklesBackground({ color = '#00ff88', density = 90 }) {
  const isMobile = useMediaQuery('(max-width:768px)');
  const prefersReducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)');

  // Reduced motion: render a still, empty layer instead of animated particles.
  if (prefersReducedMotion) {
    return <Box sx={{ position: 'absolute', inset: 0, zIndex: 0 }} aria-hidden />;
  }

  // Mobile: ~40% fewer particles. Hard cap at 120 for full-screen layers.
  const finalDensity = Math.min(isMobile ? Math.round(density * 0.6) : density, 120);

  return (
    <Box sx={{ position: 'absolute', inset: 0, zIndex: 0 }} aria-hidden>
      <SparklesCore
        background="transparent"
        minSize={0.6}
        maxSize={1.4}
        particleDensity={finalDensity}
        particleColor={color}
        speed={1}
      />
    </Box>
  );
}
