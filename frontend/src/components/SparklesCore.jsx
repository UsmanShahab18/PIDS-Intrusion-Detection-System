// Adapted from the shadcn/Aceternity "sparkles" component for this
// CRA + JS + MUI codebase: removed `'use client'`, TypeScript types, the
// `cn`/Tailwind helper, and the `@/` alias. Particle config preserved.
import React, { useId, useEffect, useState } from 'react';
import Particles, { initParticlesEngine } from '@tsparticles/react';
import { loadSlim } from '@tsparticles/slim';
import { motion, useAnimation } from 'framer-motion';

export const SparklesCore = (props) => {
  const {
    id,
    className,
    style,
    background,
    minSize,
    maxSize,
    speed,
    particleColor,
    particleDensity,
  } = props;

  const [init, setInit] = useState(false);
  const controls = useAnimation();
  const generatedId = useId();

  useEffect(() => {
    initParticlesEngine(async (engine) => {
      await loadSlim(engine);
    }).then(() => setInit(true));
  }, []);

  const particlesLoaded = async (container) => {
    if (container) {
      controls.start({ opacity: 1, transition: { duration: 1 } });
    }
  };

  return (
    <motion.div
      animate={controls}
      initial={{ opacity: 0 }}
      className={className}
      style={{ width: '100%', height: '100%', ...style }}
    >
      {init && (
        <Particles
          id={id || generatedId}
          particlesLoaded={particlesLoaded}
          style={{ width: '100%', height: '100%' }}
          options={{
            background: { color: { value: background || '#0d47a1' } },
            fullScreen: { enable: false, zIndex: 1 },
            fpsLimit: 120,
            interactivity: {
              events: {
                onClick: { enable: true, mode: 'push' },
                onHover: { enable: false, mode: 'repulse' },
                resize: true,
              },
              modes: {
                push: { quantity: 4 },
                repulse: { distance: 200, duration: 0.4 },
              },
            },
            particles: {
              color: { value: particleColor || '#ffffff' },
              move: {
                enable: true,
                direction: 'none',
                outModes: { default: 'out' },
                random: false,
                speed: { min: 0.1, max: 1 },
                straight: false,
              },
              number: {
                density: { enable: true, width: 400, height: 400 },
                value: particleDensity || 120,
              },
              opacity: {
                value: { min: 0.1, max: 1 },
                animation: {
                  enable: true,
                  speed: speed || 4,
                  sync: false,
                  startValue: 'random',
                },
              },
              shape: { type: 'circle' },
              size: { value: { min: minSize || 1, max: maxSize || 3 } },
            },
            detectRetina: true,
          }}
        />
      )}
    </motion.div>
  );
};

export default SparklesCore;
