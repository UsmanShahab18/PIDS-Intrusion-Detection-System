import React from 'react';
import { Box, Typography, useMediaQuery, useTheme } from '@mui/material';

const PIDSLogo = ({ size = 'large' }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery('(max-width:600px)');
  const isTablet = useMediaQuery('(max-width:960px)');

  // Responsive size overrides
  const getResponsiveSize = () => {
    if (isMobile) return 'small';
    if (isTablet) return 'medium';
    return size;
  };

  const sizes = {
    small:  { hex: 180, text: '2.2rem', subtitle: '0.55rem', gap: 2 },
    medium: { hex: 250, text: '3rem',   subtitle: '0.75rem', gap: 3 },
    large:  { hex: 350, text: '4.5rem', subtitle: '1rem',    gap: 4 },
    xlarge: { hex: 450, text: '6rem',   subtitle: '1.2rem',  gap: 4 }
  };

  const effectiveSize = getResponsiveSize();
  const s = sizes[effectiveSize] || sizes.large;

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        py: isMobile ? 2 : 4,
        width: '100%',
        overflow: 'hidden',
      }}
    >
      {/* Outer rotating hex ring */}
      <Box
        sx={{
          position: 'absolute',
          width: s.hex * 1.6,
          height: s.hex * 1.6,
          animation: 'rotateHex 20s linear infinite',
          opacity: 0.15,
          '@keyframes rotateHex': {
            '0%': { transform: 'rotate(0deg)' },
            '100%': { transform: 'rotate(360deg)' }
          }
        }}
      >
        <Box
          component="svg"
          viewBox="0 0 200 200"
          sx={{ width: '100%', height: '100%' }}
        >
          <polygon
            points="100,5 178,30 195,110 150,180 50,180 5,110 22,30"
            fill="none"
            stroke="#00d4ff"
            strokeWidth="0.5"
            strokeDasharray="8 4"
          />
        </Box>
      </Box>

      {/* Middle pulsing hex ring */}
      <Box
        sx={{
          position: 'absolute',
          width: s.hex * 1.35,
          height: s.hex * 1.35,
          animation: 'pulseHexRing 3s ease-in-out infinite',
          '@keyframes pulseHexRing': {
            '0%, 100%': { transform: 'scale(1)', opacity: 0.25 },
            '50%': { transform: 'scale(1.05)', opacity: 0.1 }
          }
        }}
      >
        <Box
          component="svg"
          viewBox="0 0 200 200"
          sx={{ width: '100%', height: '100%' }}
        >
          <polygon
            points="100,10 173,35 190,110 152,175 48,175 10,110 27,35"
            fill="none"
            stroke="#00d4ff"
            strokeWidth="1"
          />
        </Box>
      </Box>

      {/* Main Logo SVG */}
      <Box
        component="svg"
        viewBox="0 0 300 340"
        sx={{
          width: s.hex,
          height: s.hex * 1.13,
          maxWidth: '80vw',
          filter: isMobile
            ? 'drop-shadow(0 0 15px rgba(0, 255, 65, 0.4))'
            : 'drop-shadow(0 0 25px rgba(0, 255, 65, 0.4)) drop-shadow(0 0 50px rgba(0, 255, 65, 0.2))',
          animation: 'floatLogo 4s ease-in-out infinite',
          '@keyframes floatLogo': {
            '0%, 100%': { transform: 'translateY(0)' },
            '50%': { transform: 'translateY(-8px)' }
          }
        }}
      >
        <defs>
          <linearGradient id="hexGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00ff88" stopOpacity="0.9" />
            <stop offset="50%" stopColor="#00d4ff" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#00aa22" stopOpacity="0.8" />
          </linearGradient>
          <linearGradient id="hexDark" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#0a1f0a" />
            <stop offset="100%" stopColor="#050f05" />
          </linearGradient>
          <linearGradient id="gridGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.3" />
            <stop offset="50%" stopColor="#00d4ff" stopOpacity="0.08" />
            <stop offset="100%" stopColor="#00d4ff" stopOpacity="0.25" />
          </linearGradient>
          <linearGradient id="lockGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#00ff88" />
            <stop offset="100%" stopColor="#00a8cc" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="strongGlow">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <clipPath id="hexClip">
            <polygon points="150,18 262,68 262,228 150,298 38,228 38,68" />
          </clipPath>
        </defs>

        {/* OUTER HEXAGON BORDER */}
        <polygon
          points="150,12 268,65 268,232 150,305 32,232 32,65"
          fill="none"
          stroke="url(#hexGrad)"
          strokeWidth="2.5"
          filter="url(#glow)"
        />

        {/* MAIN HEXAGON BODY */}
        <polygon
          points="150,18 262,68 262,228 150,298 38,228 38,68"
          fill="url(#hexDark)"
          stroke="url(#hexGrad)"
          strokeWidth="1.5"
        />

        {/* CYBER GRID PATTERN */}
        <g clipPath="url(#hexClip)" stroke="url(#gridGrad)" strokeWidth="0.5" fill="none">
          <line x1="38" y1="100" x2="262" y2="100" />
          <line x1="38" y1="135" x2="262" y2="135" />
          <line x1="38" y1="170" x2="262" y2="170" />
          <line x1="38" y1="205" x2="262" y2="205" />
          <line x1="38" y1="240" x2="262" y2="240" />
          <line x1="80" y1="18" x2="80" y2="298" />
          <line x1="115" y1="18" x2="115" y2="298" />
          <line x1="150" y1="18" x2="150" y2="298" />
          <line x1="185" y1="18" x2="185" y2="298" />
          <line x1="220" y1="18" x2="220" y2="298" />
          <line x1="38" y1="68" x2="262" y2="228" strokeOpacity="0.06" />
          <line x1="262" y1="68" x2="38" y2="228" strokeOpacity="0.06" />
          <line x1="150" y1="18" x2="262" y2="228" strokeOpacity="0.04" />
          <line x1="150" y1="18" x2="38" y2="228" strokeOpacity="0.04" />
        </g>

        {/* GRID INTERSECTION DOTS */}
        <g fill="#00d4ff">
          <circle cx="80" cy="100" r="1.5" opacity="0.4" />
          <circle cx="115" cy="100" r="1.5" opacity="0.3" />
          <circle cx="185" cy="100" r="1.5" opacity="0.3" />
          <circle cx="220" cy="100" r="1.5" opacity="0.4" />
          <circle cx="80" cy="135" r="1.5" opacity="0.3" />
          <circle cx="220" cy="135" r="1.5" opacity="0.3" />
          <circle cx="80" cy="205" r="1.5" opacity="0.3" />
          <circle cx="220" cy="205" r="1.5" opacity="0.3" />
          <circle cx="80" cy="240" r="1.5" opacity="0.4" />
          <circle cx="115" cy="240" r="1.5" opacity="0.3" />
          <circle cx="185" cy="240" r="1.5" opacity="0.3" />
          <circle cx="220" cy="240" r="1.5" opacity="0.4" />
        </g>

        {/* SMALL HEX NODES */}
        <g stroke="#00d4ff" strokeWidth="0.8" fill="none" opacity="0.35">
          <polygon points="80,94 86,97 86,103 80,106 74,103 74,97" />
          <polygon points="220,94 226,97 226,103 220,106 214,103 214,97" />
          <polygon points="80,234 86,237 86,243 80,246 74,243 74,237" />
          <polygon points="220,234 226,237 226,243 220,246 214,243 214,237" />
        </g>

        {/* DATA FLOW LINES (animated) */}
        <g stroke="#00d4ff" strokeWidth="1" fill="none" opacity="0.2">
          <line x1="80" y1="100" x2="115" y2="135">
            <animate attributeName="opacity" values="0.1;0.5;0.1" dur="2s" repeatCount="indefinite" />
          </line>
          <line x1="220" y1="100" x2="185" y2="135">
            <animate attributeName="opacity" values="0.1;0.5;0.1" dur="2s" repeatCount="indefinite" begin="0.5s" />
          </line>
          <line x1="115" y1="205" x2="80" y2="240">
            <animate attributeName="opacity" values="0.1;0.5;0.1" dur="2s" repeatCount="indefinite" begin="1s" />
          </line>
          <line x1="185" y1="205" x2="220" y2="240">
            <animate attributeName="opacity" values="0.1;0.5;0.1" dur="2s" repeatCount="indefinite" begin="1.5s" />
          </line>
        </g>

        {/* CENTRAL LOCK ICON */}
        <g transform="translate(150, 162)" filter="url(#strongGlow)">
          <path d="M-18,-22 L-18,-38 C-18,-56 18,-56 18,-38 L18,-22"
            fill="none" stroke="#00d4ff" strokeWidth="4" strokeLinecap="round" opacity="0.9" />
          <path d="M-14,-22 L-14,-36 C-14,-50 14,-50 14,-36 L14,-22"
            fill="none" stroke="#00ff88" strokeWidth="1.5" strokeLinecap="round" opacity="0.4" />
          <polygon points="0,-22 26,-9 26,17 0,30 -26,17 -26,-9"
            fill="#0a1f0a" stroke="url(#lockGrad)" strokeWidth="2" />
          <polygon points="0,-18 22,-7 22,14 0,25 -22,14 -22,-7"
            fill="none" stroke="#00d4ff" strokeWidth="0.5" opacity="0.3" />
          <circle cx="0" cy="2" r="7" fill="#00d4ff" opacity="0.15" />
          <circle cx="0" cy="2" r="5.5" fill="#00d4ff" opacity="0.25" />
          <circle cx="0" cy="1" r="3.5" fill="#00ff88" opacity="0.9">
            <animate attributeName="opacity" values="0.9;0.5;0.9" dur="2.5s" repeatCount="indefinite" />
          </circle>
          <rect x="-2.5" y="3" width="5" height="12" rx="1.5" fill="#00d4ff" opacity="0.7">
            <animate attributeName="opacity" values="0.7;0.4;0.7" dur="2.5s" repeatCount="indefinite" />
          </rect>
          <circle cx="0" cy="1" r="9" fill="none" stroke="#00d4ff" strokeWidth="0.5" opacity="0.2">
            <animate attributeName="r" values="9;12;9" dur="3s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.2;0.05;0.2" dur="3s" repeatCount="indefinite" />
          </circle>
        </g>

        {/* SCANNING LINE */}
        <g clipPath="url(#hexClip)">
          <rect x="38" y="68" width="224" height="1.5" fill="#00ff88" opacity="0.6">
            <animate attributeName="y" values="68;298;68" dur="3.5s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.6;0.15;0.6" dur="3.5s" repeatCount="indefinite" />
          </rect>
        </g>

        {/* CORNER BRACKETS */}
        <g stroke="#00d4ff" strokeWidth="1.5" fill="none" opacity="0.5">
          <path d="M130,25 L150,18 L170,25" />
          <path d="M130,292 L150,298 L170,292" />
          <path d="M48,72 L38,68 L42,80" />
          <path d="M252,72 L262,68 L258,80" />
          <path d="M48,225 L38,228 L42,218" />
          <path d="M252,225 L262,228 L258,218" />
        </g>

        {/* TINY DATA PARTICLES */}
        <g fill="#00d4ff">
          <circle cx="95" cy="78" r="1" opacity="0.5">
            <animate attributeName="opacity" values="0.5;0;0.5" dur="4s" repeatCount="indefinite" />
          </circle>
          <circle cx="205" cy="85" r="1" opacity="0.3">
            <animate attributeName="opacity" values="0.3;0;0.3" dur="3s" repeatCount="indefinite" begin="1s" />
          </circle>
          <circle cx="70" cy="180" r="1" opacity="0.4">
            <animate attributeName="opacity" values="0.4;0;0.4" dur="3.5s" repeatCount="indefinite" begin="0.5s" />
          </circle>
          <circle cx="230" cy="175" r="1" opacity="0.3">
            <animate attributeName="opacity" values="0.3;0;0.3" dur="4.5s" repeatCount="indefinite" begin="2s" />
          </circle>
          <circle cx="110" cy="265" r="1" opacity="0.4">
            <animate attributeName="opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite" begin="1.5s" />
          </circle>
          <circle cx="190" cy="260" r="1" opacity="0.3">
            <animate attributeName="opacity" values="0.3;0;0.3" dur="4s" repeatCount="indefinite" begin="0.8s" />
          </circle>
        </g>
      </Box>

      {/* P.I.D.S. Text */}
      <Typography
        sx={{
          mt: s.gap,
          fontSize: { xs: '2rem', sm: '3rem', md: s.text },
          fontFamily: '"Orbitron", "Share Tech Mono", monospace',
          fontWeight: 900,
          background: 'linear-gradient(135deg, #00ff88 0%, #00d4ff 50%, #00a8cc 100%)',
          backgroundClip: 'text',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          textShadow: 'none',
          filter: 'drop-shadow(0 0 20px rgba(0, 255, 65, 0.5)) drop-shadow(0 0 40px rgba(0, 255, 65, 0.3))',
          letterSpacing: { xs: '0.15em', sm: '0.25em', md: '0.3em' },
          animation: 'textPulse 3s ease-in-out infinite',
          '@keyframes textPulse': {
            '0%, 100%': { filter: 'drop-shadow(0 0 20px rgba(0, 255, 65, 0.5)) drop-shadow(0 0 40px rgba(0, 255, 65, 0.3))' },
            '50%': { filter: 'drop-shadow(0 0 30px rgba(0, 255, 65, 0.7)) drop-shadow(0 0 60px rgba(0, 255, 65, 0.4))' }
          }
        }}
      >
        P.I.D.S.
      </Typography>

      {/* Subtitle */}
      <Typography
        sx={{
          mt: 1,
          fontSize: { xs: '0.5rem', sm: '0.7rem', md: s.subtitle },
          fontFamily: '"Share Tech Mono", monospace',
          color: '#00d4ff',
          letterSpacing: { xs: '0.2em', sm: '0.3em', md: '0.4em' },
          opacity: 0.8,
          textTransform: 'uppercase',
          textAlign: 'center',
          px: 2,
        }}
      >
        Predictive Intrusion Detection System
      </Typography>

      {/* Animated status dots */}
      <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
        {[0, 1, 2].map((i) => (
          <Box
            key={i}
            sx={{
              width: isMobile ? 6 : 8,
              height: isMobile ? 6 : 8,
              borderRadius: '50%',
              bgcolor: '#00d4ff',
              animation: `dotPulse 1.5s ease-in-out infinite ${i * 0.3}s`,
              '@keyframes dotPulse': {
                '0%, 100%': { opacity: 0.3, transform: 'scale(1)' },
                '50%': { opacity: 1, transform: 'scale(1.2)' }
              }
            }}
          />
        ))}
      </Box>
    </Box>
  );
};

export default PIDSLogo;