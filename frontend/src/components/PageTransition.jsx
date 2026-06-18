import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { Box } from '@mui/material';

const PageTransition = ({ children }) => {
  const location = useLocation();
  const [displayChildren, setDisplayChildren] = useState(children);
  const [transitionStage, setTransitionStage] = useState('enter');

  useEffect(() => {
    setTransitionStage('exit');
    const timeout = setTimeout(() => {
      setDisplayChildren(children);
      setTransitionStage('enter');
    }, 200);
    return () => clearTimeout(timeout);
  }, [location.pathname]);

  // On first mount, just show
  useEffect(() => {
    setDisplayChildren(children);
  }, [children]);

  return (
    <Box
      className={`page-transition-${transitionStage === 'exit' ? 'exit-active' : 'enter-active'}`}
      sx={{
        opacity: transitionStage === 'exit' ? 0 : 1,
        transform: transitionStage === 'exit' ? 'translateY(-8px)' : 'translateY(0)',
        transition: 'opacity 0.3s ease, transform 0.3s ease',
        minHeight: '100vh',
      }}
    >
      {displayChildren}
    </Box>
  );
};

export default PageTransition;