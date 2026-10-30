import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AegisLogo } from './AegisLogo';

interface PreloaderProps {
  onComplete?: () => void;
  minDurationMs?: number;
}

export const Preloader: React.FC<PreloaderProps> = ({
  onComplete,
  minDurationMs = 700,
}) => {
  const [isVisible, setIsVisible] = useState(true);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    // Check if user prefers reduced motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      setIsVisible(false);
      onComplete?.();
      return;
    }

    const startTime = performance.now();
    let frameId: number;

    const animateProgress = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const pct = Math.min(100, Math.round((elapsed / minDurationMs) * 100));
      setProgress(pct);

      if (elapsed < minDurationMs) {
        frameId = requestAnimationFrame(animateProgress);
      } else {
        setTimeout(() => {
          setIsVisible(false);
          onComplete?.();
        }, 150);
      }
    };

    frameId = requestAnimationFrame(animateProgress);

    return () => cancelAnimationFrame(frameId);
  }, [minDurationMs, onComplete]);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          key="aegis-preloader"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, transition: { duration: 0.35, ease: 'easeInOut' } }}
          className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-white"
          aria-live="polite"
          aria-label="Loading AEGIS System"
        >
          <div className="flex flex-col items-center">
            {/* Centered Dark Navy AEGIS emblem & wordmark */}
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
            >
              <AegisLogo size="xl" variant="navy" />
            </motion.div>

            {/* Mac-inspired slim loading indicator */}
            <div className="w-48 h-1 bg-slate-100 rounded-full mt-8 overflow-hidden relative border border-slate-200/60">
              <motion.div
                className="h-full bg-[#0B2447] rounded-full"
                style={{ width: `${progress}%` }}
                transition={{ ease: 'easeOut', duration: 0.1 }}
              />
            </div>

            <span className="text-xs font-mono text-slate-400 mt-3 tracking-wider">
              INITIALIZING DEFENSE ENGINE
            </span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
