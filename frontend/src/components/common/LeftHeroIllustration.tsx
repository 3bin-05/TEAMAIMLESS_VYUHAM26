import React from 'react';

export const LeftHeroIllustration: React.FC<{ className?: string }> = ({ className = '' }) => {
  return (
    <div className={`select-none pointer-events-none ${className}`}>
      <svg
        width="280"
        height="260"
        viewBox="0 0 280 260"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-auto drop-shadow-xl"
      >
        {/* Browser Window Card */}
        <g transform="translate(20, 20) rotate(-4)">
          <rect
            x="0"
            y="0"
            width="170"
            height="180"
            rx="16"
            fill="#FFFFFF"
            stroke="#E2E8F0"
            strokeWidth="2"
          />
          {/* Browser Header Bar */}
          <path
            d="M0 16C0 7.16344 7.16344 0 16 0H154C162.837 0 170 7.16344 170 16V34H0V16Z"
            fill="#3B82F6"
          />
          {/* Header Dots */}
          <circle cx="16" cy="17" r="3.5" fill="#BFDBFE" />
          <circle cx="28" cy="17" r="3.5" fill="#BFDBFE" />
          <circle cx="40" cy="17" r="3.5" fill="#BFDBFE" />

          {/* Browser Content */}
          <rect x="18" y="50" width="40" height="40" rx="20" fill="#60A5FA" fillOpacity="0.3" />
          {/* Globe Icon */}
          <circle cx="38" cy="70" r="14" stroke="#2563EB" strokeWidth="2" />
          <ellipse cx="38" cy="70" rx="6" ry="14" stroke="#2563EB" strokeWidth="1.5" />
          <line x1="24" y1="70" x2="52" y2="70" stroke="#2563EB" strokeWidth="1.5" />

          {/* Lines of text */}
          <rect x="18" y="105" width="80" height="8" rx="4" fill="#E2E8F0" />
          <rect x="18" y="122" width="60" height="8" rx="4" fill="#F1F5F9" />
          <rect x="18" y="139" width="45" height="8" rx="4" fill="#F1F5F9" />
        </g>

        {/* Magnifying Glass with Link */}
        <g transform="translate(110, 85)">
          {/* Lens Outer Circle */}
          <circle
            cx="48"
            cy="48"
            r="44"
            fill="#FFFFFF"
            stroke="#0066FF"
            strokeWidth="7"
            className="drop-shadow-lg"
          />
          {/* Lens Fill Soft Blue */}
          <circle cx="48" cy="48" r="38" fill="#EFF6FF" fillOpacity="0.8" />
          {/* Chain / Link Icon inside Lens */}
          <g transform="translate(26, 26) scale(1.1)">
            <path
              d="M15 25L25 15C28 12 32 12 35 15C38 18 38 22 35 25L30 30M25 15L15 25"
              stroke="#0066FF"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M25 15L30 10C33 7 37 7 40 10C43 13 43 17 40 20L35 25"
              stroke="#0066FF"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M15 25L10 30C7 33 7 37 10 40C13 43 17 43 20 40L25 35"
              stroke="#0066FF"
              strokeWidth="4"
              strokeLinecap="round"
            />
          </g>

          {/* Handle */}
          <rect
            x="20"
            y="85"
            width="14"
            height="40"
            rx="7"
            transform="rotate(-40 20 85)"
            fill="#0066FF"
          />
        </g>

        {/* Hand Illustration holding handle */}
        <g transform="translate(0, 140)">
          <path
            d="M-20 60C10 50 40 30 60 10C65 5 75 0 85 5C95 10 95 20 90 28C85 36 70 50 60 55C50 60 20 70 -20 80Z"
            fill="#FFFFFF"
            stroke="#0F172A"
            strokeWidth="2"
          />
          {/* Sleeve accent */}
          <path d="M-10 65L-5 85" stroke="#0066FF" strokeWidth="6" strokeLinecap="round" />
        </g>
      </svg>
    </div>
  );
};
