import React from 'react';

export const RightHeroIllustration: React.FC<{ className?: string }> = ({ className = '' }) => {
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
        {/* Paper Plane in Top-Right */}
        <g transform="translate(230, 20)">
          <path
            d="M0 25L32 0L20 35L14 24L0 25Z"
            fill="#0066FF"
          />
          <path
            d="M14 24L32 0L12 18L14 24Z"
            fill="#60A5FA"
          />
        </g>
        {/* Dashed flight trail */}
        <path
          d="M195 70C210 50 220 38 230 35"
          stroke="#93C5FD"
          strokeWidth="2"
          strokeDasharray="4 4"
          strokeLinecap="round"
        />

        {/* 3D Browser Window Card */}
        <g transform="translate(60, 50) rotate(3)">
          <rect
            x="0"
            y="0"
            width="180"
            height="180"
            rx="20"
            fill="#FFFFFF"
            stroke="#E2E8F0"
            strokeWidth="2.5"
            className="drop-shadow-lg"
          />
          {/* Window Top Controls */}
          <circle cx="20" cy="18" r="3.5" fill="#3B82F6" />
          <circle cx="32" cy="18" r="3.5" fill="#60A5FA" />
          <circle cx="44" cy="18" r="3.5" fill="#93C5FD" />

          {/* Shield Badge inside Browser */}
          <g transform="translate(45, 40)">
            <path
              d="M45 5L10 18V45C10 65 25 82 45 88C65 82 80 65 80 45V18L45 5Z"
              fill="#0066FF"
            />
            {/* White Checkmark */}
            <path
              d="M32 45L42 55L58 35"
              stroke="#FFFFFF"
              strokeWidth="5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </g>
        </g>

        {/* Floating File / Document card */}
        <g transform="translate(30, 160) rotate(-6)">
          <rect
            x="0"
            y="0"
            width="55"
            height="65"
            rx="10"
            fill="#DBEAFE"
            stroke="#BFDBFE"
            strokeWidth="1.5"
            className="drop-shadow-md"
          />
          <rect x="10" y="14" width="35" height="5" rx="2.5" fill="#0066FF" />
          <rect x="10" y="25" width="28" height="4" rx="2" fill="#60A5FA" />
          <rect x="10" y="35" width="22" height="4" rx="2" fill="#60A5FA" />
        </g>
      </svg>
    </div>
  );
};
