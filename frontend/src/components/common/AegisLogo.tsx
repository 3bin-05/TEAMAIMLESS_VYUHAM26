import React from 'react';

interface AegisLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  variant?: 'black' | 'navy' | 'white' | 'blue';
  showWordmark?: boolean;
}

export const AegisLogo: React.FC<AegisLogoProps> = ({
  className = '',
  size = 'md',
  variant = 'black',
  showWordmark = true,
}) => {
  const sizeMap = {
    sm: { icon: 26, text: 'text-base', spacing: 'gap-2.5' },
    md: { icon: 38, text: 'text-2xl', spacing: 'gap-3' },
    lg: { icon: 52, text: 'text-3xl', spacing: 'gap-3.5' },
    xl: { icon: 84, text: 'text-5xl', spacing: 'gap-4' },
  };

  const { icon, text, spacing } = sizeMap[size];

  const textColor =
    variant === 'white'
      ? 'text-white'
      : variant === 'blue'
      ? 'text-blue-700'
      : variant === 'navy'
      ? 'text-[#0B2447]'
      : 'text-black';

  return (
    <div className={`inline-flex items-center ${spacing} ${className}`} role="img" aria-label="AEGIS Logo">
      <img
        src="/aegis-gothic-shield-emblem.png"
        alt="AEGIS Gothic Shield Emblem"
        className="shrink-0 object-contain transition-transform duration-200 group-hover:scale-105 select-none"
        style={{ width: icon, height: icon }}
        draggable={false}
      />

      {showWordmark && (
        <div className="flex flex-col leading-none select-none justify-center">
          <span
            className={`uppercase ${text} ${textColor}`}
            style={{
              fontFamily: "'Trajan Pro', 'Cinzel', Georgia, serif",
              letterSpacing: '0.14em',
              fontWeight: 800,
              lineHeight: 1.05,
            }}
          >
            AEGIS
          </span>
          {size !== 'sm' && (
            <span
              className={`text-[8px] uppercase tracking-widest font-bold mt-1 ${
                variant === 'white' ? 'text-blue-200' : 'text-slate-600'
              }`}
            >
              AI BROWSER DEFENSE
            </span>
          )}
        </div>
      )}
    </div>
  );
};
