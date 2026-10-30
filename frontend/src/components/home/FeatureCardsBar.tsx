import React from 'react';
import { Brain, Globe, Eye } from 'lucide-react';

export const FeatureCardsBar: React.FC = () => {
  const features = [
    {
      title: 'AI Classification',
      description: 'Detects phishing, malware and suspicious content.',
      icon: Brain,
    },
    {
      title: 'Threat Intelligence',
      description: 'Checks against trusted threat databases.',
      icon: Globe,
    },
    {
      title: 'Lookalike Detection',
      description: 'Identifies brand impersonation and deceptive domains',
      icon: Eye,
    },
  ];

  return (
    <div className="w-full max-w-4xl mt-4 sm:mt-5 bg-white/90 backdrop-blur-md rounded-2xl border border-neutral-200/80 shadow-[0_4px_30px_rgba(0,0,0,0.03)] p-3 sm:py-3.5 sm:px-5 grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-neutral-100">
      {features.map((feature, idx) => {
        const Icon = feature.icon;
        return (
          <div
            key={idx}
            className={`flex items-start gap-3.5 py-1.5 px-3 ${
              idx === 0 ? 'md:pl-1' : idx === 2 ? 'md:pr-1' : ''
            }`}
          >
            <div className="w-10 h-10 rounded-xl bg-neutral-100 flex items-center justify-center text-neutral-800 shrink-0 shadow-xs border border-neutral-200/60">
              <Icon className="w-5 h-5 text-neutral-800" />
            </div>
            <div>
              <h3 className="font-bold text-xs sm:text-sm text-neutral-900 tracking-tight leading-tight mb-0.5">
                {feature.title}
              </h3>
              <p className="text-[11px] sm:text-xs text-neutral-500 leading-snug font-normal">
                {feature.description}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
};
