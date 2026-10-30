import React from 'react';
import { Link } from 'react-router-dom';
import { Lock } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-black/[0.03] bg-transparent py-2 sm:py-2.5 px-4 sm:px-8 mt-auto">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-600">
        <div className="flex items-center gap-2">
          <img src="/aegis-gothic-shield-emblem.png" alt="AEGIS Shield" className="w-4 h-4 object-contain shrink-0" />
          <span className="font-bold text-slate-800">AEGIS Browser Defense</span>
          <span>&middot;</span>
          <span>Deterministic Policy Engine &amp; Multi-Engine Verification</span>
        </div>

        <div className="flex items-center gap-6">
          <Link to="/coverage-privacy" className="hover:text-black transition-colors font-medium">
            Coverage &amp; Privacy
          </Link>
          <Link to="/settings" className="hover:text-black transition-colors font-medium">
            Backend API Configuration
          </Link>
          <div className="flex items-center gap-1.5 text-slate-600 font-medium">
            <Lock className="w-3.5 h-3.5 text-slate-700" />
            <span>Zero Client Secrets</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
