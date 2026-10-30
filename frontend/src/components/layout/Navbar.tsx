import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { AegisLogo } from '../common/AegisLogo';
import { apiClient } from '../../services/api-client';
import { Shield, History, Settings } from 'lucide-react';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  useEffect(() => {
    let isMounted = true;
    const checkConnection = async () => {
      try {
        await apiClient.checkHealth();
        if (isMounted) setBackendOnline(true);
      } catch {
        if (isMounted) setBackendOnline(false);
      }
    };

    checkConnection();
    const interval = setInterval(checkConnection, 20000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { label: 'Scanner', path: '/', icon: Shield },
    { label: 'Scan History', path: '/history', icon: History },
    { label: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <header className="sticky top-0 z-40 bg-transparent border-b border-black/[0.03] transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-8 h-14 flex items-center justify-between">
        {/* Logo */}
        <Link
          to="/"
          className="flex items-center group focus:outline-none focus-visible:ring-2 focus-visible:ring-black rounded-lg"
        >
          <AegisLogo size="md" variant="black" />
        </Link>

        {/* Center Navigation Links */}
        <nav className="flex items-center gap-2 sm:gap-4">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-2 px-4 py-2 rounded-full text-xs font-bold transition-all ${
                  isActive
                    ? 'bg-black/[0.06] text-black border border-black/[0.08] shadow-xs'
                    : 'text-slate-700 hover:text-black hover:bg-black/[0.03] font-semibold'
                }`}
              >
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-black stroke-[2.25]' : 'text-slate-600'
                  }`}
                />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Right Backend Status Pill */}
        <div className="flex items-center">
          <Link
            to="/settings"
            title={
              backendOnline === true
                ? 'Backend service is online'
                : backendOnline === false
                ? 'Backend service unreachable'
                : 'Connecting to backend...'
            }
            className="flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-bold bg-transparent border border-black/[0.1] shadow-xs hover:border-black/25 transition-colors"
          >
            <span
              className={`w-2 h-2 rounded-full ${
                backendOnline === true
                  ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]'
                  : backendOnline === false
                  ? 'bg-black'
                  : 'bg-slate-400 animate-pulse'
              }`}
            />
            <span className="text-slate-900">
              {backendOnline === true
                ? 'Backend Online'
                : backendOnline === false
                ? 'Backend Offline'
                : 'Connecting...'}
            </span>
          </Link>
        </div>
      </div>
    </header>
  );
};
