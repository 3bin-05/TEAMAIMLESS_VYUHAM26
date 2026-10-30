import React, { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Preloader } from './components/common/Preloader';
import { Layout } from './components/layout/Layout';
import { Home } from './pages/Home';
import { ScanResultPage } from './pages/ScanResultPage';
import { HistoryPage } from './pages/HistoryPage';
import { HistoryDetailPage } from './pages/HistoryDetailPage';
import { SettingsPage } from './pages/SettingsPage';
import { CoveragePrivacyPage } from './pages/CoveragePrivacyPage';
import { NotFoundPage } from './pages/NotFoundPage';

export const App: React.FC = () => {
  const [preloaderDone, setPreloaderDone] = useState(false);

  return (
    <>
      {!preloaderDone && (
        <Preloader onComplete={() => setPreloaderDone(true)} minDurationMs={750} />
      )}
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="analyze" element={<Home />} />
            <Route path="scan/:scanId" element={<ScanResultPage />} />
            <Route path="history" element={<HistoryPage />} />
            <Route path="history/:scanId" element={<HistoryDetailPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="coverage-privacy" element={<CoveragePrivacyPage />} />
            <Route path="privacy" element={<CoveragePrivacyPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </>
  );
};

export default App;
