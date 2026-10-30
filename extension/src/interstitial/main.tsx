import React from 'react';
import ReactDOM from 'react-dom/client';
import { Interstitial } from './Interstitial';
import '../styles/extension.css';

const root = document.getElementById('root');
if (root) {
  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <Interstitial />
    </React.StrictMode>
  );
}
