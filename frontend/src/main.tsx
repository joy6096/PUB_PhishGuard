import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './app-base.css';
import './styles.css';
import './admin.css';

createRoot(document.getElementById('root')!).render(
  <React.StrictMode><App /></React.StrictMode>,
);

