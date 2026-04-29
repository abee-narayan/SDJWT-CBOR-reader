import React from 'react';
import Vectorizer from './components/Vectorizer';
import { Sparkles } from 'lucide-react';
import './index.css';
import './App.css';

function App() {
  return (
    <div className="app-container">
      <header className="header animate-fade-in">
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '12px', justifyContent: 'center' }}>
          <Sparkles size={36} color="var(--primary)" />
          <h1>SVG Vectorizer</h1>
        </div>
        <p>Convert raster logos to clean, scalable, &lt;10KB vector paths</p>
      </header>

      <main>
        <Vectorizer />
      </main>
    </div>
  );
}

export default App;
