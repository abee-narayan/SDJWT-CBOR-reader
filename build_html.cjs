const fs = require('fs');

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CredentialDecoder - SD-JWT & mDOC</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <div class="bg-orbs">
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="orb orb-3"></div>
  </div>

  <header class="header">
    <div class="header-inner">
      <div class="logo">
        <div class="logo-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
        </div>
        <div>
          <span class="logo-title">CredentialDecoder</span>
          <span class="logo-sub">SD-JWT · mDOC · CBOR</span>
        </div>
      </div>
      <div class="header-badges">
        <span class="badge">🏛 UIDAI</span>
        <span class="badge">📱 ISO 18013-5</span>
        <span class="badge">🔐 SD-JWT VC</span>
      </div>
    </div>
  </header>

  <main class="main">
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-content">
        <h1 class="hero-title">Decode and Explore<br>Digital Credentials</h1>
        <p class="hero-subtitle">Inspect, validate, and understand <strong>SD-JWT VCs</strong> and <strong>mDOC</strong> credentials through an interactive developer toolkit.</p>
        <div class="hero-actions">
          <button id="btn-sample-sdjwt-hero" class="primary-cta">Generate Sample Credential</button>
        </div>
      </div>
      
      <div class="hero-visual">
        <div class="floating-card">
          <div class="fc-header">
            <span class="fc-badge">Aadhaar VC</span>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00F5C3" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          </div>
          <div class="fc-body">
            <div class="fc-row"><span class="fc-label">Name:</span> <span class="fc-value">John Doe</span></div>
            <div class="fc-row"><span class="fc-label">Age:</span> <span class="fc-value">24</span></div>
            <div class="fc-row"><span class="fc-label">Status:</span> <span class="fc-value" style="color: #00F5C3;">Verified ✓</span></div>
          </div>
          <div class="fc-glow"></div>
        </div>
      </div>
    </div>

    <!-- Stats Section -->
    <div class="stats-section">
      <div class="stat-card">
        <div class="stat-value">50M+</div>
        <div class="stat-label">Aadhaar Wallet Downloads</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">200+</div>
        <div class="stat-label">Relying Parties</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">100K+</div>
        <div class="stat-label">Monthly Verifications</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">3</div>
        <div class="stat-label">Credential Formats</div>
      </div>
    </div>

    <!-- Decoder Section -->
    <section class="decoder-section" style="margin-top: 60px;">
      
      <!-- Tools Grid -->
      <div class="tools-grid">
        <a href="blogs/key-generator.html" class="tool-link tool-link-blue">
          <div class="tool-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg></div>
          Open Key Generator
        </a>
        <a href="blogs/uidai-intent.html" class="tool-link tool-link-green">
          <div class="tool-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="8" y1="12" x2="16" y2="12"></line><line x1="12" y1="8" x2="12" y2="16"></line></svg></div>
          UIDAI Intent / QR Generator
        </a>
        <a href="blogs/cer-to-pem.html" class="tool-link tool-link-purple">
          <div class="tool-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></div>
          CER to PEM Converter
        </a>
        <a href="blogs/svg-vectorizer.html" class="tool-link tool-link-yellow">
          <div class="tool-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="16 3 21 8 8 21 3 21 3 16 16 3"></polygon></svg></div>
          SVG Logo Vectorizer
        </a>
      </div>

      <!-- Input Card -->
      <div class="input-card">
        <div class="input-header">
          <div class="input-title">CREDENTIAL INPUT</div>
          <div class="input-actions">
            <button class="btn btn-secondary" id="btn-sample-sdjwt">Sample SD-JWT</button>
            <button class="btn btn-secondary" id="btn-sample-mdoc">Sample mDOC</button>
            <button class="btn btn-secondary" id="btn-clear">Clear</button>
          </div>
        </div>
        <div class="input-body">
          <textarea id="credential-input" class="credential-textarea" placeholder="Paste SD-JWT (eyJ...) or base64-encoded mDOC (CBOR) here..."></textarea>
        </div>

        <div id="results-section" class="results-section hidden">
          <div class="results-header">
            <div class="results-title">
              <span id="credential-badge" class="badge badge-lg badge-blue">SD-JWT VC</span>
              <span>Decoded Successfully</span>
            </div>
            <button class="btn btn-primary" id="btn-copy">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              Copy JSON
            </button>
          </div>

          <div id="tabs" class="tabs">
            <button class="tab active" data-tab="identity">Identity</button>
            <button class="tab" data-tab="address">Address</button>
            <button class="tab" data-tab="contact">Contact</button>
            <button class="tab" data-tab="issuance">Issuance</button>
            <button class="tab" data-tab="photo">Photo</button>
            <button class="tab" data-tab="raw">Raw JSON</button>
          </div>

          <div id="tab-identity" class="tab-panel active"></div>
          <div id="tab-address" class="tab-panel hidden"></div>
          <div id="tab-contact" class="tab-panel hidden"></div>
          <div id="tab-issuance" class="tab-panel hidden"></div>
          <div id="tab-photo" class="tab-panel hidden"></div>
          <div id="tab-raw" class="tab-panel hidden"></div>
        </div>

        <div id="error-section" class="error-section hidden">
          <div class="error-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <div>
            <div class="error-title">Decoding Failed</div>
            <div id="error-message" class="error-message"></div>
          </div>
        </div>
      </div>
    </section>

    <!-- Premium Full Width Blogs Section -->
    <section class="blogs-section" id="blogs" style="margin-top: 60px;">
      <div class="blogs-header">
        <h2 class="section-title">Knowledge Base</h2>
        <p class="section-subtitle">Swipe to explore the latest architectures and insights</p>
      </div>
      <div class="blogs-grid">
        <a href="./blogs/registry-blog.html" class="blog-card">
          <div class="blog-card-image" style="background-image: url('./assets/trust_registry.png');"></div>
          <div class="blog-card-content">
            <div class="blog-meta">
              <span class="blog-tag">Architecture</span>
              <span class="blog-date">July 5, 2026</span>
            </div>
            <h3 class="blog-title">The Architectural Playbook</h3>
            <p class="blog-excerpt">A practical guide for governments and digital identity architects to understand the major building blocks of a Verifiable Credentials ecosystem.</p>
            <div class="blog-action">Read Article <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
          </div>
        </a>
        <a href="./blogs/rethinking-identity-blog.html" class="blog-card">
          <div class="blog-card-image" style="background-image: url('./assets/selective_disclosure.png');"></div>
          <div class="blog-card-content">
            <div class="blog-meta">
              <span class="blog-tag">Strategy</span>
              <span class="blog-date">July 5, 2026</span>
            </div>
            <h3 class="blog-title">Rethinking How Indians Share Their Identity</h3>
            <p class="blog-excerpt">An exploration into shifting the trust anchor offline, democratizing verification, and dismantling photocopy culture.</p>
            <div class="blog-action">Read Article <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
          </div>
        </a>
      </div>
    </section>
  </main>

  <footer class="footer">
    <p>This tool runs entirely in your browser. No data is sent to any server.</p>
    <p>Supports UIDAI Aadhaar SD-JWT VC · ISO 18013-5 mDOC (CBOR)</p>
  </footer>

  <!-- CBOR library (cbor-js) via CDN -->
  <script src="https://cdn.jsdelivr.net/npm/cbor-js@0.1.0/cbor.min.js"></script>
  <script src="decoder.js"></script>
  <script>
    // Hook up the new primary hero CTA to the existing sample logic
    document.getElementById('btn-sample-sdjwt-hero').addEventListener('click', () => {
      document.getElementById('btn-sample-sdjwt').click();
      document.getElementById('credential-input').scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  </script>
</body>
</html>
`;

fs.writeFileSync('index.html', html);
console.log('Successfully wrote index.html');
