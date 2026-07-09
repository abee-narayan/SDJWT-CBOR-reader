const fs = require('fs');
let css = fs.readFileSync('styles.css', 'utf8');

// Update text-muted color
css = css.replace(/--text-muted:\s*#8b93b0;/g, '--text-muted:#B8C4D0;');

// Update badges
const badgeRegex = /\/\* ─── Badges ─── \*\/[\s\S]*?(?=\/\* ─── Main layout ─── \*\/)/;
const newBadges = `/* ─── Badges ─── */
.badge {
  font-size: 11px; font-weight: 600; padding: 6px 14px;
  border-radius: 999px; letter-spacing: 0.4px;
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.header-badges { display: flex; gap: 8px; flex-wrap: wrap; }
.badge-blue   { background: rgba(0, 255, 200, 0.08); color: #00F5C3; border: 1px solid rgba(0, 255, 200, 0.2); }
.badge-purple { background: rgba(13, 148, 136, 0.18);  color: #c399f5; border: 1px solid rgba(13, 148, 136,0.3); }
.badge-green  { background: rgba(57, 217, 138, 0.15);  color: #5edf9e; border: 1px solid rgba(57,217,138,0.3); }
.badge-yellow { background: rgba(244, 185, 66, 0.15);  color: #f4c96b; border: 1px solid rgba(244,185,66,0.3); }
.badge-red    { background: rgba(242, 95, 92, 0.15);   color: #f58280; border: 1px solid rgba(242,95,92,0.3); }
.badge-lg { font-size: 13px; padding: 8px 18px; }
`;
css = css.replace(badgeRegex, newBadges);

// Replace Main Layout & Hero & Tools
const layoutRegex = /\/\* ─── Main layout ─── \*\/[\s\S]*?(?=\/\* ─── Knowledge Hub ─── \*\/)/;
const newLayout = `/* ─── Main layout ─── */
.main { position: relative; z-index: 1; max-width: 1200px; margin: 0 auto; padding: 48px 24px 80px; }

/* ─── Hero Section ────────────────────────────────────── */
.hero-section {
  display: flex;
  flex-direction: column;
  gap: 40px;
  margin-bottom: 60px;
  align-items: center;
}
@media (min-width: 992px) {
  .hero-section { flex-direction: row; text-align: left; }
  .hero-content { flex: 1.2; padding-right: 40px; }
  .hero-visual { flex: 0.8; display: flex; justify-content: center; align-items: center; }
}
.hero-title {
  font-size: clamp(36px, 5vw, 56px); font-weight: 800;
  letter-spacing: -1.5px; line-height: 1.1;
  color: #fff;
  margin-bottom: 20px;
}
.hero-subtitle {
  color: var(--text-muted); font-size: 18px; max-width: 600px; line-height: 1.7; margin-bottom: 32px;
}
.hero-actions {
  display: flex; gap: 16px;
}
.primary-cta {
  background: linear-gradient(90deg, #00F5C3, #00D4FF);
  color: #04100e;
  border: none;
  padding: 14px 28px;
  font-size: 16px;
  font-weight: 700;
  border-radius: 999px;
  cursor: pointer;
  transition: transform 0.2s, box-shadow 0.2s;
  box-shadow: 0 8px 20px rgba(0, 245, 195, 0.3);
}
.primary-cta:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 25px rgba(0, 245, 195, 0.4);
}

/* ─── Floating Credential ─────────────────────────────── */
.floating-card {
  width: 320px;
  background: rgba(17, 21, 32, 0.7);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(0, 245, 195, 0.3);
  border-radius: 24px;
  padding: 24px;
  position: relative;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
  animation: floatCard 6s ease-in-out infinite alternate;
}
.floating-card::before {
  content: ''; position: absolute; inset: 0;
  border-radius: 24px; padding: 1px;
  background: linear-gradient(135deg, rgba(0,245,195,0.5), transparent);
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  pointer-events: none;
}
.fc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px;}
.fc-badge { background: rgba(0,245,195,0.1); color: #00F5C3; font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 8px; }
.fc-row { display: flex; justify-content: space-between; margin-bottom: 12px; font-size: 14px; font-family: 'JetBrains Mono', monospace; }
.fc-label { color: var(--text-muted); }
.fc-value { color: #fff; font-weight: 500; }
.fc-glow {
  position: absolute; width: 100%; height: 100%; top: 0; left: 0;
  background: radial-gradient(circle at 50% 0%, rgba(0, 245, 195, 0.15), transparent 70%);
  pointer-events: none; border-radius: 24px;
}
@keyframes floatCard {
  0% { transform: translateY(0) rotate(0deg); }
  100% { transform: translateY(-15px) rotate(1deg); }
}

/* ─── Stats Section ───────────────────────────────────── */
.stats-section {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
  margin-bottom: 60px;
  background: rgba(255,255,255,0.02);
  border-radius: 24px;
  padding: 32px;
  border: 1px solid var(--border);
}
@media (min-width: 768px) {
  .stats-section { grid-template-columns: repeat(4, 1fr); }
}
.stat-card {
  display: flex; flex-direction: column; gap: 8px;
}
.stat-value {
  font-size: 32px; font-weight: 800; color: #fff;
  background: linear-gradient(90deg, #fff, #B8C4D0);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
}
.stat-label {
  font-size: 13px; color: var(--text-muted); font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;
}

/* ─── Tools Grid ──────────────────────────────────────── */
.tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 40px; }
.tool-link {
  display: flex; align-items: center; gap: 12px;
  background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 16px; padding: 16px;
  text-decoration: none; color: var(--text); font-size: 14px; font-weight: 600;
  transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1); backdrop-filter: blur(8px);
}
.tool-link:hover { background: rgba(255,255,255,0.06); transform: translateY(-4px); box-shadow: 0 12px 24px rgba(0,0,0,0.2); border-color: rgba(255,255,255,0.15); }
.tool-icon {
  display: grid; place-items: center; width: 36px; height: 36px; border-radius: 10px;
  background: rgba(255,255,255,0.1); flex-shrink: 0;
}
.tool-link-blue .tool-icon { color: #5eead4; background: rgba(20, 184, 166,0.15); }
.tool-link-green .tool-icon { color: #5edf9e; background: rgba(57,217,138,0.15); }
.tool-link-purple .tool-icon { color: #c399f5; background: rgba(13, 148, 136,0.15); }
.tool-link-yellow .tool-icon { color: #f4c96b; background: rgba(244,185,66,0.15); }

`;
css = css.replace(layoutRegex, newLayout);

// Apply hover shadow to blog card
css = css.replace(/box-shadow: 0 20px 40px rgba\(0,0,0,0.4\);/g, 'box-shadow: 0 20px 40px rgba(0,0,0,0.45), 0 0 30px rgba(0,255,200,0.15);');

fs.writeFileSync('styles.css', css);
console.log('Successfully updated styles.css');
