const fs = require('fs');

let html = fs.readFileSync('index.html', 'utf8');

// The goal is to completely flatten the structure inside <main class="main">.
// 1. We remove <div class="split-layout">, <div class="split-left">, <div class="split-right">, and their closing tags.
// 2. We extract the <section class="knowledge-intro"> and place it immediately after <section class="hero">.

// Extract pieces
const heroRegex = /<section class="hero">[\s\S]*?<\/section>/;
const heroMatch = html.match(heroRegex)[0];

const toolsGridRegex = /<div class="tools-grid">[\s\S]*?<\/div>\s*<\/section>/; 
// Wait, tools-grid is INSIDE hero in the current HTML! Look at lines 46-69.
// <section class="hero"> ... <div class="tools-grid"> ... </div> </section>
// Let's extract the actual tools grid and move it OUT of hero so we can place it below knowledge-intro.
const toolsGridInsideHero = html.match(/<div class="tools-grid">[\s\S]*?<\/div>\s*<\/section>/)[0];
// Actually, it's better to just regex the parts manually.

const toolsGridOnly = html.match(/<div class="tools-grid">[\s\S]*?<\/div>(?=\s*<\/section>)/)[0];
const heroTitleAndSub = html.match(/<h1 class="hero-title">[\s\S]*?<\/p>/)[0];

const inputCardRegex = /<div class="input-card">[\s\S]*?(?=<!-- Right side: Knowledge \/ Educational -->)/;
const inputCardMatch = html.match(inputCardRegex)[0].trim();

const blogsSectionRegex = /<section class="blogs-section" id="blogs">[\s\S]*?<\/section>/;
const blogsSectionMatch = html.match(blogsSectionRegex)[0];

const knowledgeIntroRegex = /<section class="knowledge-intro"[^>]*>[\s\S]*?<\/section>/;
const knowledgeIntroMatch = html.match(knowledgeIntroRegex)[0];

// Now let's reconstruct the <main> block
const newMainContent = `  <main class="main">
    <section class="hero">
      ${heroTitleAndSub}
    </section>

    ${knowledgeIntroMatch.replace('style="margin-top: 40px;"', 'style="margin-top: 10px; margin-bottom: 40px;"')}

    ${toolsGridOnly}

    ${inputCardMatch}

    ${blogsSectionMatch.replace('<section class="blogs-section" id="blogs">', '<section class="blogs-section" id="blogs" style="margin-top: 60px;">')}
  </main>`;

html = html.replace(/<main class="main">[\s\S]*?<\/main>/, newMainContent);
fs.writeFileSync('index.html', html);
console.log('Successfully restructured index.html');

// Now update styles.css
let css = fs.readFileSync('styles.css', 'utf8');

// Remove split layout
css = css.replace(/\.split-layout \{[\s\S]*?\}\s*@media \(min-width: 992px\) \{[\s\S]*?\}/, '');

// Update tools-grid to use 4 columns if possible
// The current tools grid is: grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
// It already stretches! But maybe we want it to specifically be 4 columns.
css = css.replace(/grid-template-columns: repeat\(auto-fit, minmax\(220px, 1fr\)\);/, 'grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));');

// Update knowledge-intro to be a flex row banner
const oldKnowledgeIntro = /\.knowledge-intro \{[\s\S]*?\}/;
const newKnowledgeIntro = `.knowledge-intro {
  display: flex;
  align-items: center;
  gap: 24px;
  background: rgba(24, 29, 46, 0.4);
  border: 1px solid var(--border2);
  border-radius: var(--radius);
  padding: 24px 32px;
  backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
  margin-bottom: 40px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.2);
}
.knowledge-intro .knowledge-icon {
  margin-bottom: 0;
  flex-shrink: 0;
  width: 56px; height: 56px;
}`;
css = css.replace(oldKnowledgeIntro, newKnowledgeIntro);

// To ensure icon has no margin-bottom inside the banner:
css = css.replace(/color: #c0d0ff; display: grid; place-items: center; margin-bottom: 20px;/, 'color: #c0d0ff; display: grid; place-items: center;');

// Make sure blogs section scroll works full width. The blogs-section inside a single column will naturally take 100%.

fs.writeFileSync('styles.css', css);
console.log('Successfully updated styles.css');
