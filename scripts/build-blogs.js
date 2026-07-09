import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import mammoth from 'mammoth';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const pdfParse = require('pdf-parse');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

const sourceDir = path.join(rootDir, 'blogs_source');
const outputDir = path.join(rootDir, 'blogs');
const indexHtmlPath = path.join(rootDir, 'index.html');

// Create directories if they don't exist
if (!fs.existsSync(sourceDir)) {
  fs.mkdirSync(sourceDir, { recursive: true });
  console.log(`Created source directory at ${sourceDir}`);
}
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
  console.log(`Created output directory at ${outputDir}`);
}

async function buildBlogs() {
  const files = fs.readdirSync(sourceDir);
  const blogCards = [];

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    const basename = path.basename(file, ext);
    const filePath = path.join(sourceDir, file);
    const stat = fs.statSync(filePath);
    
    // Formatting date
    const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
    const formattedDate = stat.birthtime.toLocaleDateString('en-US', dateOptions);
    
    let htmlContent = '';
    let excerpt = '';
    
    if (ext === '.docx') {
      console.log(`Processing DOCX: ${file}`);
      const result = await mammoth.convertToHtml({ path: filePath });
      htmlContent = result.value;
      excerpt = result.value.replace(/<[^>]*>?/gm, '').substring(0, 100) + '...';
    } else if (ext === '.pdf') {
      console.log(`Processing PDF: ${file}`);
      const dataBuffer = fs.readFileSync(filePath);
      const data = await pdfParse(dataBuffer);
      // Wrap text in p tags roughly
      const paragraphs = data.text.split('\n').filter(p => p.trim() !== '');
      htmlContent = paragraphs.map(p => `<p>${p}</p>`).join('');
      excerpt = data.text.replace(/\s+/g, ' ').substring(0, 100) + '...';
    } else if (ext === '.md' || ext === '.txt') {
      console.log(`Processing Text/Markdown: ${file}`);
      const text = fs.readFileSync(filePath, 'utf8');
      const paragraphs = text.split('\n\n').filter(p => p.trim() !== '');
      htmlContent = paragraphs.map(p => `<p>${p.replace(/\n/g, '<br/>')}</p>`).join('');
      excerpt = text.replace(/\s+/g, ' ').substring(0, 100) + '...';
    } else {
      console.log(`Skipping unsupported file: ${file}`);
      continue;
    }
    
    // Create the blog page HTML
    const blogPagePath = path.join(outputDir, `${basename}.html`);
    const title = basename.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    
    const pageHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} – Blog</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="../styles.css" />
  <style>
    .blog-container {
      max-width: 800px;
      margin: 60px auto;
      padding: 40px;
      background: var(--surface);
      border: 1px solid var(--border2);
      border-radius: var(--radius);
      box-shadow: 0 4px 40px rgba(0,0,0,0.4);
    }
    .blog-header { margin-bottom: 30px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }
    .blog-title { font-size: 32px; font-weight: 700; color: var(--text); }
    .blog-meta { color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 10px; }
    .blog-content { line-height: 1.8; color: var(--text); }
    .blog-content h1, .blog-content h2, .blog-content h3 { color: var(--text); margin-top: 30px; margin-bottom: 15px; }
    .blog-content p { margin-bottom: 16px; }
    .blog-content ul, .blog-content ol { margin-bottom: 16px; padding-left: 20px; }
    .back-link { display: inline-flex; align-items: center; gap: 6px; text-decoration: none; color: var(--accent); font-weight: 500; margin-bottom: 20px; font-size: 14px; }
    .back-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="bg-orbs">
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="orb orb-3"></div>
  </div>
  <div class="blog-container">
    <a href="../index.html#blogs" class="back-link">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
      Back to Home
    </a>
    <div class="blog-header">
      <h1 class="blog-title">${title}</h1>
      <div class="blog-meta">${formattedDate}</div>
    </div>
    <div class="blog-content">
      ${htmlContent}
    </div>
  </div>
</body>
</html>
    `.trim();
    
    fs.writeFileSync(blogPagePath, pageHtml);
    console.log(`Generated: ${blogPagePath}`);
    
    // Create card snippet
    blogCards.push(`
        <a href="./blogs/${encodeURIComponent(basename)}.html" class="blog-card">
          <div class="blog-card-image placeholder">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" color="rgba(255,255,255,0.2)"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
          </div>
          <div class="blog-card-content">
            <span class="blog-date">${formattedDate}</span>
            <h3 class="blog-title">${title}</h3>
            <p class="blog-excerpt">${excerpt}</p>
          </div>
        </a>
    `.trim());
  }

  // If no files found, we probably still want to update index.html to empty the list
  // or leave placeholders. For now let's just leave it empty if no files are there.
  if (blogCards.length === 0) {
    console.log('No blogs found in blogs_source/. Emptying blogs list.');
  }

  // Update index.html
  let indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
  
  const markerStart = '<!-- BLOGS_GRID_START -->';
  const markerEnd = '<!-- BLOGS_GRID_END -->';
  
  if (indexHtml.includes(markerStart) && indexHtml.includes(markerEnd)) {
    const regex = new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}`);
    indexHtml = indexHtml.replace(regex, `${markerStart}\n${blogCards.join('\n')}\n        ${markerEnd}`);
    fs.writeFileSync(indexHtmlPath, indexHtml);
    console.log('Updated index.html with new blog cards.');
  } else {
    console.log('Markers not found in index.html. Could not inject cards automatically.');
  }
}

buildBlogs().catch(err => {
  console.error("Error building blogs:", err);
});
