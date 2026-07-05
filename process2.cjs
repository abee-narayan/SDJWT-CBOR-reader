const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, 'blogs', 'rethinking_identity', 'content.txt');
const outputPath = path.join(__dirname, 'blogs', 'rethinking_identity', 'chapters.json');

const rawHtml = fs.readFileSync(contentPath, 'utf8');

// Regex to match h1, h2, h3 and capture the tag, inner text, and content until the next heading
// We use a lookahead for the next <h[123]> or end of string
const regex = /(<h[123]>.*?<\/h[123]>)([\s\S]*?)(?=<h[123]>|$)/g;

let match;
const chapters = [];
let chapterIndex = 1;

while ((match = regex.exec(rawHtml)) !== null) {
  const headingTag = match[1];
  let bodyContent = match[2].trim();
  
  // Extract pure text title from the heading tag by stripping inner tags like <strong>
  const titleText = headingTag.replace(/<[^>]+>/g, '').trim();
  
  // Clean up table tags if present (adding responsive wrappers)
  // Actually, we do this on the front-end, but we can do it here too if we want.
  // The front-end renderChapter does it: contentHtml.replace(/<table/g, '<div class="table-responsive"><table')
  
  // Combine heading and body back into content for the JSON, keeping the heading
  let fullContent = headingTag + bodyContent;
  
  chapters.push({
    id: `chapter-${chapterIndex}`,
    title: titleText || `Introduction`,
    content: fullContent
  });
  
  chapterIndex++;
}

// Add author metadata to the first chapter
if (chapters.length > 0) {
  const authorHtml = `<p style="color: var(--accent); margin-top: -15px; margin-bottom: 24px; font-weight: 500;">By: <a href="https://www.linkedin.com/in/abee-narayan-445176191/" target="_blank" style="color: inherit; text-decoration: none;">Abee Narayan</a> | <a href="https://github.com/abee-narayan" target="_blank" style="color: inherit; text-decoration: none;">GitHub</a></p>`;
  chapters[0].content = chapters[0].content.replace(/<\/h1>/i, `</h1>${authorHtml}`);
}

fs.writeFileSync(outputPath, JSON.stringify(chapters, null, 2));
console.log(`Successfully generated ${chapters.length} chapters to ${outputPath}`);
