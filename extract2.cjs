const mammoth = require('mammoth');
const fs = require('fs');
const path = require('path');

const inputDocx = path.join(__dirname, 'blogs_source', 'Rethinking How Indians Share Their Identity.docx');
const outputHtml = path.join(__dirname, 'blogs', 'rethinking_identity', 'content.txt');
const imageDir = path.join(__dirname, 'blogs', 'rethinking_identity', 'images');

// Create directories if they don't exist
if (!fs.existsSync(path.dirname(outputHtml))) {
  fs.mkdirSync(path.dirname(outputHtml), { recursive: true });
}
if (!fs.existsSync(imageDir)) {
  fs.mkdirSync(imageDir, { recursive: true });
}

let imageCounter = 1;

const options = {
  convertImage: mammoth.images.inline(function(element) {
    return element.read("base64").then(function(imageBuffer) {
      const extension = element.contentType.split("/")[1] || "png";
      const filename = `image_${imageCounter}.${extension}`;
      const imagePath = path.join(imageDir, filename);
      
      fs.writeFileSync(imagePath, Buffer.from(imageBuffer, 'base64'));
      console.log(`Saved image: ${filename}`);
      
      const src = `./images/${filename}`;
      imageCounter++;
      
      return {
        src: src
      };
    });
  })
};

mammoth.convertToHtml({path: inputDocx}, options)
  .then(function(result) {
    const html = result.value; // The generated HTML
    const messages = result.messages; // Any messages, such as warnings during conversion
    
    fs.writeFileSync(outputHtml, html);
    console.log('Extraction complete! HTML saved to', outputHtml);
    
    if (messages.length > 0) {
      console.log('Messages:', messages);
    }
  })
  .catch(function(err) {
    console.error('Error during extraction:', err);
  });
