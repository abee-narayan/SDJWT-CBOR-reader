import { defineConfig } from 'vite';

function aadhaarCallbackPlugin() {
  let latestCallback = null;

  return {
    name: 'aadhaar-callback',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url === '/api/callback' && req.method === 'POST') {
          let body = '';
          req.on('data', chunk => {
            body += chunk.toString();
          });
          req.on('end', () => {
            console.log('Received callback:', body);
            latestCallback = { timestamp: Date.now(), data: body };
            // Send Acknowledgement as per spec
            res.setHeader('Content-Type', 'application/xml');
            res.statusCode = 200;
            res.end(`<Response><TxnID>1</TxnID><ResponseCode>200</ResponseCode><ResponseMsg>Success</ResponseMsg></Response>`);
          });
        } else if (req.url === '/api/callback/latest' && req.method === 'GET') {
          res.setHeader('Content-Type', 'application/json');
          if (latestCallback) {
            res.statusCode = 200;
            res.end(JSON.stringify(latestCallback));
          } else {
            res.statusCode = 404;
            res.end(JSON.stringify({ error: 'No data' }));
          }
        } else if (req.url === '/api/callback/clear' && req.method === 'POST') {
          latestCallback = null;
          res.statusCode = 200;
          res.end(JSON.stringify({ success: true }));
        } else {
          next();
        }
      });
    }
  };
}

export default defineConfig({
  plugins: [aadhaarCallbackPlugin()]
});
