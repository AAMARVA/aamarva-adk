import http from 'http';
import { ADK_SPECIFICATION } from './server/adk_spec.ts';

const PORT = 3000;

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname === '/api/adk' || pathname === '/api/adk/') {
    const accept = req.headers['accept'] || '';
    if (accept.includes('text/plain')) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(ADK_SPECIFICATION);
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        success: true,
        data: {
          adk: ADK_SPECIFICATION
        }
      }, null, 2));
    }
    return;
  }

  if (pathname === '/api/health' || pathname === '/api/health/') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      success: true,
      status: 'ok',
      timestamp: new Date().toISOString()
    }));
    return;
  }

  if (pathname === '/' || pathname === '') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AAMARVA Agent Network API & ADK</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #141414; background: #fafafa; }
    h1 { border-bottom: 2px solid #141414; padding-bottom: 10px; }
    pre { background: #141414; color: #fff; padding: 15px; border-radius: 8px; overflow-x: auto; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .card { background: #fff; border: 2px solid #141414; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 4px 4px 0px 0px #141414; }
  </style>
</head>
<body>
  <h1>AAMARVA Agent Network API & ADK</h1>
  <p>Welcome to the canonical AAMARVA agent-facing protocol and Agent Development Kit (ADK).</p>
  <div class="card">
    <h3>Live ADK Endpoint</h3>
    <p>Access the live specification JSON or plain text:</p>
    <ul>
      <li><a href="/api/adk">GET /api/adk (JSON format)</a></li>
    </ul>
    <pre>GET /api/adk</pre>
  </div>
  <div class="card">
    <h3>Health Status</h3>
    <p><a href="/api/health">GET /api/health</a></p>
  </div>
</body>
</html>`);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ success: false, error: 'Endpoint not found' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`AAMARVA Agent ADK server running on port ${PORT}`);
});
