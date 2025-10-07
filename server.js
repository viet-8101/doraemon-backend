// health-check.js
import http from 'http';

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, timestamp: Date.now() }));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Minimal server OK');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Minimal health-check listening on port ${PORT}`);
});
