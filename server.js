import express from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const blockedHost = (host) => {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (net.isIP(h) === 4) {
    const [a,b] = h.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  if (net.isIP(h) === 6) return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:');
  return false;
};

app.use(express.static(path.join(__dirname, 'public')));
app.get('/api/proxy', async (req, res) => {
  try {
    const raw = String(req.query.url || '');
    const target = new URL(raw.includes('://') ? raw : `https://${raw}`);
    if (!['http:', 'https:'].includes(target.protocol)) return res.status(400).send('Only HTTP and HTTPS URLs are supported.');
    if (target.username || target.password || blockedHost(target.hostname)) return res.status(400).send('That destination is not allowed.');
    const records = await dns.lookup(target.hostname, { all: true });
    if (!records.length || records.some(r => blockedHost(r.address))) return res.status(400).send('That destination is not allowed.');
    const upstream = await fetch(target, { redirect: 'manual', signal: AbortSignal.timeout(12000), headers: { 'user-agent': 'OrbitProxyDemo/1.0', 'accept': req.get('accept') || '*/*' } });
    const type = upstream.headers.get('content-type') || 'application/octet-stream';
    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get('location');
      if (location) return res.redirect(302, `/api/proxy?url=${encodeURIComponent(new URL(location, target).href)}`);
    }
    if (!type.includes('text/html')) {
      res.status(upstream.status).type(type);
      return res.send(Buffer.from(await upstream.arrayBuffer()));
    }
    let html = await upstream.text();
    const base = `<base href="${target.origin}/">`;
    html = html.replace(/<head([^>]*)>/i, `<head$1>${base}`);
    // Route ordinary links and forms back through this demo endpoint.
    html = html.replace(/href=(['"])(https?:\/\/[^'"]+)\1/gi, (_, q, url) => `href="/api/proxy?url=${encodeURIComponent(url)}"`);
    html = html.replace(/action=(['"])(https?:\/\/[^'"]+)\1/gi, (_, q, url) => `action="/api/proxy?url=${encodeURIComponent(url)}"`);
    res.status(upstream.status).type('html').send(html);
  } catch (err) {
    res.status(502).send(`Could not load that page. ${err.name === 'TimeoutError' ? 'The request timed out.' : 'Check the URL and try again.'}`);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Orbit Proxy running at http://localhost:${port}`));
