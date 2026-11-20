import express from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Agent } from 'undici';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const PROXY_USER = process.env.PROXY_USER;
const PROXY_PASSWORD = process.env.PROXY_PASSWORD;

if (!PROXY_USER || !PROXY_PASSWORD) {
  throw new Error('Set PROXY_USER and PROXY_PASSWORD environment variables before starting.');
}

function safeEqual(a, b) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

// Only public IPv4 destinations are supported. The chosen IP is pinned into
// the HTTP connection so a second DNS lookup cannot rebind to a private IP.
function isPublicIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const [a, b, c] = address.split('.').map(Number);
  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0 && c === 113)
  );
}

async function resolvePublicIPv4(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Destination not allowed');
  }

  if (net.isIP(host)) {
    if (!isPublicIPv4(host)) throw new Error('Destination not allowed');
    return host;
  }

  const addresses = await dns.resolve4(host);
  const publicAddresses = addresses.filter(isPublicIPv4);
  if (publicAddresses.length === 0) throw new Error('Destination not allowed');
  return publicAddresses[0];
}

function makePinnedAgent(ip) {
  return new Agent({
    connect: {
      lookup(_hostname, options, callback) {
        if (options && options.all) {
          callback(null, [{ address: ip, family: 4 }]);
        } else {
          callback(null, ip, 4);
        }
      }
    }
  });
}

function requireLogin(req, res, next) {
  const header = req.get('authorization') || '';
  const match = header.match(/^Basic\s+(.+)$/i);
  if (match) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf8');
      const split = decoded.indexOf(':');
      const user = split >= 0 ? decoded.slice(0, split) : '';
      const pass = split >= 0 ? decoded.slice(split + 1) : '';
      if (safeEqual(user, PROXY_USER) && safeEqual(pass, PROXY_PASSWORD)) return next();
    } catch {}
  }
  res.set('WWW-Authenticate', 'Basic realm="DON’T TELL", charset="UTF-8"');
  return res.status(401).send('Sign in is required to use DON’T TELL.');
}

// Small in-memory per-IP rate limit. On a free single-instance deployment this
// is a useful basic guard, not a substitute for an edge/WAF rate limiter.
const hits = new Map();
app.use((req, res, next) => {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = hits.get(key) || { count: 0, reset: now + 60_000 };
  if (now > entry.reset) {
    entry.count = 0;
    entry.reset = now + 60_000;
  }
  entry.count += 1;
  hits.set(key, entry);
  if (hits.size > 5000) {
    for (const [ip, value] of hits) if (now > value.reset) hits.delete(ip);
  }
  if (entry.count > 60) return res.status(429).send('Too many requests. Try again in a minute.');
  next();
});

app.get('/healthz', (_req, res) => res.status(200).send('ok'));
app.use(requireLogin);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/proxy', async (req, res) => {
  let agent;
  try {
    const raw = String(req.query.url || '');
    if (!raw || raw.length > 2048) return res.status(400).send('Enter a valid URL.');
    let target = new URL(raw.includes('://') ? raw : `https://${raw}`);
    if (!['http:', 'https:'].includes(target.protocol) ||
        target.username || target.password) {
      return res.status(400).send('Only public HTTP and HTTPS URLs are supported.');
    }

    // Validate and pin every redirect destination independently.
    let upstream;
    for (let redirects = 0; redirects <= 5; redirects++) {
      const ip = await resolvePublicIPv4(target.hostname);
      agent = makePinnedAgent(ip);
      upstream = await fetch(target, {
        dispatcher: agent,
        redirect: 'manual',
        signal: AbortSignal.timeout(12_000),
        headers: {
          'user-agent': 'DontTellProxy/1.0',
          'accept': req.get('accept') || '*/*'
        }
      });

      if (upstream.status >= 300 && upstream.status < 400) {
        const location = upstream.headers.get('location');
        await upstream.body?.cancel();
        await agent.close();
        agent = undefined;
        if (!location) return res.status(upstream.status).send('The destination redirected without a location.');
        if (redirects === 5) return res.status(502).send('Too many redirects.');
        target = new URL(location, target);
        if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
          return res.status(400).send('Redirect destination not allowed.');
        }
        continue;
      }
      break;
    }

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const declaredLength = Number(upstream.headers.get('content-length') || 0);
    const MAX_BYTES = 8 * 1024 * 1024;
    if (declaredLength > MAX_BYTES) {
      await upstream.body?.cancel();
      return res.status(413).send('This response is too large for the demo proxy.');
    }

    const bytes = Buffer.from(await upstream.arrayBuffer());
    if (bytes.length > MAX_BYTES) return res.status(413).send('This response is too large for the demo proxy.');

    if (!contentType.toLowerCase().includes('text/html')) {
      res.status(upstream.status);
      res.set('content-type', contentType);
      res.set('x-content-type-options', 'nosniff');
      return res.send(bytes);
    }

    let html = bytes.toString('utf8');
    const base = `<base href="${target.origin}/">`;
    html = /<head[^>]*>/i.test(html)
      ? html.replace(/<head([^>]*)>/i, `<head$1>${base}`)
      : `${base}${html}`;
    html = html.replace(/href=(['"])(https?:\/\/[^'"]+)\1/gi,
      (_match, quote, url) => `href="/api/proxy?url=${encodeURIComponent(url)}"`);
    html = html.replace(/action=(['"])(https?:\/\/[^'"]+)\1/gi,
      (_match, quote, url) => `action="/api/proxy?url=${encodeURIComponent(url)}"`);
    res.status(upstream.status).type('html').send(html);
  } catch (error) {
    if (!res.headersSent) {
      const message = error.name === 'TimeoutError'
        ? 'The request timed out.'
        : 'Could not load that page. Check the URL and try another public website.';
      res.status(502).send(message);
    }
  } finally {
    if (agent) {
      try { await agent.close(); } catch {}
    }
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`DON'T TELL running on port ${PORT}`);
});
