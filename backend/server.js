'use strict';

const express = require('express');
const path = require('path');

const MAJOR = Number(process.versions.node.split('.')[0]);
if (MAJOR < 18) {
  console.error('BreachGuard Café needs Node.js 18 or newer.');
  process.exit(1);
}

const PORT = Number(process.env.PORT) || 3000;
const HIBP_RANGE = 'https://api.pwnedpasswords.com/range/';
const MAX_PREFIXES = 20;
const FETCH_TIMEOUT_MS = 12000;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 30;

const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  next();
});

app.use(express.json({ limit: '4kb', strict: true }));

const buckets = new Map();

function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || 'local';
  const stamps = buckets.get(key) || [];
  const recent = stamps.filter((stamp) => now - stamp < RATE_WINDOW_MS);
  if (recent.length >= RATE_MAX) {
    res.setHeader('Retry-After', '30');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(429).json({
      error: 'Too many checks from this browser. Wait a moment and try again.'
    });
  }
  recent.push(now);
  buckets.set(key, recent);
  next();
}

function parseRangeBody(text) {
  const matches = Object.create(null);
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (!line) continue;
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const suffix = line.slice(0, separator).trim().toUpperCase();
    const count = Number(line.slice(separator + 1).trim());
    if (!/^[0-9A-F]{35}$/.test(suffix) || !Number.isSafeInteger(count) || count <= 0) {
      continue;
    }
    matches[suffix] = matches[suffix] ? Math.max(matches[suffix], count) : count;
  }
  return matches;
}

async function fetchRange(prefix) {
  const response = await fetch(HIBP_RANGE + prefix, {
    method: 'GET',
    redirect: 'follow',
    headers: {
      'Add-Padding': 'true',
      Accept: 'text/plain',
      'User-Agent': 'BreachGuard-Cafe/1.0 (local k-anonymity check)'
    },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
  });

  if (!response.url.startsWith('https://api.pwnedpasswords.com/range/')) {
    const error = new Error('Unexpected breach service host.');
    error.status = 502;
    throw error;
  }

  if (response.status === 429) {
    const error = new Error('Breach service rate limit.');
    error.status = 429;
    throw error;
  }

  if (!response.ok) {
    const error = new Error('Breach service request failed.');
    error.status = 502;
    throw error;
  }

  const text = await response.text();
  if (text.length > 1000000) {
    const error = new Error('Breach service response was too large.');
    error.status = 502;
    throw error;
  }
  return parseRangeBody(text);
}

async function fetchRanges(prefixes) {
  const queue = prefixes.slice();
  const ranges = Object.create(null);
  const workers = Array.from({ length: Math.min(3, queue.length) }, async () => {
    while (queue.length) {
      const prefix = queue.shift();
      ranges[prefix] = await fetchRange(prefix);
    }
  });
  await Promise.all(workers);
  return ranges;
}

app.post('/api/range', rateLimit, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  const raw = req.body && Array.isArray(req.body.prefixes) ? req.body.prefixes : null;
  if (!raw || raw.length < 1 || raw.length > MAX_PREFIXES) {
    return res.status(400).json({ error: 'Send between 1 and 20 hash prefixes.' });
  }

  const prefixes = [];
  const seen = new Set();
  for (const item of raw) {
    const prefix = String(item || '').trim().toUpperCase();
    if (!/^[0-9A-F]{5}$/.test(prefix)) {
      return res.status(400).json({ error: 'Each prefix must be 5 hexadecimal characters.' });
    }
    if (!seen.has(prefix)) {
      seen.add(prefix);
      prefixes.push(prefix);
    }
  }

  try {
    const ranges = await fetchRanges(prefixes);
    return res.json({ ranges });
  } catch (error) {
    if (error.name === 'TimeoutError' || error.name === 'AbortError') {
      return res.status(504).json({
        error: 'The breach service took too long to answer. Try again.'
      });
    }
    if (error.status === 429) {
      return res.status(429).json({
        error: 'The breach service is busy. Wait a moment and try again.'
      });
    }
    return res.status(502).json({
      error: 'The breach service could not be reached. Check your connection and try again.'
    });
  }
});

const frontendDir = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendDir, { index: 'index.html', maxAge: 0, etag: false }));

app.use((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found.' });
  }
  return res.status(404).sendFile(path.join(frontendDir, 'index.html'));
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  res.setHeader('Cache-Control', 'no-store');
  const invalidJson = error.type === 'entity.parse.failed' || error instanceof SyntaxError;
  const status = invalidJson ? 400 : 500;
  const message = invalidJson
    ? 'The request could not be read.'
    : 'The check could not be completed.';
  return res.status(status).json({ error: message });
});

function bind(host) {
  return new Promise((resolve, reject) => {
    const server = app.listen(PORT, host, () => resolve(server));
    server.once('error', reject);
  });
}

async function main() {
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    console.error('PORT must be a number from 1 to 65535.');
    process.exit(1);
  }

  const hosts = ['127.0.0.1', '::1'];
  let listening = 0;

  for (const host of hosts) {
    try {
      await bind(host);
      listening += 1;
    } catch (error) {
      const ipv6Unavailable = host === '::1'
        && ['EAFNOSUPPORT', 'EADDRNOTAVAIL', 'EINVAL'].includes(error.code);
      if (ipv6Unavailable) continue;
      if (error.code === 'EADDRINUSE') {
        console.error(
          `Port ${PORT} is already in use. Close the other program, or start on another port in PowerShell: $env:PORT=3001; npm start`
        );
        process.exit(1);
      }
      console.error(error.message || 'The server could not start.');
      process.exit(1);
    }
  }

  if (!listening) {
    console.error('Could not listen on localhost.');
    process.exit(1);
  }

  console.log(`BreachGuard Café is running at http://localhost:${PORT}`);
}

main();
