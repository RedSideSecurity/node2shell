// Node2Shell lab target - a deliberately ordinary little Express API.
//
// There is nothing exploit-specific in here. It is a normal service that
// happens to accept JSON request bodies, which means express.json()
// (body-parser 2.x under Express 5) will transparently decompress a body
// sent with "Content-Encoding: br" - and THAT is the code path the
// CVE-2026-111497 Brotli decoder bug lives behind.
//
// Whether this instance is vulnerable or patched depends only on the Node.js
// version of the base image it runs on (24.22.0 = vulnerable, 24.22.1 = fixed);
// the application code is identical for both.

const express = require('express');

const app = express();

// Some deployments hide their stack. With HIDE_VERSION=1 this target removes
// the X-Powered-By header and stops disclosing its version at /health - so the
// only way to flag it is the behavioral Brotli probe. That is the realistic,
// hard case a good scanner still has to catch.
const HIDE = process.env.HIDE_VERSION === '1';
if (HIDE) app.disable('x-powered-by');

// Realistic small-API defaults. express.json() decompresses br/gzip/deflate
// request bodies by default - the reachable Brotli path a scanner probes for.
app.use(express.json());

// A plain landing page - no version leak here, like most real deployments.
app.get('/', (req, res) => {
  res.type('html').send(
    '<!doctype html><title>Orders API</title>' +
    '<h1>Orders API</h1><p>POST JSON to <code>/api/orders</code>.</p>'
  );
});

// A JSON API route. This is the best endpoint for the behavioral probe:
// it reads a JSON body, so it will decode a Brotli-encoded body.
app.post('/api/orders', (req, res) => {
  res.json({ ok: true, received: req.body ?? null });
});

// A health endpoint that discloses the runtime version - common in real
// deployments, and what lets a scanner move from "likely" to a definite
// vulnerable/patched verdict.
app.get('/health', (req, res) => {
  if (HIDE) return res.json({ status: 'ok' });
  res.json({
    status: 'ok',
    node: process.versions.node,
    brotli: process.versions.brotli,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `[lab] Orders API up on :${PORT} | node ${process.versions.node} | brotli ${process.versions.brotli}`
  );
});
