// FschoolAI — Copyright © 2026 Vincent Yang. All rights reserved.
// proxy.js — Canvas/Brightspace CORS proxy with token auth
//
// CHANGELOG:
//   v1.0 — Initial. Canvas proxy with SSRF protection.
//   v1.1 — Added request logging. Logs every Canvas API call with path,
//           status, duration, response_chars. Visible in Netlify logs.
//   v1.2 — Added scan visibility. Logs which Canvas endpoints are hit
//           so we can see exactly what each scan fetches.
//   v1.3 — Added version stamp. Health readable via X-FSA-Version header.
//
// FUNCTION CONTRACT:
//   READS:  event.queryStringParameters (token, path, base)
//           process.env.FS_APP_SECRET
//   WRITES: nothing (pure proxy)
//   NEVER:  stores Canvas data, modifies any Canvas resource, logs Canvas token
//
// WHAT THIS LOGS (visible in Netlify function logs):
//   [proxy] REQUEST ts=<n> path=<canvas_path> base=<host>
//   [proxy] OK status=<n> duration=<ms> response_chars=<n>
//   [proxy] ERROR <message>
//   [proxy] SSRF_BLOCKED host=<host>
//   [proxy] UNAUTHORIZED
//
// HOW TO SEE SCAN ACTIVITY:
//   Netlify → Functions → proxy → View logs
//   Filter by [proxy] REQUEST to see every Canvas API call during scan
//   This tells you: courses, assignments, submissions, files fetched
//
// VERSION: 1.3 — 2026-03-30

const crypto = require('crypto');
const FSA_VERSION = '1.3';

function verifyToken(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expires, sig] = parts;
  if (Math.floor(Date.now() / 1000) > parseInt(expires)) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(expires)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(
      Buffer.from(sig, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch(e) { return false; }
}

exports.handler = async (event) => {
  const start = Date.now();
  const origin = event.headers['origin'] || event.headers['referer'] || '';
  const allowedOrigin = process.env.ALLOWED_ORIGIN || 'https://fschoolai.com';
  const originOk = origin.includes('fschoolai.com') ||
                   origin.includes('celadon-paprenjak-d63e12.netlify.app') ||
                   origin.includes('localhost');

  const corsHeaders = {
    'Access-Control-Allow-Origin': originOk ? origin : allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-FS-Token',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'X-FSA-Version': FSA_VERSION,
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders, body: '' };
  }

  // Token validation
  const secret = process.env.FS_APP_SECRET;
  if (secret) {
    const token = event.headers['x-fs-token'] || '';
    if (!verifyToken(token, secret)) {
      console.log(`[proxy] UNAUTHORIZED ts=${Date.now()}`);
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Unauthorized' })
      };
    }
  }

  const params = new URLSearchParams(event.rawQuery || '');
  const canvasToken = params.get('token') || '';
  const path = params.get('path') || '';
  const base = params.get('base') || '';

  if (!canvasToken || canvasToken.length < 10 || !path || !base) {
    return { statusCode: 400, headers: corsHeaders, body: 'Missing params' };
  }

  // SSRF protection
  const targetUrl = base.replace(/\/+$/, '') + path;
  const allowedPatterns = [
    /\.instructure\.com$/i,
    /\.canvas\.net$/i,
    /\.brightspace\.com$/i,
    /\.desire2learn\.com$/i,
    /canvas\.[a-z0-9-]+\.edu$/i,
    /canvas\.[a-z0-9-]+\.ac\.[a-z]{2}$/i,
    /canvas\.[a-z0-9-]+\.edu\.[a-z]{2}$/i,
    /q\.utoronto\.ca$/i,
    /utsc\.utoronto\.ca$/i,
    /canvas\.ubc\.ca$/i,
    /canvas\.sfu\.ca$/i,
    /canvas\.sydney\.edu\.au$/i,
    /canvas\.uts\.edu\.au$/i,
    /canvas\.anu\.edu\.au$/i,
    /canvas\.unimelb\.edu\.au$/i,
    /canvas\.unsw\.edu\.au$/i,
    /canvas\.uq\.edu\.au$/i,
  ];

  let targetHost = '';
  try { targetHost = new URL(targetUrl).hostname.toLowerCase(); } catch(e) {}
  const domainOk = targetHost && allowedPatterns.some(p => p.test(targetHost));

  if (!domainOk || !targetUrl.startsWith('https://')) {
    console.log(`[proxy] SSRF_BLOCKED host=${targetHost}`);
    return { statusCode: 400, headers: corsHeaders, body: 'Invalid target: ' + targetHost };
  }

  // Log every Canvas API call — this is how you see what scan fetches
  console.log(`[proxy] REQUEST ts=${Date.now()} path=${path.substring(0, 120)}`);

  try {
    const resp = await fetch(targetUrl, {
      headers: {
        'Authorization': `Bearer ${canvasToken}`,
        'Accept': 'application/json',
      },
    });
    const text = await resp.text();
    const duration = Date.now() - start;

    console.log(`[proxy] RESPONSE status=${resp.status} duration=${duration}ms response_chars=${text.length} path=${path.substring(0, 80)}`);

    // Warn on empty responses — could mean bad token or wrong endpoint
    if (resp.status === 200 && text.length < 10) {
      console.log(`[proxy] WARN empty_response path=${path}`);
    }

    return {
      statusCode: resp.status,
      headers: {
        ...corsHeaders,
        'Content-Type': resp.headers.get('content-type') || 'application/json',
      },
      body: text,
    };
  } catch(err) {
    const duration = Date.now() - start;
    console.log(`[proxy] ERROR duration=${duration}ms message=${err.message} path=${path.substring(0, 80)}`);
    return {
      statusCode: 502,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Proxy error', detail: err.message }),
    };
  }
};
