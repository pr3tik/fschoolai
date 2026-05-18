// FschoolAI — Copyright © 2026 Vincent Yang. All rights reserved.
// init.js — Issues short-lived tokens for authenticated sessions
//
// CHANGELOG:
//   v1.0 — Initial. Issues HMAC-SHA256 tokens, TTL configurable via env.
//   v1.1 — Added version stamp and request logging.
//
// FUNCTION CONTRACT:
//   READS:  process.env.FS_APP_SECRET
//           process.env.FS_TOKEN_TTL_SECONDS (default: 900)
//   WRITES: nothing
//   NEVER:  stores tokens, touches user data, calls external APIs
//
// HOW TOKENS WORK:
//   Token = "<unix_expiry>.<hmac_sha256_signature>"
//   ai.js and proxy.js both verify this token before serving requests.
//   FS_APP_SECRET never leaves the server. Token is safe to send to client.
//
// VERSION: 1.1 — 2026-03-30

const crypto = require('crypto');
const FSA_VERSION = '1.1';

exports.handler = async (event) => {
  const origin = event.headers['origin'] || event.headers['referer'] || '';
  const allowedOrigin = process.env.ALLOWED_ORIGIN || 'https://fschoolai.com';
  const originOk = origin.includes('fschoolai.com') ||
                   origin.includes('celadon-paprenjak-d63e12.netlify.app') ||
                   origin.includes('localhost');

  const corsHeaders = {
    'Access-Control-Allow-Origin': originOk ? origin : allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'X-FSA-Version': FSA_VERSION,
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders, body: '' };
  }

  const secret = process.env.FS_APP_SECRET;
  if (!secret) {
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Server config error' })
    };
  }

  const ttl = parseInt(process.env.FS_TOKEN_TTL_SECONDS || '900');
  const expires = Math.floor(Date.now() / 1000) + ttl;
  const payload = `${expires}`;

  const sig = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  const token = `${expires}.${sig}`;

  console.log(`[init] TOKEN_ISSUED ts=${Date.now()} expires=${expires} ttl=${ttl}`);

  return {
    statusCode: 200,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
    body: JSON.stringify({ token, expires, version: FSA_VERSION }),
  };
};
