// FschoolAI — Copyright © 2026 Vincent Yang. All rights reserved.
// ai.js — Anthropic API proxy with short-lived token auth
//
// VERSION: 3.0 — 2026-05-15
// CHANGES:
//   - Standardized response envelope: { success, type, result, tokens, ...raw }
//   - Backend NEVER returns 500 — always returns usable JSON
//   - Model-aware max_tokens caps (Sonnet: 16000, Haiku: 8192)
//   - Full try/catch including response.json() parse
//   - Payload size guard (8MB)
//   - 25s AbortController timeout (just under Netlify 26s limit)
//   - Structured [ai] log prefixes for Netlify log filtering

const crypto = require('crypto');
const FSA_VERSION = '3.0';

const VALID_MODELS = {
  'claude-haiku-4-5-20251001': 'claude-haiku-4-5-20251001',
  'claude-sonnet-4-6':          'claude-sonnet-4-6',       // canonical — maps to itself
  'claude-sonnet-4-5':          'claude-sonnet-4-6',       // alias → current sonnet
  'claude-3-5-sonnet-20241022': 'claude-sonnet-4-6',       // legacy alias
  'claude-3-5-sonnet':          'claude-sonnet-4-6',       // legacy alias
  'claude-haiku':               'claude-haiku-4-5-20251001',
};

const MODEL_TOKEN_CAPS = {
  'claude-sonnet-4-6':          16000,
  'claude-haiku-4-5-20251001':  8192,
};

function normalizeModel(model) {
  if (!model) return 'claude-haiku-4-5-20251001';
  const m = VALID_MODELS[model];
  if (m) return m;
  console.log('[ai] WARN unknown_model=' + model + ' defaulting to haiku');
  return 'claude-haiku-4-5-20251001';
}

function verifyToken(token, secret) {
  if (!token || !secret) return false;
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [expires, sig] = parts;
    if (Math.floor(Date.now() / 1000) > parseInt(expires, 10)) return false;
    const expected = crypto.createHmac('sha256', secret).update(expires).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch(e) { return false; }
}

function extractText(data) {
  if (!data || !Array.isArray(data.content)) return '';
  return data.content
    .filter(function(b) { return b && b.type === 'text' && typeof b.text === 'string'; })
    .map(function(b) { return b.text; })
    .join('');
}

function buildEnvelope(data, type) {
  const result = extractText(data);
  const tokens  = (data && data.usage && data.usage.output_tokens) || 0;
  const success = !!(result);
  const envelope = { success: success, type: type || 'generic', result: result, tokens: tokens };
  // Spread raw Anthropic fields for backward compat (frontend still reads d.content[0].text)
  if (data) {
    Object.keys(data).forEach(function(k) { envelope[k] = data[k]; });
  }
  return envelope;
}

exports.handler = async function(event) {
  const start = Date.now();

  const origin = event.headers['origin'] || event.headers['referer'] || '';
  const allowedOrigin = process.env.ALLOWED_ORIGIN || 'https://fschoolai.com';
  const originOk = origin.includes('fschoolai.com') || origin.includes('netlify.app') || origin.includes('localhost');

  const corsHeaders = {
    'Access-Control-Allow-Origin':  originOk ? origin : allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type,X-FS-Token',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Content-Type':                 'application/json',
    'X-FSA-Version':                FSA_VERSION,
  };

  function respond(statusCode, payload) {
    return { statusCode: statusCode, headers: corsHeaders, body: JSON.stringify(payload) };
  }
  function respondErr(statusCode, message) {
    console.log('[ai] ERR status=' + statusCode + ' msg=' + message);
    return respond(statusCode, { success: false, error: { message: message, status: statusCode } });
  }

  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: corsHeaders, body: '' };
  if (event.httpMethod !== 'POST')    return respondErr(405, 'Method not allowed');

  const ct = (event.headers['content-type'] || '').toLowerCase();
  if (!ct.includes('application/json')) return respondErr(400, 'Content-Type must be application/json');

  if ((event.body || '').length > 8 * 1024 * 1024) return respondErr(413, 'Request body too large (max 8MB)');

  const secret = process.env.FS_APP_SECRET;
  if (secret) {
    const token = event.headers['x-fs-token'] || '';
    if (!verifyToken(token, secret)) {
      console.log('[ai] UNAUTHORIZED ts=' + Date.now());
      return respondErr(401, 'Unauthorized — token missing or expired');
    }
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch(e) { return respondErr(400, 'Invalid JSON: ' + e.message); }

  if (!body.messages || !Array.isArray(body.messages) || body.messages.length === 0) {
    return respondErr(400, 'Invalid payload: messages array required');
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.log('[ai] ERROR ANTHROPIC_API_KEY not set');
    return respondErr(500, 'Server configuration error: API key not set');
  }

  const model     = normalizeModel(body.model);
  const hardCap   = MODEL_TOKEN_CAPS[model] || 8192;
  const maxTokens = Math.min(body.max_tokens || 2000, hardCap);
  const reqType   = body._type || 'generic';

  console.log('[ai] REQUEST ts=' + Date.now() + ' model=' + model + ' type=' + reqType + ' max_tokens=' + maxTokens + ' sys_c=' + (body.system||'').length + ' msg_c=' + JSON.stringify(body.messages).length);

  const anthropicBody = { model: model, max_tokens: maxTokens, messages: body.messages };
  if (body.system) anthropicBody.system = body.system;
  if (body.tools)  anthropicBody.tools  = body.tools;

  const anthropicHeaders = {
    'Content-Type':      'application/json',
    'x-api-key':         apiKey,
    'anthropic-version': '2023-06-01',
  };

  if (body.tools && body.tools.some(function(t) { return t && t.type && t.type.startsWith('web_search'); })) {
    anthropicHeaders['anthropic-beta'] = 'web-search-2025-03-05';
    console.log('[ai] WEB_SEARCH enabled');
  }

  // Enable PDF/document parsing if any message content block is a document
  const hasDocument = body.messages.some(function(msg) {
    const content = msg.content;
    return Array.isArray(content) && content.some(function(b) { return b && b.type === 'document'; });
  });
  if (hasDocument) {
    anthropicHeaders['anthropic-beta'] = (anthropicHeaders['anthropic-beta'] ? anthropicHeaders['anthropic-beta'] + ',' : '') + 'pdfs-2024-09-25';
    console.log('[ai] PDF_BETA enabled');
  }

  // 25s timeout — just under Netlify's 26s function limit
  const controller = new AbortController();
  const timeoutId  = setTimeout(function() { controller.abort(); }, 25000);

  let response;
  try {
    response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', headers: anthropicHeaders,
      body: JSON.stringify(anthropicBody), signal: controller.signal,
    });
  } catch(fetchErr) {
    clearTimeout(timeoutId);
    const dur = Date.now() - start;
    const isTimeout = fetchErr.name === 'AbortError';
    console.log('[ai] FETCH_ERROR dur=' + dur + 'ms timeout=' + isTimeout + ' msg=' + fetchErr.message);
    return respondErr(isTimeout ? 504 : 502, isTimeout
      ? 'Request timed out — try a shorter prompt or retry'
      : 'Upstream error: ' + fetchErr.message
    );
  }
  clearTimeout(timeoutId);

  let data;
  try {
    data = await response.json();
  } catch(jsonErr) {
    const dur = Date.now() - start;
    console.log('[ai] JSON_ERROR dur=' + dur + 'ms status=' + response.status + ' msg=' + jsonErr.message);
    return respondErr(502, 'Upstream returned non-JSON response');
  }

  const dur        = Date.now() - start;
  const text       = extractText(data);
  const stopReason = (data && data.stop_reason) || 'unknown';
  console.log('[ai] RESPONSE status=' + response.status + ' dur=' + dur + 'ms chars=' + text.length + ' stop=' + stopReason + ' type=' + reqType);

  if (response.status === 200 && text.length < 50) {
    console.log('[ai] WARN short_response chars=' + text.length + ' data=' + JSON.stringify(data).substring(0, 300));
  }

  if (!response.ok) {
    const anthropicMsg = (data && data.error && data.error.message) || ('HTTP ' + response.status);
    console.log('[ai] ANTHROPIC_ERROR status=' + response.status + ' msg=' + anthropicMsg);
    const statusMsgs = { 429: 'Rate limit reached — please wait a moment and retry', 529: 'Claude is overloaded — please retry in a few seconds' };
    const userMsg = statusMsgs[response.status] || anthropicMsg;
    return respond(response.status, Object.assign({ success: false, type: reqType, result: '', tokens: 0, error: { message: userMsg, status: response.status } }, data || {}));
  }

  return respond(200, buildEnvelope(data, reqType));
};
