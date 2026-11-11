'use strict';
require('dotenv').config();

const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const db = require('./db');
const { ROLES, COLLECTIONS, canWrite } = require('./roles');

const PORT = Number(process.env.PORT) || 3000;
const SECRET = process.env.JWT_SECRET || '';
const COOKIE = 'gs_session';
const SECURE_COOKIE = process.env.COOKIE_SECURE === 'true';
const SESSION_HOURS = Number(process.env.SESSION_HOURS) || 12;
const ID_RE = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;

if (SECRET.length < 32) {
  console.error('JWT_SECRET must be at least 32 characters long. See .env.example.');
  process.exit(1);
}

/* ---------------- helpers ---------------- */
const pub = u => ({ id: u.id, email: u.email, name: u.name, role: u.role, active: u.active });
const sign = u => jwt.sign({ sub: u.id, v: u.token_version }, SECRET, { expiresIn: `${SESSION_HOURS}h` });
const setSession = (res, u) => res.cookie(COOKIE, sign(u), {
  httpOnly: true, sameSite: 'lax', secure: SECURE_COOKIE, maxAge: SESSION_HOURS * 3600e3, path: '/',
});
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

async function userFromToken(token) {
  if (!token) return null;
  let p;
  try { p = jwt.verify(token, SECRET); } catch { return null; }
  const { rows } = await db.q('SELECT id,email,name,role,active,token_version FROM users WHERE id=$1', [p.sub]);
  const u = rows[0];
  if (!u || !u.active || u.token_version !== p.v) return null;
  return u;
}

/* ---------------- app ---------------- */
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
  });
  next();
});
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// Every state-changing API call must carry the X-ERP header. Browsers won't let
// another website add it, which blocks cross-site request forgery.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('X-ERP') !== '1') return res.status(400).json({ error: 'Missing request header.' });
  next();
});

const auth = async (req, res, next) => {
  try {
    const u = await userFromToken(req.cookies[COOKIE]);
    if (!u) return res.status(401).json({ error: 'Please sign in.' });
    req.user = u;
    next();
  } catch (e) { next(e); }
};
const adminOnly = (req, res, next) => req.user.role === 'Admin' ? next() : res.status(403).json({ error: 'Only an Admin can do this.' });

/* ---- sign in / out ---- */
const attempts = new Map();
function tooMany(key) {
  const now = Date.now();
  const list = (attempts.get(key) || []).filter(t => now - t < 15 * 60e3);
  attempts.set(key, list);
  return list.length >= 10;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of attempts) if (!v.some(t => now - t < 15 * 60e3)) attempts.delete(k); }, 10 * 60e3).unref();

app.post('/api/login', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const key = `${req.ip}|${email}`;
    if (tooMany(key)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
    const { rows } = await db.q('SELECT * FROM users WHERE lower(email)=$1', [email]);
    const u = rows[0];
    const ok = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH);
    if (!u || !ok || !u.active) {
      attempts.get(key).push(Date.now());
      return res.status(401).json({ error: u && ok && !u.active ? 'This account has been deactivated. Contact your admin.' : 'Email or password is incorrect.' });
    }
    attempts.delete(key);
    setSession(res, u);
    res.json({ user: pub(u) });
  } catch (e) { next(e); }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: pub(req.user) }));

app.post('/api/me/password', auth, async (req, res, next) => {
  try {
    const current = String(req.body?.current || ''), next_ = String(req.body?.password || '');
    if (next_.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    const { rows } = await db.q('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    if (!(await bcrypt.compare(current, rows[0].password_hash))) return res.status(400).json({ error: 'Current password is incorrect.' });
    const hash = await bcrypt.hash(next_, 10);
    const r = await db.q('UPDATE users SET password_hash=$1, token_version=token_version+1, updated_at=now() WHERE id=$2 RETURNING *', [hash, req.user.id]);
    setSession(res, r.rows[0]);
    kick(req.user.id, true);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---- users (Admin manages) ---- */
async function allUsers() {
  const { rows } = await db.q('SELECT id,email,name,role,active FROM users ORDER BY name');
  return rows;
}
app.get('/api/users', auth, async (req, res, next) => {
  try { res.json({ users: await allUsers() }); } catch (e) { next(e); }
});

app.post('/api/users', auth, adminOnly, async (req, res, next) => {
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const role = String(req.body?.role || 'Viewer');
    if (!name) return res.status(400).json({ error: 'Name is required.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!(role in ROLES)) return res.status(400).json({ error: 'Unknown role.' });
    const id = 'u_' + crypto.randomBytes(9).toString('hex');
    const hash = await bcrypt.hash(password, 10);
    try {
      await db.q('INSERT INTO users (id,email,name,password_hash,role) VALUES ($1,$2,$3,$4,$5)', [id, email, name, hash, role]);
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'A user with this email already exists.' });
      throw e;
    }
    broadcast({ t: 'users' });
    res.json({ ok: true, id });
  } catch (e) { next(e); }
});

app.patch('/api/users/:id', auth, adminOnly, async (req, res, next) => {
  try {
    const id = req.params.id;
    const { rows } = await db.q('SELECT * FROM users WHERE id=$1', [id]);
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'User not found.' });
    const b = req.body || {};
    const sets = [], vals = [];
    let signOut = false;
    if (b.name !== undefined) { const nm = String(b.name).trim(); if (!nm) return res.status(400).json({ error: 'Name is required.' }); vals.push(nm); sets.push(`name=$${vals.length}`); }
    if (b.role !== undefined) {
      if (!(b.role in ROLES)) return res.status(400).json({ error: 'Unknown role.' });
      if (id === req.user.id && b.role !== 'Admin') return res.status(400).json({ error: 'You can’t remove your own Admin role.' });
      vals.push(b.role); sets.push(`role=$${vals.length}`);
    }
    if (b.active !== undefined) {
      if (id === req.user.id && !b.active) return res.status(400).json({ error: 'You can’t deactivate yourself.' });
      vals.push(!!b.active); sets.push(`active=$${vals.length}`);
      if (!b.active) signOut = true;
    }
    if (b.password !== undefined) {
      if (String(b.password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
      vals.push(await bcrypt.hash(String(b.password), 10)); sets.push(`password_hash=$${vals.length}`);
      signOut = true;
    }
    if (!sets.length) return res.json({ ok: true });
    if (signOut) sets.push('token_version=token_version+1');
    vals.push(id);
    await db.q(`UPDATE users SET ${sets.join(',')}, updated_at=now() WHERE id=$${vals.length}`, vals);
    if (signOut) kick(id);
    broadcast({ t: 'users' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---- ERP data ---- */
const checkCol = (req, res, next) => {
  if (!(req.params.col in COLLECTIONS)) return res.status(404).json({ error: 'Unknown collection.' });
  if (req.params.id !== undefined && !ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid record id.' });
  next();
};
const checkWrite = (req, res, next) => canWrite(req.user.role, req.params.col)
  ? next()
  : res.status(403).json({ error: `Your role (${req.user.role}) can’t change this.` });

app.get('/api/all', auth, async (req, res, next) => {
  try {
    const { rows } = await db.q('SELECT collection, id, data FROM docs');
    res.json({ docs: rows, users: await allUsers() });
  } catch (e) { next(e); }
});

app.get('/api/docs/:col', auth, checkCol, async (req, res, next) => {
  try {
    const { rows } = await db.q('SELECT id, data FROM docs WHERE collection=$1', [req.params.col]);
    res.json({ docs: rows });
  } catch (e) { next(e); }
});

app.put('/api/docs/:col/:id', auth, checkCol, checkWrite, async (req, res, next) => {
  try {
    const data = req.body;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: 'Record must be a JSON object.' });
    const { col, id } = req.params;
    await db.q(
      `INSERT INTO docs (collection,id,data,updated_at,updated_by) VALUES ($1,$2,$3,now(),$4)
       ON CONFLICT (collection,id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`,
      [col, id, data, req.user.id]);
    await db.q('INSERT INTO audit (user_id,collection,doc_id,action,data) VALUES ($1,$2,$3,$4,$5)', [req.user.id, col, id, 'save', data]);
    broadcast({ t: 'doc', c: col, id, d: data });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete('/api/docs/:col/:id', auth, checkCol, checkWrite, async (req, res, next) => {
  try {
    const { col, id } = req.params;
    const { rows } = await db.q('DELETE FROM docs WHERE collection=$1 AND id=$2 RETURNING data', [col, id]);
    if (rows[0]) await db.q('INSERT INTO audit (user_id,collection,doc_id,action,data) VALUES ($1,$2,$3,$4,$5)', [req.user.id, col, id, 'delete', rows[0].data]);
    broadcast({ t: 'doc', c: col, id, d: null });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.get('/api/backup', auth, adminOnly, async (req, res, next) => {
  try {
    const { rows } = await db.q('SELECT collection, id, data, updated_at FROM docs ORDER BY collection, id');
    res.json({ app: 'gopin-erp', exportedAt: new Date().toISOString(), docs: rows });
  } catch (e) { next(e); }
});

app.get('/api/health', async (req, res) => {
  try { await db.q('SELECT 1'); res.json({ ok: true }); } catch { res.status(503).json({ ok: false }); }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

/* ---- static files ---- */
app.use('/vendor', express.static(path.join(__dirname, 'node_modules', 'xlsx', 'dist'), { maxAge: '7d' }));
// Android app (Play Store) verification file goes in public/.well-known/assetlinks.json
app.use('/.well-known', express.static(path.join(__dirname, 'public', '.well-known')));
app.get('/sw.js', (req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(__dirname, 'public', 'sw.js')); });
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'That record is too large to save.' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  console.error(err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

/* ---------------- live updates (WebSocket) ---------------- */
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) { try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch {} }
  }
  return out;
}

server.on('upgrade', async (req, socket, head) => {
  try {
    if (!req.url.startsWith('/ws')) return socket.destroy();
    const origin = req.headers.origin;
    if (origin && new URL(origin).host !== req.headers.host) return socket.destroy();
    const u = await userFromToken(parseCookies(req.headers.cookie)[COOKIE]);
    wss.handleUpgrade(req, socket, head, ws => {
      if (!u) return ws.close(4001, 'unauthorized');
      ws.uid = u.id;
      ws.alive = true;
      ws.on('pong', () => { ws.alive = true; });
      ws.on('message', () => {});
    });
  } catch { socket.destroy(); }
});

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false;
    ws.ping();
  }
}, 30000).unref();

function broadcast(msg) {
  const s = JSON.stringify(msg);
  for (const ws of wss.clients) if (ws.readyState === 1) ws.send(s);
}
// Close a user's live connections (deactivated or password changed).
function kick(uid, refreshOnly) {
  for (const ws of wss.clients) if (ws.uid === uid) ws.close(refreshOnly ? 4002 : 4001, 'session ended');
}

/* ---------------- start ---------------- */
async function ensureAdmin() {
  const { rows } = await db.q('SELECT count(*)::int AS n FROM users');
  if (rows[0].n > 0) return;
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!validEmail(email) || password.length < 8) {
    console.warn('No users yet. Set ADMIN_EMAIL and ADMIN_PASSWORD (8+ chars) in .env and restart, or run: npm run create-admin');
    return;
  }
  const hash = await bcrypt.hash(password, 10);
  await db.q('INSERT INTO users (id,email,name,password_hash,role) VALUES ($1,$2,$3,$4,$5)',
    ['u_' + crypto.randomBytes(9).toString('hex'), email, process.env.ADMIN_NAME || 'Administrator', hash, 'Admin']);
  console.log(`Created first Admin user: ${email}`);
}

// First start on an empty database: add standard units, warehouses and the company name.
async function seedDefaults() {
  const { rows } = await db.q('SELECT count(*)::int AS n FROM docs');
  if (rows[0].n > 0) return;
  const seed = [
    ['uoms', 'NOS', { code: 'NOS', name: 'Numbers / Pieces', decimals: 0 }],
    ['uoms', 'KG', { code: 'KG', name: 'Kilogram', decimals: 3 }],
    ['uoms', 'MTR', { code: 'MTR', name: 'Metre', decimals: 2 }],
    ['uoms', 'LTR', { code: 'LTR', name: 'Litre', decimals: 2 }],
    ['uoms', 'SET', { code: 'SET', name: 'Set', decimals: 0 }],
    ['uoms', 'BOX', { code: 'BOX', name: 'Box', decimals: 0 }],
    ['warehouses', 'RM', { code: 'RM', name: 'Raw Material Store', type: 'Raw Material', location: '' }],
    ['warehouses', 'WIP', { code: 'WIP', name: 'Shop Floor (WIP)', type: 'Work in Progress', location: '' }],
    ['warehouses', 'FG', { code: 'FG', name: 'Finished Goods Store', type: 'Finished Goods', location: '' }],
    ['warehouses', 'REJ', { code: 'REJ', name: 'Rejection & Scrap', type: 'Rejected / Scrap', location: '' }],
    ['settings', 'company', { name: process.env.COMPANY_NAME || 'Gopin Semicon Private Limited', legal: process.env.COMPANY_NAME || 'Gopin Semicon Private Limited', fy: 'April', shiftStart: '09:00', weeklyOff: 'Sunday' }],
  ];
  for (const [c, id, d] of seed) await db.q("INSERT INTO docs (collection,id,data,updated_by) VALUES ($1,$2,$3,'setup') ON CONFLICT DO NOTHING", [c, id, d]);
  console.log('Added standard units, warehouses and company name.');
}

(async () => {
  try {
    await db.init();
    await ensureAdmin();
    await seedDefaults();
    server.listen(PORT, () => console.log(`Gopin Semicon ERP running on http://localhost:${PORT}`));
  } catch (e) {
    console.error('Could not start:', e.message);
    process.exit(1);
  }
})();

process.on('SIGTERM', () => { server.close(() => db.pool.end().then(() => process.exit(0))); });
