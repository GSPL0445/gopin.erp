'use strict';
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const db = require('./db');
const R = require('./roles');
// Role definitions: built-in roles plus the admin's Role Center changes (settings/roles).
let DEFS = R.effective({});
const parseRoles = s => R.parseRoles(s, DEFS);
async function loadRoleDefs() {
  const { rows } = await db.q("SELECT data FROM docs WHERE collection='settings' AND id='roles'");
  DEFS = R.effective(rows[0]?.data || {});
}

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
const PROFILE_KEYS = ['empCode', 'dept', 'designation', 'phone', 'reportsTo'];
const pub = u => ({ id: u.id, email: u.email, name: u.name, role: parseRoles(u.role).join(','), roles: parseRoles(u.role), active: u.active,
  ...Object.fromEntries(PROFILE_KEYS.map(k => [k, (u.profile || {})[k] || ''])) });
// Keeps only the known profile fields, as short strings.
function cleanProfile(p) {
  const out = {};
  for (const k of PROFILE_KEYS) if (p && p[k] !== undefined) out[k] = String(p[k] ?? '').trim().slice(0, 120);
  return out;
}
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
  const { rows } = await db.q('SELECT id,email,name,role,active,token_version,profile FROM users WHERE id=$1', [p.sub]);
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
const adminOnly = (req, res, next) => parseRoles(req.user.role).includes('Admin') ? next() : res.status(403).json({ error: 'Only an Admin can do this.' });

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

// Company name and logo for the sign-in page (no login needed).
app.get('/api/brand', async (req, res, next) => {
  try {
    const { rows } = await db.q("SELECT data FROM docs WHERE collection='settings' AND id='company'");
    const d = rows[0]?.data || {};
    res.set('Cache-Control', 'no-cache').json({ name: d.name || '', logo: d.logo || '' });
  } catch (e) { next(e); }
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
// Accepts "Role A,Role B"; returns the cleaned list string, or null if a role is unknown.
function cleanRoles(input) {
  const list = [...new Set(String(input || 'Viewer').split(',').map(r => r.trim()).filter(Boolean))];
  if (!list.length) return 'Viewer';
  if (list.some(r => r !== 'Admin' && !(r in DEFS))) return null;
  return list.filter(r => r !== 'Viewer' || list.length === 1).join(',');
}
async function allUsers() {
  const { rows } = await db.q('SELECT id,email,name,role,active,profile FROM users ORDER BY name');
  return rows.map(pub);
}
app.get('/api/users', auth, async (req, res, next) => {
  try { res.json({ users: await allUsers() }); } catch (e) { next(e); }
});

app.post('/api/users', auth, adminOnly, async (req, res, next) => {
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const role = cleanRoles(req.body?.role);
    if (!name) return res.status(400).json({ error: 'Name is required.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!role) return res.status(400).json({ error: 'Unknown role.' });
    const id = 'u_' + crypto.randomBytes(9).toString('hex');
    const hash = await bcrypt.hash(password, 10);
    try {
      const profile = cleanProfile(req.body?.profile);
      if (profile.reportsTo && !(await db.q('SELECT 1 FROM users WHERE id=$1', [profile.reportsTo])).rows.length) return res.status(400).json({ error: 'Reporting manager not found.' });
      await db.q('INSERT INTO users (id,email,name,password_hash,role,profile) VALUES ($1,$2,$3,$4,$5,$6)', [id, email, name, hash, role, profile]);
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
      const role = cleanRoles(b.role);
      if (!role) return res.status(400).json({ error: 'Unknown role.' });
      if (id === req.user.id && !parseRoles(role).includes('Admin')) return res.status(400).json({ error: 'You can’t remove your own Admin role.' });
      vals.push(role); sets.push(`role=$${vals.length}`);
    }
    if (b.profile !== undefined) {
      const prof = cleanProfile(b.profile);
      if (prof.reportsTo === id) return res.status(400).json({ error: 'A user can’t report to themselves.' });
      if (prof.reportsTo && !(await db.q('SELECT 1 FROM users WHERE id=$1', [prof.reportsTo])).rows.length) return res.status(400).json({ error: 'Reporting manager not found.' });
      vals.push(prof); sets.push(`profile = profile || $${vals.length}::jsonb`);
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
  if (!(req.params.col in R.COLLECTIONS)) return res.status(404).json({ error: 'Unknown collection.' });
  if (req.params.id !== undefined && !ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid record id.' });
  next();
};
const checkWrite = (req, res, next) => R.canWrite(parseRoles(req.user.role), DEFS, req.params.col)
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
    if (req.query.create === '1') {
      // New record: never overwrite one that another user saved a moment ago with the same number/code.
      const r = await db.q(
        `INSERT INTO docs (collection,id,data,updated_at,updated_by) VALUES ($1,$2,$3,now(),$4) ON CONFLICT (collection,id) DO NOTHING RETURNING id`,
        [col, id, data, req.user.id]);
      if (!r.rows.length) return res.status(409).json({ error: 'This number or code is already used.' });
    } else {
      await db.q(
        `INSERT INTO docs (collection,id,data,updated_at,updated_by) VALUES ($1,$2,$3,now(),$4)
         ON CONFLICT (collection,id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`,
        [col, id, data, req.user.id]);
    }
    await db.q('INSERT INTO audit (user_id,collection,doc_id,action,data) VALUES ($1,$2,$3,$4,$5)', [req.user.id, col, id, 'save', data]);
    if (col === 'settings' && id === 'roles') await loadRoleDefs();
    if (col === 'settings' && id === 'company') BRAND = null;
    broadcast({ t: 'doc', c: col, id, d: data });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// Deleting a record: Master role only (Admin included otherwise can't).
const checkDelete = (req, res, next) => R.canDelete(parseRoles(req.user.role))
  ? next()
  : res.status(403).json({ error: 'Only the Master role can delete records.' });

app.delete('/api/docs/:col/:id', auth, checkCol, checkDelete, async (req, res, next) => {
  try {
    const { col, id } = req.params;
    const { rows } = await db.q('DELETE FROM docs WHERE collection=$1 AND id=$2 RETURNING data', [col, id]);
    if (rows[0]) await db.q('INSERT INTO audit (user_id,collection,doc_id,action,data) VALUES ($1,$2,$3,$4,$5)', [req.user.id, col, id, 'delete', rows[0].data]);
    if (col === 'settings' && id === 'roles') await loadRoleDefs();
    broadcast({ t: 'doc', c: col, id, d: null });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// Master role: clear every transaction (documents + stock ledger). Masters, setup, users and settings stay.
app.post('/api/reset-transactions', auth, async (req, res, next) => {
  try {
    if (!R.canDelete(parseRoles(req.user.role))) return res.status(403).json({ error: 'Only the Master role can reset transactions.' });
    if (req.body?.confirm !== 'RESET') return res.status(400).json({ error: 'Type RESET to confirm.' });
    const { rows } = await db.q('DELETE FROM docs WHERE collection = ANY($1) RETURNING collection', [R.TXN_COLLECTIONS]);
    const deleted = {};
    for (const r of rows) deleted[r.collection] = (deleted[r.collection] || 0) + 1;
    await db.q('INSERT INTO audit (user_id,collection,doc_id,action,data) VALUES ($1,$2,$3,$4,$5)', [req.user.id, '*', 'all-transactions', 'reset', { deleted, total: rows.length }]);
    broadcast({ t: 'reset', by: req.user.name });
    res.json({ ok: true, deleted, total: rows.length });
  } catch (e) { next(e); }
});

// Full backup: Admin or Master (Master needs it before a reset).
app.get('/api/backup', auth, (req, res, next) => { const r = parseRoles(req.user.role); return r.includes('Admin') || R.canDelete(r) ? next() : res.status(403).json({ error: 'Only an Admin or Master can download a backup.' }); }, async (req, res, next) => {
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
// Shared permission rules, used by the browser too.
app.get('/roles.js', (req, res) => { res.set('Cache-Control', 'no-cache').type('application/javascript').sendFile(path.join(__dirname, 'roles.js')); });
// Works with the normal layout (index.html inside a "public" folder) and with a flat
// upload where every file sits next to server.js (what GitHub's web upload can produce).
const PUB = fs.existsSync(path.join(__dirname, 'public', 'index.html')) ? path.join(__dirname, 'public') : null;
if (!PUB && !fs.existsSync(path.join(__dirname, 'index.html'))) console.error('index.html not found. Upload index.html (or the public folder) next to server.js.');
app.use('/vendor', express.static(path.join(__dirname, 'node_modules', 'xlsx', 'dist'), { maxAge: '7d' }));
app.use('/vendor', express.static(path.join(__dirname, 'node_modules', 'exceljs', 'dist'), { maxAge: '7d' })); // Excel export with drop-downs

// App icons: from public/icons when present, otherwise the built-in copies below.
const ICONS = {
  'apple-touch-icon.png': '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',
  'icon-192.png': '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',
  'icon-512.png': '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',
  'maskable-512.png': 'iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAfUklEQVR4Xu3dCbQedX3w8V/Wm5CQsCQQlrAkEJYAsoY17AKyKVIQRUUqitq6UDfElkpFW1vhhRah8qLWDcUKsVDABRAT2UGWkLAECISE7CRkIblZ3zPT4osYQpZ57p3n+X0+59yD55jMMzMwM987z8z/32XA0OErAwBIpWuqrQUASgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAk1D3hNtOJ2k8Z2YmfDvXXNmpM/VeSltBlwNDhK1tiS6gVF3qoljCgagKASrjgQ8cSBKwvAcA6c9GHehADrAsBwFpz4Yd6EgKsDQHAGnHRh+YiBngrAoDVcuGH5iYEeDMCgFVy4YfWIgR4IwHAn3Dhh9YmBHiNkQD5Ixd/aH2Oc17jDgBOCJCUuwG5uQOQnN8GIC/Hf24CIDEHP+A8kJevABJywAOr4iuBXNwBSMbFH3gzzg+5CIBEHNzAW3GeyEMAJOGgBtaU80UOAiABBzOwtpw3Wp8AaHEOYmBdOX+0NgHQwhy8wPpyHmldAqBFOWiBqjiftCYB0IIcrEDVnFdajwBoMQ5SoFGcX1qLAGghDk6g0ZxnWocAAICEBECLUOVAR3G+aQ0CoAU4GIGO5rzT/ARAk3MQAp3F+ae5CQAASEgANDH1DXQ256HmJQCalIMOqAvno+YkAAAgIQHQhNQ2UDfOS81HAABAQgKgyahsoK6cn5qLAACAhARAE1HXQN05TzUPAQAACQkAAEhIADQJt9WAZuF81RwEAAAkJACagJoGmo3zVv0JAABISAAAQEICoObcRgOalfNXvQkAAEhIAABAQgIAABISADXm+zOg2TmP1ZcAAICEBAAAJCQAACAhAQAACQkAAEhIANSUJ2eBVuF8Vk8CAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQELdE24zNFz3rl1j+BZbx44DN4vtNx34vz8DYpM+faNPz56xQc+28p9t3XtE+7JlsXjpkpjfvjimvvJKTJ03NybOnhXjpk2J8VOnxBPTp8byFSsavs4dZeMN+sTuW2wVu225dewwcPPYst9GsUX//jGwb7/o3aNH+dOrR89ym9uXLS33z7zFi2Lmgvnlz0uvzI1nZ80ofybMnF7uq5UrV3bU6kPLEABQgS5dusR+22wfh+4wLA4ZMiz233ZI9GlrW6Mlv3bRKy6M22y86Z/9nQXti+Pe55+NMc8+HTePeyyenjFtjZZbF72694jDd9w5jtpplzhq2K7lRX9NdO3WLXp06xZ92yI27dO3jKhVKeLg4cmT4uHJL8Tvn50Qd02cEAvb29fkIyC1LgOGDpfONdR+ysgarhVvNHTAZnHGPvvHGXuPiG03GdAhO+ipGdPihkcfih/ef3dMnvtyh3zmuthr623jAyMOitP23C/69+69LotYJ0uXL48HJ02MXz85Lm4c+3B5l4DO1zZqTOevBH9CANSUAKi3g4fsGF865sQ4dOiwTlvRFStXxh1Pj48rRt8edzz9RKetxxsdsN3Qct8csePOtVin14Lpxw/cE5PmzK7FOmUkAOpHANSUAKinEdsOib899qTy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AUOHr2zmDWhV7aeMbNVNa0rFxb+IgGJinzoqYuUnD90XX7rp5w25rb1hr15x7sGHx7kHHxGbb9ivjrtgtRa0Ly4nf7q6QdNA89baRo156z9EhxIANSUA6un44XvEhce9s5y0py6KBxYvvGVUjH1pcsNXqUe3buVsfx89+PA4YLuhDf+89VU81PnjB++Ji279r5gxf976Lo71IADqRwDUlACor65dusRpe+0X57/9hE4bPrh4cv3W8WPjW2Nuj7uem9ApO2unzQbF6XuPiNP23C+223RAp6zDmynG9L/2ofviqjF3xISZ02u1blkJgPoRADUlAOqvS5cucciQHeP9+x0Y79pj73ISm0YrBqy5/tGHygmMikl06mKfwdvFcbvuHsfsPDz23Gqbct90tGIo52LGwWLmwWIaYt/z14sAqB8BUFMCoLn0besVR++0axy6w05x6NBhMWyzQZVsQDF73mNTXiwHrLnp8Yfj0SkvVrLcRiqm6j1k6LAYse32MWLbIbHHVoOjV/celX9kcRdk3LSX4t6Jz8Q9E5+N3054wpgHNSYA6kcA1JQAaG7Fg3LFha+YYXDogIHlPwf12yj69myLPm1t0adnz+jVo2d5gS/GHShuWc9euDAmzZld/pY/cfaseGTKpHh08ouxZPmypt4Z3bt2jSEDNothm20ewwYOim03GRCD+vWLzTfsXz5cWeyPXt27R1v3HuWdg2J7lyxbVu6bhe3tMWvh/Ji54H9+Js+dExNmTI+nZ06LZ2ZO95pjExEA9SMAakoAAK1EANSPkQABICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIANdU2akxN1wxg7Tif1ZMAAICEBAAAJCQAACAhAQAACQkAAEhIANSYJ2eBZuc8Vl8CAAASEgAAkJAAAICEBEDN+f4MaFbOX/UmAAAgIQEAAAkJgCbgNhrQbJy36k8AAEBCAqBJqGmgWThfNQcBAAAJCQAASEgANBG31YC6c55qHgIAABISAE1GXQN15fzUXAQAACQkAJqQygbqxnmp+QgAAEhIADQptQ3UhfNRcxIATcxBB3Q256HmJQAAICEB0OTUN9BZnH+amwBoAQ5CoKM57zQ/AdAiHIxAR3G+aQ0CAAASEgAtRJUDjeY80zoEQItxcAKN4vzSWgRAC3KQAlVzXmk9AqBFOViBqjiftCYB0MIctMD6ch5pXQKgxTl4gXXl/NHaBEACDmJgbTlvtD4BkISDGVhTzhc5CIBEHNTAW3GeyEMAJOPgBt6M80MuXQYMHb4y1ybzmvZTRtoZgAt/Uu4AJKb2AeeBvARAcg5+yMvxn5uvAPgjXwlADi78FNwB4I+cFKD1Oc55jTsArJK7AdBaXPh5IwHAagkBaG4u/LwZAcAaEQLQXFz4eSsCgLUmBqCeXPRZGwKAdSYEoB5c+FkXAoBKiAHoWC76rC8BQEMIAqiWCz5VEwB0KGEAq+dCT0cRAACQkJEAASAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQv8P9Jy+4uhQS/UAAAAASUVORK5CYII=',
};
// Company logo as app icon: icons generated in Company Profile are stored in settings/company.icons (data URLs).
let BRAND = null, BRAND_AT = 0;
async function brand() {
  if (BRAND && Date.now() - BRAND_AT < 60000) return BRAND;
  try { const { rows } = await db.q("SELECT data FROM docs WHERE collection='settings' AND id='company'"); BRAND = rows[0]?.data || {}; BRAND_AT = Date.now(); }
  catch { BRAND = BRAND || {}; }
  return BRAND;
}
const ICON_KEY = { 'icon-192.png': 'i192', 'icon-512.png': 'i512', 'maskable-512.png': 'm512', 'apple-touch-icon.png': 'a180', 'favicon.png': 'f64' };
app.get('/icons/:name', async (req, res, next) => {
  const k = ICON_KEY[req.params.name], ic = k && (await brand()).icons;
  const m = ic && typeof ic[k] === 'string' && ic[k].match(/^data:image\/png;base64,(.+)$/);
  if (m) return res.type('png').set('Cache-Control', 'no-cache').send(Buffer.from(m[1], 'base64'));
  if (req.params.name === 'favicon.png') req.params.name = 'icon-192.png';
  const f = PUB && path.join(PUB, 'icons', path.basename(req.params.name));
  if (f && fs.existsSync(f)) return res.sendFile(f);
  const b = ICONS[req.params.name];
  if (!b) return next();
  if ((await brand()).icons) res.set('Cache-Control', 'no-cache');
  if (!res.get('Cache-Control')) res.set('Cache-Control', 'public, max-age=604800');
  res.type('png').send(Buffer.from(b, 'base64'));
});
// Manifest with the company name and the logo icons (version in the URL so phones pick up a new logo).
app.get('/manifest.webmanifest', async (req, res, next) => {
  try {
    const f = [PUB && path.join(PUB, 'manifest.webmanifest'), path.join(__dirname, 'manifest.webmanifest')].find(x => x && fs.existsSync(x));
    if (!f) return next();
    const m = JSON.parse(fs.readFileSync(f, 'utf8')), b = await brand(), v = b.icons?.v ? '?v=' + b.icons.v : '';
    if (b.name) { m.name = b.name + ' ERP'; m.short_name = (b.short || b.name).split(/\s+/).slice(0, 2).join(' '); m.description = b.name + ' — manufacturing ERP'; }
    for (const i of [...(m.icons || []), ...(m.shortcuts || []).flatMap(s => s.icons || [])]) i.src = i.src.split('?')[0] + v;
    res.set('Cache-Control', 'no-cache').type('application/manifest+json').send(JSON.stringify(m, null, 2));
  } catch (e) { next(e); }
});

if (PUB) {
  // Android app (Play Store) verification file goes in public/.well-known/assetlinks.json
  app.use('/.well-known', express.static(path.join(PUB, '.well-known')));
  app.get('/sw.js', (req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(PUB, 'sw.js')); });
  app.use(express.static(PUB, { maxAge: 0 }));
} else {
  // Flat layout: serve only the app's own page files, never the server code.
  const page = (file, type) => (req, res, next) => {
    const f = path.join(__dirname, file);
    if (!fs.existsSync(f)) return next();
    res.set('Cache-Control', 'no-cache').type(type).sendFile(f);
  };
  app.get(['/', '/index.html'], page('index.html', 'html'));
  app.get('/sw.js', page('sw.js', 'application/javascript'));
}

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

// Default item types, and a Quality Hold store for QC, if the database doesn't have them yet.
async function seedItemTypes() {
  const n = (await db.q("SELECT count(*)::int AS n FROM docs WHERE collection='itemtypes'")).rows[0].n;
  if (!n) {
    const types = [['Raw Material', false, true], ['Packing Material', false, true], ['Semi-Finished', true, true], ['Finished Good', true, true],
      ['Consumable', false, true], ['Spare Part', false, true], ['Service', false, false]];
    for (const [code, made, inventory] of types) {
      await db.q("INSERT INTO docs (collection,id,data,updated_by) VALUES ('itemtypes',$1,$2,'setup') ON CONFLICT DO NOTHING",
        [code.replace(/[^A-Za-z0-9_\-.~:@+]/g, '_'), { code, desc: '', made, inventory, active: true, lines: [] }]);
    }
    console.log('Added default item types.');
  }
  const hold = (await db.q("SELECT 1 FROM docs WHERE collection='warehouses' AND data->>'type'='Quality Hold' LIMIT 1")).rows.length;
  if (!hold) await db.q("INSERT INTO docs (collection,id,data,updated_by) VALUES ('warehouses','QC',$1,'setup') ON CONFLICT DO NOTHING",
    [{ code: 'QC', name: 'Quality Hold (QC)', type: 'Quality Hold', location: '' }]);
}

(async () => {
  try {
    await db.init();
    await db.q("ALTER TABLE users ADD COLUMN IF NOT EXISTS profile JSONB NOT NULL DEFAULT '{}'::jsonb");
    await loadRoleDefs();
    await ensureAdmin();
    await seedDefaults();
    await seedItemTypes();
    server.listen(PORT, () => console.log(`Gopin Semicon ERP running on http://localhost:${PORT}`));
  } catch (e) {
    console.error('Could not start:', e.message);
    process.exit(1);
  }
})();

process.on('SIGTERM', () => { server.close(() => db.pool.end().then(() => process.exit(0))); });
