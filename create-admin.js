'use strict';
// Create an Admin user, or reset an existing user to Admin with a new password.
// Usage: npm run create-admin -- --email you@company.com --name "Your Name" --password "S3cure-pass"
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../db');

const arg = k => { const i = process.argv.indexOf('--' + k); return i > -1 ? process.argv[i + 1] : undefined; };

(async () => {
  const email = String(arg('email') || process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const name = String(arg('name') || process.env.ADMIN_NAME || 'Administrator');
  const password = String(arg('password') || process.env.ADMIN_PASSWORD || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
    console.error('Usage: npm run create-admin -- --email you@company.com --name "Your Name" --password "at-least-8-chars"');
    process.exit(1);
  }
  await db.init();
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await db.q('SELECT id FROM users WHERE lower(email)=$1', [email]);
  if (rows[0]) {
    await db.q("UPDATE users SET role='Admin', active=TRUE, password_hash=$1, name=$2, token_version=token_version+1, updated_at=now() WHERE id=$3", [hash, name, rows[0].id]);
    console.log(`Updated ${email}: now Admin with the new password.`);
  } else {
    await db.q('INSERT INTO users (id,email,name,password_hash,role) VALUES ($1,$2,$3,$4,$5)',
      ['u_' + crypto.randomBytes(9).toString('hex'), email, name, hash, 'Admin']);
    console.log(`Created Admin ${email}.`);
  }
  await db.pool.end();
})().catch(e => { console.error(e.message); process.exit(1); });
