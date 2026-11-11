'use strict';
// Load a JSON backup (downloaded from Company Setup → "Download full backup") into the database.
// Records with the same collection + id are overwritten; nothing else is deleted.
// Usage: npm run restore -- path/to/gopin-erp-backup.json
require('dotenv').config();
const fs = require('fs');
const db = require('../db');
const { COLLECTIONS } = require('../roles');

(async () => {
  const file = process.argv[2];
  if (!file) { console.error('Usage: npm run restore -- path/to/backup.json'); process.exit(1); }
  const backup = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (backup.app !== 'gopin-erp' || !Array.isArray(backup.docs)) { console.error('This is not a Gopin ERP backup file.'); process.exit(1); }
  await db.init();
  const client = await db.pool.connect();
  let n = 0;
  try {
    await client.query('BEGIN');
    for (const d of backup.docs) {
      if (!(d.collection in COLLECTIONS) || !d.id || typeof d.data !== 'object') continue;
      await client.query(
        `INSERT INTO docs (collection,id,data,updated_at,updated_by) VALUES ($1,$2,$3,now(),'restore')
         ON CONFLICT (collection,id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by='restore'`,
        [d.collection, d.id, d.data]);
      n++;
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  console.log(`Restored ${n} records from ${file}. Restart the app or reload the browser to see them.`);
  await db.pool.end();
})().catch(e => { console.error(e.message); process.exit(1); });
