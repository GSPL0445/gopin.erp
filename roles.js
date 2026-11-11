'use strict';
// Who may change what. Must match ROLES in public/index.html.

const ROLES = {
  'Admin': '*',
  'Purchase Manager': ['purchase', 'masters'],
  'Purchase Executive': ['purchase'],
  'Stores Manager': ['stores', 'gate', 'masters'],
  'Stores Executive': ['stores', 'gate'],
  'Production Manager': ['production'],
  'Production Supervisor': ['production'],
  'Sales Manager': ['sales'],
  'Sales Executive': ['sales'],
  'Accounts': ['accounts'],
  'Security Guard': ['gate'],
  'Viewer': [],
};

// Which modules may write each collection. Some posting steps update a document
// owned by another module (a GRN updates its PO's received qty, a dispatch
// updates its SO, an invoice marks its dispatch/GRN as billed), so those
// modules are listed too.
const COLLECTIONS = {
  items: ['masters'], uoms: ['masters'],
  suppliers: ['purchase'], customers: ['sales'], warehouses: ['stores'],
  boms: ['production'], routings: ['production'], workcenters: ['production'],
  pos: ['purchase', 'stores'],
  grns: ['stores', 'accounts'],
  prods: ['production'],
  sos: ['sales', 'stores'],
  dispatches: ['stores', 'accounts'],
  sinv: ['accounts'], pinv: ['accounts'],
  journals: ['stores'],
  gatepasses: ['gate'],
  ledger: ['stores', 'production'],
  settings: [],            // Admin only
};

function canWrite(role, collection) {
  if (!(collection in COLLECTIONS)) return false;
  if (role === 'Admin') return true;
  const mods = ROLES[role];
  if (!Array.isArray(mods)) return false;
  return COLLECTIONS[collection].some(m => mods.includes(m));
}

module.exports = { ROLES, COLLECTIONS, canWrite };
