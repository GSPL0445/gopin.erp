'use strict';
// Who may change what. Must match ROLES in public/index.html.

const ROLES = {
  'Admin': '*',
  'Purchase Manager': ['purchase', 'masters', 'request'],
  'Purchase Executive': ['purchase', 'request'],
  'Stores Manager': ['stores', 'gate', 'masters', 'request'],
  'Stores Executive': ['stores', 'gate', 'request'],
  'Production Manager': ['production', 'masters', 'request'],
  'Production Supervisor': ['production', 'request'],
  'Sales Manager': ['sales', 'request'],
  'Sales Executive': ['sales', 'request'],
  'Accounts': ['accounts', 'request'],
  'Security Guard': ['gate'],
  'Viewer': [],
};

// Which modules may write each collection. Some posting steps update a document
// owned by another module (a GRN updates its PO's received qty, a dispatch
// updates its SO, an invoice marks its dispatch/GRN as billed), so those
// modules are listed too.
const COLLECTIONS = {
  items: ['masters'], uoms: ['masters'], departments: ['masters'],
  suppliers: ['purchase'], customers: ['sales'], warehouses: ['stores'],
  boms: ['production'], routings: ['production'], workcenters: ['production'],
  prs: ['request', 'purchase'],          // PO approval marks PR lines as ordered
  pos: ['purchase', 'stores'],
  grns: ['stores', 'accounts'],
  mrs: ['request', 'stores'],            // material issue marks MR lines as issued
  mins: ['stores'], mrets: ['stores'],
  prods: ['production', 'stores'],       // material issue against an MO updates it
  sos: ['sales', 'stores'],
  dispatches: ['stores', 'accounts'],
  sinv: ['accounts'], pinv: ['accounts'],
  journals: ['stores'],
  gatepasses: ['gate'],
  ledger: ['stores', 'production'],
  settings: [],            // Admin only
};

// A user can hold several roles, stored as "Stores Executive,Accounts".
function parseRoles(role) {
  const list = String(role || '').split(',').map(r => r.trim()).filter(r => r in ROLES);
  return list.length ? [...new Set(list)] : ['Viewer'];
}

function canWrite(role, collection) {
  if (!(collection in COLLECTIONS)) return false;
  const roles = parseRoles(role);
  if (roles.includes('Admin')) return true;
  return roles.some(r => Array.isArray(ROLES[r]) && COLLECTIONS[collection].some(m => ROLES[r].includes(m)));
}

module.exports = { ROLES, COLLECTIONS, canWrite, parseRoles };
