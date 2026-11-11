/* Gopin ERP — roles and permissions.
   Shared by the server (require('./roles')) and the browser (<script src="/roles.js">),
   so both always apply exactly the same rules. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ERP_ROLES = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // v view · c create · e edit · d delete · a approve (approve / reject / release / confirm / final post) · p process (post GRN, issue, dispatch, gate in/out…)
  const ACTIONS = ['v', 'c', 'e', 'd', 'a', 'p'];
  const ACTION_LABELS = { v: 'View', c: 'Create', e: 'Edit', d: 'Delete', a: 'Approve', p: 'Post / Process' };

  // Every work page: [key, menu group, title, which actions apply]
  const PAGES = [
    ['items', 'Masters', 'Items', 'vced'], ['itemtypes', 'Masters', 'Item Types', 'vced'], ['products', 'Masters', 'Product Master', 'v'], ['boms', 'Masters', 'Bill of Materials', 'vced'],
    ['routings', 'Masters', 'Routings', 'vced'], ['suppliers', 'Masters', 'Suppliers', 'vced'], ['customers', 'Masters', 'Customers', 'vced'],
    ['departments', 'Masters', 'Departments', 'vced'], ['warehouses', 'Masters', 'Warehouses', 'vced'], ['workcenters', 'Masters', 'Work Centers', 'vced'],
    ['uoms', 'Masters', 'Units of Measure', 'vced'],
    ['prs', 'Procurement', 'Purchase Requisitions', 'vceda'], ['pos', 'Procurement', 'Purchase Orders', 'vceda'],
    ['grns', 'Procurement', 'Goods Receipt (GRN)', 'vcedp'], ['pinv', 'Procurement', 'Purchase Invoices', 'vceda'],
    ['mrs', 'Stores', 'Material Requests', 'vceda'], ['mins', 'Stores', 'Material Issues', 'vcedp'], ['mrets', 'Stores', 'Material Returns', 'vcedp'],
    ['gatepasses', 'Stores', 'Gate Passes', 'vcedap'],
    ['qcs', 'Quality', 'QC Inspections', 'vep'],
    ['prods', 'Production', 'Production Orders', 'vcedap'], ['sched', 'Production', 'Machine Schedule', 'v'], ['plan', 'Production', 'Material Planning', 'v'],
    ['sos', 'Sales', 'Sales Orders', 'vcedap'], ['dispatches', 'Sales', 'Dispatch Notes', 'vcedp'], ['sinv', 'Sales', 'Sales Invoices', 'vceda'],
    ['stock', 'Inventory', 'Stock on Hand', 'v'], ['batches', 'Inventory', 'Batch Stock & Aging', 'v'], ['ledger', 'Inventory', 'Stock Ledger', 'v'],
    ['journals', 'Inventory', 'Stock Journal', 'vceda'],
  ].map(([key, group, title, acts]) => ({ key, group, title, acts: acts.split('') }));
  const PAGE = Object.fromEntries(PAGES.map(p => [p.key, p]));

  // Ready-made roles (each can be edited, copied or deleted in Role Center).
  const P = (s) => s; // readability helper
  const BUILT_IN = {
    'Purchase Manager': { desc: 'Requisitions and purchase orders; approves PRs and POs', perms: {
      items: P('vced'), itemtypes: 'vced', products: 'v', suppliers: 'vced', uoms: 'vced', departments: 'v', boms: 'v', prs: 'vceda', pos: 'vceda', grns: 'v', pinv: 'v',
      mrs: 'v', plan: 'v', stock: 'v', batches: 'v', sos: 'v' } },
    'Purchase Executive': { desc: 'Creates purchase orders from approved requisitions; adds suppliers', perms: {
      items: 'v', suppliers: 'vce', prs: 'vce', pos: 'vce', grns: 'v', plan: 'v', stock: 'v' } },
    'Stores Manager': { desc: 'GRN, material issue and returns, dispatch, stock journals, gate passes; approves material requests and journals', perms: {
      items: 'vced', itemtypes: 'vced', products: 'v', qcs: 'v', uoms: 'vced', warehouses: 'vced', departments: 'vced', suppliers: 'v', customers: 'v', prs: 'vceda', pos: 'v', grns: 'vcedp',
      mrs: 'vceda', mins: 'vcedp', mrets: 'vcedp', gatepasses: 'vcedap', prods: 'v', plan: 'v', sos: 'v', dispatches: 'vcedp',
      stock: 'v', batches: 'v', ledger: 'v', journals: 'vceda' } },
    'Stores Executive': { desc: 'Enters GRN, material issues and returns, dispatch, stock journals and gate passes', perms: {
      items: 'v', itemtypes: 'v', qcs: 'v', warehouses: 'v', suppliers: 'v', customers: 'v', prs: 'vce', pos: 'v', grns: 'vcep', mrs: 'vce', mins: 'vcep', mrets: 'vcep',
      gatepasses: 'vcep', prods: 'v', sos: 'v', dispatches: 'vcep', stock: 'v', batches: 'v', ledger: 'v', journals: 'vce' } },
    'Production Manager': { desc: 'Product master, BOMs, routings, work centers; releases production orders; approves material requests', perms: {
      items: 'vced', itemtypes: 'vced', qcs: 'v', products: 'v', boms: 'vced', routings: 'vced', workcenters: 'vced', uoms: 'v', departments: 'v', prs: 'vceda', mrs: 'vceda',
      prods: 'vcedap', sched: 'v', plan: 'v', sos: 'v', stock: 'v', batches: 'v' } },
    'Production Supervisor': { desc: 'Creates production orders and material requests, marks operations done', perms: {
      items: 'v', products: 'v', boms: 'v', routings: 'v', prs: 'vce', mrs: 'vce', prods: 'vcep', sched: 'v', plan: 'v', stock: 'v' } },
    'Sales Manager': { desc: 'Customers and sales orders; confirms sales orders', perms: {
      items: 'v', products: 'v', customers: 'vced', prs: 'vce', mrs: 'vce', sos: 'vceda', dispatches: 'v', sinv: 'v', stock: 'v' } },
    'Sales Executive': { desc: 'Creates customers and sales orders', perms: {
      products: 'v', customers: 'vce', prs: 'vce', mrs: 'vce', sos: 'vce', dispatches: 'v', sinv: 'v', stock: 'v' } },
    'Accounts': { desc: 'Creates and posts sales and purchase invoices', perms: {
      suppliers: 'v', customers: 'v', prs: 'vce', pos: 'v', grns: 'v', pinv: 'vceda', sos: 'v', dispatches: 'v', sinv: 'vceda', stock: 'v', ledger: 'v' } },
    'Quality Inspector': { desc: 'Inspects goods held for QC and posts accepted / rejected quantities', perms: {
      qcs: 'vep', items: 'v', itemtypes: 'v', suppliers: 'v', grns: 'v', prods: 'v', mrs: 'vce', prs: 'vce', stock: 'v', batches: 'v', ledger: 'v' } },
    'Security Guard': { desc: 'Creates gate passes and marks gate in / gate out', perms: { gatepasses: 'vcep' } },
    'Viewer': { desc: 'Can look at every work page, change nothing', perms: Object.fromEntries(PAGES.map(p => [p.key, 'v'])) },
  };

  // Built-in roles, then the admin's changes (stored in settings/roles) on top.
  function effective(custom) {
    const out = {};
    for (const [k, v] of Object.entries(BUILT_IN)) out[k] = { desc: v.desc, perms: { ...v.perms }, builtIn: true };
    for (const [k, v] of Object.entries(custom || {})) {
      if (!v || k === 'Admin') continue;
      if (v.deleted) { delete out[k]; continue; }
      out[k] = { desc: v.desc || '', perms: { ...(v.perms || {}) }, builtIn: k in BUILT_IN };
    }
    return out;
  }

  // "Stores Executive,Accounts" -> ['Stores Executive','Accounts'] (unknown names dropped).
  function parseRoles(s, defs) {
    const list = [...new Set(String(s || '').split(',').map(r => r.trim()).filter(r => r === 'Admin' || (defs && r in defs)))];
    if (list.length) return list;
    return defs && defs.Viewer ? ['Viewer'] : [];
  }

  function can(userRoles, defs, page, act) {
    if (userRoles.includes('Admin')) return true;
    return userRoles.some(r => String(defs[r]?.perms?.[page] || '').includes(act));
  }

  // Posting one document also updates linked documents and the stock ledger.
  // [page, action, collections that action writes besides its own]
  const LINKED = [
    ['pos', 'a', ['prs']],                       // approving a PO marks PR lines as ordered
    ['grns', 'p', ['pos', 'ledger', 'qcs']],     // GRN updates PO received qty + stock, opens QC inspections
    ['pinv', 'a', ['grns']],                     // purchase invoice marks GRN billed
    ['mins', 'p', ['mrs', 'prods', 'ledger']],   // issue updates MR + its production order + stock
    ['mrets', 'p', ['ledger']],
    ['prods', 'p', ['ledger', 'qcs']],           // issue materials / report finished (QC items open an inspection)
    ['qcs', 'p', ['grns', 'prods', 'ledger']],   // QC result releases stock and updates its GRN / production order
    ['dispatches', 'p', ['sos', 'ledger']],      // dispatch updates SO + stock
    ['sinv', 'a', ['dispatches']],               // invoice marks dispatch billed
    ['journals', 'a', ['ledger']], ['journals', 'p', ['ledger']],
  ];
  const WRITE_ACTS = ['c', 'e', 'd', 'a', 'p'];
  // Every data collection the server stores.
  const COLLECTIONS = Object.fromEntries(['items', 'itemtypes', 'boms', 'routings', 'suppliers', 'customers', 'departments', 'warehouses', 'workcenters', 'uoms',
    'prs', 'pos', 'grns', 'pinv', 'mrs', 'mins', 'mrets', 'gatepasses', 'qcs', 'prods', 'sos', 'dispatches', 'sinv', 'journals', 'ledger', 'settings'].map(c => [c, true]));

  function canWrite(userRoles, defs, collection) {
    if (userRoles.includes('Admin')) return true;
    if (collection === 'settings') return false;
    if (PAGE[collection] && WRITE_ACTS.some(a => can(userRoles, defs, collection, a))) return true;
    return LINKED.some(([page, act, cols]) => cols.includes(collection) && can(userRoles, defs, page, act));
  }

  return { ACTIONS, ACTION_LABELS, PAGES, PAGE, BUILT_IN, COLLECTIONS, effective, parseRoles, can, canWrite };
});
