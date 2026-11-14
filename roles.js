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
    ['plantdash', 'Home', 'Plant Dashboard', 'v'],
    ['items', 'Masters', 'Items', 'vced'], ['itemtypes', 'Masters', 'Item Types', 'vced'], ['products', 'Masters', 'Product Master', 'v'], ['boms', 'Masters', 'Bill of Materials', 'vced'],
    ['routings', 'Masters', 'Routings', 'vced'], ['suppliers', 'Masters', 'Suppliers', 'vced'], ['supcodes', 'Masters', 'Supplier Item Codes', 'vced'], ['customers', 'Masters', 'Customers', 'vced'],
    ['departments', 'Masters', 'Departments', 'vced'], ['warehouses', 'Masters', 'Warehouses', 'vced'], ['workcenters', 'Masters', 'Work Centers', 'vced'],
    ['uoms', 'Masters', 'Units of Measure', 'vced'],
    ['prs', 'Procurement', 'Purchase Requisitions', 'vceda'], ['pos', 'Procurement', 'Purchase Orders', 'vceda'],
    ['grns', 'Stores', 'Goods Receipt (GRN)', 'vcedp'], ['pinv', 'Procurement', 'Purchase Invoices', 'vceda'],
    ['mtns', 'Stores', 'Material Transfers', 'vcedp'], ['mrs', 'Stores', 'Direct Material Requests', 'vceda'], ['mins', 'Stores', 'Direct Material Issues', 'vcedp'], ['mrets', 'Stores', 'Material Returns', 'vcedp'],
    ['gatepasses', 'Security', 'Gate Passes', 'vcedap'],
    ['qcs', 'Quality', 'QC Inspections', 'vep'],
    ['prods', 'Production', 'Production Orders', 'vcedap'], ['mtrs', 'Production', 'Material Transfer Requests', 'vceda'], ['sched', 'Production', 'Machine Schedule', 'v'], ['plan', 'Production', 'Material Planning', 'v'],
    ['sos', 'Sales', 'Sales Orders', 'vcedap'], ['dispatches', 'Sales', 'Dispatch Notes', 'vcedp'], ['sinv', 'Sales', 'Sales Invoices', 'vceda'],
    ['stock', 'Inventory', 'Stock on Hand', 'v'], ['batches', 'Inventory', 'Batch Stock & Aging', 'v'], ['ledger', 'Inventory', 'Stock Ledger', 'v'],
    ['journals', 'Inventory', 'Stock Journal', 'vceda'],
    ['hrdash', 'HR', 'HR Dashboard', 'v'], ['orgchart', 'HR', 'Organization Chart', 'v'], ['notices', 'HR', 'Circulars, News & Policies', 'vced'],
    ['employees', 'HR', 'Employees', 'vced'], ['grades', 'HR', 'Grade Master', 'vced'], ['shifts', 'HR', 'Shifts', 'vced'], ['holidays', 'HR', 'Holidays', 'vced'], ['leavetypes', 'HR', 'Leave Types', 'vced'],
    ['punches', 'HR', 'Punch Data', 'vced'], ['attreg', 'HR', 'Attendance Register', 'v'], ['lvapps', 'HR', 'Leave Applications', 'vceda'], ['compoffs', 'HR', 'Comp-Off', 'vceda'],
    ['leavebal', 'HR', 'Leave Balance', 'v'], ['eops', 'HR', 'Employee Out Pass', 'vcedap'], ['resigns', 'HR', 'Resignation & Exit', 'vcedap'],
    ['ctcs', 'HR', 'Salary Structure (CTC)', 'vced'], ['payruns', 'HR', 'Payroll', 'vcedap'], ['payslips', 'HR', 'Salary Slip', 'v'], ['appraisals', 'HR', 'Performance Review (PMS)', 'vcedap'],
    ['mprs', 'HR', 'Manpower Requisition', 'vcedap'], ['candidates', 'HR', 'Candidates', 'vced'], ['letters', 'HR', 'HR Letters', 'vced'], ['inductions', 'HR', 'Induction', 'vcedp'],
    ['meals', 'HR', 'Canteen Meal Rates', 'vced'], ['canteen', 'HR', 'Canteen Entries', 'vced'], ['insurances', 'HR', 'Employee Insurance', 'vced'], ['claims', 'HR', 'Insurance Claims', 'vcedap'],
  ].map(([key, group, title, acts]) => ({ key, group, title, acts: acts.split('') }));
  const PAGE = Object.fromEntries(PAGES.map(p => [p.key, p]));

  // Ready-made roles (each can be edited, copied or deleted in Role Center).
  const P = (s) => s; // readability helper
  const BUILT_IN = {
    'Purchase Manager': { desc: 'Requisitions and purchase orders; approves PRs and POs', perms: {
      items: P('vced'), itemtypes: 'vced', products: 'v', suppliers: 'vced', supcodes: 'vced', uoms: 'vced', departments: 'v', boms: 'v', prs: 'vceda', pos: 'vceda', grns: 'v', pinv: 'v',
      mrs: 'v', plan: 'v', stock: 'v', batches: 'v', sos: 'v' } },
    'Purchase Executive': { desc: 'Creates purchase orders from approved requisitions; adds suppliers', perms: {
      items: 'v', suppliers: 'vce', supcodes: 'vce', prs: 'vce', pos: 'vce', grns: 'v', plan: 'v', stock: 'v' } },
    'Stores Manager': { desc: 'GRN, material issue and returns, dispatch, stock journals, gate passes; approves material requests and journals', perms: {
      items: 'vced', itemtypes: 'vced', products: 'v', qcs: 'v', uoms: 'vced', warehouses: 'vced', departments: 'vced', employees: 'vced', suppliers: 'v', supcodes: 'vced', customers: 'v', prs: 'vceda', pos: 'v', grns: 'vcedp',
      mrs: 'vceda', mins: 'vcedp', mrets: 'vcedp', mtrs: 'v', mtns: 'vcedp', gatepasses: 'vcedap', prods: 'v', plan: 'v', sos: 'v', dispatches: 'vcedp',
      stock: 'v', batches: 'v', ledger: 'v', journals: 'vceda' } },
    'Stores Executive': { desc: 'Enters GRN, material issues and returns, dispatch, stock journals and gate passes', perms: {
      items: 'v', itemtypes: 'v', qcs: 'v', warehouses: 'v', suppliers: 'v', supcodes: 'v', customers: 'v', prs: 'vce', pos: 'v', grns: 'vcep', mrs: 'vce', mins: 'vcep', mrets: 'vcep', mtrs: 'v', mtns: 'vcep',
      gatepasses: 'vcep', prods: 'v', sos: 'v', dispatches: 'vcep', stock: 'v', batches: 'v', ledger: 'v', journals: 'vce' } },
    'Production Manager': { desc: 'Product master, BOMs, routings, work centers; releases production orders; approves material requests', perms: {
      items: 'vced', itemtypes: 'vced', supcodes: 'v', qcs: 'v', products: 'v', boms: 'vced', routings: 'vced', workcenters: 'vced', uoms: 'v', departments: 'v', employees: 'vce', prs: 'vceda', mrs: 'vceda', mtrs: 'vceda', mtns: 'v',
      prods: 'vcedap', sched: 'v', plan: 'v', sos: 'v', stock: 'v', batches: 'v' } },
    'Production Planner': { desc: 'Plans production and raises material transfer requests (store → WIP) against production orders', perms: {
      items: 'v', products: 'v', boms: 'v', routings: 'v', workcenters: 'v', warehouses: 'v', prods: 'vce', mtrs: 'vce', mtns: 'v', sched: 'v', plan: 'v', sos: 'v', stock: 'v', batches: 'v' } },
    'Production Supervisor': { desc: 'Creates production orders and material requests, marks operations done', perms: {
      items: 'v', products: 'v', boms: 'v', routings: 'v', prs: 'vce', mrs: 'vce', mtrs: 'vce', prods: 'vcep', sched: 'v', plan: 'v', stock: 'v' } },
    'Sales Manager': { desc: 'Customers and sales orders; confirms sales orders', perms: {
      items: 'v', products: 'v', customers: 'vced', prs: 'vce', mrs: 'vce', sos: 'vceda', dispatches: 'v', sinv: 'v', stock: 'v' } },
    'Sales Executive': { desc: 'Creates customers and sales orders', perms: {
      products: 'v', customers: 'vce', prs: 'vce', mrs: 'vce', sos: 'vce', dispatches: 'v', sinv: 'v', stock: 'v' } },
    'Accounts': { desc: 'Creates and posts sales and purchase invoices', perms: {
      suppliers: 'v', supcodes: 'v', customers: 'v', prs: 'vce', pos: 'v', grns: 'v', pinv: 'vceda', sos: 'v', dispatches: 'v', sinv: 'vceda', stock: 'v', ledger: 'v' } },
    'Quality Inspector': { desc: 'Inspects goods held for QC and posts accepted / rejected quantities', perms: {
      qcs: 'vep', items: 'v', itemtypes: 'v', suppliers: 'v', supcodes: 'v', grns: 'v', prods: 'v', mrs: 'vce', prs: 'vce', stock: 'v', batches: 'v', ledger: 'v' } },
    'Security Guard': { desc: 'Creates gate passes, marks gate in / gate out and employee out passes', perms: { gatepasses: 'vcep', eops: 'vp' } },
    'HR Manager': { desc: 'Full HR: employees, attendance, leave and exit; approves leave, comp-off, out pass and resignation', perms: {
      departments: 'vce', employees: 'vce', grades: 'vce', shifts: 'vce', holidays: 'vce', leavetypes: 'vce', punches: 'vce', attreg: 'v', lvapps: 'vcea', compoffs: 'vcea', leavebal: 'v', eops: 'vceap', resigns: 'vceap',
      hrdash: 'v', orgchart: 'v', notices: 'vce', ctcs: 'vce', payruns: 'vceap', payslips: 'v', appraisals: 'vceap', mprs: 'vceap', candidates: 'vce', letters: 'vce', inductions: 'vcep', meals: 'vce', canteen: 'vce', insurances: 'vce', claims: 'vceap' } },
    'HR Executive': { desc: 'Maintains employees and punch data, completes exit clearance', perms: {
      departments: 'v', employees: 'vce', grades: 'vce', shifts: 'v', holidays: 'vce', leavetypes: 'v', punches: 'vce', attreg: 'v', lvapps: 'vce', compoffs: 'vce', leavebal: 'v', eops: 'vcep', resigns: 'vcep',
      hrdash: 'v', orgchart: 'v', notices: 'vce', payslips: 'v', appraisals: 'vce', mprs: 'vce', candidates: 'vce', letters: 'vce', inductions: 'vcep', meals: 'v', canteen: 'vce', insurances: 'vce', claims: 'vcep' } },
    'Employee (Self Service)': { desc: 'Applies for own leave, comp-off, out pass and resignation; sees own attendance and leave balance', perms: {
      holidays: 'v', attreg: 'v', leavebal: 'v', lvapps: 'vce', compoffs: 'vce', eops: 'vce', resigns: 'vce', notices: 'v', orgchart: 'v', payslips: 'v', appraisals: 'vce', insurances: 'v', claims: 'vce', canteen: 'v' } },
    'Payroll Executive': { desc: 'Salary structures, monthly payroll and salary slips', perms: {
      employees: 'v', attreg: 'v', leavebal: 'v', canteen: 'v', meals: 'v', ctcs: 'vce', payruns: 'vcep', payslips: 'v', hrdash: 'v' } },
    'Canteen Operator': { desc: 'Records canteen meals', perms: { meals: 'v', canteen: 'vce' } },
    'Viewer': { desc: 'Can look at every work page, change nothing', perms: Object.fromEntries(PAGES.filter(p => !['ctcs', 'payruns'].includes(p.key)).map(p => [p.key, 'v'])) },
  };
  // Master: everything on every work page, and the ONLY role that can delete records.
  const MASTER = 'Master';
  const MASTER_DEF = { desc: 'Full access to every work page, and the only role that can delete records', perms: Object.fromEntries(PAGES.map(p => [p.key, p.acts.join('')])) };
  const noDel = (perms) => Object.fromEntries(Object.entries(perms || {}).map(([k, v]) => [k, String(v || '').replace(/d/g, '')]));

  // Built-in roles, then the admin's changes (stored in settings/roles) on top.
  function effective(custom) {
    const out = {};
    for (const [k, v] of Object.entries(BUILT_IN)) out[k] = { desc: v.desc, perms: noDel(v.perms), builtIn: true };
    for (const [k, v] of Object.entries(custom || {})) {
      if (!v || k === 'Admin' || k === MASTER) continue;
      if (v.deleted) { delete out[k]; continue; }
      out[k] = { desc: v.desc || '', perms: noDel(v.perms), builtIn: k in BUILT_IN };   // delete is never given to other roles
    }
    out[MASTER] = { desc: MASTER_DEF.desc, perms: { ...MASTER_DEF.perms }, builtIn: true, fixed: true };
    return out;
  }

  // "Stores Executive,Accounts" -> ['Stores Executive','Accounts'] (unknown names dropped).
  function parseRoles(s, defs) {
    const list = [...new Set(String(s || '').split(',').map(r => r.trim()).filter(r => r === 'Admin' || (defs && r in defs)))];
    if (list.length) return list;
    return defs && defs.Viewer ? ['Viewer'] : [];
  }

  function can(userRoles, defs, page, act) {
    if (act === 'd') return userRoles.includes(MASTER);          // only Master deletes — not even Admin
    if (userRoles.includes('Admin') || userRoles.includes(MASTER)) return true;
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
    ['mtns', 'p', ['mtrs', 'ledger']],             // transfer moves stock store → WIP and updates its request
    ['prods', 'p', ['ledger', 'qcs']],           // issue materials / report finished (QC items open an inspection)
    ['qcs', 'p', ['grns', 'prods', 'ledger']],   // QC result releases stock and updates its GRN / production order
    ['dispatches', 'p', ['sos', 'ledger']],      // dispatch updates SO + stock
    ['sinv', 'a', ['dispatches']],               // invoice marks dispatch billed
    ['journals', 'a', ['ledger']], ['journals', 'p', ['ledger']],
    ['resigns', 'a', ['employees']], ['resigns', 'p', ['employees']],
    ['candidates', 'c', ['employees']], ['appraisals', 'a', ['employees']],   // joining creates the employee; closing a probation review confirms them   // accepting / completing an exit updates the employee
  ];
  const WRITE_ACTS = ['c', 'e', 'd', 'a', 'p'];
  // Every data collection the server stores.
  const COLLECTIONS = Object.fromEntries(['items', 'itemtypes', 'boms', 'routings', 'suppliers', 'supcodes', 'customers', 'departments', 'employees', 'warehouses', 'workcenters', 'uoms',
    'prs', 'pos', 'grns', 'pinv', 'mrs', 'mins', 'mrets', 'mtrs', 'mtns', 'gatepasses', 'qcs', 'prods', 'sos', 'dispatches', 'sinv', 'journals', 'ledger', 'settings', 'shifts', 'holidays', 'leavetypes', 'punches', 'lvapps', 'compoffs', 'eops', 'resigns', 'grades', 'notices', 'ctcs', 'payruns', 'appraisals', 'meals', 'canteen', 'insurances', 'claims', 'mprs', 'candidates', 'inductions', 'letters'].map(c => [c, true]));

  // Transaction data (cleared by "Reset all transactions"); masters, setup, users and settings are kept.
  const TXN_COLLECTIONS = ['prs', 'pos', 'grns', 'pinv', 'mrs', 'mins', 'mrets', 'mtrs', 'mtns', 'gatepasses', 'qcs', 'prods', 'sos', 'dispatches', 'sinv', 'journals', 'ledger', 'punches', 'lvapps', 'compoffs', 'eops', 'resigns', 'payruns', 'appraisals', 'canteen', 'claims', 'mprs', 'candidates', 'inductions', 'letters'];

  function canWrite(userRoles, defs, collection) {
    if (userRoles.includes('Admin')) return true;
    if (collection === 'settings') return false;
    if (PAGE[collection] && WRITE_ACTS.some(a => can(userRoles, defs, collection, a))) return true;
    return LINKED.some(([page, act, cols]) => cols.includes(collection) && can(userRoles, defs, page, act));
  }

  const canDelete = (userRoles) => userRoles.includes(MASTER);
  return { ACTIONS, ACTION_LABELS, PAGES, PAGE, BUILT_IN, MASTER, COLLECTIONS, TXN_COLLECTIONS, effective, parseRoles, can, canWrite, canDelete };
});
