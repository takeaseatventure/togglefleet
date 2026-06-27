'use strict';
// ToggleFleet — multi-tenant cloud feature flags. SSO via the shared auth proxy, Postgres storage,
// per-org billing via the central payment service. A cheaper, flat-priced alternative to Flipper Cloud.

const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');
const { Issuer, generators } = require('openid-client');
const jwt = require('jsonwebtoken');

const PORT = parseInt(process.env.PORT || '8080', 10);
const BASE_URL = process.env.BASE_URL || 'https://togglefleet.com';
const SESSION_SECRET = process.env.SESSION_SECRET || (() => { throw new Error('SESSION_SECRET is required'); })();
const BILLING_SECRET = process.env.BILLING_SECRET || (() => { throw new Error('BILLING_SECRET is required'); })();
const BILLING_CHECKOUT = process.env.BILLING_CHECKOUT || 'https://billing.takeaseatventure.com/checkout';
function checkoutUrl(product, plan, user, email) {
  const exp = Date.now() + 3600000;
  const sig = crypto.createHmac('sha256', BILLING_SECRET).update(`${product}:${plan}:${user}:${exp}`).digest('hex');
  const q = new URLSearchParams({ product, plan, user, email: email||'', exp:String(exp), sig });
  return `${BILLING_CHECKOUT}?${q.toString()}`;
}
const FREE_FLAG_LIMIT = parseInt(process.env.FREE_FLAG_LIMIT || '10', 10); // free tier: 10 flags
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------------------------------------------------------------- db
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (id text PRIMARY KEY, sub text UNIQUE NOT NULL, email text, name text, email_verified boolean NOT NULL DEFAULT false, created_at timestamptz DEFAULT now());
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
    CREATE TABLE IF NOT EXISTS orgs (id text PRIMARY KEY, name text NOT NULL, plan text NOT NULL DEFAULT 'free', stripe_customer text, created_at timestamptz DEFAULT now());
    CREATE TABLE IF NOT EXISTS memberships (org_id text NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, user_id text NOT NULL REFERENCES users(id), role text NOT NULL DEFAULT 'member', created_at timestamptz DEFAULT now(), PRIMARY KEY (org_id, user_id));
    CREATE TABLE IF NOT EXISTS invites (org_id text NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, email text NOT NULL, role text NOT NULL DEFAULT 'member', created_at timestamptz DEFAULT now(), PRIMARY KEY (org_id, email));
    CREATE TABLE IF NOT EXISTS environments (id text PRIMARY KEY, org_id text NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, name text NOT NULL, sdk_key text UNIQUE NOT NULL, created_at timestamptz DEFAULT now());
    CREATE TABLE IF NOT EXISTS flags (id text PRIMARY KEY, org_id text NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, fkey text NOT NULL, name text, description text, created_at timestamptz DEFAULT now(), UNIQUE (org_id, fkey));
    CREATE TABLE IF NOT EXISTS flag_states (flag_id text NOT NULL REFERENCES flags(id) ON DELETE CASCADE, environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE, enabled boolean NOT NULL DEFAULT false, rollout int NOT NULL DEFAULT 0, pct_time int NOT NULL DEFAULT 0, actors text NOT NULL DEFAULT '', groups text NOT NULL DEFAULT '', updated_at timestamptz DEFAULT now(), PRIMARY KEY (flag_id, environment_id));
    ALTER TABLE flag_states ADD COLUMN IF NOT EXISTS pct_time int NOT NULL DEFAULT 0;
    ALTER TABLE flag_states ADD COLUMN IF NOT EXISTS groups text NOT NULL DEFAULT '';
  `);
  console.log('[db] schema ready');
}
const uid = () => crypto.randomUUID();
const sdkKey = () => 'tf_' + crypto.randomBytes(20).toString('hex');

async function upsertUser(sub, email, name, emailVerified) {
  const id = uid();
  const r = await pool.query(`INSERT INTO users (id, sub, email, name, email_verified) VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT (sub) DO UPDATE SET email=EXCLUDED.email, name=COALESCE(EXCLUDED.name, users.name), email_verified=EXCLUDED.email_verified RETURNING id`, [id, sub, email, name, !!emailVerified]);
  return r.rows[0].id;
}
async function ensureWorkspace(userId, email, name, emailVerified) {
  // accept pending invites ONLY for a verified email (prevents cross-provider email-spoof org takeover)
  const pend = emailVerified ? await pool.query('SELECT org_id, role FROM invites WHERE lower(email)=lower($1)', [email || '']) : {rows:[]};
  for (const inv of pend.rows) {
    await pool.query(`INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [inv.org_id, userId, inv.role]);
  }
  if (pend.rows.length) await pool.query('DELETE FROM invites WHERE lower(email)=lower($1)', [email || '']);  // only reached when emailVerified
  // if user has no org at all, create a personal workspace
  const mem = await pool.query('SELECT 1 FROM memberships WHERE user_id=$1 LIMIT 1', [userId]);
  if (!mem.rows[0]) {
    const oid = uid();
    const wsName = (name || (email ? email.split('@')[0] : 'My') ) + "'s workspace";
    await pool.query('INSERT INTO orgs (id, name) VALUES ($1,$2)', [oid, wsName]);
    await pool.query('INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,$3)', [oid, userId, 'owner']);
    for (const en of ['Production', 'Staging', 'Development']) await pool.query('INSERT INTO environments (id, org_id, name, sdk_key) VALUES ($1,$2,$3,$4)', [uid(), oid, en, sdkKey()]);
  }
}
async function membership(userId, orgId) {
  const r = await pool.query('SELECT role FROM memberships WHERE user_id=$1 AND org_id=$2', [userId, orgId]);
  return r.rows[0] ? r.rows[0].role : null;
}
async function userOrgs(userId) {
  const r = await pool.query(`SELECT o.id, o.name, o.plan, m.role FROM orgs o JOIN memberships m ON m.org_id=o.id WHERE m.user_id=$1 ORDER BY o.created_at`, [userId]);
  return r.rows;
}

// ---------------------------------------------------------------- oidc + session
let oidc = null;
async function initOIDC() {
  const issuer = await Issuer.discover(process.env.OIDC_ISSUER);
  oidc = new issuer.Client({ client_id: process.env.OIDC_CLIENT_ID, client_secret: process.env.OIDC_CLIENT_SECRET, redirect_uris: [BASE_URL + '/auth/callback'], response_types: ['code'] });
  console.log('[oidc] ready');
}
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=').map(decodeURIComponent)).filter(p => p[0])); }
function setCookie(res, name, val, maxAge) {
  const parts = [`${name}=${val}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax'];
  if (maxAge != null) parts.push(`Max-Age=${maxAge}`);
  const prev = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', [...(Array.isArray(prev) ? prev : [prev]).filter(Boolean), parts.join('; ')]);
}
function sessionUser(req) { try { return jwt.verify(parseCookies(req).tf_session || '', SESSION_SECRET, {algorithms:['HS256']}).uid; } catch { return null; } }

// ---------------------------------------------------------------- http utils
function send(res, s, body, ct='text/html; charset=utf-8') { res.writeHead(s, { 'Content-Type': ct }); res.end(body); }
function sendJSON(res, s, o, cors=false) { const h={ 'Content-Type': 'application/json' }; if (cors) h['Access-Control-Allow-Origin']='*'; res.writeHead(s, h); res.end(JSON.stringify(o)); }
function redirect(res, loc) { res.writeHead(302, { Location: loc }); res.end(); }
function readBody(req) { return new Promise((resolve, reject) => { let d=''; req.on('data', c => { d+=c; if (d.length > 1e6) req.destroy(); }); req.on('end', () => resolve(d)); req.on('error', reject); }); }
function form(body) { return Object.fromEntries(new URLSearchParams(body)); }
const esc = s => String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const _iprl = new Map();
function clientIp(req){ return (String(req.headers['x-forwarded-for']||'').split(',')[0].trim()) || (req.socket && req.socket.remoteAddress) || 'unknown'; }
function ipRateLimit(key, max, windowMs){ const now=Date.now(); let e=_iprl.get(key); if(!e||now>e.reset){ e={c:0,reset:now+windowMs}; _iprl.set(key,e);} if(_iprl.size>10000){ for(const [k,v] of _iprl) if(now>v.reset) _iprl.delete(k);} e.c++; return e.c<=max; }

// flag evaluation (shared logic; SDK mirrors this)
function evalFlag(st, actor, groups) {
  if (!st) return false;
  if (st.enabled) return true;                                   // boolean gate: on for everyone
  const a = actor != null ? String(actor) : '';
  const actorList = (st.actors || '').split(',').map(s=>s.trim()).filter(Boolean);
  if (a && actorList.includes(a)) return true;                   // actor gate
  const flagGroups = (st.groups || '').split(',').map(s=>s.trim()).filter(Boolean);
  if (groups && groups.length && flagGroups.some(g=>groups.includes(g))) return true; // group gate
  if (st.rollout > 0 && a) {                                     // percentage of actors (sticky)
    const h = crypto.createHash('md5').update(st.flag_id + ':' + a).digest();
    if ((h.readUInt32BE(0) % 100) < st.rollout) return true;
  }
  if (st.pct_time > 0 && (Math.floor(Math.random() * 100) < st.pct_time)) return true; // percentage of time (random)
  return false;
}

// ---------------------------------------------------------------- UI
const CSS = `*{margin:0;padding:0;box-sizing:border-box}
:root{--housing:#1B1D24;--panel:#23262F;--panel-2:#2A2E39;--seam:#3A3F4D;--seam-2:#4A5063;--amber:#FFC24B;--amber-d:#F0A92E;--teal:#2FE3B3;--teal-d:#1FC79B;--dim:#5C6273;--ink:#ECEDF2;--muted:#969CAD;--faint:#6B7180;--red:#E0625A;--disp:'Archivo Expanded','Archivo',sans-serif;--body:'Hanken Grotesk',system-ui,sans-serif;--mono:'Space Mono',ui-monospace,monospace}
body{font-family:var(--body);background:var(--housing);color:var(--ink);line-height:1.5;background-image:radial-gradient(rgba(255,255,255,0.02) 1px,transparent 1px);background-size:22px 22px;-webkit-font-smoothing:antialiased}
a{color:var(--teal);text-decoration:none}.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
.top{background:rgba(27,29,36,.82);backdrop-filter:blur(12px);border-bottom:1px solid var(--seam);position:sticky;top:0;z-index:50}
.top .wrap{display:flex;align-items:center;gap:16px;height:62px}
.brand{font-family:var(--disp);font-weight:800;font-size:1.02rem;color:var(--ink);display:flex;align-items:center;gap:10px;letter-spacing:-.01em}.brand b{color:var(--teal)}
.brand .m{width:28px;height:28px;border-radius:7px;background:var(--panel);border:1px solid var(--seam);display:grid;place-items:center}
.nav{display:flex;gap:4px;margin-left:8px}.nav a{font-family:var(--mono);padding:7px 12px;border-radius:7px;color:var(--muted);font-size:.78rem}.nav a.on{background:var(--panel);color:var(--ink)}.nav a:hover{color:var(--ink)}
.spacer{flex:1}
.orgsel{font-family:var(--mono);font-size:.8rem;padding:7px 11px;border:1px solid var(--seam-2);border-radius:8px;background:var(--panel);color:var(--ink)}
.btn{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-weight:700;font-size:.8rem;padding:9px 15px;border-radius:8px;border:1px solid var(--seam-2);background:var(--panel);color:var(--ink);cursor:pointer;text-decoration:none;transition:transform .08s,border-color .15s}
.btn:hover{transform:translateY(-1px);border-color:var(--dim)}
.btn-p{background:var(--amber);color:#241A05;border-color:var(--amber)}.btn-p:hover{background:var(--amber-d);border-color:var(--amber-d)}
.btn-sm{padding:6px 10px;font-size:.74rem}.btn-d{color:var(--red);border-color:#5A3A3A;background:transparent}.btn-d:hover{border-color:var(--red)}
main{padding:36px 0}h1{font-family:var(--disp);font-size:1.5rem;font-weight:800;margin-bottom:4px;letter-spacing:-.015em}.sub{color:var(--muted);margin-bottom:26px;font-size:.95rem}
.card{background:linear-gradient(180deg,var(--panel-2),var(--panel));border:1px solid var(--seam);border-radius:13px;padding:20px;margin-bottom:16px}
.row{display:flex;align-items:center;gap:11px;flex-wrap:wrap}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:13px 10px;border-bottom:1px solid var(--seam);font-size:.9rem;vertical-align:middle}
th{font-family:var(--mono);font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);font-weight:400}
input,select{font-family:var(--mono);font-size:.84rem;padding:8px 11px;border:1px solid var(--seam-2);border-radius:8px;background:var(--housing);color:var(--ink)}
input::placeholder{color:var(--faint)}input[type=number]{width:74px}input:focus,select:focus{outline:none;border-color:var(--amber)}
.pill{font-family:var(--mono);font-size:.66rem;font-weight:700;letter-spacing:.06em;padding:3px 9px;border-radius:5px}.pill.on{background:rgba(47,227,179,.16);color:var(--teal)}.pill.off{background:var(--housing);color:var(--faint)}
.code{font-family:var(--mono);font-size:.8rem;background:#15171D;color:var(--teal);padding:9px 12px;border-radius:7px;border:1px solid var(--seam);overflow-x:auto;word-break:break-all}
.muted{color:var(--muted);font-size:.85rem}
.envtabs{display:flex;gap:6px;margin-bottom:18px;flex-wrap:wrap}.envtabs a{font-family:var(--mono);padding:7px 13px;border-radius:8px;background:var(--panel);border:1px solid var(--seam);font-size:.78rem;color:var(--muted)}.envtabs a.on{background:var(--amber);color:#241A05;border-color:var(--amber);font-weight:700}.envtabs a.add{border-style:dashed;color:var(--faint)}
h3{font-family:var(--mono);font-weight:700}
form.inline{display:inline}
:focus-visible{outline:2px solid var(--amber);outline-offset:2px}`;

function layout(title, user, orgs, curOrg, nav, body) {
  const orgOpts = orgs.map(o => `<option value="${o.id}"${o.id===curOrg.id?' selected':''}>${esc(o.name)}</option>`).join('');
  const navlink = (h, l, k) => `<a href="${h}" class="${nav===k?'on':''}">${l}</a>`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — ToggleFleet</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%231B1D24'/%3E%3Crect x='5' y='12' width='22' height='9' rx='4.5' fill='%232FE3B3'/%3E%3Ccircle cx='21.5' cy='16.5' r='5.5' fill='%231B1D24'/%3E%3Ccircle cx='21.5' cy='16.5' r='2.8' fill='%23FFC24B'/%3E%3C/svg%3E">
<link href="https://fonts.googleapis.com/css2?family=Archivo+Expanded:wght@700;800;900&family=Hanken+Grotesk:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet"><style>${CSS}</style></head><body>
<header class="top"><div class="wrap">
<a href="/app/flags" class="brand"><span class="m"><svg width="18" height="18" viewBox="0 0 32 32"><rect x="5" y="12" width="22" height="9" rx="4.5" fill="#2FE3B3"/><circle cx="21.5" cy="16.5" r="5.5" fill="#23262F"/><circle cx="21.5" cy="16.5" r="2.8" fill="#FFC24B"/></svg></span>Toggle<b>Fleet</b></a>
<nav class="nav">${navlink('/app/flags','Flags','flags')}${navlink('/app/members','Members','members')}${navlink('/app/settings','Settings','settings')}</nav>
<span class="spacer"></span>
<form method="post" action="/app/org/switch" class="inline"><select name="org" class="orgsel" onchange="this.form.submit()">${orgOpts}</select></form>
<a href="/auth/logout" class="muted" style="font-size:.82rem">Sign out</a>
</div></header><main><div class="wrap">${body}</div></main></body></html>`;
}

// ---------------------------------------------------------------- server
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, `http://${req.headers.host}`);
    const path = u.pathname;
    if (req.method === 'OPTIONS') { res.writeHead(204, {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization,Content-Type'}); return res.end(); }
    if (path.startsWith('/v1/') && !ipRateLimit('tf:'+clientIp(req), 600, 60000)) return sendJSON(res, 429, { error: 'rate_limited, slow down' }, true);

    if (path === '/v1/health') { let db=true; try{await pool.query('SELECT 1');}catch{db=false;} return sendJSON(res,200,{status:db?'ok':'degraded',service:'togglefleet',db,auth:!!oidc}); }

    // HEAD requests for landing/health: respond 200 with no body
    if (req.method === 'HEAD' && (path === '/' || path === '/v1/health')) { res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'}); return res.end(); }

    // ---- SDK eval API (auth via env SDK key) ----
    if (path === '/v1/config' && req.method === 'GET') {
      const auth = (req.headers['authorization']||'').replace(/^Bearer /,'').trim();
      if (!auth) return sendJSON(res,401,{error:'missing SDK key'},true);
      const env = await pool.query('SELECT id, org_id FROM environments WHERE sdk_key=$1', [auth]);
      if (!env.rows[0]) return sendJSON(res,401,{error:'invalid SDK key'},true);
      const fs = await pool.query(`SELECT f.fkey, s.enabled, s.rollout, s.pct_time, s.actors, s.groups, s.flag_id FROM flags f
        JOIN flag_states s ON s.flag_id=f.id AND s.environment_id=$1 WHERE f.org_id=$2`, [env.rows[0].id, env.rows[0].org_id]);
      const flags = {}; const csv = v => (v||'').split(',').map(x=>x.trim()).filter(Boolean);
      for (const r of fs.rows) flags[r.fkey] = { boolean: r.enabled, percentage_of_actors: r.rollout, percentage_of_time: r.pct_time, actors: csv(r.actors), groups: csv(r.groups), id: r.flag_id };
      return sendJSON(res,200,{ flags },true);
    }
    if (path === '/v1/evaluate' && req.method === 'GET') {
      const auth = (req.headers['authorization']||'').replace(/^Bearer /,'').trim();
      const fkey = u.searchParams.get('flag'), actor = u.searchParams.get('actor')||'';
      const evGroups = (u.searchParams.get('groups')||'').split(',').map(x=>x.trim()).filter(Boolean);
      const env = await pool.query('SELECT id, org_id FROM environments WHERE sdk_key=$1', [auth]);
      if (!env.rows[0]) return sendJSON(res,401,{error:'invalid SDK key'},true);
      const r = await pool.query(`SELECT s.enabled,s.rollout,s.pct_time,s.actors,s.groups,s.flag_id FROM flags f JOIN flag_states s ON s.flag_id=f.id AND s.environment_id=$1 WHERE f.org_id=$2 AND f.fkey=$3`, [env.rows[0].id, env.rows[0].org_id, fkey]);
      return sendJSON(res,200,{ flag: fkey, enabled: evalFlag(r.rows[0], actor, evGroups) },true);
    }

    // ---- internal billing (per-org; the ref's "user" field carries the org id) ----
    if (path === '/internal/billing' && req.method === 'POST') {
      const got=Buffer.from(String(req.headers['x-billing-secret']||'')), want=Buffer.from(BILLING_SECRET);
      if (got.length!==want.length || !crypto.timingSafeEqual(got,want)) return sendJSON(res,401,{error:'unauthorized'},false);
      const b = JSON.parse(await readBody(req));
      const plan = (b.plan==='pro')?'pro':'free';
      await pool.query('UPDATE orgs SET plan=$2, stripe_customer=COALESCE($3,stripe_customer) WHERE id=$1', [b.user_id, plan, b.customer||null]);
      console.log(`[billing] org ${b.user_id} -> ${b.plan}`);
      return sendJSON(res,200,{ok:true});
    }

    // ---- auth ----
    if (path === '/auth/login') { if(!oidc) return sendJSON(res,503,{error:'auth down'}); const state=generators.state(),nonce=generators.nonce(); setCookie(res,'tf_oidc',jwt.sign({state,nonce},SESSION_SECRET,{expiresIn:'10m'}),600); return redirect(res, oidc.authorizationUrl({scope:'openid email profile',state,nonce})); }
    if (path === '/auth/callback') {
      if(!oidc) return sendJSON(res,503,{error:'auth down'});
      let chk; try { chk = jwt.verify(parseCookies(req).tf_oidc||'', SESSION_SECRET, {algorithms:['HS256']}); } catch { return redirect(res,'/auth/login'); }
      try {
        const params = oidc.callbackParams(req);
        const ts = await oidc.callback(BASE_URL+'/auth/callback', params, {state:chk.state, nonce:chk.nonce});
        const c = ts.claims();
        const userId = await upsertUser(c.sub, c.email, c.name, c.email_verified);
        await ensureWorkspace(userId, c.email, c.name, c.email_verified);
        setCookie(res,'tf_session',jwt.sign({uid:userId},SESSION_SECRET,{expiresIn:'30d'}),30*86400);
        return redirect(res,'/app/flags');
      } catch(e){ console.error('[auth]',e.message); return send(res,400,'Auth failed: '+esc(e.message)); }
    }
    if (path === '/auth/logout') { setCookie(res,'tf_session','',0); return redirect(res,'/'); }

    // ---- marketing landing (served from /site if present, else simple) ----
    if (path === '/' && req.method === 'GET') {
      const fs = require('fs'); const p = require('path').join(__dirname,'site','index.html');
      if (fs.existsSync(p)) return send(res,200,fs.readFileSync(p,'utf8'));
      return send(res,200,'<h1>ToggleFleet</h1><p>Cloud feature flags. <a href="/auth/login">Sign in</a></p>');
    }

    // ===================== app (requires session + org) =====================
    if (path.startsWith('/app')) {
      const userId = sessionUser(req);
      if (!userId) return redirect(res,'/auth/login');
      const ur = await pool.query('SELECT email,name FROM users WHERE id=$1',[userId]);
      if (!ur.rows[0]) { setCookie(res,'tf_session','',0); return redirect(res,'/auth/login'); }
      const orgs = await userOrgs(userId);
      if (!orgs.length) { await ensureWorkspace(userId, ur.rows[0].email, ur.rows[0].name); return redirect(res,'/app/flags'); }
      const cookieOrg = parseCookies(req).tf_org;
      let curOrg = orgs.find(o => o.id === cookieOrg) || orgs[0];
      const role = curOrg.role;

      // -- POST actions --
      if (req.method === 'POST') {
        const b = form(await readBody(req));
        if (path === '/app/org/switch') { setCookie(res,'tf_org', b.org, 30*86400); return redirect(res,'/app/flags'); }
        // verify membership for any write
        if (!await membership(userId, curOrg.id)) return redirect(res,'/app/flags');
        if (path === '/app/flags/create') {
          const key = (b.fkey||'').trim().toLowerCase().replace(/[^a-z0-9_.-]/g,'_').slice(0,60);
          if (key) {
            const cnt = await pool.query('SELECT count(*)::int n FROM flags WHERE org_id=$1',[curOrg.id]);
            if (curOrg.plan==='free' && cnt.rows[0].n >= FREE_FLAG_LIMIT) return redirect(res,'/app/flags?err=limit');
            const fid=uid();
            await pool.query('INSERT INTO flags (id,org_id,fkey,name) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',[fid,curOrg.id,key,b.name||key]);
            const envs = await pool.query('SELECT id FROM environments WHERE org_id=$1',[curOrg.id]);
            for (const e of envs.rows) await pool.query('INSERT INTO flag_states (flag_id,environment_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[fid,e.id]);
          }
          return redirect(res,'/app/flags?env='+(b.env||''));
        }
        if (path === '/app/flags/state') {
          const clamp=x=>Math.max(0,Math.min(100,parseInt(x||'0',10)||0)), csvn=x=>(x||'').split(',').map(z=>z.trim()).filter(Boolean).join(',');
          await pool.query(`UPDATE flag_states SET enabled=$3, rollout=$4, pct_time=$5, actors=$6, groups=$7, updated_at=now()
            WHERE flag_id=$1 AND environment_id=$2
              AND flag_id IN (SELECT id FROM flags WHERE org_id=$8)
              AND environment_id IN (SELECT id FROM environments WHERE org_id=$8)`,
            [b.flag_id, b.env_id, b.enabled==='1', clamp(b.rollout), clamp(b.pct_time), csvn(b.actors), csvn(b.groups), curOrg.id]);
          return redirect(res,'/app/flags?env='+b.env_id);
        }
        if (path === '/app/flags/delete') { await pool.query('DELETE FROM flags WHERE id=$1 AND org_id=$2',[b.flag_id,curOrg.id]); return redirect(res,'/app/flags'); }
        if (path === '/app/members/invite' && (role==='owner'||role==='admin')) {
          const email=(b.email||'').trim().toLowerCase();
          if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            const existing = await pool.query('SELECT id FROM users WHERE lower(email)=lower($1) AND email_verified=true',[email]);
            const invRole = (b.role==='admin')?'admin':'member';
            if (existing.rows[0]) await pool.query('INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',[curOrg.id,existing.rows[0].id,invRole]);
            else await pool.query('INSERT INTO invites (org_id,email,role) VALUES ($1,$2,$3) ON CONFLICT (org_id,email) DO UPDATE SET role=EXCLUDED.role',[curOrg.id,email,invRole]);
          }
          return redirect(res,'/app/members');
        }
        if (path === '/app/members/remove' && (role==='owner'||role==='admin')) {
          if (b.user_id) await pool.query("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2 AND role<>'owner'",[curOrg.id,b.user_id]);
          if (b.email) await pool.query('DELETE FROM invites WHERE org_id=$1 AND email=$2',[curOrg.id,b.email]);
          return redirect(res,'/app/members');
        }
        if (path === '/app/org/rename' && role==='owner') { if(b.name) await pool.query('UPDATE orgs SET name=$2 WHERE id=$1',[curOrg.id,b.name.slice(0,60)]); return redirect(res,'/app/settings'); }
        if (path === '/app/env/create' && (role==='owner'||role==='admin')) {
          const name=(b.name||'').trim().slice(0,30);
          if (name) { const eid=uid(); await pool.query('INSERT INTO environments (id,org_id,name,sdk_key) VALUES ($1,$2,$3,$4)',[eid,curOrg.id,name,sdkKey()]); const fl=await pool.query('SELECT id FROM flags WHERE org_id=$1',[curOrg.id]); for(const f of fl.rows) await pool.query('INSERT INTO flag_states (flag_id,environment_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[f.id,eid]); }
          return redirect(res,'/app/settings');
        }
        if (path === '/app/env/delete' && (role==='owner'||role==='admin')) {
          const cnt=await pool.query('SELECT count(*)::int n FROM environments WHERE org_id=$1',[curOrg.id]);
          if (cnt.rows[0].n>1 && b.env_id) await pool.query('DELETE FROM environments WHERE id=$1 AND org_id=$2',[b.env_id,curOrg.id]);
          return redirect(res,'/app/settings');
        }
        if (path === '/app/env/copy' && (role==='owner'||role==='admin')) {
          const from=b.from_env, to=b.to_env;
          if (from && to && from!==to) {
            const chk=await pool.query('SELECT count(*)::int n FROM environments WHERE org_id=$1 AND id IN ($2,$3)',[curOrg.id,from,to]);
            if (chk.rows[0].n===2) {
              await pool.query(`UPDATE flag_states t SET enabled=s.enabled, rollout=s.rollout, pct_time=s.pct_time, actors=s.actors, groups=s.groups, updated_at=now()
                FROM flag_states s WHERE t.flag_id=s.flag_id AND s.environment_id=$1 AND t.environment_id=$2
                AND t.flag_id IN (SELECT id FROM flags WHERE org_id=$3)`,[from,to,curOrg.id]);
            }
          }
          return redirect(res,'/app/flags?env='+(b.to_env||'')+'&copied=1');
        }
        if (path === '/app/env/rotate' && (role==='owner'||role==='admin')) {
          if (b.env_id) await pool.query('UPDATE environments SET sdk_key=$3 WHERE id=$1 AND org_id=$2',[b.env_id,curOrg.id,sdkKey()]);
          return redirect(res,'/app/settings?rotated=1');
        }
        if (path === '/app/org/create') { const oid=uid(); await pool.query('INSERT INTO orgs (id,name) VALUES ($1,$2)',[oid,(b.name||'New workspace').slice(0,60)]); await pool.query('INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3)',[oid,userId,'owner']); for(const en of ['Production','Staging','Development']) await pool.query('INSERT INTO environments (id,org_id,name,sdk_key) VALUES ($1,$2,$3,$4)',[uid(),oid,en,sdkKey()]); setCookie(res,'tf_org',oid,30*86400); return redirect(res,'/app/flags'); }
        return redirect(res,'/app/flags');
      }

      // -- GET pages --
      const envs = await pool.query('SELECT id,name,sdk_key FROM environments WHERE org_id=$1 ORDER BY created_at',[curOrg.id]);
      if (path === '/app' || path === '/app/flags') {
        const curEnv = envs.rows.find(e=>e.id===u.searchParams.get('env')) || envs.rows[0];
        const tabs = envs.rows.map(e=>`<a href="/app/flags?env=${e.id}" class="${e.id===curEnv.id?'on':''}">${esc(e.name)}</a>`).join('') + '<a href="/app/settings" class="add" title="Add an environment">+ env</a>';
        const flags = await pool.query(`SELECT f.id,f.fkey,f.name,s.enabled,s.rollout,s.pct_time,s.actors,s.groups FROM flags f JOIN flag_states s ON s.flag_id=f.id AND s.environment_id=$1 WHERE f.org_id=$2 ORDER BY f.created_at DESC`,[curEnv.id,curOrg.id]);
        const SCOPED = `<style>
.flagcard{background:linear-gradient(180deg,var(--panel-2),var(--panel));border:1px solid var(--seam);border-radius:13px;margin-bottom:14px;overflow:hidden;transition:border-color .15s}
.flagcard:hover{border-color:var(--seam-2)}
.fc-head{display:flex;align-items:center;gap:13px;padding:14px 18px;border-bottom:1px solid var(--seam)}
.fc-key{font-family:var(--mono);font-weight:700;font-size:.94rem}.fc-key::before{content:"› ";color:var(--teal)}
.fc-key small{display:block;color:var(--faint);font-weight:400;font-size:.72rem}
.fc-led{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.fc-led .d{width:9px;height:9px;border-radius:50%;background:var(--dim)}
.fc-led.on .d{background:var(--teal);box-shadow:0 0 9px var(--teal);animation:tfp 2.4s infinite}
.fc-led.part .d{background:var(--amber);box-shadow:0 0 9px var(--amber)}
@keyframes tfp{0%{box-shadow:0 0 0 0 rgba(47,227,179,.5)}70%{box-shadow:0 0 0 6px rgba(47,227,179,0)}100%{box-shadow:0 0 0 0 rgba(47,227,179,0)}}
.fc-body{display:flex;align-items:flex-end;gap:18px;padding:16px 18px;flex-wrap:wrap}
.gctl{display:flex;flex-direction:column;gap:6px}
.gctl .gl{font-family:var(--mono);font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.swc{width:56px;height:30px;border-radius:16px;background:var(--housing);border:1px solid var(--seam-2);position:relative;cursor:pointer;display:inline-block}
.swc::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:50%;background:#C9CDD8;transition:transform .22s cubic-bezier(.5,1.6,.4,1),background .2s;box-shadow:0 2px 4px rgba(0,0,0,.5)}
.swc input{position:absolute;inset:0;opacity:0;cursor:pointer;margin:0}
.swc:has(input:checked){background:var(--teal-d);border-color:var(--teal)}
.swc:has(input:checked)::after{transform:translateX(26px);background:#0C1512}
.bar{height:4px;border-radius:3px;background:var(--housing);border:1px solid var(--seam);overflow:hidden;width:88px;margin-top:5px}.bar i{display:block;height:100%;background:var(--amber)}
.fc-sp{flex:1}.numin{width:60px}
</style>`;
        const card = f => {
          const partial = !f.enabled && (f.rollout>0||f.pct_time>0||(f.actors||'')||(f.groups||''));
          const lc = f.enabled?'on':(partial?'part':''), lt = f.enabled?'On':(partial?'Partial':'Off');
          return `<div class="flagcard">
            <div class="fc-head"><span class="fc-key">${esc(f.fkey)}${(f.name&&f.name!==f.fkey)?`<small>${esc(f.name)}</small>`:''}</span><span class="fc-sp"></span>
              <span class="fc-led ${lc}"><span class="d"></span>${lt}</span>
              <form method="post" action="/app/flags/delete" class="inline" onsubmit="return confirm('Delete ${esc(f.fkey)}?')"><input type="hidden" name="flag_id" value="${f.id}"><button class="btn btn-sm btn-d">Delete</button></form></div>
            <form method="post" action="/app/flags/state" class="fc-body">
              <input type="hidden" name="flag_id" value="${f.id}"><input type="hidden" name="env_id" value="${curEnv.id}">
              <div class="gctl"><span class="gl">Boolean</span><label class="swc"><input type="checkbox" name="enabled" value="1" ${f.enabled?'checked':''} onchange="this.form.requestSubmit()"></label></div>
              <div class="gctl"><span class="gl">% of actors</span><input class="numin" type="number" name="rollout" value="${f.rollout}" min="0" max="100"><div class="bar"><i style="width:${f.rollout}%"></i></div></div>
              <div class="gctl"><span class="gl">% of time</span><input class="numin" type="number" name="pct_time" value="${f.pct_time}" min="0" max="100"></div>
              <div class="gctl"><span class="gl">Actors</span><input type="text" name="actors" value="${esc(f.actors||'')}" placeholder="dave, acct_42" style="width:150px"></div>
              <div class="gctl"><span class="gl">Groups</span><input type="text" name="groups" value="${esc(f.groups||'')}" placeholder="admins" style="width:118px"></div>
              <span class="fc-sp"></span><button class="btn btn-sm btn-p">Save</button></form></div>`;
        };
        const rows = flags.rows.map(card).join('') || '<div class="card"><span class="muted">No flags yet — create your first one above.</span></div>';
        const err = u.searchParams.get('err')==='limit' ? `<div class="card" style="border-color:var(--amber)">Free plan is limited to ${FREE_FLAG_LIMIT} flags. <a href="/app/settings">Upgrade</a> for unlimited.</div>`:'';
        const body = `${SCOPED}<h1>Feature flags</h1><p class="sub">${esc(curOrg.name)} · <b style="color:var(--ink)">${esc(curEnv.name)}</b> environment · read by the SDK with this env's key.</p>${err}
        <div class="envtabs">${tabs}</div>
        ${u.searchParams.get('copied')?`<div class="card" style="border-color:var(--teal);padding:11px 16px;margin-bottom:14px"><span class="muted">Flag states copied into <b style="color:var(--ink)">${esc(curEnv.name)}</b>.</span></div>`:''}
        ${envs.rows.length>1?`<form method="post" action="/app/env/copy" class="row" style="margin:-2px 0 16px;gap:9px"><input type="hidden" name="to_env" value="${curEnv.id}"><span class="muted">Copy all flag states into <b style="color:var(--ink)">${esc(curEnv.name)}</b> from</span><select name="from_env">${envs.rows.filter(e=>e.id!==curEnv.id).map(e=>`<option value="${e.id}">${esc(e.name)}</option>`).join('')}</select><button class="btn btn-sm">Copy →</button></form>`:''}
        <div class="card"><form method="post" action="/app/flags/create" class="row"><input type="hidden" name="env" value="${curEnv.id}">
          <input name="fkey" placeholder="flag_key (e.g. new_dashboard)" required style="flex:1;min-width:200px">
          <input name="name" placeholder="description (optional)" style="flex:1;min-width:160px"><button class="btn btn-p">Create flag</button></form></div>
        ${rows}`;
        return send(res,200,layout('Flags',ur.rows[0],orgs,curOrg,'flags',body));
      }
      if (path === '/app/members') {
        const mem = await pool.query(`SELECT u.id,u.email,u.name,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 ORDER BY m.created_at`,[curOrg.id]);
        const inv = await pool.query('SELECT email,role FROM invites WHERE org_id=$1 ORDER BY created_at',[curOrg.id]);
        const canManage = role==='owner'||role==='admin';
        const mrows = mem.rows.map(m=>`<tr><td><b>${esc(m.name||m.email)}</b><div class="muted">${esc(m.email)}</div></td><td><span class="pill ${m.role==='owner'?'on':'off'}">${esc(m.role)}</span></td>
          <td>${(canManage && m.role!=='owner')?`<form method="post" action="/app/members/remove"><input type="hidden" name="user_id" value="${m.id}"><button class="btn btn-sm btn-d">Remove</button></form>`:''}</td></tr>`).join('');
        const irows = inv.rows.map(i=>`<tr><td>${esc(i.email)} <span class="muted">(invited)</span></td><td><span class="pill off">${esc(i.role)}</span></td><td>${canManage?`<form method="post" action="/app/members/remove"><input type="hidden" name="email" value="${esc(i.email)}"><button class="btn btn-sm btn-d">Cancel</button></form>`:''}</td></tr>`).join('');
        const body = `<h1>Members</h1><p class="sub">${esc(curOrg.name)} · invite teammates by email — they join automatically when they sign in.</p>
        ${canManage?`<div class="card"><form method="post" action="/app/members/invite" class="row"><input name="email" type="email" placeholder="teammate@company.com" required style="flex:1;min-width:220px"><select name="role"><option value="member">Member</option><option value="admin">Admin</option></select><button class="btn btn-p">Invite</button></form></div>`:''}
        <div class="card" style="padding:6px 16px"><table><thead><tr><th>Person</th><th>Role</th><th></th></tr></thead><tbody>${mrows}${irows}</tbody></table></div>`;
        return send(res,200,layout('Members',ur.rows[0],orgs,curOrg,'members',body));
      }
      if (path === '/app/settings') {
        const canManageEnv = role==='owner'||role==='admin';
        const keys = envs.rows.map(e=>`<tr><td><b>${esc(e.name)}</b></td><td><div class="code">${esc(e.sdk_key)}</div></td><td style="white-space:nowrap;text-align:right">${canManageEnv?`<form method="post" action="/app/env/rotate" class="inline" onsubmit="return confirm('Rotate the SDK key for ${esc(e.name)}? The current key stops working immediately — update your app first.')"><input type="hidden" name="env_id" value="${e.id}"><button class="btn btn-sm" title="Generate a new key, invalidate the old one">Rotate</button></form> `:''}${(canManageEnv&&envs.rows.length>1)?`<form method="post" action="/app/env/delete" class="inline" onsubmit="return confirm('Delete environment ${esc(e.name)}? Its flag states are removed.')"><input type="hidden" name="env_id" value="${e.id}"><button class="btn btn-sm btn-d">Delete</button></form>`:''}</td></tr>`).join('');
        const planPill = curOrg.plan==='pro'?'<span class="pill on">PRO</span>':'<span class="pill off">FREE</span>';
        const upgrade = curOrg.plan==='pro' ? '<p class="muted">On Pro — unlimited flags, members and environments.</p>'
          : `<p class="muted" style="margin-bottom:10px">Free plan: up to ${FREE_FLAG_LIMIT} flags. Pro is $15/mo flat — unlimited everything, no per-seat fees.</p><a class="btn btn-p" href="${checkoutUrl('togglefleet','pro',curOrg.id,ur.rows[0].email||'')}">Upgrade to Pro — $15/mo</a>`;
        const body = `<h1>Settings</h1><p class="sub">${esc(curOrg.name)}</p>
        ${u.searchParams.get('rotated')?`<div class="card" style="border-color:var(--teal);padding:11px 16px"><span class="muted">SDK key rotated. Update it wherever the old key was configured.</span></div>`:''}
        <div class="card"><h3 style="margin-bottom:6px">Plan ${planPill}</h3>${upgrade}</div>
        <div class="card"><h3 style="margin-bottom:10px">Environments &amp; SDK keys</h3><p class="muted" style="margin-bottom:10px">One SDK key per environment — pass it to the SDK to read that environment's flags. You start with Production, Staging &amp; Development; add as many custom environments as you need.</p><table>${keys}</table>
        ${canManageEnv?`<form method="post" action="/app/env/create" class="row" style="margin-top:14px"><input name="name" placeholder="New environment (e.g. QA, Preview, EU-prod)" required style="flex:1"><button class="btn">Add environment</button></form>`:''}</div>
        ${role==='owner'?`<div class="card"><h3 style="margin-bottom:10px">Workspace</h3><form method="post" action="/app/org/rename" class="row"><input name="name" value="${esc(curOrg.name)}" style="flex:1"><button class="btn">Rename</button></form>
        <form method="post" action="/app/org/create" class="row" style="margin-top:12px"><input name="name" placeholder="New workspace name" style="flex:1"><button class="btn">Create another workspace</button></form></div>`:''}`;
        return send(res,200,layout('Settings',ur.rows[0],orgs,curOrg,'settings',body));
      }
    }
    // ---- static site files: /docs, /flipper-cloud-alternative, robots.txt, sitemap.xml, css, indexnow key ----
    if (req.method === 'GET' || req.method === 'HEAD') {
      const fs = require('fs'); const pth = require('path');
      const root = pth.join(__dirname,'site');
      const rel = decodeURIComponent(path).replace(/\/+$/,'');
      let fp = pth.normalize(pth.join(root, rel));
      if (fp === root || fp.startsWith(root + pth.sep)) {
        if (fs.existsSync(fp) && fs.statSync(fp).isDirectory()) fp = pth.join(fp,'index.html');
        if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
          const ct = {'.html':'text/html; charset=utf-8','.xml':'application/xml; charset=utf-8','.txt':'text/plain; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'}[pth.extname(fp)]||'application/octet-stream';
          return send(res,200,req.method==='HEAD'?undefined:fs.readFileSync(fp),ct);
        }
      }
    }
    return sendJSON(res,404,{error:'not_found'});
  } catch(e) { console.error('[server]',e.message); try{sendJSON(res,500,{error:'server_error'});}catch{} }
});

(async()=>{ await initDB(); try{await initOIDC();}catch(e){console.error('[oidc] init fail:',e.message);} server.listen(PORT,()=>console.log('[togglefleet] listening :'+PORT)); })();
for (const sig of ['SIGTERM','SIGINT']) process.on(sig, async()=>{ server.close(); try{await pool.end();}catch{} process.exit(0); });
