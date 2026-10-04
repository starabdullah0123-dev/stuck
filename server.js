// UNITED KERALAM backend (Express 5 + PostgreSQL)
// Auth: email/mobile + password, real OTP (email via SMTP, SMS via Twilio), httpOnly cookie session.
require('dotenv').config();
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 24) { console.error('JWT_SECRET missing or too short (use 24+ random characters) in .env'); process.exit(1); }
const crypto = require('crypto'), path = require('path');
const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcrypt'), jwt = require('jsonwebtoken');
const sendSms = require('./sms'), nodemailer = require('nodemailer'), multer = require('multer'), helmet = require('helmet'), rate = require('express-rate-limit');
let OpenAI = null;
try { OpenAI = require('openai'); } catch { /* installed in package.json; server can still start without AI until npm install */ }
const db = new Pool({ connectionString: process.env.DATABASE_URL }), app = express();
const PROD = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
const mail = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: +(process.env.SMTP_PORT || 587), auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5e6 }, fileFilter: (_, f, cb) => cb(null, /^image\//.test(f.mimetype)) }); // swap for S3 / Cloudinary in production
if (process.env.TRUST_PROXY) app.set('trust proxy', +process.env.TRUST_PROXY || process.env.TRUST_PROXY);
// CSP stays off because the page uses CDN scripts (Tailwind, Chart.js) and inline handlers; tighten before going public
app.use(helmet({ contentSecurityPolicy: false }), express.json({ limit: '5mb' }), rate({ windowMs: 6e4, max: 200 }));
// CSRF defence: the session cookie is SameSite=Lax, and any cross-site write request is also refused here
app.use((q, res, next) => { const o = q.headers.origin; if (!['GET', 'HEAD', 'OPTIONS'].includes(q.method) && o) { try { if (new URL(o).host !== q.headers.host) return res.status(403).json({ error: 'Cross-site request blocked' }); } catch { return res.sendStatus(403); } } next(); });
app.use('/uploads', express.static('uploads'));
app.use(express.static(path.join(__dirname, 'public'))); // only /public is served, never .env or server.js

const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-6-luna';
const openaiClient = () => {
  if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY is not configured in .env');
  if (!OpenAI) throw new Error('OpenAI SDK is not installed. Run: npm install');
  return new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
};

// ---------- sessions ----------
const COOKIE = 'ukt', DAY = 864e5;
const cookies = q => Object.fromEntries((q.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x[0]));
function startSession(res, u) {
  const t = jwt.sign({ id: u.id, v: u.token_ver }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.setHeader('Set-Cookie', `${COOKIE}=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 86400}${PROD ? '; Secure' : ''}`);
}
const endSession = res => res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${PROD ? '; Secure' : ''}`);
// auth(): any signed-in user; auth('admin'): admin only. The role is read from the database on every request.
const auth = role => async (q, res, next) => {
  try {
    const p = jwt.verify(cookies(q)[COOKIE] || '', process.env.JWT_SECRET);
    const u = (await db.query('SELECT id,name,role,token_ver FROM users WHERE id=$1', [p.id])).rows[0];
    if (!u || u.token_ver !== p.v) return res.sendStatus(401);
    if (role && u.role !== role) return res.sendStatus(403);
    q.user = u; next();
  } catch { res.sendStatus(401); }
};

// ---------- identifiers & OTP ----------
const normId = s => { s = String(s || '').trim().toLowerCase(); if (s.includes('@')) return s; const d = s.replace(/\D/g, ''); return d.length === 12 && d.startsWith('91') ? d.slice(2) : d; };
const validId = s => /^\S+@\S+\.\S+$/.test(s) || /^\d{10}$/.test(s);
const kindOf = s => s.includes('@') ? 'email' : 'mobile';
const strongPw = p => /^(?=.*[A-Za-z])(?=.*\d).{8,72}$/.test(String(p || ''));
const isAdminId = id => !!process.env.ADMIN_IDENT && id === normId(process.env.ADMIN_IDENT);
async function sendCode(ident, code) {
  if (process.env.OTP_DEV === 'true') { console.log(`[DEV] OTP for ${ident}: ${code}`); return; } // development only, never enable in production
  if (ident.includes('@')) { await mail.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to: ident, subject: 'Your UNITED KERALAM verification code', text: `Your code is ${code}. It is valid for 10 minutes. If you did not request it, ignore this message.` }); return; }
  await sendSms(ident, code);
}
const PURPOSES = ['login', 'register', 'reset', 'link'];
const findUserByIdent = async (ident, ex = db) => (await ex.query('SELECT u.* FROM users u JOIN user_idents i ON i.user_id=u.id WHERE i.ident=$1', [ident])).rows[0];
const authLimit = rate({ windowMs: 6e4, max: 15 });
app.post('/api/auth/otp', authLimit, async (q, res) => {
  const ident = normId(q.body.ident), purpose = q.body.purpose;
  if (!validId(ident) || !PURPOSES.includes(purpose)) return res.status(400).json({ error: 'Enter a valid email or 10-digit mobile number' });
  let uid = null;
  if (purpose === 'link') { try { uid = jwt.verify(cookies(q)[COOKIE] || '', process.env.JWT_SECRET).id; } catch { return res.sendStatus(401); } }
  const last = (await db.query('SELECT created FROM otps WHERE ident=$1 AND purpose=$2', [ident, purpose])).rows[0];
  if (last && Date.now() - new Date(last.created).getTime() < 60000) return res.status(429).json({ error: 'Please wait a minute before asking for another code' });
  const existing = await findUserByIdent(ident);
  // Same reply whether or not the account exists, so the endpoint cannot be used to discover who is registered
  if ((purpose === 'login' || purpose === 'reset') && !existing) return res.json({ ok: true });
  if (purpose === 'register' && existing) return res.json({ ok: true });
  if (purpose === 'link' && existing) return res.status(409).json({ error: 'This email/mobile already belongs to an account' });
  const code = String(crypto.randomInt(100000, 1000000));
  try { await sendCode(ident, code); } catch (e) { console.error(e); return res.status(502).json({ error: e.message.startsWith('SMS') ? e.message : 'Could not send the code. Try again.' }); }
  await db.query("INSERT INTO otps(ident,purpose,code,exp,attempts,created) VALUES($1,$2,$3,now()+interval '10 min',0,now()) ON CONFLICT(ident,purpose) DO UPDATE SET code=$3,exp=now()+interval '10 min',attempts=0,created=now()", [ident, purpose, await bcrypt.hash(code, 10)]);
  res.json({ ok: true });
});
async function checkOtp(ident, purpose, code, ex = db) {
  const o = (await ex.query('SELECT * FROM otps WHERE ident=$1 AND purpose=$2 AND exp>now()', [ident, purpose])).rows[0];
  if (!o || o.attempts >= 5) return false;
  await ex.query('UPDATE otps SET attempts=attempts+1 WHERE ident=$1 AND purpose=$2', [ident, purpose]);
  if (!(await bcrypt.compare(String(code || ''), o.code))) return false;
  await ex.query('DELETE FROM otps WHERE ident=$1 AND purpose=$2', [ident, purpose]); return true;
}
const DUMMY = bcrypt.hashSync('not-a-real-password-1', 12); // keeps login timing the same for unknown accounts
async function me(id) {
  const u = (await db.query('SELECT id,name,role FROM users WHERE id=$1', [id])).rows[0], ids = (await db.query('SELECT ident,kind FROM user_idents WHERE user_id=$1 ORDER BY created', [id])).rows;
  return { id: u.id, name: u.name || '', role: u.role, ident: ids[0]?.ident || '', idents: ids };
}
const promote = async (uid, ident) => { if (isAdminId(ident)) await db.query("UPDATE users SET role='admin' WHERE id=$1", [uid]); };
app.post('/api/auth/register', authLimit, async (q, res) => {
  const ident = normId(q.body.ident), { code, password } = q.body, name = String(q.body.name || '').trim().slice(0, 60);
  if (!validId(ident) || !name) return res.status(400).json({ error: 'Enter your name and a valid email or 10-digit mobile number' });
  if (!strongPw(password)) return res.status(400).json({ error: 'Password needs 8+ characters with letters and numbers' });
  const c = await db.connect();
  try {
    await c.query('BEGIN');
    if (!(await checkOtp(ident, 'register', code, c))) { await c.query('COMMIT'); return res.status(400).json({ error: 'Wrong or expired code' }); }
    if (await findUserByIdent(ident, c)) { await c.query('ROLLBACK'); return res.status(409).json({ error: 'This email/mobile is already registered. Sign in instead.' }); }
    const u = (await c.query('INSERT INTO users(name,pw,role) VALUES($1,$2,$3) RETURNING *', [name, await bcrypt.hash(password, 12), isAdminId(ident) ? 'admin' : 'user'])).rows[0];
    await c.query('INSERT INTO user_idents(user_id,ident,kind) VALUES($1,$2,$3)', [u.id, ident, kindOf(ident)]);
    await c.query('COMMIT'); startSession(res, u); res.json(await me(u.id));
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); console.error(e); res.status(500).json({ error: 'Could not create the account' }); } finally { c.release(); }
});
app.post('/api/auth/login', authLimit, async (q, res) => {
  const ident = normId(q.body.ident), u = await findUserByIdent(ident), pw = String(q.body.password || '');
  if (u?.locked_until && new Date(u.locked_until) > new Date()) return res.status(429).json({ error: 'Too many wrong attempts. Try again in a few minutes or reset your password.' });
  const good = await bcrypt.compare(pw, u ? u.pw : DUMMY);
  if (!u || !good) {
    if (u) await db.query("UPDATE users SET failed=failed+1, locked_until=CASE WHEN failed+1>=5 THEN now()+interval '15 min' ELSE locked_until END, failed=CASE WHEN failed+1>=5 THEN 0 ELSE failed+1 END WHERE id=$1", [u.id]);
    return res.status(401).json({ error: 'Wrong ID or password' });
  }
  await db.query('UPDATE users SET failed=0, locked_until=NULL WHERE id=$1', [u.id]); await promote(u.id, ident);
  startSession(res, u); res.json(await me(u.id));
});
app.post('/api/auth/login-otp', authLimit, async (q, res) => {
  const ident = normId(q.body.ident), u = await findUserByIdent(ident);
  if (!u || !(await checkOtp(ident, 'login', q.body.code))) return res.status(401).json({ error: 'Wrong or expired code' });
  await promote(u.id, ident); startSession(res, u); res.json(await me(u.id));
});
app.post('/api/auth/reset', authLimit, async (q, res) => {
  const ident = normId(q.body.ident), { code, password } = q.body;
  if (!strongPw(password)) return res.status(400).json({ error: 'Password needs 8+ characters with letters and numbers' });
  const u = await findUserByIdent(ident);
  if (!u || !(await checkOtp(ident, 'reset', code))) return res.status(400).json({ error: 'Wrong or expired code' });
  // token_ver+1 signs the account out on every other device
  await db.query('UPDATE users SET pw=$2, token_ver=token_ver+1, failed=0, locked_until=NULL WHERE id=$1', [u.id, await bcrypt.hash(password, 12)]);
  res.json({ ok: true });
});
app.post('/api/auth/link', auth(), async (q, res) => {
  const ident = normId(q.body.ident);
  if (!validId(ident)) return res.status(400).json({ error: 'Enter a valid email or 10-digit mobile number' });
  const have = (await db.query('SELECT kind FROM user_idents WHERE user_id=$1', [q.user.id])).rows.map(x => x.kind);
  if (have.includes(kindOf(ident))) return res.status(400).json({ error: `Your account already has a ${kindOf(ident)}` });
  if (!(await checkOtp(ident, 'link', q.body.code))) return res.status(400).json({ error: 'Wrong or expired code' });
  try { await db.query('INSERT INTO user_idents(user_id,ident,kind) VALUES($1,$2,$3)', [q.user.id, ident, kindOf(ident)]); } catch { return res.status(409).json({ error: 'This email/mobile already belongs to an account' }); }
  await promote(q.user.id, ident); res.json(await me(q.user.id));
});
app.post('/api/auth/logout', (_, res) => { endSession(res); res.json({ ok: true }); });
app.get('/api/me', auth(), async (q, res) => res.json(await me(q.user.id)));
app.put('/api/me', auth(), async (q, res) => {
  const name = String(q.body.name || '').trim().slice(0, 60); if (!name) return res.status(400).json({ error: 'Enter a name' });
  await db.query('UPDATE users SET name=$2 WHERE id=$1', [q.user.id, name]); res.json(await me(q.user.id));
});

// ---------- stats ----------
const FMT = ['Test', 'ODI', 'T20I'];
// short frontend key -> DB column
const SM = { m: 'matches', i: 'innings', no: 'not_outs', r: 'runs', f: 'fifties', h: 'hundreds', h2: 'double_hundreds', h3: 'triple_hundreds', s6: 'sixes', s4: 'fours', hs: 'hs', sr: 'sr', w: 'wickets', bi: 'bowl_inn', bb: 'best', w3: 'w3', w5: 'w5', ec: 'econ', ba: 'bowl_avg', ct: 'catches', ro: 'runouts', st: 'stumpings' }, KS = Object.keys(SM);
async function upsert(table, keys, b, ex = db) {
  const cols = [...keys, ...KS.map(k => SM[k])], vals = [...keys.map(k => b[k]), ...KS.map(k => { if (k === 'bb') return String(b[k] || '-').slice(0, 12); const x = +b[k]; return Number.isFinite(x) ? (['sr', 'ec', 'ba'].includes(k) ? x : Math.round(x)) : 0; })];
  const sql = `INSERT INTO ${table}(${cols}) VALUES(${cols.map((_, i) => '$' + (i + 1))}) ON CONFLICT(${keys}) DO UPDATE SET ${cols.slice(keys.length).map((c, i) => c + '=$' + (i + keys.length + 1))} RETURNING *`;
  return (await ex.query(sql, vals)).rows[0];
}
const SKEYS = ['player_id', 'format', 'year', 'team_id'];
async function teamOf(pid, tm, ex = db) { const t = +tm; if (t) return t; return (await ex.query('SELECT team_id FROM players WHERE id=$1', [pid])).rows[0]?.team_id; }
const cleanImg = v => (typeof v === 'string' && /^(https?:\/\/|data:image\/|\/uploads\/)/i.test(v.trim())) ? v.trim() : null;
app.get('/api/bootstrap', async (_, res) => {
  const Q = ['SELECT id,name,logo,years,captain,coach,owner,venue,website,facebook,instagram,x FROM teams ORDER BY lower(name), id', 'SELECT id,code,name,team_id,role,photo_url,dob,bat_style,bowl_style,playing_role,career FROM players ORDER BY lower(name), id', 'SELECT * FROM season_stats', 'SELECT * FROM tournaments ORDER BY year DESC NULLS LAST, id ASC', 'SELECT * FROM tournament_stats', 'SELECT * FROM champions ORDER BY year DESC, id DESC', 'SELECT * FROM sponsors ORDER BY id', 'SELECT * FROM trophies ORDER BY year DESC', 'SELECT * FROM matches ORDER BY match_date', "SELECT value FROM settings WHERE key='logo'", 'SELECT * FROM news ORDER BY created_at DESC, id DESC', 'SELECT * FROM team_ratings ORDER BY id', "SELECT value FROM settings WHERE key='rank_rule'", 'SELECT * FROM awards ORDER BY id', 'SELECT * FROM fixtures ORDER BY match_date, match_time, id', "SELECT key,value FROM settings WHERE key IN ('footer','awards_info','photos','team_stats')", 'SELECT id,name,location,home_team_id,capacity,established_year,matches_count,rating,reviews FROM venues ORDER BY id'];
  const [t, p, s, tn, tsr, chm, sp, tr, mt, lg, nw, rt, rr, aw, fx, cs, vn] = await Promise.all(Q.map(x => db.query(x)));
  const num = (r, k) => (k === 'bb' ? r[SM[k]] : Number(r[SM[k]]));
  const tours = tn.rows.map(x => ({ id: x.id, n: x.name, y: x.year, fm: x.format, rows: tsr.rows.filter(r => r.tour_id === x.id).map(r => ({ p: r.player_id, ...Object.fromEntries(KS.map(k => [k, num(r, k)])) })) }));
  const players = p.rows.map(x => { const st = { Test: [], ODI: [], T20I: [] };
    s.rows.filter(r => r.player_id === x.id).forEach(r => st[r.format]?.push({ y: r.year, tm: r.team_id, ...Object.fromEntries(KS.map(k => [k, num(r, k)])) }));
    return { id: x.id, code: x.code, n: x.name, t: x.team_id, role: x.role || 'Batter', photo: x.photo_url, dob: x.dob || '', bs: x.bat_style || '', bw: x.bowl_style || '', playing_role: x.playing_role || '', career: x.career || '', st }; });
  res.json({ nid: 0, pin: '', champions: chm.rows.map(x => ({ id:x.id, tournament_id:x.tournament_id, year:x.year, winner_team_id:x.winner_team_id, runner_team_id:x.runner_team_id, trophy:x.trophy||'', img:x.img||'', note:x.note||'' })), teams: t.rows.map(x => ({ id:x.id,n:x.name,logo:x.logo||'',years:x.years||'',captain:x.captain||'',coach:x.coach||'',owner:x.owner||'',venue:x.venue||'',website:x.website||'',facebook:x.facebook||'',instagram:x.instagram||'',x:x.x||'' })), players, tours,
    trophies: tr.rows.map(x => ({ id: x.id, tid: x.team_id, n: x.name, y: x.year, img: x.img || '', photo: x.photo || '' })),
    matches: mt.rows.map(x => ({ id: x.id, v: x.venue, a: x.team_a, b: x.team_b, d: x.match_date, fm: x.format, base: x.base_price, cap: x.capacity, sold: x.sold, hype: x.hype })),
    logo: lg.rows[0]?.value || '', sponsors: sp.rows.map(x => ({ id: x.id, n: x.name, tier: x.tier, color: x.color })),
    news: nw.rows.map(x => ({ id: x.id, t: x.title, tag: x.tag || 'News', img: x.img || '', body: x.body || '', d: x.created_at, ai: !!x.ai_generated, sources: (() => { try { return x.source_urls ? JSON.parse(x.source_urls) : []; } catch { return []; } })() })),
    ratings: rt.rows.map(x => ({ id: x.id, tid: x.team_id, fm: x.format, w: x.wins, l: x.losses, d: x.draws })), rule: cleanRule(rr.rows[0]?.value),
    awards: aw.rows.map(x => ({ id: x.id, kind: x.kind, title: x.title, period: x.period || '', status: x.status || 'Winner announced', n: x.name, pid: x.player_id || null, tid: x.team_id, photo: x.photo || '', note: x.note || '' })),
    fixtures: fx.rows.map(x => ({ id: x.id, kind: x.kind, series: x.series || '', venue: x.venue || '', d: x.match_date, tm: x.match_time || '', fm: x.format || 'T20I', a: x.team_a, b: x.team_b, sa: x.score_a || '', sb: x.score_b || '', res: x.result || '', hl: x.highlights || '', mc: x.centre || '' })),
    venues: vn.rows.map(x => ({id:x.id,n:x.name,location:x.location||'',home_team_id:x.home_team_id,capacity:x.capacity||0,established_year:x.established_year||'',matches_count:x.matches_count||0,rating:Number(x.rating)||7.5,reviews:x.reviews||0})), cfg: cleanCfg(cs.rows.find(r => r.key === 'footer')?.value), awInfo: cs.rows.find(r => r.key === 'awards_info')?.value ?? null, teamStats: (() => { try { const v=cs.rows.find(r=>r.key==='team_stats')?.value; return v ? JSON.parse(v) : {}; } catch { return {}; } })(), photos: (() => { try { const v=cs.rows.find(r=>r.key==='photos')?.value; return v ? JSON.parse(v) : []; } catch { return []; } })() });
});
app.post('/api/stats', auth('admin'), async (q, res) => {
  if (!FMT.includes(q.body.format)) return res.status(400).json({ error: 'Bad format' });
  const tm = await teamOf(q.body.player_id, q.body.tm); if (!tm) return res.status(400).json({ error: 'Player or team not found' });
  res.json(await upsert('season_stats', SKEYS, { ...q.body, team_id: tm }));
});
app.post('/api/tstats', auth('admin'), async (q, res) => res.json(await upsert('tournament_stats', ['tour_id', 'player_id'], q.body)));
app.delete('/api/tstats/:t/:p', auth('admin'), async (q, res) => { await db.query('DELETE FROM tournament_stats WHERE tour_id=$1 AND player_id=$2', [q.params.t, q.params.p]); res.sendStatus(204); });
// Replaces ALL of one player's season rows in one transaction. Each row keeps its team (tm), so a player who played for several teams shows up in every team list.
app.put('/api/players/:id/stats', auth('admin'), async (q, res) => {
  const c = await db.connect();
  try {
    await c.query('BEGIN'); await c.query('DELETE FROM season_stats WHERE player_id=$1', [q.params.id]);
    for (const f of FMT) for (const r of (q.body.st?.[f] || [])) await upsert('season_stats', SKEYS, { ...r, player_id: q.params.id, format: f, year: r.y, team_id: await teamOf(q.params.id, r.tm, c) }, c);
    await c.query('COMMIT'); res.sendStatus(204);
  } catch (e) { await c.query('ROLLBACK'); res.status(400).json({ error: e.message }); } finally { c.release(); }
});
app.delete('/api/admin/stats', auth('admin'), async (q, res) => { await db.query('TRUNCATE season_stats, tournament_stats'); res.sendStatus(204); });
// bulk import: players are matched by unique Player ID (code) first, then by name
app.post('/api/admin/import', auth('admin'), async (q, res) => {
  const rows = (q.body.rows || []).slice(0, 5000), c = await db.connect(), out = { rows: 0, players: 0, teams: 0 };
  try {
    await c.query('BEGIN');
    for (const v of rows) {
      if (!v.name || !FMT.includes(v.fm)) continue;
      let tid = null;
      if (v.team) { let t = (await c.query('SELECT id FROM teams WHERE lower(name)=lower($1)', [v.team])).rows[0]; if (!t) { t = (await c.query('INSERT INTO teams(name) VALUES($1) RETURNING id', [v.team])).rows[0]; out.teams++; } tid = t.id; }
      let p = v.code ? (await c.query('SELECT id,team_id FROM players WHERE code=upper($1)', [String(v.code).trim()])).rows[0] : null;
      p = p || (await c.query('SELECT id,team_id FROM players WHERE lower(name)=lower($1) LIMIT 1', [v.name])).rows[0];
      if (!p) { tid = tid || (await c.query('SELECT id FROM teams ORDER BY id LIMIT 1')).rows[0]?.id; if (!tid) continue; p = (await c.query("INSERT INTO players(name,team_id,role) VALUES($1,$2,'Batter') RETURNING id,team_id", [v.name, tid])).rows[0]; out.players++; }
      await upsert('season_stats', SKEYS, { ...v, player_id: p.id, format: v.fm, year: v.y, team_id: tid || p.team_id }, c); out.rows++;
    }
    await c.query('COMMIT'); res.json(out);
  } catch (e) { await c.query('ROLLBACK'); res.status(400).json({ error: e.message }); } finally { c.release(); }
});

// ---------- tickets: prices rise with hype and with seats sold ----------
const CAT = { General: 1, Premium: 2, VIP: 4 };
const tprice = (m, c) => Math.round(m.base_price * CAT[c] * (1 + m.hype / 100 * 0.8) * (1 + m.sold / m.capacity * 0.75) / 10) * 10;
app.get('/api/bookings', auth(), async (q, res) => res.json((await db.query('SELECT id,match_id AS mid,category AS cat,qty,amount,created_at AS at FROM bookings WHERE user_id=$1 ORDER BY id', [q.user.id])).rows));
app.post('/api/bookings', auth(), async (q, res) => {
  const { match_id, category } = q.body, qty = Math.round(+q.body.qty);
  if (!CAT[category] || !(qty >= 1 && qty <= 10)) return res.status(400).json({ error: 'Bad request' });
  const c = await db.connect();
  try {
    await c.query('BEGIN');
    const m = (await c.query('SELECT * FROM matches WHERE id=$1 FOR UPDATE', [match_id])).rows[0];
    if (!m) throw new Error('Match not found'); if (m.sold + qty > m.capacity) throw new Error('Not enough seats left');
    const b = (await c.query('INSERT INTO bookings(match_id,user_id,category,qty,amount) VALUES($1,$2,$3,$4,$5) RETURNING id,match_id AS mid,category AS cat,qty,amount,created_at AS at', [m.id, q.user.id, category, qty, tprice(m, category) * qty])).rows[0];
    await c.query('UPDATE matches SET sold=sold+$2 WHERE id=$1', [m.id, qty]); await c.query('COMMIT'); res.json(b);
  } catch (e) { await c.query('ROLLBACK'); res.status(400).json({ error: e.message }); } finally { c.release(); }
});
app.put('/api/settings/logo', auth('admin'), async (q, res) => { await db.query("INSERT INTO settings(key,value) VALUES('logo',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [cleanImg(q.body.value) || '']); res.sendStatus(204); });

// ---------- CRUD: reads are public, writes need admin ----------
const IMGK = ['logo', 'img', 'photo', 'photo_url'];
const crud = (route, table, cols, required) => {
  const L = cols.split(','), vals = b => L.map(c => IMGK.includes(c) ? cleanImg(b[c]) : (typeof b[c] === 'string' ? b[c].trim().slice(0, 20000) : b[c]));
  const bad = b => required && !String(b[required] || '').trim();
  app.get(`/api/${route}`, async (_, r) => r.json((await db.query(`SELECT * FROM ${table} ORDER BY id`)).rows));
  app.post(`/api/${route}`, auth('admin'), async (q, r) => bad(q.body) ? r.status(400).json({ error: `${required} is required` }) : r.json((await db.query(`INSERT INTO ${table}(${cols}) VALUES(${L.map((_, i) => '$' + (i + 1))}) RETURNING *`, vals(q.body))).rows[0]));
  app.put(`/api/${route}/:id`, auth('admin'), async (q, r) => bad(q.body) ? r.status(400).json({ error: `${required} is required` }) : r.json((await db.query(`UPDATE ${table} SET ${L.map((c, i) => c + '=$' + (i + 1))} WHERE id=$${L.length + 1} RETURNING *`, [...vals(q.body), q.params.id])).rows[0]));
  app.delete(`/api/${route}/:id`, auth('admin'), async (q, r) => { await db.query(`DELETE FROM ${table} WHERE id=$1`, [q.params.id]); r.sendStatus(204); });
};
crud('teams', 'teams', 'name,logo,years,captain,coach,owner,venue,website,facebook,instagram,x', 'name'); crud('trophies', 'trophies', 'team_id,name,year,img,photo', 'name'); crud('matches', 'matches', 'venue,team_a,team_b,match_date,format,base_price,capacity,sold,hype', 'venue');
crud('tournaments', 'tournaments', 'name,year,format', 'name'); crud('champions', 'champions', 'tournament_id,year,winner_team_id,runner_team_id,trophy,img,note', 'tournament_id'); crud('sponsors', 'sponsors', 'name,tier,color', 'name');
crud('players', 'players', 'name,team_id,role,photo_url,dob,bat_style,bowl_style,playing_role,career', 'name');
crud('news', 'news', 'title,tag,img,body', 'title');

// ---------- OpenAI AI newsroom ----------
const AI_NEWS_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    stories: { type: 'array', minItems: 1, maxItems: 5, items: {
      type: 'object', additionalProperties: false,
      properties: {
        title: { type: 'string' },
        tag: { type: 'string' },
        summary: { type: 'string' },
        body: { type: 'string' },
        source_urls: { type: 'array', items: { type: 'string' } }
      },
      required: ['title','tag','summary','body','source_urls']
    }}
  }, required: ['stories']
};

async function generateAINews() {
  const ai = openaiClient();
  const [teams, fixtures, matches] = await Promise.all([
    db.query('SELECT id,name,venue FROM teams ORDER BY lower(name),id'),
    db.query("SELECT series,venue,match_date,match_time,format,team_a,team_b,result FROM fixtures ORDER BY match_date DESC LIMIT 25"),
    db.query("SELECT venue,match_date,format,team_a,team_b,capacity,sold,hype FROM matches ORDER BY match_date DESC LIMIT 25")
  ]);
  const now = new Date().toISOString();
  const teamMap = Object.fromEntries(teams.rows.map(x => [x.id, x.name]));
  const payload = {
    now,
    teams: teams.rows,
    recent_fixtures: fixtures.rows.map(x => ({...x, team_a_name: teamMap[x.team_a] || x.team_a, team_b_name: teamMap[x.team_b] || x.team_b})),
    ticket_matches: matches.rows.map(x => ({...x, team_a_name: teamMap[x.team_a] || x.team_a, team_b_name: teamMap[x.team_b] || x.team_b}))
  };
  const response = await ai.responses.create({
    model: OPENAI_MODEL,
    tools: [{ type: 'web_search' }],
    include: ['web_search_call.action.sources'],
    instructions: `You are the real-time cricket newsroom editor for UNITED KERALAM.\nUse web search to find genuinely current cricket news as of ${now}. Prioritize Kerala cricket, Indian cricket, players/teams/venues relevant to this site, and major cricket developments that affect fans. Never invent a result, quote, injury, transfer, score, date or player statement. If a fact cannot be verified, omit it. Use only sources you can actually find. Write concise publish-ready news for a sports website. Mention exact dates when useful. Return 2-5 distinct stories. Each story must have a clear headline, category tag, one-sentence summary, 2-4 short paragraphs in body, and direct source URLs.`,
    input: `Current UNITED KERALAM data:\n${JSON.stringify(payload)}\n\nFind the latest relevant cricket stories now. Do not treat the local database as proof of real-world events; use web search for current facts.`,
    text: { format: { type: 'json_schema', name: 'united_keralam_news', strict: true, schema: AI_NEWS_SCHEMA } },
    store: false
  });
  let parsed;
  try { parsed = JSON.parse(response.output_text); } catch { throw new Error('OpenAI returned an invalid newsroom response'); }
  const webSources = [];
  for (const item of (response.output || [])) {
    if (item.type === 'web_search_call' && item.action?.sources) {
      for (const src of item.action.sources) if (src.url) webSources.push(src.url);
    }
  }
  const stories = (parsed.stories || []).slice(0,5).map(x => ({
    title: String(x.title || '').trim().slice(0,240), tag: String(x.tag || 'AI News').trim().slice(0,60) || 'AI News',
    summary: String(x.summary || '').trim(), body: String(x.body || '').trim(),
    sources: [...new Set([...(Array.isArray(x.source_urls) ? x.source_urls : []), ...webSources])].filter(u => /^https?:\/\//i.test(u)).slice(0,8)
  })).filter(x => x.title && x.body);
  if (!stories.length) throw new Error('No verified news stories were returned');
  for (const story of stories) {
    const duplicate = (await db.query('SELECT id FROM news WHERE lower(title)=lower($1) LIMIT 1', [story.title])).rows[0];
    if (duplicate) {
      await db.query('UPDATE news SET tag=$1,body=$2,source_urls=$3,ai_generated=true,ai_updated_at=now(),created_at=now() WHERE id=$4', [story.tag || 'AI News', `${story.summary ? story.summary+'\\n\\n' : ''}${story.body}`, JSON.stringify(story.sources), duplicate.id]);
    } else {
      await db.query('INSERT INTO news(title,tag,body,created_at,ai_generated,source_urls,ai_updated_at) VALUES($1,$2,$3,now(),true,$4,now())', [story.title, story.tag || 'AI News', `${story.summary ? story.summary+'\\n\\n' : ''}${story.body}`, JSON.stringify(story.sources)]);
    }
  }
  await db.query("DELETE FROM news WHERE ai_generated=true AND id NOT IN (SELECT id FROM news WHERE ai_generated=true ORDER BY created_at DESC,id DESC LIMIT 30)");
  return stories;
}

app.get('/api/ai/news-status', async (_, res) => res.json({ configured: !!process.env.OPENAI_API_KEY, model: OPENAI_MODEL }));
app.post('/api/ai/news', auth('admin'), authLimit, async (_, res) => {
  try { res.json({ ok: true, stories: await generateAINews() }); }
  catch (e) { console.error('AI newsroom failed:', e); res.status(502).json({ error: e.message || 'AI newsroom failed' }); }
});
crud('venues', 'venues', 'name,location,home_team_id,capacity,established_year,matches_count,rating,reviews', 'name');


// ---------- awards, results & fixtures, footer / social links ----------
const urlOk = v => { v = String(v || '').trim(); return v.length < 2000 && /^https?:\/\/\S+$/i.test(v) ? v : null; };
const txt = n => v => String(v ?? '').trim().slice(0, n);
const idOrNull = v => (Number.isInteger(+v) && +v > 0 ? +v : (+v === 0 && v !== '' && v !== null && v !== undefined ? 0 : null));
function cleanCfg(v) {
  let o = {}; try { o = typeof v === 'string' ? JSON.parse(v) : (v || {}); } catch { }
  const u = x => urlOk(x) || '', t = (x, n) => String(x ?? '').trim().slice(0, n);
  return { fb: u(o.fb), yt: u(o.yt), ig: u(o.ig), x: u(o.x), slogo: cleanImg(o.slogo) || '', surl: u(o.surl), copy: t(o.copy, 200),
    links: Object.fromEntries(['terms', 'privacy', 'careers', 'related'].map(k => [k, u(o.links?.[k])])),
    pages: Object.fromEntries(['terms', 'privacy', 'careers', 'related', 'cookie'].map(k => [k, t(o.pages?.[k], 20000)])) };
}
app.put('/api/settings/footer', auth('admin'), async (q, r) => { await db.query("INSERT INTO settings(key,value) VALUES('footer',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [JSON.stringify(cleanCfg(q.body.value))]); r.sendStatus(204); });
app.put('/api/settings/awards_info', auth('admin'), async (q, r) => { await db.query("INSERT INTO settings(key,value) VALUES('awards_info',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [String(q.body.value ?? '').slice(0, 20000)]); r.sendStatus(204); });
app.put('/api/settings/team_stats', auth('admin'), async (q, r) => { let v={}; try { v=typeof q.body.value==='string'?JSON.parse(q.body.value):(q.body.value||{}); } catch { return r.status(400).json({error:'Invalid team statistics'}); } await db.query("INSERT INTO settings(key,value) VALUES('team_stats',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [JSON.stringify(v)]); r.sendStatus(204); });
// Photos are stored as JSON in the existing settings table so no separate migration is required.
const readPhotos = async () => { const r = await db.query("SELECT value FROM settings WHERE key='photos'"); try { return r.rows[0]?.value ? JSON.parse(r.rows[0].value) : []; } catch { return []; } };
const savePhotos = async rows => db.query("INSERT INTO settings(key,value) VALUES('photos',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [JSON.stringify(rows.slice(0,500))]);
app.get('/api/photos', async (_, r) => r.json(await readPhotos()));
app.post('/api/photos', auth('admin'), async (q, r) => { const title=String(q.body.title||'').trim().slice(0,160), caption=String(q.body.caption||'').trim().slice(0,2000), img=cleanImg(q.body.img)||''; if(!title)return r.status(400).json({error:'Title is required'}); const rows=await readPhotos(); const row={id:Date.now(),title,caption,img}; rows.push(row); await savePhotos(rows); r.json(row); });
app.put('/api/photos/:id', auth('admin'), async (q, r) => { const id=+q.params.id,title=String(q.body.title||'').trim().slice(0,160),caption=String(q.body.caption||'').trim().slice(0,2000),img=cleanImg(q.body.img)||''; if(!Number.isInteger(id)||!title)return r.status(400).json({error:'Invalid photo'}); const rows=await readPhotos(),i=rows.findIndex(x=>x.id==id); if(i<0)return r.status(404).json({error:'Photo not found'}); rows[i]={...rows[i],title,caption,img}; await savePhotos(rows); r.json(rows[i]); });
app.delete('/api/photos/:id', auth('admin'), async (q, r) => { const id=+q.params.id; await savePhotos((await readPhotos()).filter(x=>x.id!=id)); r.sendStatus(204); });

// small validated CRUD (writes need admin). spec: column -> sanitizer; check(row) returns an error message or null
const vcrud = (route, table, spec, check) => {
  const cols = Object.keys(spec), clean = b => Object.fromEntries(cols.map(c => [c, spec[c](b[c])])), vals = row => cols.map(c => row[c]);
  const fail = (e, r) => r.status(400).json({ error: e.code === '23503' ? 'Team or player not found' : 'Could not save' });
  app.post(`/api/${route}`, auth('admin'), async (q, r) => {
    const row = clean(q.body), err = check(row); if (err) return r.status(400).json({ error: err });
    try { r.json((await db.query(`INSERT INTO ${table}(${cols}) VALUES(${cols.map((_, i) => '$' + (i + 1))}) RETURNING *`, vals(row))).rows[0]); } catch (e) { fail(e, r); }
  });
  app.put(`/api/${route}/:id`, auth('admin'), async (q, r) => {
    const id = +q.params.id; if (!Number.isInteger(id)) return r.status(400).json({ error: 'Bad id' });
    const row = clean(q.body), err = check(row); if (err) return r.status(400).json({ error: err });
    try { const x = (await db.query(`UPDATE ${table} SET ${cols.map((c, i) => c + '=$' + (i + 1))} WHERE id=$${cols.length + 1} RETURNING *`, [...vals(row), id])).rows[0]; x ? r.json(x) : r.status(404).json({ error: 'Not found' }); } catch (e) { fail(e, r); }
  });
  app.delete(`/api/${route}/:id`, auth('admin'), async (q, r) => { const id = +q.params.id; if (!Number.isInteger(id)) return r.status(400).json({ error: 'Bad id' }); await db.query(`DELETE FROM ${table} WHERE id=$1`, [id]); r.sendStatus(204); });
};
vcrud('awards', 'awards', { kind: v => (['month', 'year', 'other'].includes(v) ? v : null), title: txt(120), period: txt(60), status: v => (v === 'Voting open' ? v : 'Winner announced'), name: txt(120), player_id: v => (+v > 0 ? idOrNull(v) : null), team_id: v => (+v > 0 || v === 0 || v === '0' ? idOrNull(v) : null), photo: cleanImg, note: txt(2000) },
  b => !b.kind ? 'Choose a type' : !b.title ? 'Title is required' : !b.name ? 'Player name is required' : null);
vcrud('fixtures', 'fixtures', { kind: v => (['Result', 'Fixture'].includes(v) ? v : null), series: txt(200), venue: txt(150), match_date: v => (/^\d{4}-\d{2}-\d{2}$/.test(String(v || '').trim()) ? String(v).trim() : null), match_time: v => (/^\d{2}:\d{2}$/.test(String(v || '').trim()) ? String(v).trim() : ''), format: v => (['Test', 'ODI', 'T20I'].includes(v) ? v : 'T20I'), team_a: idOrNull, team_b: idOrNull, score_a: txt(40), score_b: txt(40), result: txt(200), highlights: urlOk, centre: urlOk },
  b => !b.kind ? 'Choose Result or Fixture' : !b.match_date ? 'Choose a date' : (b.team_a === null || b.team_b === null) ? 'Choose both teams' : b.team_a === b.team_b ? 'Team A and Team B must be different' : null);
// ---------- team rankings (Test / ODI / T20I): admin enters won/lost/drawn, the page works out points & rating ----------
const RFMT = ['Test', 'ODI', 'T20I'], cnt = v => { const n = Math.floor(+v); return Number.isFinite(n) && n >= 0 && n <= 9999 ? n : 0; };
function cleanRule(v) {
  let o = {}; try { o = typeof v === 'string' ? JSON.parse(v) : (v || {}); } catch { }
  const pt = x => { const n = +x; return x !== '' && x != null && Number.isFinite(n) && n >= 0 && n <= 1000 ? Math.round(n * 100) / 100 : null; };
  return Object.fromEntries(RFMT.map(f => [f, { w: pt(o[f]?.w) ?? 100, d: pt(o[f]?.d) ?? 50, l: pt(o[f]?.l) ?? 0 }]));
}
const ratingIn = b => { const x = { tid: +b.team_id, fm: b.format, w: cnt(b.wins), l: cnt(b.losses), d: cnt(b.draws) }; x.err = !RFMT.includes(x.fm) ? 'Bad format' : !(x.tid > 0) ? 'Choose a team' : x.w + x.l + x.d < 1 ? 'Enter at least one match' : null; return x; };
app.post('/api/ratings', auth('admin'), async (q, r) => {
  const b = ratingIn(q.body); if (b.err) return r.status(400).json({ error: b.err });
  try { r.json((await db.query('INSERT INTO team_ratings(team_id,format,wins,losses,draws) VALUES($1,$2,$3,$4,$5) ON CONFLICT(team_id,format) DO UPDATE SET wins=$3,losses=$4,draws=$5 RETURNING *', [b.tid, b.fm, b.w, b.l, b.d])).rows[0]); }
  catch (e) { r.status(400).json({ error: e.code === '23503' ? 'Team or player not found' : 'Could not save' }); }
});
app.put('/api/ratings/:id', auth('admin'), async (q, r) => {
  const id = +q.params.id, b = ratingIn(q.body); if (!Number.isInteger(id)) return r.status(400).json({ error: 'Bad id' }); if (b.err) return r.status(400).json({ error: b.err });
  try { const row = (await db.query('UPDATE team_ratings SET team_id=$1,format=$2,wins=$3,losses=$4,draws=$5 WHERE id=$6 RETURNING *', [b.tid, b.fm, b.w, b.l, b.d, id])).rows[0]; row ? r.json(row) : r.status(404).json({ error: 'Not found' }); }
  catch (e) { r.status(400).json({ error: e.code === '23505' ? 'That team already has a ranking in this format. Edit that row instead.' : e.code === '23503' ? 'Team or player not found' : 'Could not save' }); }
});
app.delete('/api/ratings/:id', auth('admin'), async (q, r) => { const id = +q.params.id; if (!Number.isInteger(id)) return r.status(400).json({ error: 'Bad id' }); await db.query('DELETE FROM team_ratings WHERE id=$1', [id]); r.sendStatus(204); });
app.put('/api/settings/rank_rule', auth('admin'), async (q, r) => { await db.query("INSERT INTO settings(key,value) VALUES('rank_rule',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [JSON.stringify(cleanRule(q.body.value))]); r.sendStatus(204); });
app.post('/api/upload', auth('admin'), upload.single('file'), (q, r) => q.file ? r.json({ url: '/uploads/' + q.file.filename }) : r.status(400).json({ error: 'Choose an image file' }));
app.use((e, _q, res, _n) => { console.error(e); res.status(500).json({ error: 'Server error' }); });

// ---------- first-run demo fixtures (SEED_DEMO=true) ----------
const hash = s => [...s].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
async function seedMatches() {
  if ((await db.query('SELECT 1 FROM matches LIMIT 1')).rowCount) return;
  const teams = (await db.query('SELECT id,name FROM teams ORDER BY id')).rows; let d = 0;
  for (const [venue, home] of [['Kozhikode', 'Kozhikode'], ['Kochi', 'Cochin'], ['Trivandrum', 'Trivandrum'], ['Munnar', 'Munnar'], ['Wayanad', 'Wayanad']]) for (let k = 0; k < 2; k++) {
    const h = hash(venue + k), a = teams.find(t => t.name === home) || teams[0], others = teams.filter(t => t.id !== a.id), b = others[h % others.length], cap = 8000 + (h % 5) * 4000;
    await db.query('INSERT INTO matches(venue,team_a,team_b,match_date,format,base_price,capacity,sold,hype) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)', [venue, a.id, b.id, `2026-10-${String(10 + d++ * 2).padStart(2, '0')} 19:00`, ['T20I', 'ODI', 'T20I'][h % 3], 300 + (h % 6) * 100, cap, Math.round(cap * (0.2 + (h % 50) / 100)), 40 + (h % 60)]);
  }
}
async function seedNews() {
  if ((await db.query('SELECT 1 FROM news LIMIT 1')).rowCount) return;
  const L = [['Kozhikode announce squad for the new season', 'Announcement'], ['Rankings updated after latest fixtures', 'Rankings'], ['Wayanad crowned Malabar Cup 2026 champions after thrilling victory over Kozhikode', 'Match report'], ['Fixtures for Champions Trophy 2026 released', 'Announcement'], ['Aathif Khan crowned No.1 T20 Player in 2025–26 Rankings', 'Rankings'], ['KCA announces grade-wise player salary structure for Kerala Super League 2027', 'Announcement'], ['KCA Inter-Zone U-23 competition underway', 'News'], ['70,000+ fans: Old Stafford Stadium sets historic attendance record', 'Fans'], ['Kerala discuss new captain for Ranji Trophy 2026–27', 'News']];
  for (const [i, [t, tag]] of L.entries()) await db.query("INSERT INTO news(title,tag,created_at) VALUES($1,$2,now()-($3||' hours')::interval)", [t, tag, i * 7]);
}
async function seedRatings() {
  if ((await db.query('SELECT 1 FROM team_ratings LIMIT 1')).rowCount) return;
  const teams = (await db.query('SELECT id,name FROM teams ORDER BY id')).rows, q = (h, k, n) => Math.abs((h >> k) % n);
  for (const t of teams) for (const f of RFMT) {
    const h = hash(t.name + f), mat = 14 + q(h, 2, 22), w = Math.round(mat * (0.2 + q(h, 5, 60) / 100)), d = f === 'Test' ? Math.min(mat - w, q(h, 9, 5)) : (q(h, 9, 8) === 0 ? 1 : 0);
    await db.query('INSERT INTO team_ratings(team_id,format,wins,losses,draws) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING', [t.id, f, w, mat - w - d, d]);
  }
}
async function seedAwardsFixtures() {
  const teams = (await db.query('SELECT id,name FROM teams ORDER BY id')).rows, tn = i => teams[i % teams.length], MON = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'], now = new Date();
  if (teams.length && !(await db.query('SELECT 1 FROM awards LIMIT 1')).rowCount) {
    const pl = (await db.query('SELECT id,name FROM players ORDER BY id LIMIT 20')).rows.map(x => ({id:x.id,name:x.name.replace(/\(.*\)/, '').trim()})), y = now.getFullYear(), m = now.getMonth();
    for (const [k, t, p, i] of [['month', 'Player of the Month', MON[(m + 11) % 12] + ' ' + y, 1], ['month', 'Player of the Month', MON[(m + 10) % 12] + ' ' + y, 6], ['year', 'Player of the Year', String(y - 1), 0], ['year', 'Emerging Player of the Year', String(y - 1), 17]].reverse()) {
      if (pl[i]) {
        const tm = (await db.query('SELECT team_id FROM players WHERE id=$1', [pl[i].id])).rows[0]?.team_id || tn(0).id;
        await db.query("INSERT INTO awards(kind,title,period,status,name,player_id,team_id) VALUES($1,$2,$3,'Winner announced',$4,$5,$6)", [k, t, p, pl[i].name, pl[i].id, tm]);
      }
    }
  }
  if (teams.length > 1 && !(await db.query('SELECT 1 FROM fixtures LIMIT 1')).rowCount) {
    const day = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10), VN = ['Kozhikode', 'Kochi', 'Trivandrum', 'Munnar', 'Wayanad', 'Kannur'];
    for (const [i, [n, a, b]] of [[-1, 0, 1], [-1, 2, 3], [-3, 4, 5], [-3, 6, 7], [-5, 8, 9], [-6, 10, 11], [-8, 12, 13], [-9, 1, 2]].entries()) {
      const h = hash(a + 'x' + b), q = (k, m) => Math.abs((h >> k) % m), ra = 118 + q(2, 90), wa = q(5, 9), rb = ra + (i % 2 ? -1 : 1) * (6 + q(8, 40)), wb = q(11, 9), A = tn(a), B = tn(b), bw = rb > ra;
      await db.query("INSERT INTO fixtures(kind,series,venue,match_date,match_time,format,team_a,team_b,score_a,score_b,result) VALUES('Result',$1,$2,$3,'19:00','T20I',$4,$5,$6,$7,$8)", ['Kerala Premier League T20 - Match ' + (20 - i), VN[i % VN.length] + ' Cricket Ground', day(n), A.id, B.id, ra + '/' + wa + ' (20.0)', bw ? rb + '/' + wb + ' (' + (15 + q(14, 5)) + '.' + q(3, 6) + ')' : rb + '/' + wb + ' (20.0)', bw ? B.name + ' beat ' + A.name + ' by ' + (10 - wb) + ' wickets' : A.name + ' beat ' + B.name + ' by ' + (ra - rb) + ' runs']);
    }
    for (const [i, [n, a, b]] of [[2, 0, 3], [4, 5, 6], [6, 7, 8], [9, 10, 11], [12, 13, 0], [16, 1, 4]].entries())
      await db.query("INSERT INTO fixtures(kind,series,venue,match_date,match_time,format,team_a,team_b) VALUES('Fixture',$1,$2,$3,'19:00',$4,$5,$6)", ['Kerala Premier League T20 - Match ' + (21 + i), VN[(i + 2) % VN.length] + ' Cricket Ground', day(n), ['T20I', 'ODI', 'T20I'][i % 3], tn(a).id, tn(b).id]);
  }
}

// ---------- hourly generated news + series fixture pack ----------
async function hourlyStatsNews(){
  try{
    const [{rows:ps},{rows:ts},{rows:vs},{rows:ms},{rows:fx}] = await Promise.all([
      db.query('SELECT id,name FROM players ORDER BY lower(name),id'),
      db.query('SELECT id,name FROM teams ORDER BY lower(name),id'),
      db.query('SELECT id,name FROM venues ORDER BY lower(name),id'),
      db.query('SELECT COALESCE(SUM(sold),0)::int AS sold, COALESCE(SUM(capacity),0)::int AS cap FROM matches'),
      db.query("SELECT team_a,team_b,score_a,score_b,result,match_date FROM fixtures WHERE kind='Result' ORDER BY match_date DESC,id DESC LIMIT 1")
    ]);
    const [topRun] = (await db.query('SELECT p.name,COALESCE(SUM(s.runs),0)::int runs FROM season_stats s JOIN players p ON p.id=s.player_id GROUP BY p.id,p.name ORDER BY runs DESC,p.name ASC LIMIT 1')).rows;
    const [topWkt] = (await db.query('SELECT p.name,COALESCE(SUM(s.wickets),0)::int wickets FROM season_stats s JOIN players p ON p.id=s.player_id GROUP BY p.id,p.name ORDER BY wickets DESC,p.name ASC LIMIT 1')).rows;
    const pct=ms[0]?.cap?Math.round(ms[0].sold/ms[0].cap*100):0;
    const last=fx[0];
    const title=`UNITED KERALAM hourly update: ${ps.length} players, ${ts.length} teams, ${vs.length} venues`;
    const body=[
      `Live database snapshot refreshed at ${new Date().toISOString()}.`,
      topRun?`Runs leader: ${topRun.name} — ${topRun.runs} runs.`:'Runs leader: no season data yet.',
      topWkt?`Wickets leader: ${topWkt.name} — ${topWkt.wickets} wickets.`:'Wickets leader: no season data yet.',
      `Tickets: ${ms[0]?.sold||0} sold from ${ms[0]?.cap||0} capacity (${pct}% sold).`,
      last?`Latest result: ${last.result||`${last.score_a||''} vs ${last.score_b||''}`} on ${last.match_date}.`:'No completed match result yet.'
    ].join(' ');
    const existing=(await db.query("SELECT id FROM news WHERE tag='Auto Update' ORDER BY id DESC LIMIT 1")).rows[0];
    if(existing) await db.query("UPDATE news SET title=$1,body=$2,created_at=now() WHERE id=$3",[title,body,existing.id]);
    else await db.query("INSERT INTO news(title,tag,body,created_at) VALUES($1,'Auto Update',$2,now())",[title,body]);
  }catch(e){ console.error('Hourly news update failed:',e.message); }
}
async function seedSeriesFixtures(){
  try{
    const teams=(await db.query('SELECT id,name FROM teams ORDER BY lower(name),id')).rows;
    if(teams.length<2) return;
    const marker='UNITED KERALAM Demo Series 2026';
    const exists=(await db.query("SELECT 1 FROM fixtures WHERE series LIKE $1 LIMIT 1",[marker+'%'])).rowCount;
    if(exists) return;
    const n=teams.length, rows=[];
    // Regular opponent schedules: every team gets exactly 5 T20, 3 ODI and 2 Test matches.
    const addPairs=(offsets,format,label)=>{
      const seen=new Set();
      for(let i=0;i<n;i++) for(const off of offsets){
        const j=(i+off)%n, a=Math.min(i,j), b=Math.max(i,j), key=`${a}-${b}-${format}`;
        if(a!==b&&!seen.has(key)){seen.add(key);rows.push({a:teams[a].id,b:teams[b].id,format,label});}
      }
    };
    // 5-degree graph: offsets 1,2 plus the opposite team (7 for 14; fallback odd offsets for other sizes)
    const opp=Math.floor(n/2);
    addPairs([1,2,opp],'T20I', 'UNITED KERALAM Demo Series 2026 - T20');
    addPairs([1,opp],'ODI', 'UNITED KERALAM Demo Series 2026 - ODI');
    addPairs([opp],'Test', 'UNITED KERALAM Demo Series 2026 - Test');
    // For non-14 team counts, fill degree deficits deterministically until target counts are met.
    const targets={T20I:5,ODI:3,Test:2}, deg=new Map();
    for(const t of teams) deg.set(t.id,{T20I:0,ODI:0,Test:0});
    for(const r of rows){deg.get(r.a)[r.format]++;deg.get(r.b)[r.format]++}
    for(const format of Object.keys(targets)){
      const need=targets[format];
      while([...deg.values()].some(d=>d[format]<need)){
        let made=false;
        for(let i=0;i<n&&!made;i++) if(deg.get(teams[i].id)[format]<need){
          for(let j=i+1;j<n;j++) if(deg.get(teams[j].id)[format]<need){
            const a=teams[i].id,b=teams[j].id;
            if(!rows.some(r=>r.format===format&&((r.a===a&&r.b===b)||(r.a===b&&r.b===a)))){
              rows.push({a,b,format,label:`${marker} - ${format==='T20I'?'T20':format}`});
              deg.get(a)[format]++;deg.get(b)[format]++;made=true;break;
            }
          }
        }
        if(!made) break;
      }
    }
    // Keep the requested 50–100 range; for the normal 14-team database this is exactly 70.
    let seq=1, day=0;
    for(const r of rows.slice(0,100)){
      const d=new Date(Date.now()+(day-25)*864e5); day++;
      const fmtLabel=r.format==='T20I'?'T20':r.format;
      const h=hash(`${r.a}-${r.b}-${r.format}`);
      const ra=r.format==='Test'?280+(h%160):r.format==='ODI'?220+(h%120):145+(h%100);
      const rb=ra-20+((h>>5)%70);
      const sa=r.format==='Test'?`${ra}/${(h%10)} dec`:`${ra}/${h%8} (${r.format==='ODI'?'50.0':'20.0'})`;
      const sb=r.format==='Test'?`${rb}/${((h>>4)%10)} dec`:`${rb}/${((h>>4)%8)} (${r.format==='ODI'?'50.0':'20.0'})`;
      const A=teams.find(t=>t.id===r.a),B=teams.find(t=>t.id===r.b);
      const result=ra>=rb?`${A.name} beat ${B.name} by ${Math.max(1,ra-rb)} runs`:`${B.name} beat ${A.name} by ${Math.max(1,ra-rb)} runs`;
      await db.query(`INSERT INTO fixtures(kind,series,venue,match_date,match_time,format,team_a,team_b,score_a,score_b,result)
        VALUES('Result',$1,$2,$3,'19:00',$4,$5,$6,$7,$8,$9)`,
        [r.label+` - Match ${seq++}`, A.name+' Cricket Ground',d.toISOString().slice(0,10),r.format,r.a,r.b,sa,sb,result]);
    }
    console.log(`Demo series fixtures ready: ${Math.min(rows.length,100)} matches`);
  }catch(e){ console.error('Series fixture seed failed:',e.message); }
}

// Player profile extension: safe on existing PostgreSQL databases.
async function ensureNewsAiColumns(){
  await db.query(`ALTER TABLE news ADD COLUMN IF NOT EXISTS ai_generated BOOLEAN NOT NULL DEFAULT false`);
  await db.query(`ALTER TABLE news ADD COLUMN IF NOT EXISTS source_urls TEXT`);
  await db.query(`ALTER TABLE news ADD COLUMN IF NOT EXISTS ai_updated_at TIMESTAMPTZ`);
}
async function ensureVenues(){
  await db.query(`CREATE TABLE IF NOT EXISTS venues(id SERIAL PRIMARY KEY,name TEXT UNIQUE NOT NULL,location TEXT DEFAULT '',home_team_id INT REFERENCES teams(id) ON DELETE SET NULL,capacity INT NOT NULL DEFAULT 0,established_year INT,matches_count INT NOT NULL DEFAULT 0,rating NUMERIC(3,1) NOT NULL DEFAULT 7.5,reviews INT NOT NULL DEFAULT 0)`);
  await db.query(`ALTER TABLE venues ADD COLUMN IF NOT EXISTS matches_count INT NOT NULL DEFAULT 0`);
  await db.query(`ALTER TABLE venues ADD COLUMN IF NOT EXISTS rating NUMERIC(3,1) NOT NULL DEFAULT 7.5`);
  await db.query(`ALTER TABLE venues ADD COLUMN IF NOT EXISTS reviews INT NOT NULL DEFAULT 0`);
  await db.query(`UPDATE venues v SET matches_count = COALESCE((SELECT COUNT(*) FROM matches m WHERE lower(trim(m.venue)) = lower(trim(v.name))), 0) WHERE COALESCE(v.matches_count,0)=0`);
  const n=(await db.query('SELECT count(*)::int AS n FROM venues')).rows[0].n;
  if(!n){
    const teams=(await db.query('SELECT id,name FROM teams ORDER BY id')).rows, find=n=>teams.find(x=>x.name===n)?.id||null;
    const rows=[['Old Stafford Stadium','Kozhikode, Kerala',find('Kozhikode'),70000,1950,2],['Greenfield International Stadium','Thiruvananthapuram, Kerala',find('Trivandrum'),50000,2014,2],['Jawaharlal Nehru Stadium','Kochi, Kerala',find('Cochin'),60000,1996,2],['Munnar Cricket Ground','Munnar, Kerala',find('Munnar'),15000,2018,2]];
    for(const r of rows) await db.query('INSERT INTO venues(name,location,home_team_id,capacity,established_year,matches_count) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(name) DO NOTHING',r);
    for(const r of rows) if(r[2]) await db.query("UPDATE teams SET venue=$1 WHERE id=$2 AND (venue IS NULL OR venue='')",[r[0],r[2]]);
  }
}
async function ensureStatsNotOutColumns() {
  await db.query(`ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS not_outs INT DEFAULT 0`);
  await db.query(`ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS double_hundreds INT DEFAULT 0`);
  await db.query(`ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS triple_hundreds INT DEFAULT 0`);
  await db.query(`ALTER TABLE tournament_stats ADD COLUMN IF NOT EXISTS not_outs INT DEFAULT 0`);
}
async function ensurePlayerProfileColumns() {
  await db.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS playing_role TEXT`);
  await db.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS career TEXT`);
}
// Optional first-run admin: set ADMIN_IDENT (email), ADMIN_MOBILE (optional), ADMIN_PASSWORD in .env. The password is hashed; remove ADMIN_PASSWORD from .env after the first start.
async function bootstrapAdmin() {
  const e = normId(process.env.ADMIN_IDENT), m = normId(process.env.ADMIN_MOBILE), pw = process.env.ADMIN_PASSWORD;
  if (!e || !pw) return;
  if (!strongPw(pw)) return console.error('ADMIN_PASSWORD needs 8+ characters with letters and numbers');
  if (await findUserByIdent(e)) return;
  const u = (await db.query("INSERT INTO users(name,pw,role) VALUES($1,$2,'admin') RETURNING id", [process.env.ADMIN_NAME || 'Admin', await bcrypt.hash(pw, 12)])).rows[0];
  await db.query('INSERT INTO user_idents(user_id,ident,kind) VALUES($1,$2,$3)', [u.id, e, kindOf(e)]);
  if (validId(m) && !(await findUserByIdent(m))) await db.query('INSERT INTO user_idents(user_id,ident,kind) VALUES($1,$2,$3)', [u.id, m, kindOf(m)]);
  console.log('Admin account created for ' + e);
}
ensureStatsNotOutColumns().then(() => ensurePlayerProfileColumns()).then(() => ensureNewsAiColumns()).then(() => ensureVenues()).then(() => bootstrapAdmin()).then(async () => {
  app.listen(process.env.PORT || 3000, async () => {
    console.log('UNITED KERALAM on :' + (process.env.PORT || 3000));
    if (process.env.SEED_DEMO === 'true') await Promise.all([seedMatches(), seedNews(), seedRatings(), seedAwardsFixtures()]);
    await seedSeriesFixtures();
    await hourlyStatsNews();
    if (process.env.OPENAI_API_KEY) {
      generateAINews().then(() => console.log('AI newsroom refresh complete')).catch(e => console.error('AI newsroom startup refresh failed:', e.message));
      setInterval(() => generateAINews().then(() => console.log('AI newsroom refresh complete')).catch(e => console.error('AI newsroom refresh failed:', e.message)), 60 * 60 * 1000);
    }
    setInterval(hourlyStatsNews, 60 * 60 * 1000);
  });
}).catch(e => { console.error(e); process.exit(1); });
