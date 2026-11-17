const express = require('express');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.13+, no native build
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'promptshelf.db');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.warn('JWT_SECRET not set: logins reset on every restart.');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';

const CATEGORIES = [
  ['writing', 'Writing'], ['coding', 'Coding'], ['marketing', 'Marketing'], ['business', 'Business'],
  ['education', 'Education'], ['productivity', 'Productivity'], ['image-generation', 'Image Generation'],
  ['data-analysis', 'Data & Analysis'],
];
const CAT_SET = new Set(CATEGORIES.map((c) => c[0]));

/* ---------- db ---------- */
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.transaction = (fn) => (...args) => {
  db.exec('BEGIN');
  try { const r = fn(...args); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
};
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pass_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS prompts(
  id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL, category TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]',
  author_id INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending',
  likes INTEGER NOT NULL DEFAULT 0, copies INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_prompts_status ON prompts(status, category);
CREATE TABLE IF NOT EXISTS likes(
  user_id INTEGER NOT NULL REFERENCES users(id), prompt_id INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, prompt_id));
CREATE TABLE IF NOT EXISTS saves(
  user_id INTEGER NOT NULL REFERENCES users(id), prompt_id INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, PRIMARY KEY(user_id, prompt_id));
`);

/* ---------- helpers ---------- */
const now = () => Date.now();
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const buckets = new Map();
function limited(key, max, windowMs) {
  const t = now(), arr = (buckets.get(key) || []).filter((x) => t - x < windowMs);
  if (arr.length >= max) { buckets.set(key, arr); return true; }
  arr.push(t); buckets.set(key, arr); return false;
}
const clean = (s, max) => String(s == null ? '' : s).trim().slice(0, max);
function cleanTags(t) {
  const arr = Array.isArray(t) ? t : String(t || '').split(',');
  return [...new Set(arr.map((x) => clean(x, 24).toLowerCase().replace(/[^a-z0-9 -]/g, '')).filter(Boolean))].slice(0, 8);
}
function toPrompt(r) {
  return {
    id: r.id, title: r.title, description: r.description, body: r.body, category: r.category,
    tags: JSON.parse(r.tags), author: r.author, likes: r.likes, copies: r.copies, created: r.created,
    status: r.status, liked: !!r.liked, saved: !!r.saved,
  };
}
const SEL = `SELECT p.*, u.name AS author,
  EXISTS(SELECT 1 FROM likes l WHERE l.user_id=? AND l.prompt_id=p.id) AS liked,
  EXISTS(SELECT 1 FROM saves s WHERE s.user_id=? AND s.prompt_id=p.id) AS saved
  FROM prompts p JOIN users u ON u.id=p.author_id`;
function sign(u) { return jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '30d' }); }

/* ---------- app + auth middleware ---------- */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '300kb' }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'same-origin');
  next();
});
function loadUser(req, _res, next) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  req.user = null;
  if (m) {
    try {
      const { id } = jwt.verify(m[1], JWT_SECRET);
      req.user = db.prepare('SELECT id,email,name,role FROM users WHERE id=?').get(id) || null;
    } catch (_) { /* invalid token = anonymous */ }
  }
  next();
}
const needAuth = (req, res, next) => (req.user ? next() : bad(res, 'Login required', 401));
const needAdmin = (req, res, next) => (req.user && req.user.role === 'admin' ? next() : bad(res, 'Admin only', 403));
app.use('/api', loadUser);

/* ---------- auth ---------- */
app.post('/api/auth/register', (req, res) => {
  if (limited('reg:' + req.ip, 10, 3600e3)) return bad(res, 'Too many attempts', 429);
  const email = clean(req.body.email, 200).toLowerCase(), name = clean(req.body.name, 60), pw = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return bad(res, 'Valid email required');
  if (!name) return bad(res, 'Name required');
  if (pw.length < 8) return bad(res, 'Password must be at least 8 characters');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return bad(res, 'Email already registered', 409);
  const role = ADMIN_EMAIL && email === ADMIN_EMAIL ? 'admin' : 'user';
  const info = db.prepare('INSERT INTO users(email,name,pass_hash,role,created) VALUES(?,?,?,?,?)')
    .run(email, name, bcrypt.hashSync(pw, 10), role, now());
  const u = { id: Number(info.lastInsertRowid), email, name, role };
  res.status(201).json({ token: sign(u), user: u });
});
app.post('/api/auth/login', (req, res) => {
  if (limited('login:' + req.ip, 20, 900e3)) return bad(res, 'Too many attempts', 429);
  const email = clean(req.body.email, 200).toLowerCase();
  const row = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!row || !bcrypt.compareSync(String(req.body.password || ''), row.pass_hash)) return bad(res, 'Wrong email or password', 401);
  const u = { id: row.id, email: row.email, name: row.name, role: row.role };
  res.json({ token: sign(u), user: u });
});
app.get('/api/auth/me', needAuth, (req, res) => res.json({ user: req.user }));

/* ---------- public browse ---------- */
app.get('/api/categories', (_req, res) => {
  const counts = Object.fromEntries(db.prepare("SELECT category, COUNT(*) c FROM prompts WHERE status='approved' GROUP BY category").all().map((r) => [r.category, r.c]));
  res.json(CATEGORIES.map(([slug, name]) => ({ slug, name, count: counts[slug] || 0 })));
});
app.get('/api/tags', (_req, res) => {
  const freq = {};
  db.prepare("SELECT tags FROM prompts WHERE status='approved'").all().forEach((r) => JSON.parse(r.tags).forEach((t) => { freq[t] = (freq[t] || 0) + 1; }));
  res.json(Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 30).map(([tag, count]) => ({ tag, count })));
});
app.get('/api/prompts', (req, res) => {
  const { q, category, tag, sort = 'new' } = req.query;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1), limit = Math.min(50, parseInt(req.query.limit, 10) || 20);
  const w = ["p.status='approved'"], a = [];
  if (category) { w.push('p.category=?'); a.push(String(category)); }
  if (tag) { w.push('p.tags LIKE ?'); a.push('%"' + String(tag).toLowerCase().replace(/[%_"\\]/g, '') + '"%'); }
  if (q) {
    const like = '%' + String(q).replace(/[%_\\]/g, '') + '%';
    w.push('(p.title LIKE ? OR p.body LIKE ? OR p.description LIKE ? OR p.tags LIKE ?)');
    a.push(like, like, like, like);
  }
  const order = { new: 'p.created DESC', popular: 'p.likes DESC, p.created DESC', copied: 'p.copies DESC, p.created DESC' }[sort] || 'p.created DESC';
  const where = w.join(' AND '), uid = req.user ? req.user.id : 0;
  const total = db.prepare(`SELECT COUNT(*) c FROM prompts p WHERE ${where}`).get(...a).c;
  const rows = db.prepare(`${SEL} WHERE ${where} ORDER BY ${order} LIMIT ? OFFSET ?`).all(uid, uid, ...a, limit, (page - 1) * limit);
  res.json({ total, page, limit, items: rows.map(toPrompt) });
});
app.get('/api/prompts/:id', (req, res) => {
  const uid = req.user ? req.user.id : 0;
  const r = db.prepare(`${SEL} WHERE p.id=?`).get(uid, uid, req.params.id);
  const mine = r && req.user && (r.author_id === req.user.id || req.user.role === 'admin');
  if (!r || (r.status !== 'approved' && !mine)) return bad(res, 'Not found', 404);
  res.json(toPrompt(r));
});
app.post('/api/prompts/:id/copy', (req, res) => {
  if (limited('copy:' + req.ip + ':' + req.params.id, 3, 60e3)) return res.json({ ok: true });
  db.prepare("UPDATE prompts SET copies=copies+1 WHERE id=? AND status='approved'").run(req.params.id);
  res.json({ ok: true });
});

/* ---------- submit / manage ---------- */
function validatePrompt(b) {
  const title = clean(b.title, 120), body = clean(b.body, 8000), description = clean(b.description, 300), category = String(b.category || '');
  if (title.length < 3) return { error: 'Title needs at least 3 characters' };
  if (body.length < 10) return { error: 'Prompt text needs at least 10 characters' };
  if (!CAT_SET.has(category)) return { error: 'Pick a valid category' };
  return { title, body, description, category, tags: cleanTags(b.tags) };
}
app.post('/api/prompts', needAuth, (req, res) => {
  if (limited('submit:' + req.user.id, 20, 3600e3)) return bad(res, 'Submission limit reached. Try later.', 429);
  const v = validatePrompt(req.body);
  if (v.error) return bad(res, v.error);
  const status = req.user.role === 'admin' ? 'approved' : 'pending';
  const info = db.prepare('INSERT INTO prompts(title,description,body,category,tags,author_id,status,created) VALUES(?,?,?,?,?,?,?,?)')
    .run(v.title, v.description, v.body, v.category, JSON.stringify(v.tags), req.user.id, status, now());
  res.status(201).json({ id: Number(info.lastInsertRowid), status });
});
app.put('/api/prompts/:id', needAuth, (req, res) => {
  const r = db.prepare('SELECT * FROM prompts WHERE id=?').get(req.params.id);
  if (!r) return bad(res, 'Not found', 404);
  if (r.author_id !== req.user.id && req.user.role !== 'admin') return bad(res, 'Not allowed', 403);
  const v = validatePrompt(req.body);
  if (v.error) return bad(res, v.error);
  const status = req.user.role === 'admin' ? r.status : 'pending'; // edits by authors go back to review
  db.prepare('UPDATE prompts SET title=?,description=?,body=?,category=?,tags=?,status=? WHERE id=?')
    .run(v.title, v.description, v.body, v.category, JSON.stringify(v.tags), status, r.id);
  res.json({ id: r.id, status });
});
app.delete('/api/prompts/:id', needAuth, (req, res) => {
  const r = db.prepare('SELECT author_id FROM prompts WHERE id=?').get(req.params.id);
  if (!r) return bad(res, 'Not found', 404);
  if (r.author_id !== req.user.id && req.user.role !== 'admin') return bad(res, 'Not allowed', 403);
  db.prepare('DELETE FROM prompts WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/* ---------- likes / saves ---------- */
function toggle(table, req, res) {
  const p = db.prepare("SELECT id FROM prompts WHERE id=? AND status='approved'").get(req.params.id);
  if (!p) return bad(res, 'Not found', 404);
  const uid = req.user.id;
  const tx = db.transaction(() => {
    const has = db.prepare(`SELECT 1 FROM ${table} WHERE user_id=? AND prompt_id=?`).get(uid, p.id);
    if (has) db.prepare(`DELETE FROM ${table} WHERE user_id=? AND prompt_id=?`).run(uid, p.id);
    else if (table === 'saves') db.prepare('INSERT INTO saves(user_id,prompt_id,created) VALUES(?,?,?)').run(uid, p.id, now());
    else db.prepare('INSERT INTO likes(user_id,prompt_id) VALUES(?,?)').run(uid, p.id);
    if (table === 'likes') db.prepare('UPDATE prompts SET likes=(SELECT COUNT(*) FROM likes WHERE prompt_id=?) WHERE id=?').run(p.id, p.id);
    return !has;
  });
  const on = tx();
  const likes = db.prepare('SELECT likes FROM prompts WHERE id=?').get(p.id).likes;
  res.json({ on, likes });
}
app.post('/api/prompts/:id/like', needAuth, (req, res) => toggle('likes', req, res));
app.post('/api/prompts/:id/save', needAuth, (req, res) => toggle('saves', req, res));
app.get('/api/me/saved', needAuth, (req, res) => {
  const rows = db.prepare(`${SEL} JOIN saves sv ON sv.prompt_id=p.id AND sv.user_id=? WHERE p.status='approved' ORDER BY sv.created DESC`).all(req.user.id, req.user.id, req.user.id);
  res.json({ items: rows.map(toPrompt) });
});
app.get('/api/me/prompts', needAuth, (req, res) => {
  const rows = db.prepare(`${SEL} WHERE p.author_id=? ORDER BY p.created DESC`).all(req.user.id, req.user.id, req.user.id);
  res.json({ items: rows.map(toPrompt) });
});

/* ---------- admin ---------- */
app.get('/api/admin/pending', needAuth, needAdmin, (req, res) => {
  const rows = db.prepare(`${SEL} WHERE p.status='pending' ORDER BY p.created ASC`).all(req.user.id, req.user.id);
  res.json({ items: rows.map(toPrompt) });
});
app.post('/api/admin/prompts/:id/:action(approve|reject)', needAuth, needAdmin, (req, res) => {
  const status = req.params.action === 'approve' ? 'approved' : 'rejected';
  const info = db.prepare('UPDATE prompts SET status=? WHERE id=?').run(status, req.params.id);
  if (!info.changes) return bad(res, 'Not found', 404);
  res.json({ id: Number(req.params.id), status });
});
// Accepts the JSON exported from Prompt Bench: [{title, body, tags}]
app.post('/api/admin/import', needAuth, needAdmin, (req, res) => {
  const items = Array.isArray(req.body) ? req.body : req.body && req.body.items;
  if (!Array.isArray(items)) return bad(res, 'Send a JSON array');
  const fallbackCat = CAT_SET.has(req.query.category) ? req.query.category : 'productivity';
  const ins = db.prepare('INSERT INTO prompts(title,description,body,category,tags,author_id,status,created) VALUES(?,?,?,?,?,?,?,?)');
  const dupe = db.prepare('SELECT 1 FROM prompts WHERE title=? AND body=?');
  let added = 0;
  db.transaction(() => items.slice(0, 500).forEach((p) => {
    const title = clean(p && p.title, 120), body = clean(p && p.body, 8000);
    if (title.length < 3 || body.length < 10 || dupe.get(title, body)) return;
    const category = CAT_SET.has(p.category) ? p.category : fallbackCat;
    ins.run(title, clean(p.description, 300), body, category, JSON.stringify(cleanTags(p.tags)), req.user.id, 'approved', now());
    added++;
  }))();
  res.json({ added });
});

/* ---------- AI improve ---------- */
const SYSTEM = 'You are an expert prompt engineer. Rewrite the user\'s draft prompt so a language model follows it reliably. ' +
  'State the goal and audience first; give needed context; make the task specific; specify output format, length and tone; ' +
  'add constraints and what to do when information is missing; remove filler and contradictions; keep the author\'s intent. ' +
  'Preserve every {{variable}} placeholder exactly. Do not invent facts. ' +
  'Reply with JSON only, no code fence: {"improved":"<full rewritten prompt>","changes":["<short reason>"]} with at most 6 changes.';
// No-key fallback: checks the draft for common prompt parts and adds {{placeholders}} for what is missing.
function ruleImprove(draft) {
  const checks = [
    ['role', /\b(you are|act as|acting as|as an? [a-z]+ (expert|editor|analyst|engineer|writer))\b/i, 'Added a role line. Naming a role sets expertise and tone.'],
    ['audience', /\b(audience|aimed at|written for|context|background|for (a|an|the|my|our) [a-z]+)\b/i, 'Added context. State who it is for and why.'],
    ['output_format', /\b(format|bullets?|table|json|markdown|paragraphs?|headings?|steps|\d+\s*(words|sentences|bullets|items)|under \d+|at most \d+)\b/i, 'Added an output format. Say the shape and length you want.'],
    ['constraints', /\b(must|do not|don't|never|only|avoid|without|no more than|at least|limit)\b/i, 'Added constraints. Say what to avoid or always include.'],
    ['example', /\b(example|e\.g\.|for instance|such as)\b|```/i, 'Added an optional example slot. One sample output removes ambiguity.'],
  ];
  const missing = checks.filter((c) => !c[1].test(draft)).map((c) => c[0]);
  const changes = [];
  const hasTask = /\b(write|create|explain|summari[sz]e|list|generate|analy[sz]e|review|draft|rewrite|translate|compare|plan|outline|extract|classify|fix|suggest|give|make|describe|convert|help)\b/i.test(draft);
  if (!hasTask) changes.push('No clear task verb found. Start the task with an action such as "Write", "Summarize" or "Compare".');
  if (draft.split(/\s+/).length < 8) changes.push('Draft is very short. More detail usually gives better results.');
  const vague = draft.match(/\b(good|nice|better|best|great|some|stuff|things)\b/gi);
  if (vague) changes.push('Vague words found (' + [...new Set(vague.map((v) => v.toLowerCase()))].join(', ') + '). Replace with measurable criteria.');
  const parts = [];
  if (missing.includes('role')) parts.push('You are {{role}}.');
  parts.push('Task: ' + draft);
  if (missing.includes('audience')) parts.push('Context: {{audience}}');
  if (missing.includes('output_format')) parts.push('Output format: {{output_format}}');
  const cons = [];
  if (missing.includes('constraints')) cons.push('- {{constraints}}');
  cons.push('- If information is missing, ask me or list your assumptions before answering.');
  parts.push('Constraints:\n' + cons.join('\n'));
  if (missing.includes('example')) parts.push('Example output (optional): {{example}}');
  checks.forEach((c) => { if (missing.includes(c[0])) changes.push(c[2]); });
  changes.unshift('Rule-based suggestions (no AI key configured). Fill the {{placeholders}} or delete the lines you do not need.');
  return { improved: parts.join('\n\n'), changes: changes.slice(0, 8), mode: 'rules' };
}
app.post('/api/ai/improve', needAuth, async (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY;
  const draft = clean(req.body.prompt, 8000);
  if (draft.length < 5) return bad(res, 'Send a prompt to improve');
  if (!key) return res.json(ruleImprove(draft));
  if (limited('ai:' + req.user.id, 20, 3600e3)) return bad(res, 'Improve limit reached. Try again later.', 429);
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: MODEL, max_tokens: 4096, system: SYSTEM, messages: [{ role: 'user', content: 'Draft prompt:\n"""\n' + draft + '\n"""' }] }),
    });
    if (!r.ok) return bad(res, 'AI service error (' + r.status + ')', 502);
    const j = await r.json();
    let t = (j.content || []).map((b) => b.text || '').join('').trim().replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
    let o = null;
    try { o = JSON.parse(t); } catch (_) { const m = t.match(/\{[\s\S]*\}/); if (m) try { o = JSON.parse(m[0]); } catch (_e) { /* fall through */ } }
    if (!o || !o.improved) o = { improved: t, changes: [] };
    res.json({ improved: String(o.improved), changes: (o.changes || []).map(String).slice(0, 6) });
  } catch (e) { bad(res, 'AI service unreachable', 502); }
});

app.get('/healthz', (_req, res) => res.send('ok'));
app.use('/api', (_req, res) => bad(res, 'Not found', 404));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, _req, res, _next) => bad(res, err.type === 'entity.parse.failed' ? 'Invalid JSON' : 'Server error', err.status || 500));

/* ---------- seed (original starter prompts) ---------- */
require('./seed')(db, bcrypt, now);

app.listen(PORT, () => console.log('PromptShelf on :' + PORT));
