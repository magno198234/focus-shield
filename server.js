const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const ADMIN_KEY = process.env.ADMIN_KEY || 'Pitaya251534@';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guardians (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      token TEXT UNIQUE NOT NULL,
      paid INTEGER DEFAULT 0,
      payment_id TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS children (
      id SERIAL PRIMARY KEY,
      guardian_id INTEGER REFERENCES guardians(id),
      name TEXT NOT NULL,
      email TEXT,
      setup_token TEXT UNIQUE NOT NULL,
      deactivate_token TEXT,
      nextdns_id TEXT,
      active INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      guardian_id INTEGER,
      child_id INTEGER,
      mp_payment_id TEXT UNIQUE,
      status TEXT DEFAULT 'pending',
      amount NUMERIC DEFAULT 29.90,
      created_at TIMESTAMP DEFAULT NOW(),
      paid_at TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'guardian',
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS organizations (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      pastor TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      address TEXT,
      document TEXT,
      mp_token TEXT,
      token TEXT UNIQUE NOT NULL,
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS org_guardians (
      id SERIAL PRIMARY KEY,
      org_id INTEGER REFERENCES organizations(id),
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      token TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS org_children (
      id SERIAL PRIMARY KEY,
      org_guardian_id INTEGER REFERENCES org_guardians(id),
      org_id INTEGER REFERENCES organizations(id),
      name TEXT NOT NULL,
      email TEXT,
      setup_token TEXT UNIQUE NOT NULL,
      deactivate_token TEXT,
      active INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS org_payments (
      id SERIAL PRIMARY KEY,
      org_id INTEGER,
      org_child_id INTEGER,
      mp_payment_id TEXT UNIQUE,
      status TEXT DEFAULT 'pending',
      amount NUMERIC DEFAULT 50.00,
      created_at TIMESTAMP DEFAULT NOW(),
      paid_at TIMESTAMP
    );
  `);
  console.log('✅ Tabelas verificadas/criadas');
}

async function initAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@focusshield.app';
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
  if (rows.length === 0) {
    await pool.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3)', [adminEmail, adminPassword, 'admin']);
    console.log('✅ Admin criado:', adminEmail);
  } else {
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [adminPassword, adminEmail]);
    console.log('✅ Admin atualizado:', adminEmail);
  }
  const { rows: gRows } = await pool.query('SELECT id FROM guardians WHERE email = $1', [adminEmail]);
  if (gRows.length === 0) {
    const token = crypto.randomBytes(16).toString('hex');
    await pool.query('INSERT INTO guardians (name, email, token, paid) VALUES ($1, $2, $3, 1)', ['Admin', adminEmail, token]);
    console.log('✅ Guardião admin criado');
  }
}

async function start() {
  try {
    await initDB();
    await initAdmin();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🛡️ Focus Shield rodando na porta ${PORT}`));
  } catch (err) {
    console.error('❌ Erro ao iniciar:', err);
    process.exit(1);
  }
}

// ════════════════════════════════════════════════════════════
// ROTAS DO ADMIN
// ════════════════════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1 AND password = $2', [email, password]);
    if (rows.length === 0) return res.status(401).json({ error: 'Email ou senha inválidos' });
    const user = rows[0];
    res.json({
      success: true, role: user.role, email: user.email,
      token: Buffer.from(`${email}:${password}`).toString('base64'),
      adminKey: user.role === 'admin' ? ADMIN_KEY : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/me', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Não autenticado' });
  try {
    const decoded = Buffer.from(auth, 'base64').toString('utf8');
    const [email, password] = decoded.split(':');
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1 AND password = $2', [email, password]);
    if (rows.length === 0) return res.status(401).json({ error: 'Token inválido' });
    res.json({ email: rows[0].email, role: rows[0].role });
  } catch { res.status(401).json({ error: 'Token inválido' }); }
});

app.post('/api/admin/create-guardian', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
  const token = crypto.randomBytes(16).toString('hex');
  try {
    await pool.query('INSERT INTO guardians (name, email, token, paid) VALUES ($1, $2, $3, 1) RETURNING id', [name, email, token]);
    res.json({
      success: true,
      guardianToken: token,
      guardianLink: `${req.protocol}://${req.get('host')}/guardiao.html?token=${token}`,
    });
  } catch (err) {
    if (err.message.includes('unique') || err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email já cadastrado' });
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: CRIAR PROTEGIDO (Agora Gratuito por Padrão) ─────────────────────────────────────
app.post('/api/admin/create-child', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
  try {
    const { rows: gRows } = await pool.query('SELECT id FROM guardians WHERE email = $1', [process.env.ADMIN_EMAIL || 'admin@focusshield.app']);
    if (gRows.length === 0) return res.status(500).json({ error: 'Guardião admin não encontrado' });
    const setupToken = crypto.randomBytes(16).toString('hex');
    // Insere já com active = 1
    await pool.query('INSERT INTO children (guardian_id, name, email, setup_token, active) VALUES ($1, $2, $3, $4, 1)', [gRows[0].id, name, email, setupToken]);
    // Retorna direto o link de setup, ignorando pagamento
    res.json({ success: true, setupLink: `${req.protocol}://${req.get('host')}/setup.html?token=${setupToken}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Mantive a rota antiga para compatibilidade, caso algum lugar do painel ainda chame ela
app.post('/api/admin/create-child-free', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
  try {
    const { rows: gRows } = await pool.query('SELECT id FROM guardians WHERE email = $1', [process.env.ADMIN_EMAIL || 'admin@focusshield.app']);
    if (gRows.length === 0) return res.status(500).json({ error: 'Guardião admin não encontrado' });
    const setupToken = crypto.randomBytes(16).toString('hex');
    await pool.query('INSERT INTO children (guardian_id, name, email, setup_token, active) VALUES ($1, $2, $3, $4, 1)', [gRows[0].id, name, email, setupToken]);
    res.json({ success: true, setupLink: `${req.protocol}://${req.get('host')}/setup.html?token=${setupToken}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/children', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    const { rows: gRows } = await pool.query('SELECT id FROM guardians WHERE email = $1', [process.env.ADMIN_EMAIL || 'admin@focusshield.app']);
    if (gRows.length === 0) return res.json([]);
    // Removido o LEFT JOIN com payments
    const { rows } = await pool.query(`
      SELECT id, name, email, active, created_at
      FROM children
      WHERE guardian_id = $1
      ORDER BY created_at DESC
    `, [gRows[0].id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/guardians', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    const { rows } = await pool.query('SELECT id, name, email, paid, payment_id, created_at FROM guardians ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/guardian/:id', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM payments WHERE guardian_id = $1', [id]);
    await pool.query('DELETE FROM children WHERE guardian_id = $1', [id]);
    await pool.query('DELETE FROM guardians WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Rota mantida caso precise do histórico, mas sem Mercado Pago ativo
app.get('/api/admin/payments', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    const { rows } = await pool.query(`
      SELECT p.*, g.name as guardian_name, g.email
      FROM payments p JOIN guardians g ON g.id = p.guardian_id
      ORDER BY p.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/deactivate/:childId', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    const deactivateToken = crypto.randomBytes(16).toString('hex');
    await pool.query('UPDATE children SET deactivate_token = $1 WHERE id = $2', [deactivateToken, req.params.childId]);
    res.json({ success: true, deactivateLink: `${req.protocol}://${req.get('host')}/desativar.html?token=${deactivateToken}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GUARDIÃO ───────────────────────────────────────────────────────────────────
app.get('/api/guardian/:token', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email FROM guardians WHERE token = $1', [req.params.token]);
    if (rows.length === 0) return res.status(404).json({ error: 'Guardião não encontrado' });
    const guardian = rows[0];
    // Removido o LEFT JOIN com payments
    const { rows: children } = await pool.query(`
      SELECT id, name, email, active, nextdns_id, created_at
      FROM children
      WHERE guardian_id = $1 ORDER BY created_at DESC
    `, [guardian.id]);
    res.json({ guardian, children });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/guardian/:token/create-child', async (req, res) => {
  try {
    const { rows: gRows } = await pool.query('SELECT id FROM guardians WHERE token = $1', [req.params.token]);
    if (gRows.length === 0) return res.status(404).json({ error: 'Guardião não encontrado' });
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
    const setupToken = crypto.randomBytes(16).toString('hex');
    // Insere já com active = 1
    const { rows } = await pool.query('INSERT INTO children (guardian_id, name, email, setup_token, active) VALUES ($1, $2, $3, $4, 1) RETURNING id', [gRows[0].id, name, email, setupToken]);
    // Retorna direto o setupLink ao invés do paymentLink
    res.json({ success: true, childId: rows[0].id, setupLink: `${req.protocol}://${req.get('host')}/setup.html?token=${setupToken}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/guardian/:token/deactivate/:childId', async (req, res) => {
  try {
    const { rows: gRows } = await pool.query('SELECT id FROM guardians WHERE token = $1', [req.params.token]);
    if (gRows.length === 0) return res.status(404).json({ error: 'Guardião não encontrado' });
    const { rows: cRows } = await pool.query('SELECT id FROM children WHERE id = $1 AND guardian_id = $2', [req.params.childId, gRows[0].id]);
    if (cRows.length === 0) return res.status(404).json({ error: 'Protegido não encontrado' });
    const deactivateToken = crypto.randomBytes(16).toString('hex');
    await pool.query('UPDATE children SET deactivate_token = $1 WHERE id = $2', [deactivateToken, req.params.childId]);
    res.json({ success: true, deactivateLink: `${req.protocol}://${req.get('host')}/desativar.html?token=${deactivateToken}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PROTEGIDO (Telas de Setup) ──────────────────────────────────────────────────

app.get('/api/validate-setup/:token', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, g.name as guardian_name FROM children c
      JOIN guardians g ON g.id = c.guardian_id WHERE c.setup_token = $1
    `, [req.params.token]);
    if (rows.length === 0) {
      // Tenta buscar nas igrejas se não achar nos normais
      const { rows: orgRows } = await pool.query(`
         SELECT c.*, g.name as guardian_name FROM org_children c
         JOIN org_guardians g ON g.id = c.org_guardian_id WHERE c.setup_token = $1
      `, [req.params.token]);
      if(orgRows.length === 0) return res.status(404).json({ error: 'Token inválido' });
      return res.json({ valid: true, childName: orgRows[0].name, guardianName: orgRows[0].guardian_name, active: orgRows[0].active });
    }
    res.json({ valid: true, childName: rows[0].name, guardianName: rows[0].guardian_name, active: rows[0].active });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/setup-complete', async (req, res) => {
  const { token, nextdnsId } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM children WHERE setup_token = $1', [token]);
    if (rows.length === 0) {
        // Se não for criança normal, atualiza org_children
        const { rows: orgRows } = await pool.query('SELECT * FROM org_children WHERE setup_token = $1', [token]);
        if(orgRows.length === 0) return res.status(404).json({ error: 'Token inválido' });
        // Na org_children não tem nextdns_id no schema atual, apenas marca como ativo
        await pool.query('UPDATE org_children SET active = 1 WHERE setup_token = $1', [token]);
        return res.json({ success: true });
    }
    await pool.query('UPDATE children SET nextdns_id = $1, active = 1 WHERE setup_token = $2', [nextdnsId, token]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/validate-deactivate/:token', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, g.name as guardian_name FROM children c
      JOIN guardians g ON g.id = c.guardian_id WHERE c.deactivate_token = $1
    `, [req.params.token]);
    if (rows.length === 0) {
        const { rows: orgRows } = await pool.query(`
          SELECT c.*, g.name as guardian_name FROM org_children c
          JOIN org_guardians g ON g.id = c.org_guardian_id WHERE c.deactivate_token = $1
        `, [req.params.token]);
        if(orgRows.length === 0) return res.status(404).json({ error: 'Link inválido ou já utilizado' });
        return res.json({ valid: true, childName: orgRows[0].name, guardianName: orgRows[0].guardian_name });
    }
    res.json({ valid: true, childName: rows[0].name, guardianName: rows[0].guardian_name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/deactivate', async (req, res) => {
  const { token } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM children WHERE deactivate_token = $1', [token]);
    if (rows.length === 0) {
        const { rows: orgRows } = await pool.query('SELECT * FROM org_children WHERE deactivate_token = $1', [token]);
        if (orgRows.length === 0) return res.status(404).json({ error: 'Link inválido' });
        await pool.query('UPDATE org_children SET active = 0, deactivate_token = NULL WHERE deactivate_token = $1', [token]);
        return res.json({ success: true });
    }
    await pool.query('UPDATE children SET active = 0, deactivate_token = NULL WHERE deactivate_token = $1', [token]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════
// ROTAS DAS IGREJAS
// ════════════════════════════════════════════════════════════

app.post('/api/admin/create-org', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  const { name, pastor, email, phone, address, document, mp_token } = req.body;
  if (!name || !pastor || !email) return res.status(400).json({ error: 'Nome, pastor e email obrigatórios' });
  const token = crypto.randomBytes(16).toString('hex');
  try {
    await pool.query('INSERT INTO organizations (name, pastor, email, phone, address, document, mp_token, token) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [name, pastor, email, phone || null, address || null, document || null, mp_token || null, token]);
    res.json({ success: true, orgLink: `${req.protocol}://${req.get('host')}/igreja.html?token=${token}` });
  } catch (err) {
    if (err.message.includes('unique') || err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email já cadastrado' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/orgs', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    // Removido o count de org_payments
    const { rows } = await pool.query(`
      SELECT o.id, o.name, o.pastor, o.email, o.phone, o.address, o.document, o.mp_token, o.token, o.active, o.created_at,
        (SELECT COUNT(*) FROM org_guardians WHERE org_id = o.id) as total_guardians,
        (SELECT COUNT(*) FROM org_children WHERE org_id = o.id) as total_children
      FROM organizations o ORDER BY o.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/org/:id', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Não autorizado' });
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM org_payments WHERE org_id = $1', [id]);
    await pool.query('DELETE FROM org_children WHERE org_id = $1', [id]);
    await pool.query('DELETE FROM org_guardians WHERE org_id = $1', [id]);
    await pool.query('DELETE FROM organizations WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/org/:token', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, pastor, email FROM organizations WHERE token = $1 AND active = 1', [req.params.token]);
    if (rows.length === 0) return res.status(404).json({ error: 'Igreja não encontrada' });
    const org = rows[0];
    const { rows: guardians } = await pool.query(`
      SELECT g.id, g.name, g.email, g.created_at,
        (SELECT COUNT(*) FROM org_children WHERE org_guardian_id = g.id) as total_children
      FROM org_guardians g WHERE g.org_id = $1 ORDER BY g.created_at DESC
    `, [org.id]);
    res.json({ org, guardians });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/org/:token/create-guardian', async (req, res) => {
  try {
    const { rows: oRows } = await pool.query('SELECT id FROM organizations WHERE token = $1 AND active = 1', [req.params.token]);
    if (oRows.length === 0) return res.status(404).json({ error: 'Igreja não encontrada' });
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
    const guardianToken = crypto.randomBytes(16).toString('hex');
    await pool.query('INSERT INTO org_guardians (org_id, name, email, token) VALUES ($1, $2, $3, $4)', [oRows[0].id, name, email, guardianToken]);
    res.json({ success: true, guardianLink: `${req.protocol}://${req.get('host')}/guardiao-igreja.html?token=${guardianToken}` });
  } catch (err) {
    if (err.message.includes('unique') || err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email já cadastrado' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/org-guardian/:token', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT g.*, o.name as org_name FROM org_guardians g
      JOIN organizations o ON o.id = g.org_id WHERE g.token = $1
    `, [req.params.token]);
    if (rows.length === 0) return res.status(404).json({ error: 'Guardião não encontrado' });
    const guardian = rows[0];
    // Removido o LEFT JOIN com org_payments
    const { rows: children } = await pool.query(`
      SELECT id, name, email, active, created_at
      FROM org_children
      WHERE org_guardian_id = $1 ORDER BY created_at DESC
    `, [guardian.id]);
    res.json({ guardian, children });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/org-guardian/:token/create-child', async (req, res) => {
  try {
    const { rows: gRows } = await pool.query(`
      SELECT g.*, o.mp_token as org_mp_token FROM org_guardians g
      JOIN organizations o ON o.id = g.org_id WHERE g.token = $1
    `, [req.params.token]);
    if (gRows.length === 0) return res.status(404).json({ error: 'Guardião não encontrado' });
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
    const setupToken = crypto.randomBytes(16).toString('hex');
    // Insere já com active = 1
    await pool.query('INSERT INTO org_children (org_guardian_id, org_id, name, email, setup_token, active) VALUES ($1, $2, $3, $4, $5, 1)', [gRows[0].id, gRows[0].org_id, name, email, setupToken]);
    // Redireciona direto pro setup normal (ou uma página específica, caso você crie um setup-org no futuro)
    res.json({ success: true, setupLink: `${req.protocol}://${req.get('host')}/setup.html?token=${setupToken}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

start();
