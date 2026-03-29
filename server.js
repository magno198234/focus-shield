const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const MP_TOKEN = process.env.MP_ACCESS_TOKEN || '';

const db = new Database('focusshield.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS guardians (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    group_name TEXT,
    role TEXT DEFAULT 'guardian',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS protected_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    gender TEXT NOT NULL,
    guardian_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protected_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    blocked_count INTEGER DEFAULT 0,
    installed_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    guardian_id INTEGER NOT NULL,
    protected_name TEXT,
    gender TEXT,
    device_type TEXT,
    payment_type TEXT DEFAULT 'free',
    payment_status TEXT DEFAULT 'pending',
    payment_id TEXT,
    pix_qr_code_base64 TEXT,
    pix_copia_cola TEXT,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
  );
`);

const admin = db.prepare('SELECT * FROM guardians WHERE role = ?').get('admin');
if (!admin) {
  const hash = crypto.createHash('sha256').update('admin123').digest('hex');
  db.prepare('INSERT INTO guardians (name, email, password, group_name, role) VALUES (?, ?, ?, ?, ?)').run('Magno R.', 'admin@focusshield.app', hash, 'Célula Graça Viva', 'admin');
  console.log('Admin criado: admin@focusshield.app / admin123');
}

function authenticate(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Token necessário' });
  const guardian = db.prepare('SELECT * FROM guardians WHERE id = ?').get(parseInt(token));
  if (!guardian) return res.status(401).json({ error: 'Não autorizado' });
  req.guardian = guardian;
  next();
}

// LOGIN
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash('sha256').update(password || '').digest('hex');
  const g = db.prepare('SELECT * FROM guardians WHERE email = ? AND password = ?').get(email, hash);
  if (!g) return res.status(401).json({ error: 'Email ou senha inválidos' });
  res.json({ id: g.id, name: g.name, email: g.email, role: g.role, group: g.group_name });
});

// GUARDIÕES
app.get('/api/guardians', authenticate, (req, res) => {
  if (req.guardian.role !== 'admin') return res.status(403).json({ error: 'Apenas admin' });
  const gs = db.prepare('SELECT g.*, COUNT(DISTINCT p.id) as protected_count FROM guardians g LEFT JOIN protected_users p ON p.guardian_id = g.id GROUP BY g.id').all();
  res.json(gs.map(g => ({ ...g, password: undefined })));
});

app.post('/api/guardians', authenticate, (req, res) => {
  if (req.guardian.role !== 'admin') return res.status(403).json({ error: 'Apenas admin' });
  const { name, email, group_name } = req.body;
  const pw = crypto.randomBytes(4).toString('hex');
  const hash = crypto.createHash('sha256').update(pw).digest('hex');
  try {
    const r = db.prepare('INSERT INTO guardians (name, email, password, group_name) VALUES (?, ?, ?, ?)').run(name, email, hash, group_name);
    res.json({ id: r.lastInsertRowid, name, email, group_name, password: pw });
  } catch(e) { res.status(400).json({ error: 'Email já cadastrado' }); }
});

// PROTEGIDOS
app.get('/api/protected', authenticate, (req, res) => {
  let users = req.guardian.role === 'admin'
    ? db.prepare('SELECT * FROM protected_users').all()
    : db.prepare('SELECT * FROM protected_users WHERE guardian_id = ?').all(req.guardian.id);
  res.json(users.map(u => ({ ...u, devices: db.prepare('SELECT * FROM devices WHERE protected_id = ?').all(u.id) })));
});

// GERAR LINK
app.post('/api/tokens/generate', authenticate, (req, res) => {
  const { name, gender, device_type, type, payment_type } = req.body;
  const token = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000).toISOString();
  const pType = req.guardian.role === 'admin' ? (payment_type || 'free') : 'paid';
  const pStatus = pType === 'free' ? 'confirmed' : 'pending';

  db.prepare('INSERT INTO tokens (token, type, guardian_id, protected_name, gender, device_type, payment_type, payment_status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
    token, type || 'activation', req.guardian.id, name, gender, device_type, pType, pStatus, expiresAt
  );

  const base = req.headers.host || 'localhost:3000';
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const link = pType === 'paid' ? proto+'://'+base+'/pay/'+token : proto+'://'+base+'/setup/'+token;

  res.json({ token, link, expires_in: '20 minutos', device_type, payment_type: pType });
});

// CRIAR PIX
app.post('/api/payment/create', async (req, res) => {
  const { token } = req.body;
  const td = db.prepare('SELECT * FROM tokens WHERE token = ?').get(token);
  if (!td) return res.status(404).json({ error: 'Token não encontrado' });
  if (td.payment_status === 'confirmed') return res.json({ status: 'already_paid' });
  if (td.pix_copia_cola) return res.json({ status: 'pending', pix_qr_code_base64: td.pix_qr_code_base64, pix_copia_cola: td.pix_copia_cola });

  try {
    const r = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + MP_TOKEN, 'X-Idempotency-Key': token },
      body: JSON.stringify({
        transaction_amount: 29.90,
        description: 'Focus Shield - Proteção Digital',
        payment_method_id: 'pix',
        payer: { email: 'protegido_' + token.slice(0,8) + '@focusshield.app', first_name: td.protected_name || 'Protegido', last_name: 'Shield' }
      })
    });
    const data = await r.json();
    if (data.id) {
      const pix = data.point_of_interaction?.transaction_data;
      db.prepare('UPDATE tokens SET payment_id=?, pix_qr_code_base64=?, pix_copia_cola=? WHERE token=?').run(String(data.id), pix?.qr_code_base64||'', pix?.qr_code||'', token);
      res.json({ status: 'pending', pix_qr_code_base64: pix?.qr_code_base64, pix_copia_cola: pix?.qr_code });
    } else { res.status(400).json({ error: 'Erro ao criar pagamento', details: data }); }
  } catch(e) { console.error('Erro MP:', e); res.status(500).json({ error: 'Erro interno' }); }
});

// VERIFICAR PAGAMENTO
app.get('/api/payment/status/:token', async (req, res) => {
  const td = db.prepare('SELECT * FROM tokens WHERE token = ?').get(req.params.token);
  if (!td) return res.status(404).json({ error: 'Não encontrado' });
  if (td.payment_status === 'confirmed') return res.json({ status: 'confirmed' });
  if (td.payment_id && MP_TOKEN) {
    try {
      const r = await fetch('https://api.mercadopago.com/v1/payments/' + td.payment_id, { headers: { 'Authorization': 'Bearer ' + MP_TOKEN } });
      const data = await r.json();
      if (data.status === 'approved') {
        db.prepare('UPDATE tokens SET payment_status=? WHERE token=?').run('confirmed', req.params.token);
        const ex = db.prepare('SELECT * FROM protected_users WHERE name=? AND guardian_id=?').get(td.protected_name, td.guardian_id);
        if (!ex) {
          const result = db.prepare('INSERT INTO protected_users (name, gender, guardian_id) VALUES (?, ?, ?)').run(td.protected_name, td.gender, td.guardian_id);
          db.prepare('INSERT INTO devices (protected_id, type) VALUES (?, ?)').run(result.lastInsertRowid, td.device_type);
        }
        return res.json({ status: 'confirmed' });
      }
      return res.json({ status: data.status || 'pending' });
    } catch(e) { console.error('Erro:', e); }
  }
  res.json({ status: 'pending' });
});

// WEBHOOK MERCADO PAGO
app.post('/api/webhook/mercadopago', async (req, res) => {
  res.sendStatus(200);
  if (req.body.type === 'payment' && req.body.data?.id) {
    try {
      const r = await fetch('https://api.mercadopago.com/v1/payments/' + req.body.data.id, { headers: { 'Authorization': 'Bearer ' + MP_TOKEN } });
      const p = await r.json();
      if (p.status === 'approved') {
        const td = db.prepare('SELECT * FROM tokens WHERE payment_id = ?').get(String(req.body.data.id));
        if (td && td.payment_status !== 'confirmed') {
          db.prepare('UPDATE tokens SET payment_status=? WHERE payment_id=?').run('confirmed', String(req.body.data.id));
          const ex = db.prepare('SELECT * FROM protected_users WHERE name=? AND guardian_id=?').get(td.protected_name, td.guardian_id);
          if (!ex) {
            const result = db.prepare('INSERT INTO protected_users (name, gender, guardian_id) VALUES (?, ?, ?)').run(td.protected_name, td.gender, td.guardian_id);
            db.prepare('INSERT INTO devices (protected_id, type) VALUES (?, ?)').run(result.lastInsertRowid, td.device_type);
          }
          console.log('Pagamento confirmado:', td.protected_name);
        }
      }
    } catch(e) { console.error('Webhook erro:', e); }
  }
});

// VALIDAR TOKEN
app.get('/api/tokens/:token/validate', (req, res) => {
  const td = db.prepare('SELECT * FROM tokens WHERE token = ?').get(req.params.token);
  if (!td) return res.status(404).json({ error: 'Não encontrado' });
  if (td.used) return res.status(400).json({ error: 'Já utilizado' });
  res.json({ valid: true, type: td.type, gender: td.gender, device_type: td.device_type, payment_type: td.payment_type, payment_status: td.payment_status });
});

app.post('/api/tokens/:token/use', (req, res) => {
  const td = db.prepare('SELECT * FROM tokens WHERE token = ?').get(req.params.token);
  if (!td || td.used) return res.status(400).json({ error: 'Inválido' });
  if (td.payment_type === 'paid' && td.payment_status !== 'confirmed') return res.status(400).json({ error: 'Pagamento pendente' });
  db.prepare('UPDATE tokens SET used = 1 WHERE token = ?').run(req.params.token);
  res.json({ success: true });
});

// STATS
app.get('/api/stats', authenticate, (req, res) => {
  if (req.guardian.role === 'admin') {
    res.json({
      users: db.prepare('SELECT COUNT(*) as c FROM protected_users').get().c,
      devices: db.prepare("SELECT COUNT(*) as c FROM devices WHERE status='active'").get().c,
      blocked: db.prepare('SELECT COALESCE(SUM(blocked_count),0) as t FROM devices').get().t,
      guardians: db.prepare('SELECT COUNT(*) as c FROM guardians').get().c
    });
  } else {
    const ds = db.prepare('SELECT d.* FROM devices d JOIN protected_users p ON d.protected_id=p.id WHERE p.guardian_id=?').all(req.guardian.id);
    res.json({
      users: db.prepare('SELECT COUNT(*) as c FROM protected_users WHERE guardian_id=?').get(req.guardian.id).c,
      devices: ds.length, blocked: ds.reduce((s,d) => s+d.blocked_count, 0), guardians: 0
    });
  }
});

// PÁGINAS
app.get('/setup/:token', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'setup.html')); });
app.get('/pay/:token', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'payment.html')); });
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.use((req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('\n🛡️  Focus Shield Backend rodando!');
  console.log('📍 http://localhost:' + PORT);
  console.log('🔑 admin@focusshield.app / admin123');
  console.log('💰 MP: ' + (MP_TOKEN ? 'OK' : 'NÃO configurado') + '\n');
});
