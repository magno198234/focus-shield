const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ============================================
// BANCO DE DADOS
// ============================================
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guardian_id) REFERENCES guardians(id)
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protected_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    blocked_count INTEGER DEFAULT 0,
    installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (protected_id) REFERENCES protected_users(id)
  );

  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    guardian_id INTEGER NOT NULL,
    protected_name TEXT,
    gender TEXT,
    device_type TEXT,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (guardian_id) REFERENCES guardians(id)
  );
`);

// Cria admin padrão se não existir
const admin = db.prepare('SELECT * FROM guardians WHERE role = ?').get('admin');
if (!admin) {
  const hash = crypto.createHash('sha256').update('admin123').digest('hex');
  db.prepare('INSERT INTO guardians (name, email, password, group_name, role) VALUES (?, ?, ?, ?, ?)').run(
    'Magno R.', 'admin@focusshield.app', hash, 'Célula Graça Viva', 'admin'
  );
  console.log('Admin criado: email=admin@focusshield.app senha=admin123');
}

// ============================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ============================================
function authenticate(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Token necessário' });
  
  const guardian = db.prepare('SELECT * FROM guardians WHERE id = ?').get(parseInt(token));
  if (!guardian) return res.status(401).json({ error: 'Não autorizado' });
  
  req.guardian = guardian;
  next();
}

// ============================================
// ROTAS DE AUTENTICAÇÃO
// ============================================
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash('sha256').update(password || '').digest('hex');
  const guardian = db.prepare('SELECT * FROM guardians WHERE email = ? AND password = ?').get(email, hash);
  
  if (!guardian) return res.status(401).json({ error: 'Email ou senha inválidos' });
  
  res.json({ 
    id: guardian.id, 
    name: guardian.name, 
    email: guardian.email, 
    role: guardian.role,
    group: guardian.group_name 
  });
});

// ============================================
// ROTAS DE GUARDIÕES (Admin only)
// ============================================
app.get('/api/guardians', authenticate, (req, res) => {
  if (req.guardian.role !== 'admin') return res.status(403).json({ error: 'Apenas admin' });
  
  const guardians = db.prepare(`
    SELECT g.*, COUNT(DISTINCT p.id) as protected_count 
    FROM guardians g 
    LEFT JOIN protected_users p ON p.guardian_id = g.id 
    GROUP BY g.id
  `).all();
  
  res.json(guardians.map(g => ({ ...g, password: undefined })));
});

app.post('/api/guardians', authenticate, (req, res) => {
  if (req.guardian.role !== 'admin') return res.status(403).json({ error: 'Apenas admin' });
  
  const { name, email, group_name } = req.body;
  const password = crypto.randomBytes(4).toString('hex');
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  
  try {
    const result = db.prepare('INSERT INTO guardians (name, email, password, group_name) VALUES (?, ?, ?, ?)').run(name, email, hash, group_name);
    res.json({ id: result.lastInsertRowid, name, email, group_name, password, message: `Guardião criado! Senha: ${password}` });
  } catch(e) {
    res.status(400).json({ error: 'Email já cadastrado' });
  }
});

// ============================================
// ROTAS DE PROTEGIDOS
// ============================================
app.get('/api/protected', authenticate, (req, res) => {
  let users;
  if (req.guardian.role === 'admin') {
    users = db.prepare('SELECT * FROM protected_users').all();
  } else {
    users = db.prepare('SELECT * FROM protected_users WHERE guardian_id = ?').all(req.guardian.id);
  }
  
  const result = users.map(u => {
    const devices = db.prepare('SELECT * FROM devices WHERE protected_id = ?').all(u.id);
    return { ...u, devices };
  });
  
  res.json(result);
});

// ============================================
// ROTAS DE TOKENS (Links)
// ============================================
app.post('/api/tokens/generate', authenticate, (req, res) => {
  const { name, gender, device_type, type } = req.body;
  const token = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000).toISOString(); // 20 minutos
  
  db.prepare(`INSERT INTO tokens (token, type, guardian_id, protected_name, gender, device_type, expires_at) 
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(token, type || 'activation', req.guardian.id, name, gender, device_type, expiresAt);
  
  const baseUrl = req.headers.host || 'localhost:3000';
  const protocol = req.headers['x-forwarded-proto'] || 'http';
  let link;
  
  if (device_type === 'iphone') {
    link = `https://apple.nextdns.io`;
  } else if (device_type === 'android') {
    link = `${protocol}://${baseUrl}/setup/${token}`;
  } else {
    link = `${protocol}://${baseUrl}/setup/${token}`;
  }
  
  res.json({ token, link, expires_in: '20 minutos', device_type });
});

app.get('/api/tokens/:token/validate', (req, res) => {
  const tokenData = db.prepare('SELECT * FROM tokens WHERE token = ?').get(req.params.token);
  
  if (!tokenData) return res.status(404).json({ error: 'Token não encontrado' });
  if (tokenData.used) return res.status(400).json({ error: 'Token já utilizado' });
  if (new Date(tokenData.expires_at) < new Date()) return res.status(400).json({ error: 'Token expirado' });
  
  res.json({ valid: true, type: tokenData.type, gender: tokenData.gender, device_type: tokenData.device_type });
});

app.post('/api/tokens/:token/use', (req, res) => {
  const tokenData = db.prepare('SELECT * FROM tokens WHERE token = ?').get(req.params.token);
  
  if (!tokenData || tokenData.used || new Date(tokenData.expires_at) < new Date()) {
    return res.status(400).json({ error: 'Token inválido ou expirado' });
  }
  
  // Marca como usado
  db.prepare('UPDATE tokens SET used = 1 WHERE token = ?').run(req.params.token);
  
  if (tokenData.type === 'activation') {
    // Cria protegido e dispositivo
    const result = db.prepare('INSERT INTO protected_users (name, gender, guardian_id) VALUES (?, ?, ?)').run(
      tokenData.protected_name, tokenData.gender, tokenData.guardian_id
    );
    db.prepare('INSERT INTO devices (protected_id, type) VALUES (?, ?)').run(result.lastInsertRowid, tokenData.device_type);
    
    res.json({ success: true, message: 'Proteção ativada!' });
  } else {
    res.json({ success: true, message: 'Proteção desativada.' });
  }
});

// ============================================
// ROTA DE ESTATÍSTICAS
// ============================================
app.get('/api/stats', authenticate, (req, res) => {
  let stats;
  if (req.guardian.role === 'admin') {
    const users = db.prepare('SELECT COUNT(*) as count FROM protected_users').get();
    const devices = db.prepare('SELECT COUNT(*) as count FROM devices WHERE status = ?').get('active');
    const blocked = db.prepare('SELECT COALESCE(SUM(blocked_count),0) as total FROM devices').get();
    const guardians = db.prepare('SELECT COUNT(*) as count FROM guardians').get();
    stats = { users: users.count, devices: devices.count, blocked: blocked.total, guardians: guardians.count };
  } else {
    const users = db.prepare('SELECT COUNT(*) as count FROM protected_users WHERE guardian_id = ?').get(req.guardian.id);
    const deviceIds = db.prepare('SELECT d.* FROM devices d JOIN protected_users p ON d.protected_id = p.id WHERE p.guardian_id = ?').all(req.guardian.id);
    stats = { users: users.count, devices: deviceIds.length, blocked: deviceIds.reduce((s,d) => s + d.blocked_count, 0), guardians: 0 };
  }
  res.json(stats);
});

// ============================================
// PÁGINA DE SETUP (para links de instalação)
// ============================================
app.get('/setup/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

// ============================================
// PÁGINA PRINCIPAL (Painel do Guardião)
// ============================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// INICIAR SERVIDOR
// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛡️  Focus Shield Backend rodando!`);
  console.log(`📍 Acesse: http://localhost:${PORT}`);
  console.log(`🔑 Login admin: admin@focusshield.app / admin123\n`);
});
