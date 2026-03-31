const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const MP_TOKEN = process.env.MP_ACCESS_TOKEN || '';

// ─── CONEXÃO POSTGRESQL ───────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // obrigatório no Neon.tech
});

// ─── BANCO DE DADOS: CRIAR TABELAS ────────────────────────────────────────────
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
      setup_token TEXT UNIQUE NOT NULL,
      nextdns_id TEXT,
      active INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      guardian_id INTEGER,
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
  `);

  console.log('✅ Tabelas verificadas/criadas');
}

// ─── CRIAR ADMIN AUTOMATICAMENTE ─────────────────────────────────────────────
async function initAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@focusshield.app';
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail]);

  if (rows.length === 0) {
    await pool.query(
      'INSERT INTO users (email, password, role) VALUES ($1, $2, $3)',
      [adminEmail, adminPassword, 'admin']
    );
    console.log('✅ Admin criado:', adminEmail);
  } else {
    console.log('✅ Admin já existe:', adminEmail);
  }
}

// ─── INICIAR BANCO E SERVIDOR ─────────────────────────────────────────────────
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

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    const user = rows[0];
    res.json({
      success: true,
      role: user.role,
      email: user.email,
      token: Buffer.from(`${email}:${password}`).toString('base64')
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── VERIFICAR TOKEN ──────────────────────────────────────────────────────────
app.get('/api/me', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Não autenticado' });

  try {
    const decoded = Buffer.from(auth, 'base64').toString('utf8');
    const [email, password] = decoded.split(':');
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (rows.length === 0) return res.status(401).json({ error: 'Token inválido' });
    res.json({ email: rows[0].email, role: rows[0].role });
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ─── ADMIN: CRIAR GUARDIÃO GRATUITO ──────────────────────────────────────────
app.post('/api/admin/create-guardian', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Não autorizado' });
  }

  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });

  const token = crypto.randomBytes(16).toString('hex');

  try {
    const { rows } = await pool.query(
      'INSERT INTO guardians (name, email, token, paid) VALUES ($1, $2, $3, 1) RETURNING id',
      [name, email, token]
    );
    const guardianId = rows[0].id;

    const setupToken = crypto.randomBytes(16).toString('hex');
    await pool.query(
      'INSERT INTO children (guardian_id, name, setup_token) VALUES ($1, $2, $3)',
      [guardianId, 'Filho', setupToken]
    );

    res.json({
      success: true,
      guardianToken: token,
      setupLink: `${req.protocol}://${req.get('host')}/setup.html?token=${setupToken}`,
      message: 'Guardião gratuito criado (admin)'
    });
  } catch (err) {
    if (err.message.includes('unique') || err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ─── ADMIN: LISTAR GUARDIÕES ──────────────────────────────────────────────────
app.get('/api/admin/guardians', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Não autorizado' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, name, email, paid, payment_id, created_at FROM guardians ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── ADMIN: LISTAR PAGAMENTOS ─────────────────────────────────────────────────
app.get('/api/admin/payments', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Não autorizado' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT p.*, g.name as guardian_name, g.email
      FROM payments p
      JOIN guardians g ON g.id = p.guardian_id
      ORDER BY p.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── CRIAR PAGAMENTO PIX ─────────────────────────────────────────────────────
app.post('/api/create-payment', async (req, res) => {
  const { guardianName, childName, email } = req.body;

  if (!guardianName || !childName || !email) {
    return res.status(400).json({ error: 'guardianName, childName e email são obrigatórios' });
  }

  try {
    const token = crypto.randomBytes(16).toString('hex');
    let guardianId;

    const { rows: existing } = await pool.query(
      'SELECT id FROM guardians WHERE email = $1',
      [email]
    );

    if (existing.length > 0) {
      guardianId = existing[0].id;
    } else {
      const { rows } = await pool.query(
        'INSERT INTO guardians (name, email, token, paid) VALUES ($1, $2, $3, 0) RETURNING id',
        [guardianName, email, token]
      );
      guardianId = rows[0].id;
    }

    const idempotencyKey = crypto.randomBytes(16).toString('hex');

    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${MP_TOKEN}`,
        'Content-Type': 'application/json',
        'X-Idempotency-Key': idempotencyKey
      },
      body: JSON.stringify({
        transaction_amount: 29.90,
        description: `Focus Shield — Proteção Digital para ${childName}`,
        payment_method_id: 'pix',
        payer: { email: email, first_name: guardianName },
        metadata: { guardian_id: guardianId, child_name: childName }
      })
    });

    const mpData = await mpResponse.json();

    if (!mpResponse.ok) {
      console.error('Erro MP:', JSON.stringify(mpData));
      return res.status(500).json({ error: 'Erro ao criar pagamento', details: mpData });
    }

    await pool.query(
      'INSERT INTO payments (guardian_id, mp_payment_id, status, amount) VALUES ($1, $2, $3, 29.90) ON CONFLICT (mp_payment_id) DO NOTHING',
      [guardianId, String(mpData.id), mpData.status]
    );

    const qrData = mpData.point_of_interaction?.transaction_data;

    res.json({
      success: true,
      payment_id: mpData.id,
      status: mpData.status,
      qr_code: qrData?.qr_code,
      qr_code_base64: qrData?.qr_code_base64,
      expires_at: qrData?.ticket_url,
      guardian_id: guardianId
    });

  } catch (err) {
    console.error('Erro create-payment:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── VERIFICAR STATUS DO PAGAMENTO ───────────────────────────────────────────
app.get('/api/payment-status/:paymentId', async (req, res) => {
  const { paymentId } = req.params;

  try {
    const mpResponse = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
      headers: { 'Authorization': `Bearer ${MP_TOKEN}` }
    });

    const mpData = await mpResponse.json();

    if (mpData.status === 'approved') {
      const { rows } = await pool.query(
        'SELECT * FROM payments WHERE mp_payment_id = $1',
        [String(paymentId)]
      );
      if (rows.length > 0) {
        await pool.query(
          'UPDATE payments SET status = $1, paid_at = NOW() WHERE mp_payment_id = $2',
          ['approved', String(paymentId)]
        );
        await pool.query(
          'UPDATE guardians SET paid = 1, payment_id = $1 WHERE id = $2',
          [String(paymentId), rows[0].guardian_id]
        );
      }
    }

    res.json({ status: mpData.status, payment_id: paymentId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── WEBHOOK MERCADO PAGO ─────────────────────────────────────────────────────
app.post('/api/webhook/mercadopago', async (req, res) => {
  const { type, data } = req.body;

  res.sendStatus(200); // MP exige resposta rápida

  if (type !== 'payment' || !data?.id) return;

  try {
    const mpResponse = await fetch(`https://api.mercadopago.com/v1/payments/${data.id}`, {
      headers: { 'Authorization': `Bearer ${MP_TOKEN}` }
    });

    const mpData = await mpResponse.json();

    if (mpData.status === 'approved') {
      const { rows } = await pool.query(
        'SELECT * FROM payments WHERE mp_payment_id = $1',
        [String(data.id)]
      );

      if (rows.length > 0) {
        const payment = rows[0];

        await pool.query(
          'UPDATE payments SET status = $1, paid_at = NOW() WHERE mp_payment_id = $2',
          ['approved', String(data.id)]
        );
        await pool.query(
          'UPDATE guardians SET paid = 1, payment_id = $1 WHERE id = $2',
          [String(data.id), payment.guardian_id]
        );

        const { rows: existingChild } = await pool.query(
          'SELECT id FROM children WHERE guardian_id = $1',
          [payment.guardian_id]
        );

        if (existingChild.length === 0) {
          const setupToken = crypto.randomBytes(16).toString('hex');
          await pool.query(
            'INSERT INTO children (guardian_id, name, setup_token) VALUES ($1, $2, $3)',
            [payment.guardian_id, 'Filho', setupToken]
          );
        }

        console.log(`✅ Pagamento aprovado para guardião ID ${payment.guardian_id}`);
      }
    }
  } catch (err) {
    console.error('Erro webhook:', err);
  }
});

// ─── VERIFICAR SE GUARDIÃO ESTÁ PAGO ─────────────────────────────────────────
app.get('/api/guardian-status/:guardianId', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, name, paid FROM guardians WHERE id = $1',
      [req.params.guardianId]
    );

    if (rows.length === 0) return res.status(404).json({ error: 'Guardião não encontrado' });

    const guardian = rows[0];

    if (guardian.paid) {
      const { rows: childRows } = await pool.query(
        'SELECT setup_token FROM children WHERE guardian_id = $1',
        [guardian.id]
      );
      res.json({
        paid: true,
        setupLink: childRows.length > 0 ? `/setup.html?token=${childRows[0].setup_token}` : null
      });
    } else {
      res.json({ paid: false });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── SETUP: VALIDAR TOKEN DO FILHO ───────────────────────────────────────────
app.get('/api/validate-setup/:token', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, g.name as guardian_name, g.paid
      FROM children c
      JOIN guardians g ON g.id = c.guardian_id
      WHERE c.setup_token = $1
    `, [req.params.token]);

    if (rows.length === 0) return res.status(404).json({ error: 'Token inválido' });
    const child = rows[0];
    if (!child.paid) return res.status(403).json({ error: 'Pagamento pendente' });

    res.json({
      valid: true,
      childName: child.name,
      guardianName: child.guardian_name,
      active: child.active
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── SETUP: SALVAR NEXTDNS ────────────────────────────────────────────────────
app.post('/api/setup-complete', async (req, res) => {
  const { token, nextdnsId } = req.body;

  try {
    const { rows } = await pool.query(
      'SELECT * FROM children WHERE setup_token = $1',
      [token]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Token inválido' });

    await pool.query(
      'UPDATE children SET nextdns_id = $1, active = 1 WHERE setup_token = $2',
      [nextdnsId, token]
    );

    res.json({ success: true, message: 'Configuração concluída!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── INICIAR ──────────────────────────────────────────────────────────────────
start();
