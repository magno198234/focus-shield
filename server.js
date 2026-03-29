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

// ─── BANCO DE DADOS ───────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS guardians (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    token TEXT UNIQUE NOT NULL,
    paid INTEGER DEFAULT 0,
    payment_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS children (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guardian_id INTEGER,
    name TEXT NOT NULL,
    setup_token TEXT UNIQUE NOT NULL,
    nextdns_id TEXT,
    active INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guardian_id) REFERENCES guardians(id)
  );

  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guardian_id INTEGER,
    mp_payment_id TEXT UNIQUE,
    status TEXT DEFAULT 'pending',
    amount REAL DEFAULT 29.90,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    paid_at DATETIME
  );
`);

// ─── ADMIN: CRIAR GUARDIÃO GRATUITO ──────────────────────────────────────────
app.post('/api/admin/create-guardian', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Não autorizado' });
  }

  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });

  const token = crypto.randomBytes(16).toString('hex');

  try {
    const stmt = db.prepare(`
      INSERT INTO guardians (name, email, token, paid)
      VALUES (?, ?, ?, 1)
    `);
    const result = stmt.run(name, email, token);
    const guardianId = result.lastInsertRowid;

    const setupToken = crypto.randomBytes(16).toString('hex');
    db.prepare(`INSERT INTO children (guardian_id, name, setup_token) VALUES (?, ?, ?)`).run(guardianId, 'Filho', setupToken);

    res.json({
      success: true,
      guardianToken: token,
      setupLink: `${req.protocol}://${req.get('host')}/setup.html?token=${setupToken}`,
      message: 'Guardião gratuito criado (admin)'
    });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email já cadastrado' });
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
    // Criar guardião pendente (paid=0) antes do pagamento
    const token = crypto.randomBytes(16).toString('hex');
    let guardianId;

    const existing = db.prepare('SELECT id FROM guardians WHERE email = ?').get(email);
    if (existing) {
      guardianId = existing.id;
    } else {
      const result = db.prepare(`
        INSERT INTO guardians (name, email, token, paid) VALUES (?, ?, ?, 0)
      `).run(guardianName, email, token);
      guardianId = result.lastInsertRowid;
    }

    // Chamar API Mercado Pago
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
        payer: {
          email: email,
          first_name: guardianName
        },
        metadata: {
          guardian_id: guardianId,
          child_name: childName
        }
      })
    });

    const mpData = await mpResponse.json();

    if (!mpResponse.ok) {
      console.error('Erro MP:', JSON.stringify(mpData));
      return res.status(500).json({ error: 'Erro ao criar pagamento', details: mpData });
    }

    // Salvar pagamento no banco
    db.prepare(`
      INSERT OR IGNORE INTO payments (guardian_id, mp_payment_id, status, amount)
      VALUES (?, ?, ?, 29.90)
    `).run(guardianId, String(mpData.id), mpData.status);

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

    // Atualizar banco se aprovado
    if (mpData.status === 'approved') {
      const payment = db.prepare('SELECT * FROM payments WHERE mp_payment_id = ?').get(String(paymentId));
      if (payment) {
        db.prepare('UPDATE payments SET status = ?, paid_at = CURRENT_TIMESTAMP WHERE mp_payment_id = ?')
          .run('approved', String(paymentId));
        db.prepare('UPDATE guardians SET paid = 1, payment_id = ? WHERE id = ?')
          .run(String(paymentId), payment.guardian_id);
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

  // Responder 200 imediatamente (MP exige resposta rápida)
  res.sendStatus(200);

  if (type !== 'payment' || !data?.id) return;

  try {
    const mpResponse = await fetch(`https://api.mercadopago.com/v1/payments/${data.id}`, {
      headers: { 'Authorization': `Bearer ${MP_TOKEN}` }
    });

    const mpData = await mpResponse.json();

    if (mpData.status === 'approved') {
      const payment = db.prepare('SELECT * FROM payments WHERE mp_payment_id = ?').get(String(data.id));

      if (payment) {
        db.prepare('UPDATE payments SET status = ?, paid_at = CURRENT_TIMESTAMP WHERE mp_payment_id = ?')
          .run('approved', String(data.id));

        const guardian = db.prepare('UPDATE guardians SET paid = 1, payment_id = ? WHERE id = ?')
          .run(String(data.id), payment.guardian_id);

        // Criar setup token para o filho
        const setupToken = crypto.randomBytes(16).toString('hex');
        const existingChild = db.prepare('SELECT id FROM children WHERE guardian_id = ?').get(payment.guardian_id);

        if (!existingChild) {
          db.prepare('INSERT INTO children (guardian_id, name, setup_token) VALUES (?, ?, ?)')
            .run(payment.guardian_id, 'Filho', setupToken);
        }

        console.log(`✅ Pagamento aprovado para guardião ID ${payment.guardian_id}`);
      }
    }
  } catch (err) {
    console.error('Erro webhook:', err);
  }
});

// ─── VERIFICAR SE GUARDIÃO ESTÁ PAGO (para liberar setup) ───────────────────
app.get('/api/guardian-status/:guardianId', (req, res) => {
  const guardian = db.prepare('SELECT id, name, paid FROM guardians WHERE id = ?').get(req.params.guardianId);

  if (!guardian) return res.status(404).json({ error: 'Guardião não encontrado' });

  if (guardian.paid) {
    const child = db.prepare('SELECT setup_token FROM children WHERE guardian_id = ?').get(guardian.id);
    res.json({
      paid: true,
      setupLink: child ? `/setup.html?token=${child.setup_token}` : null
    });
  } else {
    res.json({ paid: false });
  }
});

// ─── ADMIN: LISTAR PAGAMENTOS ─────────────────────────────────────────────────
app.get('/api/admin/payments', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Não autorizado' });
  }

  const payments = db.prepare(`
    SELECT p.*, g.name as guardian_name, g.email
    FROM payments p
    JOIN guardians g ON g.id = p.guardian_id
    ORDER BY p.created_at DESC
  `).all();

  res.json(payments);
});

// ─── SETUP: VALIDAR TOKEN DO FILHO ───────────────────────────────────────────
app.get('/api/validate-setup/:token', (req, res) => {
  const child = db.prepare(`
    SELECT c.*, g.name as guardian_name, g.paid
    FROM children c
    JOIN guardians g ON g.id = c.guardian_id
    WHERE c.setup_token = ?
  `).get(req.params.token);

  if (!child) return res.status(404).json({ error: 'Token inválido' });
  if (!child.paid) return res.status(403).json({ error: 'Pagamento pendente' });

  res.json({
    valid: true,
    childName: child.name,
    guardianName: child.guardian_name,
    active: child.active
  });
});

// ─── SETUP: SALVAR NEXTDNS ────────────────────────────────────────────────────
app.post('/api/setup-complete', (req, res) => {
  const { token, nextdnsId } = req.body;

  const child = db.prepare('SELECT * FROM children WHERE setup_token = ?').get(token);
  if (!child) return res.status(404).json({ error: 'Token inválido' });

  db.prepare('UPDATE children SET nextdns_id = ?, active = 1 WHERE setup_token = ?')
    .run(nextdnsId, token);

  res.json({ success: true, message: 'Configuração concluída!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🛡️ Focus Shield rodando na porta ${PORT}`));
