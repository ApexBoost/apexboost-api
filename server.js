/**
 * ApexBoost License API
 * Servidor de validação de chaves de licença
 */

const express  = require('express')
const crypto   = require('crypto')
const path     = require('path')
const cors     = require('cors')
const Database = require('better-sqlite3')

const app  = express()
const PORT = process.env.PORT || 3000

// ── Configuração — altere antes do deploy ──────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'apexboost-admin-2025'
const API_SECRET   = process.env.API_SECRET   || 'apexboost-api-key-v3'
// ──────────────────────────────────────────────────────────

app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

// ── Banco de dados ─────────────────────────────────────────
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'licenses.db'))

db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key          TEXT    UNIQUE NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'unused',
    hardware_id  TEXT,
    activated_at TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    ip           TEXT,
    note         TEXT
  );

  CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT,
    action     TEXT,
    hardware_id TEXT,
    ip         TEXT,
    result     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`)

// ── Helpers ────────────────────────────────────────────────

function generateKey() {
  // Formato: APEX-XXXX-XXXX-XXXX-XXXX (letras maiúsculas + números, sem ambiguidade)
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const segment = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('')
  return `APEX-${segment()}-${segment()}-${segment()}-${segment()}`
}

function getHardwareFingerprint(hardwareId) {
  // Normaliza o hardware ID para comparação
  return crypto.createHash('sha256').update(hardwareId || '').digest('hex').slice(0, 32)
}

function logAction(key, action, hardwareId, ip, result) {
  try {
    db.prepare(`INSERT INTO logs (key, action, hardware_id, ip, result) VALUES (?,?,?,?,?)`)
      .run(key, action, hardwareId, ip, result)
  } catch {}
}

function checkAdminAuth(req) {
  const auth = req.headers['x-admin-secret'] || req.body?.adminSecret || req.query?.secret
  return auth === ADMIN_SECRET
}

function checkApiAuth(req) {
  const auth = req.headers['x-api-key'] || req.body?.apiKey
  return auth === API_SECRET
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || 'unknown'
}

// ── ROTAS PÚBLICAS (ApexBoost chama essas) ─────────────────

/**
 * POST /api/activate
 * Ativa uma chave pela primeira vez
 * Body: { key, hardwareId, apiKey }
 */
app.post('/api/activate', (req, res) => {
  if (!checkApiAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const { key, hardwareId } = req.body
  const ip = getClientIp(req)

  if (!key || !hardwareId) {
    return res.status(400).json({ success: false, error: 'missing_fields' })
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key)

  if (!license) {
    logAction(key, 'activate_failed', hardwareId, ip, 'key_not_found')
    return res.json({ success: false, error: 'key_not_found', message: 'Chave não encontrada.' })
  }

  if (license.status === 'activated') {
    logAction(key, 'activate_failed', hardwareId, ip, 'already_used')
    return res.json({ success: false, error: 'already_used', message: 'Esta chave já foi utilizada em outro computador.' })
  }

  if (license.status === 'revoked') {
    logAction(key, 'activate_failed', hardwareId, ip, 'revoked')
    return res.json({ success: false, error: 'revoked', message: 'Esta chave foi revogada.' })
  }

  const hwFingerprint = getHardwareFingerprint(hardwareId)

  db.prepare(`
    UPDATE licenses
    SET status = 'activated', hardware_id = ?, activated_at = datetime('now'), ip = ?
    WHERE key = ?
  `).run(hwFingerprint, ip, key)

  logAction(key, 'activated', hwFingerprint, ip, 'success')

  return res.json({
    success: true,
    message: 'ApexBoost ativado com sucesso!',
    activatedAt: new Date().toISOString()
  })
})

/**
 * POST /api/validate
 * Valida uma chave já ativada (chamada a cada abertura do app)
 * Body: { key, hardwareId, apiKey }
 */
app.post('/api/validate', (req, res) => {
  if (!checkApiAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const { key, hardwareId } = req.body
  const ip = getClientIp(req)

  if (!key || !hardwareId) {
    return res.status(400).json({ success: false, error: 'missing_fields' })
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key)

  if (!license) {
    logAction(key, 'validate_failed', hardwareId, ip, 'not_found')
    return res.json({ success: false, error: 'key_not_found' })
  }

  if (license.status !== 'activated') {
    logAction(key, 'validate_failed', hardwareId, ip, `status_${license.status}`)
    return res.json({ success: false, error: `status_${license.status}` })
  }

  const hwFingerprint = getHardwareFingerprint(hardwareId)

  if (license.hardware_id !== hwFingerprint) {
    logAction(key, 'validate_failed', hwFingerprint, ip, 'hardware_mismatch')
    return res.json({ success: false, error: 'hardware_mismatch', message: 'Esta chave está registrada em outro computador.' })
  }

  logAction(key, 'validated', hwFingerprint, ip, 'success')
  return res.json({ success: true, activatedAt: license.activated_at })
})

// ── ROTAS ADMIN (só você acessa) ───────────────────────────

/**
 * POST /admin/generate
 * Gera uma nova chave de licença
 */
app.post('/admin/generate', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const { note, quantity = 1 } = req.body
  const qty = Math.min(parseInt(quantity) || 1, 100) // máx 100 por vez

  const keys = []
  for (let i = 0; i < qty; i++) {
    let key, attempts = 0
    do {
      key = generateKey()
      attempts++
    } while (db.prepare('SELECT id FROM licenses WHERE key = ?').get(key) && attempts < 10)

    db.prepare('INSERT INTO licenses (key, note) VALUES (?, ?)').run(key, note || '')
    keys.push(key)
  }

  return res.json({ success: true, keys, quantity: keys.length })
})

/**
 * GET /admin/keys
 * Lista todas as chaves com filtros opcionais
 */
app.get('/admin/keys', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const { status, limit = 100, offset = 0 } = req.query
  let query = 'SELECT * FROM licenses'
  const params = []

  if (status) {
    query += ' WHERE status = ?'
    params.push(status)
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
  params.push(parseInt(limit), parseInt(offset))

  const keys  = db.prepare(query).all(...params)
  const stats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status='unused' THEN 1 ELSE 0 END) as unused,
      SUM(CASE WHEN status='activated' THEN 1 ELSE 0 END) as activated,
      SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) as revoked
    FROM licenses
  `).get()

  return res.json({ success: true, keys, stats })
})

/**
 * POST /admin/revoke
 * Revoga uma chave (impede uso mesmo se já ativada)
 */
app.post('/admin/revoke', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const { key } = req.body
  if (!key) return res.status(400).json({ success: false, error: 'missing_key' })

  const result = db.prepare("UPDATE licenses SET status = 'revoked' WHERE key = ?").run(key)

  if (result.changes === 0) {
    return res.json({ success: false, error: 'key_not_found' })
  }

  return res.json({ success: true, message: `Chave ${key} revogada.` })
})

/**
 * POST /admin/reset
 * Reseta uma chave para 'unused' (permite reativação — use em casos de formatação com reembolso)
 */
app.post('/admin/reset', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const { key } = req.body
  if (!key) return res.status(400).json({ success: false, error: 'missing_key' })

  db.prepare("UPDATE licenses SET status='unused', hardware_id=NULL, activated_at=NULL, ip=NULL WHERE key=?").run(key)

  return res.json({ success: true, message: `Chave ${key} resetada. Pode ser ativada novamente.` })
})

/**
 * GET /admin/logs
 * Histórico de ativações e validações
 */
app.get('/admin/logs', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ success: false, error: 'unauthorized' })
  }

  const logs = db.prepare('SELECT * FROM logs ORDER BY created_at DESC LIMIT 200').all()
  return res.json({ success: true, logs })
})

// Painel admin (HTML)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'))
})

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', version: '1.0.0' }))

app.listen(PORT, () => {
  console.log(`ApexBoost License API rodando na porta ${PORT}`)
  console.log(`Admin: http://localhost:${PORT}/admin`)
})
