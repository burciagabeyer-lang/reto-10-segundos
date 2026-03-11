const crypto = require('crypto');
const { kv } = require('@vercel/kv');

// ─── Configuración ───────────────────────────────────────────────
const SECRET = process.env.SESSION_SECRET || 'dev-secret-cambiar-en-produccion-x9k2m';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin2024';
const TARGET_MS = 10000;
const TOLERANCE_MS = 50; // Dificultad aumentada a 50ms como pediste
const MAX_AUDIT_ENTRIES = 500;

// ─── Utilidades ──────────────────────────────────────────────────
function signPayload(data) {
  const json = JSON.stringify(data);
  const sig = crypto.createHmac('sha256', SECRET).update(json).digest('hex');
  return Buffer.from(json).toString('base64url') + '.' + sig;
}

function verifyPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [b64, sig] = parts;
    const json = Buffer.from(b64, 'base64url').toString();
    const expected = crypto.createHmac('sha256', SECRET).update(json).digest('hex');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    return JSON.parse(json);
  } catch { return null; }
}

function getIP(req) {
  try {
    let ip = req.headers['x-forwarded-for'];
    if (Array.isArray(ip)) return ip.trim();
    if (typeof ip === 'string') return ip.split(',').trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'desconocido';
  } catch (e) { return 'desconocido'; }
}

// NUEVA FUNCIÓN: Generador de claves aleatorias
function generateRandomKey(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// ─── Main Handler ───────────────────────────────────────────────
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  
  const action = req.query.action;
  const ip = getIP(req);

  try {
    switch (action) {
      case 'start':  return await handleStart(req, res, ip);
      case 'stop':   return await handleStop(req, res, ip);
      case 'ping':   return res.status(200).json({ ok: true });
      case 'audit':  return await handleAudit(req, res);
      case 'gen':    return await handleGenerateKeys(req, res); // Nueva acción
      default:       return res.status(400).json({ error: 'Acción no válida' });
    }
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
};

async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  
  // Bloqueo por IP (Fase 2 de seguridad)
  const attemptsKey = `attempts:${ip}`;
  const fails = await kv.get(attemptsKey) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'IP Bloqueada por seguridad (1h).' });

  if (!key) return res.status(400).json({ error: 'Clave requerida.' });

  // Verificar si la clave existe y NO ha sido usada
  const exists = await kv.sismember('valid_keys', key);
  const used = await kv.sismember('used_keys', key);

  if (!exists || used) {
    await kv.set(attemptsKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave inválida o ya utilizada.' });
  }

  // Quemar clave
  await kv.sadd('used_keys', key);
  await kv.srem('valid_keys', key); // Opcional: quitarla de válidas para limpiar

  const token = signPayload({ sid: crypto.randomUUID(), st: Date.now(), ip, key });
  return res.status(200).json({ token, serverTime: Date.now() });
}

async function handleStop(req, res, ip) {
  const { token, isTrusted, clientElapsed } = req.body || {};
  const session = verifyPayload(token);
  if (!session) return res.status(403).json({ error: 'Sesión inválida.' });

  const serverElapsed = Date.now() - session.st;
  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWinner = diff <= TOLERANCE_MS && isTrusted !== false;
  const status = (isTrusted === false || Math.abs(serverElapsed - clientElapsed) > 400) ? 'SOSPECHOSO' : (isWinner ? 'PENDIENTE_REVISION' : 'LIMPIO');

  const entry = {
    playerKey: session.key, ip: session.ip, serverElapsed, diff, isWinner, status,
    timestamp: new Date().toISOString()
  };

  await kv.lpush('auditLog', entry);
  await kv.ltrim('auditLog', 0, MAX_AUDIT_ENTRIES - 1);

  return res.status(200).json({ serverElapsed, diff, isWinner, status });
}

// NUEVA FUNCIÓN: Maneja la generación de claves desde Admin
async function handleGenerateKeys(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'Acceso denegado.' });
  
  const count = parseInt(req.query.count) || 10;
  if (count > 1000) return res.status(400).json({ error: 'Máximo 1000 claves.' });

  const newKeys = [];
  for (let i = 0; i < count; i++) {
    newKeys.push(generateRandomKey());
  }

  // Guardar en la base de datos Redis
  await kv.sadd('valid_keys', ...newKeys);

  return res.status(200).json({ 
    message: `Se generaron ${count} claves con éxito.`,
    keys: newKeys 
  });
}

async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'Acceso denegado.' });
  const entries = await kv.lrange('auditLog', 0, -1);
  return res.status(200).json({ entries: entries || [] });
}
