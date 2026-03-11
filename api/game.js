const crypto = require('crypto');
const { kv } = require('@vercel/kv');

const SECRET = process.env.SESSION_SECRET || 'dev-secret-123';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin2024';
const TARGET_MS = 10000;
const TOLERANCE_MS = 50; 
const MAX_AUDIT_ENTRIES = 500;

// IP Helpers
function getIP(req) {
  try {
    let ip = req.headers['x-forwarded-for'];
    if (Array.isArray(ip)) return ip.trim();
    if (typeof ip === 'string') return ip.split(',').trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'desconocido';
  } catch (e) { return 'desconocido'; }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const ip = getIP(req);
  const banKey = `banned:${ip}`;

  // 1. Verificar si la IP está baneada
  const isBanned = await kv.get(banKey);
  if (isBanned) return res.status(403).json({ error: 'Acceso denegado por actividad sospechosa.' });

  // 2. TRAMPA PARA HACKERS (Honeypot)
  // Si intentan acciones que no existen, baneamos de inmediato
  const validActions = ['start', 'stop', 'ping', 'audit', 'gen'];
  if (action && !validActions.includes(action)) {
    await kv.set(banKey, true, { ex: 86400 }); // Baneo de 24 horas
    return res.status(403).json({ error: 'IP Bloqueada.' });
  }

  // 3. RATE LIMIT (Límite de velocidad)
  const rateKey = `rate:${ip}`;
  const requests = await kv.incr(rateKey);
  if (requests === 1) await kv.expire(rateKey, 60); // Reset cada minuto
  if (requests > 20) return res.status(429).json({ error: 'Demasiadas peticiones. Calma.' });

  try {
    switch (action) {
      case 'start': return await handleStart(req, res, ip);
      case 'stop': return await handleStop(req, res, ip);
      case 'ping': return res.status(200).json({ ok: true });
      case 'audit': return await handleAudit(req, res);
      case 'gen': return await handleGenerateKeys(req, res);
      default: return res.status(400).json({ error: 'Accion no valida' });
    }
  } catch (e) { return res.status(500).json({ error: 'Error interno' }); }
};

// ... (Las funciones handleStart, handleStop, handleGenerateKeys y handleAudit se mantienen igual que la versión anterior)
// Asegúrate de incluir handleStart con el baneo de 1h por 5 intentos fallidos que pusimos antes.
async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  const attKey = `att:${ip}`;
  const fails = await kv.get(attKey) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'IP Bloqueada temporalmente por fallos.' });

  const exists = await kv.sismember('valid_keys', key);
  if (!exists) {
    await kv.set(attKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave invalida.' });
  }

  await kv.srem('valid_keys', key);
  const sig = crypto.createHmac('sha256', SECRET).update(JSON.stringify({sid:ip, st:Date.now()})).digest('hex');
  const token = Buffer.from(JSON.stringify({sid:crypto.randomUUID(), st:Date.now(), ip, key})).toString('base64url') + '.' + sig;
  return res.status(200).json({ token, serverTime: Date.now() });
}

async function handleStop(req, res, ip) {
  const { token, isTrusted, clientElapsed } = req.body || {};
  const parts = token ? token.split('.') : [];
  if (parts.length !== 2) return res.status(403).json({ error: 'Sesion invalida' });
  
  const session = JSON.parse(Buffer.from(parts, 'base64url').toString());
  const serverElapsed = Date.now() - session.st;
  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWinner = diff <= TOLERANCE_MS && isTrusted === true;
  const status = (isTrusted === false || Math.abs(serverElapsed - clientElapsed) > 400) ? 'SOSPECHOSO' : (isWinner ? 'PENDIENTE_REVISION' : 'LIMPIO');

  await kv.lpush('auditLog', { playerKey: session.key, ip: session.ip, serverElapsed, diff, isWinner, status, timestamp: new Date().toISOString() });
  await kv.ltrim('auditLog', 0, MAX_AUDIT_ENTRIES - 1);
  return res.status(200).json({ serverElapsed, diff, isWinner, status });
}

async function handleGenerateKeys(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado' });
  const count = Math.min(parseInt(req.query.count) || 10, 1000);
  const keys = Array.from({length: count}, () => Math.random().toString(36).substring(2, 12));
  await kv.sadd('valid_keys', ...keys);
  return res.status(200).json({ keys });
}

async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado' });
  const entries = await kv.lrange('auditLog', 0, -1);
  return res.status(200).json({ entries: entries || [] });
}
