const crypto = require('crypto');
const { kv } = require('@vercel/kv');

const SECRET = process.env.SESSION_SECRET || 'clave-secreta-ultra-larga-y-aleatoria-2026';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin2024';
const TARGET_MS = 10000;
const TOLERANCE_MS = 50; 
const MAX_AUDIT_ENTRIES = 500;

function getIP(req) {
  try {
    let ip = req.headers['x-forwarded-for'];
    if (Array.isArray(ip)) return ip.trim();
    if (typeof ip === 'string') return ip.split(',').trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'desconocido';
  } catch (e) { return 'desconocido'; }
}

module.exports = async (req, res) => {
  // Seguridad de Origen: Solo permite peticiones de tu dominio
  const origin = req.headers.origin || req.headers.referer || '';
  const myDomain = 'reto-10-segundos.vercel.app'; // <--- ASEGÚRATE QUE SEA TU DOMINIO REAL
  
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const ip = getIP(req);
  const banKey = `banned:${ip}`;

  // Verificar Baneo
  if (await kv.get(banKey)) return res.status(403).json({ error: 'Acceso denegado.' });

  // Bloqueo de Referer (Si no viene de tu web, banea)
  if (origin && !origin.includes(myDomain) && !origin.includes('localhost')) {
    await kv.set(banKey, true, { ex: 86400 }); 
    return res.status(403).json({ error: 'Origen no autorizado.' });
  }

  // Rate Limit Estricto
  const requests = await kv.incr(`rate:${ip}`);
  if (requests === 1) await kv.expire(`rate:${ip}`, 60);
  if (requests > 25) return res.status(429).json({ error: 'Demasiadas peticiones.' });

  try {
    switch (action) {
      case 'start': return await handleStart(req, res, ip);
      case 'stop': return await handleStop(req, res, ip);
      case 'ping': return res.status(200).json({ ok: true });
      case 'audit': return await handleAudit(req, res);
      case 'gen': return await handleGenerateKeys(req, res);
      default: 
        // Si intentan acciones raras, baneo por Honeypot
        await kv.set(banKey, true, { ex: 86400 });
        return res.status(403).json({ error: 'IP Bloqueada.' });
    }
  } catch (e) { return res.status(500).json({ error: 'Error' }); }
};

async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  const attKey = `att:${ip}`;
  const fails = await kv.get(attKey) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'IP bloqueada por 1h.' });

  const exists = await kv.sismember('valid_keys', key);
  if (!exists) {
    await kv.set(attKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave no valida.' });
  }

  await kv.srem('valid_keys', key);
  const sid = crypto.randomUUID();
  const st = Date.now();
  const payload = JSON.stringify({ sid, st, ip, key });
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  const token = Buffer.from(payload).toString('base64url') + '.' + sig;
  
  return res.status(200).json({ token, serverTime: st });
}

async function handleStop(req, res, ip) {
  const { token, isTrusted, clientElapsed } = req.body || {};
  const parts = token ? token.split('.') : [];
  if (parts.length !== 2) return res.status(403).json({ error: 'Token corrupto.' });

  const payloadStr = Buffer.from(parts, 'base64url').toString();
  const expectedSig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('hex');
  if (parts !== expectedSig) return res.status(403).json({ error: 'Firma invalida.' });

  const session = JSON.parse(payloadStr);
  const now = Date.now();
  const serverElapsed = now - session.st;

  // REGLA: Expiración de sesión (15 segundos máximo)
  if (serverElapsed > 15000) return res.status(403).json({ error: 'Sesion expirada.' });
  
  // REGLA: Cooldown mínimo (Un humano no tarda menos de 2s en reaccionar)
  if (serverElapsed < 2000) return res.status(403).json({ error: 'Intento demasiado rapido.' });

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
