const crypto = require('crypto');
const { kv } = require('@vercel/kv');

// Variables de entorno (Configuradas en el panel de Vercel)
const SECRET = process.env.SESSION_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;

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
  // --- SEGURIDAD DE ORIGEN ESTRICTA ---
  const origin = req.headers.origin || req.headers.referer || '';
  const myDomain = 'reto-10-segundos.vercel.app';
  
  // Solo permitimos nuestro dominio oficial
  res.setHeader('Access-Control-Allow-Origin', origin.includes(myDomain) ? origin : `https://${myDomain}`);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const ip = getIP(req);
  const banKey = `banned:${ip}`;

  try {
    // 1. Verificar Baneo Permanente
    const isBanned = await kv.get(banKey);
    if (isBanned) return res.status(403).json({ error: 'IP Bloqueada.' });

    // 2. Validar Origen (Si no es nuestro dominio, baneo inmediato)
    if (origin && !origin.includes(myDomain) && !origin.includes('localhost')) {
      await kv.set(banKey, true, { ex: 86400 }); // Baneo 24h
      return res.status(403).json({ error: 'Acceso no autorizado.' });
    }

    // 3. Rate Limit (Máximo 25 peticiones por minuto por IP)
    const rateKey = `rate:${ip}`;
    const requests = await kv.incr(rateKey);
    if (requests === 1) await kv.expire(rateKey, 60);
    if (requests > 25) return res.status(429).json({ error: 'Demasiadas peticiones.' });

    // 4. Router de Acciones
    switch (action) {
      case 'start': return await handleStart(req, res, ip);
      case 'stop': return await handleStop(req, res, ip);
      case 'ping': return res.status(200).json({ ok: true });
      case 'audit': return await handleAudit(req, res);
      case 'gen': return await handleGenerateKeys(req, res);
      default: 
        // Honeypot: Acción desconocida = Intento de hackeo
        await kv.set(banKey, true, { ex: 86400 });
        return res.status(403).json({ error: 'Acción inválida.' });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Error de servidor.' });
  }
};

async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  const attKey = `att:${ip}`;
  
  // Límite de intentos de clave (5 fallos = 1h bloqueo)
  const fails = await kv.get(attKey) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'Demasiados intentos. Espera 1h.' });

  if (!key) return res.status(400).json({ error: 'Clave requerida.' });

  const exists = await kv.sismember('valid_keys', key);
  if (!exists) {
    await kv.set(attKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave inválida o usada.' });
  }

  // Quemamos la clave para que sea de un solo uso
  await kv.srem('valid_keys', key);

  const payload = JSON.stringify({ sid: crypto.randomUUID(), st: Date.now(), ip, key });
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  const token = Buffer.from(payload).toString('base64url') + '.' + sig;
  
  return res.status(200).json({ token, serverTime: Date.now() });
}

async function handleStop(req, res, ip) {
  const { token, isTrusted, clientElapsed } = req.body || {};
  const parts = token ? token.split('.') : [];
  if (parts.length !== 2) return res.status(403).json({ error: 'Sesión inválida.' });

  const payloadStr = Buffer.from(parts, 'base64url').toString();
  const expectedSig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('hex');
  
  if (parts !== expectedSig) return res.status(403).json({ error: 'Firma corrupta.' });

  const session = JSON.parse(payloadStr);
  const serverElapsed = Date.now() - session.st;

  // Filtros de seguridad temporal
  if (serverElapsed > 15000) return res.status(403).json({ error: 'Tiempo agotado.' });
  if (serverElapsed < 2000) return res.status(403).json({ error: 'Intento no humano.' });

  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWinner = diff <= TOLERANCE_MS && isTrusted === true;
  
  const status = (isTrusted === false || Math.abs(serverElapsed - clientElapsed) > 400) ? 'SOSPECHOSO' : (isWinner ? 'PENDIENTE_REVISION' : 'LIMPIO');

  await kv.lpush('auditLog', { 
    playerKey: session.key, ip: session.ip, serverElapsed, diff, isWinner, status, 
    timestamp: new Date().toISOString() 
  });
  await kv.ltrim('auditLog', 0, MAX_AUDIT_ENTRIES - 1);

  return res.status(200).json({ serverElapsed, diff, isWinner, status });
}

async function handleGenerateKeys(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });
  const count = Math.min(parseInt(req.query.count) || 10, 1000);
  const keys = Array.from({length: count}, () => Math.random().toString(36).substring(2, 12));
  await kv.sadd('valid_keys', ...keys);
  return res.status(200).json({ keys });
}

async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });
  const entries = await kv.lrange('auditLog', 0, -1);
  return res.status(200).json({ entries: entries || [] });
}
