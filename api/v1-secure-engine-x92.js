const crypto = require('crypto');
const { kv } = require('@vercel/kv');

// Configuración desde Variables de Entorno de Vercel
const SECRET = process.env.SESSION_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;
const TARGET_MS = 10000;
const TOLERANCE_MS = 50; 
const MAX_AUDIT_ENTRIES = 500;

// Helper para obtener la IP real del jugador
function getIP(req) {
  try {
    let ip = req.headers['x-forwarded-for'];
    if (Array.isArray(ip)) return ip.trim();
    if (typeof ip === 'string') return ip.split(',').trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  } catch (e) { return 'unknown'; }
}

// Handler Principal
module.exports = async (req, res) => {
  const origin = req.headers.origin || req.headers.referer || '';
  const OFFICIAL_DOMAIN = 'reto-10-segundos.vercel.app';
  
  // Validación de Origen (CORS) - Flexible para subdominios pero segura
  const isAllowed = origin.includes(OFFICIAL_DOMAIN) || origin.includes('localhost');

  res.setHeader('Access-Control-Allow-Origin', isAllowed ? origin : `https://${OFFICIAL_DOMAIN}`);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const ip = getIP(req);
  const banKey = `banned:${ip}`;

  try {
    // 1. Verificar si la IP está baneada
    const isBanned = await kv.get(banKey);
    if (isBanned) return res.status(403).json({ error: 'Acceso denegado.' });

    // 2. Seguridad de Origen Estricta
    if (origin && !isAllowed) {
      await kv.set(banKey, true, { ex: 86400 }); // Baneo 24h por intento de acceso externo
      return res.status(403).json({ error: 'Origen no autorizado.' });
    }

    // 3. Límite de peticiones (Rate Limit)
    const rateKey = `rate:${ip}`;
    const requests = await kv.incr(rateKey);
    if (requests === 1) await kv.expire(rateKey, 60);
    if (requests > 30) return res.status(429).json({ error: 'Demasiadas peticiones. Espera un minuto.' });

    // 4. Router de Acciones
    switch (action) {
      case 'ping': 
        return res.status(200).json({ ok: true });
        
      case 'start': 
        return await handleStart(req, res, ip);
        
      case 'stop': 
        return await handleStop(req, res, ip);
        
      case 'gen': 
        return await handleGenerateKeys(req, res);
        
      case 'audit': 
        return await handleAudit(req, res);
        
      default: 
        await kv.set(banKey, true, { ex: 86400 }); // Honeypot
        return res.status(400).json({ error: 'Accion invalida.' });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
};

// --- FUNCIONES DE LÓGICA ---

async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  const attKey = `att:${ip}`;
  
  const fails = await kv.get(attKey) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'IP bloqueada por 1h debido a fallos.' });

  if (!key) return res.status(400).json({ error: 'Clave requerida.' });

  // Verificar si la clave existe en el Set de Redis
  const exists = await kv.sismember('valid_keys', key);
  if (!exists) {
    await kv.set(attKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave invalida o ya utilizada.' });
  }

  // Eliminar clave (un solo uso)
  await kv.srem('valid_keys', key);

  // Crear Token Firmado
  const payload = JSON.stringify({ sid: crypto.randomUUID(), st: Date.now(), ip, key });
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  const token = Buffer.from(payload).toString('base64url') + '.' + sig;
  
  return res.status(200).json({ token, serverTime: Date.now() });
}

async function handleStop(req, res, ip) {
  const { token, isTrusted, clientElapsed } = req.body || {};
  const parts = token ? token.split('.') : [];
  if (parts.length !== 2) return res.status(403).json({ error: 'Token corrupto.' });

  const payloadStr = Buffer.from(parts, 'base64url').toString();
  const expectedSig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('hex');
  
  if (parts !== expectedSig) return res.status(403).json({ error: 'Firma invalida.' });

  const session = JSON.parse(payloadStr);
  const serverElapsed = Date.now() - session.st;

  // Validaciones de seguridad temporal
  if (serverElapsed > 15000) return res.status(403).json({ error: 'Sesion expirada (Max 15s).' });
  if (serverElapsed < 2000) return res.status(403).json({ error: 'Intento no humano.' });

  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWinner = diff <= TOLERANCE_MS && isTrusted === true;
  
  // Detección de trampas
  const status = (isTrusted === false || Math.abs(serverElapsed - clientElapsed) > 400) ? 'SOSPECHOSO' : (isWinner ? 'GANADOR_PENDIENTE' : 'LIMPIO');

  // Registrar en Log de Auditoría
  const entry = { 
    playerKey: session.key, 
    ip: session.ip, 
    serverElapsed, 
    diff, 
    isWinner, 
    status, 
    timestamp: new Date().toISOString() 
  };
  
  await kv.lpush('auditLog', entry);
  await kv.ltrim('auditLog', 0, MAX_AUDIT_ENTRIES - 1);

  return res.status(200).json({ serverElapsed, diff, isWinner, status });
}

async function handleGenerateKeys(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });
  
  const count = Math.min(parseInt(req.query.count) || 10, 1000);
  const newKeys = [];
  for (let i = 0; i < count; i++) {
    newKeys.push(Math.random().toString(36).substring(2, 12).toUpperCase());
  }

  // Guardar masivamente en Redis
  await kv.sadd('valid_keys', ...newKeys);

  return res.status(200).json({ 
    message: `Se generaron ${count} claves con exito.`,
    keys: newKeys 
  });
}

async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });
  const entries = await kv.lrange('auditLog', 0, -1);
  return res.status(200).json({ entries: entries || [] });
}
