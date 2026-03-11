const crypto = require('crypto');
const { kv } = require('@vercel/kv');

// Configuración desde Variables de Entorno de Vercel
const SECRET = process.env.SESSION_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;
const TARGET_MS = 10000;
const TOLERANCE_MS = 100;
const MAX_AUDIT_ENTRIES = 500;

// Helper para obtener la IP real del jugador
function getIP(req) {
  try {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
    if (Array.isArray(forwarded)) return forwarded[0].trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  } catch (e) { return 'unknown'; }
}

// Handler Principal
module.exports = async (req, res) => {
  const origin = req.headers.origin || req.headers.referer || '';

  // ═══════════════════════════════════════════════════════════
  // CORS — Permitir tu dominio de Vercel y previews
  // ═══════════════════════════════════════════════════════════
  const isAllowed =
    origin.includes('.vercel.app') ||   // Cualquier deploy de Vercel (previews incluidos)
    origin.includes('localhost') ||
    origin === '';                       // Peticiones directas (Postman, curl, etc.)

  res.setHeader('Access-Control-Allow-Origin', isAllowed ? (origin || '*') : 'https://reto-10-segundos.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const ip = getIP(req);
  const banKey = `banned:${ip}`;

  try {
    // 1. Verificar si la IP está baneada
    const isBanned = await kv.get(banKey);
    if (isBanned) return res.status(403).json({ error: 'Acceso denegado. Tu IP fue bloqueada temporalmente.' });

    // 2. Límite de peticiones (Rate Limit)
    const rateKey = `rate:${ip}`;
    const requests = await kv.incr(rateKey);
    if (requests === 1) await kv.expire(rateKey, 60);
    if (requests > 30) return res.status(429).json({ error: 'Demasiadas peticiones. Espera un minuto.' });

    // 3. Router de Acciones
    switch (action) {
      case 'ping':
        return res.status(200).json({ ok: true, serverTime: Date.now() });

      case 'start':
        return await handleStart(req, res, ip);

      case 'stop':
        return await handleStop(req, res, ip);

      case 'gen':
        return await handleGenerateKeys(req, res);

      case 'audit':
        return await handleAudit(req, res);

      case 'unban':
        return await handleUnban(req, res);

      default:
        // NO banear por default — solo responder con error
        return res.status(400).json({ error: 'Acción no especificada. Usa ?action=ping para verificar.' });
    }
  } catch (e) {
    console.error('Error en handler:', e.message || e);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
};

// --- FUNCIONES DE LÓGICA ---

async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  const attKey = `att:${ip}`;

  const fails = (await kv.get(attKey)) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'IP bloqueada por 1h debido a fallos.' });

  if (!key) return res.status(400).json({ error: 'Clave requerida.' });

  // Verificar si la clave existe en el Set de Redis
  const exists = await kv.sismember('valid_keys', key);
  if (!exists) {
    await kv.set(attKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave inválida o ya utilizada.' });
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

  if (!token) return res.status(400).json({ error: 'Token requerido.' });

  const parts = token.split('.');
  if (parts.length !== 2) return res.status(403).json({ error: 'Token corrupto.' });

  let payloadStr;
  try {
    payloadStr = Buffer.from(parts[0], 'base64url').toString();
  } catch (e) {
    return res.status(403).json({ error: 'Token no decodificable.' });
  }

  const expectedSig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('hex');

  if (parts[1] !== expectedSig) return res.status(403).json({ error: 'Firma inválida.' });

  let session;
  try {
    session = JSON.parse(payloadStr);
  } catch (e) {
    return res.status(403).json({ error: 'Payload corrupto.' });
  }

  const serverElapsed = Date.now() - session.st;

  // Validaciones de seguridad temporal
  if (serverElapsed > 15000) return res.status(403).json({ error: 'Sesión expirada (Max 15s).' });
  if (serverElapsed < 2000) return res.status(403).json({ error: 'Intento no humano.' });

  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWinner = diff <= TOLERANCE_MS && isTrusted === true;

  // Detección de trampas
  let status = 'LIMPIO';
  if (isTrusted === false) status = 'SOSPECHOSO';
  else if (clientElapsed && Math.abs(serverElapsed - clientElapsed) > 400) status = 'SOSPECHOSO';

  if (isWinner) status = (status === 'SOSPECHOSO') ? 'REVISION_MANUAL' : 'GANADOR_PENDIENTE';

  // Registrar en Log de Auditoría
  const entry = {
    playerKey: session.key,
    ip: session.ip,
    serverElapsed,
    diff,
    isWinner,
    status,
    timestamp: new Date().toISOString(),
  };

  await kv.lpush('auditLog', JSON.stringify(entry));
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
    message: `Se generaron ${count} claves con éxito.`,
    keys: newKeys,
  });
}

async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });

  const raw = await kv.lrange('auditLog', 0, -1);
  const entries = (raw || []).map(entry => {
    if (typeof entry === 'string') {
      try { return JSON.parse(entry); } catch (e) { return entry; }
    }
    return entry;
  });

  return res.status(200).json({ entries });
}

async function handleUnban(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });

  const ipToUnban = req.query.ip;
  if (ipToUnban) {
    await kv.del(`banned:${ipToUnban}`);
    await kv.del(`att:${ipToUnban}`);
    return res.status(200).json({ message: `IP ${ipToUnban} desbaneada.` });
  }

  // Si no se pasa IP, limpiar todos los baneos (opción nuclear)
  // Esto no es ideal pero funciona para emergencias
  return res.status(400).json({ error: 'Pasa ?ip=X.X.X.X para desbanear una IP específica.' });
}
