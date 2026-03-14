const crypto = require('crypto');
const { kv } = require('@vercel/kv');

const SECRET = process.env.SESSION_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;
const TARGET_MS = 10000;
const TOLERANCE_MS = 9000;
const MAX_AUDIT_ENTRIES = 500;
const MAX_SESSION_MS = 15000;
const MIN_SESSION_MS = 2000;
const DRIFT_TOLERANCE_MS = 400;

function getIP(req) {
  try {
    const f = req.headers['x-forwarded-for'];
    if (typeof f === 'string') return f.split(',')[0].trim();
    if (Array.isArray(f)) return f[0].trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  } catch (e) { return 'unknown'; }
}

// Registrar en auditoría
async function logAudit(entry) {
  try {
    await kv.lpush('auditLog', JSON.stringify({ ...entry, timestamp: new Date().toISOString() }));
    await kv.ltrim('auditLog', 0, MAX_AUDIT_ENTRIES - 1);
  } catch (e) { console.error('Audit log error:', e); }
}

module.exports = async (req, res) => {
  const origin = req.headers.origin || req.headers.referer || '';
  const isAllowed = origin.includes('.vercel.app') || origin.includes('localhost') || origin === '';

  res.setHeader('Access-Control-Allow-Origin', isAllowed ? (origin || '*') : 'https://reto-10-segundos.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const ip = getIP(req);

  try {
    // IP baneada
    const isBanned = await kv.get(`banned:${ip}`);
    if (isBanned) return res.status(403).json({ error: 'Acceso denegado.' });

    // Rate limit
    const rateKey = `rate:${ip}`;
    const reqs = await kv.incr(rateKey);
    if (reqs === 1) await kv.expire(rateKey, 60);
    if (reqs > 30) return res.status(429).json({ error: 'Demasiadas peticiones. Espera un minuto.' });

    switch (action) {
      case 'ping':   return res.status(200).json({ ok: true, serverTime: Date.now() });
      case 'start':  return await handleStart(req, res, ip);
      case 'stop':   return await handleStop(req, res, ip);
      case 'gen':    return await handleGenerateKeys(req, res);
      case 'audit':  return await handleAudit(req, res);
      case 'unban':  return await handleUnban(req, res);
      case 'keys':   return await handleListKeys(req, res);
      default:       return res.status(400).json({ error: 'Acción no válida.' });
    }
  } catch (e) {
    console.error('Error:', e.message || e);
    return res.status(500).json({ error: 'Error interno.' });
  }
};

// ═══════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════
async function handleStart(req, res, ip) {
  const { key } = req.body || {};
  const attKey = `att:${ip}`;

  const fails = (await kv.get(attKey)) || 0;
  if (fails >= 5) return res.status(429).json({ error: 'IP bloqueada por 1h.' });

  if (!key || typeof key !== 'string' || key.trim().length < 3) {
    return res.status(400).json({ error: 'Clave requerida.' });
  }

  const cleanKey = key.trim().toUpperCase();
  const exists = await kv.sismember('valid_keys', cleanKey);
  if (!exists) {
    await kv.set(attKey, fails + 1, { ex: 3600 });
    return res.status(403).json({ error: 'Clave inválida o ya utilizada.' });
  }

  // Eliminar clave (UN SOLO USO)
  await kv.srem('valid_keys', cleanKey);

  const sid = crypto.randomUUID();
  const startTime = Date.now();

  // Token firmado
  const payload = JSON.stringify({ sid, st: startTime, ip, key: cleanKey });
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  const token = Buffer.from(payload).toString('base64url') + '.' + sig;

  // ══════════════════════════════════════════════
  // Guardar sesión en Redis para PREVENIR REPLAY
  // Expira en 25s (margen sobre MAX_SESSION_MS)
  // ══════════════════════════════════════════════
  await kv.set(`ses:${sid}`, 'active', { ex: 25 });

  return res.status(200).json({ token, serverTime: startTime });
}

// ═══════════════════════════════════════════════════════════════
// STOP
// ═══════════════════════════════════════════════════════════════
async function handleStop(req, res, ip) {
  const { token, isTrusted, clientElapsed } = req.body || {};

  // ── Validar y decodificar token ──
  if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Token requerido.' });

  const parts = token.split('.');
  if (parts.length !== 2) return res.status(403).json({ error: 'Token corrupto.' });

  let payloadStr;
  try { payloadStr = Buffer.from(parts[0], 'base64url').toString(); }
  catch (e) { return res.status(403).json({ error: 'Token no decodificable.' }); }

  const expectedSig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('hex');
  if (parts[1] !== expectedSig) return res.status(403).json({ error: 'Firma inválida.' });

  let session;
  try { session = JSON.parse(payloadStr); }
  catch (e) { return res.status(403).json({ error: 'Payload corrupto.' }); }

  // ══════════════════════════════════════════════
  // ANTI-REPLAY: Verificar que el token no se usó
  // ══════════════════════════════════════════════
  const sesKey = `ses:${session.sid}`;
  const sesStatus = await kv.get(sesKey);

  if (!sesStatus) {
    // Sesión expirada (>25s) o no existe
    await logAudit({
      playerKey: session.key, ip, serverElapsed: 0, diff: 0,
      isWinner: false, status: 'SESION_EXPIRADA', flags: ['TOKEN_EXPIRADO'],
    });
    return res.status(403).json({ error: 'Sesión expirada.' });
  }

  if (sesStatus === 'used') {
    // ¡REPLAY DETECTADO!
    await logAudit({
      playerKey: session.key, ip, serverElapsed: 0, diff: 0,
      isWinner: false, status: 'REPLAY_DETECTADO', flags: ['TOKEN_REUSADO'],
    });
    return res.status(403).json({ error: 'Token ya utilizado.' });
  }

  // Marcar como usado INMEDIATAMENTE (antes de calcular)
  await kv.set(sesKey, 'used', { ex: 25 });

  // ══════════════════════════════════════════════
  // CÁLCULO — EL SERVIDOR ES LA FUENTE DE VERDAD
  // ══════════════════════════════════════════════
  const stopTime = Date.now();
  const serverElapsed = stopTime - session.st;

  // ── Recopilar flags de seguridad ──
  const flags = [];

  // 1. Sesión expirada (pasó de 15 segundos)
  if (serverElapsed > MAX_SESSION_MS) {
    flags.push('TIEMPO_EXCEDIDO');
    await logAudit({
      playerKey: session.key, ip, serverElapsed,
      diff: Math.abs(serverElapsed - TARGET_MS),
      isWinner: false, status: 'EXPIRADO', flags,
    });
    return res.status(200).json({
      serverElapsed, diff: Math.abs(serverElapsed - TARGET_MS),
      isWinner: false, status: 'EXPIRADO',
    });
  }

  // 2. Demasiado rápido (menos de 2 segundos = bot)
  if (serverElapsed < MIN_SESSION_MS) {
    flags.push('TIEMPO_INHUMANO');
  }

  // 3. isTrusted — ¿fue clic real?
  if (isTrusted !== true) {
    flags.push('CLICK_NO_CONFIABLE');
  }

  // 4. Drift entre reloj cliente y servidor
  if (clientElapsed && typeof clientElapsed === 'number') {
    const drift = Math.abs(serverElapsed - clientElapsed);
    if (drift > DRIFT_TOLERANCE_MS) {
      flags.push('DRIFT_' + drift + 'ms');
    }
  } else {
    flags.push('SIN_TIEMPO_CLIENTE');
  }

  // 5. IP diferente entre start y stop
  if (session.ip !== ip) {
    flags.push('IP_DIFERENTE');
  }

  // ── Determinar resultado ──
  const diff = Math.abs(serverElapsed - TARGET_MS);
  const inRange = diff <= TOLERANCE_MS;

  const isSuspicious = flags.some(function(f){
    return f === 'CLICK_NO_CONFIABLE' ||
           f === 'IP_DIFERENTE' ||
           f === 'TIEMPO_INHUMANO' ||
           f.startsWith('DRIFT_');
  });

  let status;
  if (inRange && !isSuspicious) {
    status = 'GANADOR_PENDIENTE';
  } else if (inRange && isSuspicious) {
    status = 'REVISION_MANUAL';
  } else if (isSuspicious) {
    status = 'SOSPECHOSO';
  } else {
    status = 'LIMPIO';
  }

  const isWinner = inRange && !isSuspicious;

  await logAudit({
    playerKey: session.key, ip, serverElapsed, diff,
    isWinner, status, flags,
  });

  return res.status(200).json({ serverElapsed, diff, isWinner, status });
}

// ═══════════════════════════════════════════════════════════════
// ADMIN: Generar claves
// ═══════════════════════════════════════════════════════════════
async function handleGenerateKeys(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });

  const count = Math.min(parseInt(req.query.count) || 10, 1000);
  const newKeys = [];
  for (let i = 0; i < count; i++) {
    newKeys.push(Math.random().toString(36).substring(2, 12).toUpperCase());
  }
  await kv.sadd('valid_keys', ...newKeys);

  return res.status(200).json({ message: count + ' claves generadas.', keys: newKeys });
}

// ═══════════════════════════════════════════════════════════════
// ADMIN: Auditoría
// ═══════════════════════════════════════════════════════════════
async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });

  const raw = await kv.lrange('auditLog', 0, -1);
  const entries = (raw || []).map(function(entry){
    if (typeof entry === 'string') { try { return JSON.parse(entry); } catch(e){ return entry; } }
    return entry;
  });

  return res.status(200).json({ entries });
}

// ═══════════════════════════════════════════════════════════════
// ADMIN: Listar claves activas
// ═══════════════════════════════════════════════════════════════
async function handleListKeys(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });

  const keys = await kv.smembers('valid_keys');
  return res.status(200).json({ count: keys ? keys.length : 0, keys: keys || [] });
}

// ═══════════════════════════════════════════════════════════════
// ADMIN: Desbanear IP
// ═══════════════════════════════════════════════════════════════
async function handleUnban(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'No autorizado.' });

  const ipToUnban = req.query.ip;
  if (!ipToUnban) return res.status(400).json({ error: 'Pasa ?ip=X.X.X.X' });

  await kv.del(`banned:${ipToUnban}`);
  await kv.del(`att:${ipToUnban}`);
  return res.status(200).json({ message: 'IP ' + ipToUnban + ' desbaneada.' });
}

