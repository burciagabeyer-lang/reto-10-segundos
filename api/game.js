const crypto = require('crypto');

// ─── Configuration ───────────────────────────────────────────────
const SECRET = process.env.SESSION_SECRET || 'dev-secret-cambiar-en-produccion-' + 'x9k2m';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin2024';
const TARGET_MS = 10000;       // Objetivo: 10 segundos
const TOLERANCE_MS = 100;      // Tolerancia: ±100ms
const RATE_LIMIT_MAX = 10;     // Max intentos por ventana
const RATE_LIMIT_WINDOW = 30000; // Ventana de 30 segundos
const SESSION_MAX_AGE = 60000; // Sesión expira en 60 segundos
const MAX_AUDIT_ENTRIES = 500;

// ─── In-Memory Stores (persisten mientras la función está "warm") ─
const auditLog = [];
const rateLimits = new Map();

// ─── Crypto: Firmar y Verificar Tokens ───────────────────────────
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
  } catch {
    return null;
  }
}

// ─── Rate Limiting ───────────────────────────────────────────────
function checkRateLimit(ip) {
  const now = Date.now();
  let record = rateLimits.get(ip);
  if (!record || now > record.resetAt) {
    record = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
  }
  record.count++;
  rateLimits.set(ip, record);

  // Limpiar entradas viejas cada 100 checks
  if (rateLimits.size > 1000) {
    for (const [key, val] of rateLimits) {
      if (now > val.resetAt) rateLimits.delete(key);
    }
  }
  return record.count <= RATE_LIMIT_MAX;
}

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket?.remoteAddress ||
    'desconocido'
  );
}

// ─── Main Handler ────────────────────────────────────────────────
module.exports = (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // No-cache para evitar respuestas cacheadas
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  const action = req.query.action;
  const ip = getIP(req);

  // Rate limit (excepto admin)
  if (action !== 'audit' && action !== 'ping' && !checkRateLimit(ip)) {
    return res.status(429).json({
      error: 'Demasiados intentos. Espera 30 segundos.',
      retryAfter: 30
    });
  }

  switch (action) {
    case 'start':  return handleStart(req, res, ip);
    case 'stop':   return handleStop(req, res, ip);
    case 'ping':   return handlePing(req, res);
    case 'audit':  return handleAudit(req, res);
    case 'stats':  return handleStats(req, res);
    default:
      return res.status(400).json({ error: 'Acción no válida' });
  }
};

// ─── START: Generar sesión firmada ───────────────────────────────
function handleStart(req, res, ip) {
  const sessionId = crypto.randomUUID();
  const startTime = Date.now();
  const nonce = crypto.randomBytes(8).toString('hex');

  const token = signPayload({
    sid: sessionId,
    st: startTime,
    ip: ip,
    n: nonce,
    ua: (req.headers['user-agent'] || 'desconocido').substring(0, 200)
  });

  return res.status(200).json({
    sessionId,
    token,
    serverTime: startTime
  });
}

// ─── STOP: Verificar token y calcular resultado ─────────────────
function handleStop(req, res, ip) {
  const stopTime = Date.now();
  const body = req.body || {};
  const { token, isTrusted, clientElapsed, clientStartTime } = body;

  if (!token) {
    return res.status(400).json({ error: 'Token de sesión requerido.' });
  }

  // Verificar firma del token
  const session = verifyPayload(token);
  if (!session) {
    logSuspicious(ip, 'TOKEN_INVALIDO', body);
    return res.status(403).json({ error: 'Token inválido o manipulado.' });
  }

  // Verificar que la IP coincida (anti-robo de token)
  if (session.ip !== ip) {
    logSuspicious(ip, 'IP_MISMATCH', { expected: session.ip, got: ip });
    return res.status(403).json({ error: 'Sesión inválida desde esta conexión.' });
  }

  // Verificar expiración
  if (stopTime - session.st > SESSION_MAX_AGE) {
    return res.status(403).json({ error: 'Sesión expirada. Inicia un nuevo intento.' });
  }

  // ─── Calcular resultado (SOLO el servidor decide) ───
  const serverElapsed = stopTime - session.st;
  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWithinTolerance = diff <= TOLERANCE_MS;

  // ─── Detección de anomalías ───
  const anomalies = [];

  // 1. Drift del reloj del cliente vs servidor
  const clientDrift = clientElapsed != null ? Math.abs(serverElapsed - clientElapsed) : null;
  if (clientDrift != null && clientDrift > 500) {
    anomalies.push(`CLOCK_DRIFT: ${clientDrift}ms`);
  }

  // 2. Evento no fue generado por humano
  if (isTrusted === false) {
    anomalies.push('EVENT_NOT_TRUSTED');
  }

  // 3. Tiempo sospechosamente preciso (< 5ms de diferencia en múltiples intentos)
  // Se verificaría en el panel de auditoría manualmente

  const isSuspicious = anomalies.length > 0;
  let status;
  if (isSuspicious) {
    status = 'SOSPECHOSO';
  } else if (isWithinTolerance) {
    status = 'PENDIENTE_REVISION';
  } else {
    status = 'LIMPIO';
  }

  const result = {
    sessionId: session.sid,
    serverElapsed,
    diff,
    isWinner: isWithinTolerance && !isSuspicious,
    status,
    targetMs: TARGET_MS,
    toleranceMs: TOLERANCE_MS,
    message: isWithinTolerance
      ? (isSuspicious ? '⚠️ Resultado sospechoso. Bajo revisión.' : '🏆 ¡Posible ganador! Pendiente de verificación.')
      : `❌ Diferencia de ${diff}ms. Sigue intentando.`
  };

  // ─── Guardar en auditoría ───
  const entry = {
    sessionId: session.sid,
    ip: session.ip,
    userAgent: session.ua,
    serverElapsed,
    diff,
    isWinner: result.isWinner,
    status,
    isTrustedEvent: isTrusted,
    clientElapsed: clientElapsed || null,
    clientDrift,
    anomalies,
    timestamp: new Date(stopTime).toISOString()
  };

  auditLog.push(entry);
  if (auditLog.length > MAX_AUDIT_ENTRIES) {
    auditLog.splice(0, auditLog.length - MAX_AUDIT_ENTRIES);
  }

  return res.status(200).json(result);
}

// ─── PING: Medir latencia ────────────────────────────────────────
function handlePing(req, res) {
  return res.status(200).json({
    serverTime: Date.now(),
    ok: true
  });
}

// ─── AUDIT: Panel de administración ──────────────────────────────
function handleAudit(req, res) {
  const key = req.query.key;
  if (key !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Clave de administración incorrecta.' });
  }

  const filter = req.query.filter; // 'all', 'winners', 'suspicious'
  let entries = auditLog.slice().reverse();

  if (filter === 'winners') {
    entries = entries.filter(e => e.isWinner);
  } else if (filter === 'suspicious') {
    entries = entries.filter(e => e.status === 'SOSPECHOSO');
  } else if (filter === 'pending') {
    entries = entries.filter(e => e.status === 'PENDIENTE_REVISION');
  }

  return res.status(200).json({
    total: auditLog.length,
    filtered: entries.length,
    config: { targetMs: TARGET_MS, toleranceMs: TOLERANCE_MS },
    entries
  });
}

// ─── STATS: Estadísticas públicas ────────────────────────────────
function handleStats(req, res) {
  const total = auditLog.length;
  const winners = auditLog.filter(e => e.isWinner).length;
  const avgDiff = total > 0
    ? Math.round(auditLog.reduce((sum, e) => sum + e.diff, 0) / total)
    : 0;
  const bestDiff = total > 0
    ? Math.min(...auditLog.map(e => e.diff))
    : null;

  return res.status(200).json({
    totalAttempts: total,
    winners,
    averageDiffMs: avgDiff,
    bestDiffMs: bestDiff,
    targetMs: TARGET_MS,
    toleranceMs: TOLERANCE_MS
  });
}

// ─── Helper: Registrar actividad sospechosa ──────────────────────
function logSuspicious(ip, reason, details) {
  auditLog.push({
    sessionId: 'BLOCKED',
    ip,
    userAgent: 'N/A',
    serverElapsed: 0,
    diff: 0,
    isWinner: false,
    status: 'BLOQUEADO',
    isTrustedEvent: false,
    clientElapsed: null,
    clientDrift: null,
    anomalies: [`${reason}: ${JSON.stringify(details).substring(0, 200)}`],
    timestamp: new Date().toISOString()
  });
}
