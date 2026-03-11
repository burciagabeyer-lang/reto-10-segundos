const crypto = require('crypto');
const { kv } = require('@vercel/kv');

// ─── Configuración ───────────────────────────────────────────────
const SECRET = process.env.SESSION_SECRET || 'dev-secret-cambiar-en-produccion-x9k2m';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin2024';
const TARGET_MS = 10000;
const TOLERANCE_MS = 100;
const MAX_AUDIT_ENTRIES = 500;

// ─── LAS 100 CLAVES ÚNICAS (10 caracteres, alfanuméricas + símbolos) ───
const VALID_KEYS = [
  "xY7!mQ2@pL", "B4#kZ9$vW1", "rT6%nC8^hJ", "M2&fX5*dG9", "pL3@jK7!bV",
  "W8$vN1#cC4", "zQ9^hM6%xY", "D5*gB2&tT8", "kR1!pW4@fL", "N7#mX9$cZ3",
  "yV2%bH6^jK", "F8&dC5*gM1", "tT4@rP8!wW", "H9$zK2#nN7", "mQ6^xY1%bV",
  "C3*fL8&dG5", "vW1!jK4@pP", "Z7#cC9$hH2", "gB5%tT8^mX", "K2&rR1*wW6",
  "nN4@yV7!zQ", "X9$fF2#cC5", "bV6^hM1%pL", "L8*dG5&tT3", "jK1!wW4@rR",
  "P7#mX9$yY2", "cC5%zQ8^bB6", "hM2&fF1*gG4", "tT4@pP7!nN9", "wW9$rR2#xX5",
  "yY6^vV1%mM8", "dG3*cC5&bB7", "pP1!tT4@hH9", "fF7#kK9$zZ2", "mX5%gG8^rR6",
  "vV2&wW1*yY4", "bB4@mM7!pP9", "cC9$dD2#fF5", "hH6^jJ1%kK8", "tT3*vV5&wW7",
  "rR1!yY4@zZ9", "mM7#bB9$cC2", "kK5%fF8^hH6", "wW2&pP1*tT4", "yY4@rR7!vV9",
  "zZ9$mM2#bB5", "fF6^kK1%cC8", "vV3*wW5&yY7", "pP1!tT4@rR9", "bB7#mM9$fF2",
  "cC5%hH8^kK6", "wW2&yY1*zZ4", "tT4@pP7!bB9", "mM9$fF2#cC5", "kK6^hH1%vV8",
  "yY3*zZ5&wW7", "rR1!tT4@mM9", "fF7#kK9$bB2", "hH5%cC8^yY6", "pP2&bB1*tT4",
  "wW4@yY7!zZ9", "vV9$rR2#mM5", "kK6^fF1%hH8", "zZ3*wW5&yY7", "tT1!pP4@bB9",
  "mM7#fF9$kK2", "cC5%hH8^vV6", "yY2&zZ1*wW4", "rR4@tT7!pP9", "bB9$mM2#fF5",
  "hH6^kK1%cC8", "wW3*yY5&zZ7", "vV1!rR4@tT9", "fF7#cC9$hH2", "kK5%mM8^bB6",
  "pP2&tT1*rR4", "zZ4@yY7!wW9", "mM9$bB2#cC5", "hH6^fF1%kK8", "yY3*wW5&vV7",
  "tT1!rR4@pP9", "cC7#hH9$fF2", "bB5%mM8^kK6", "wW2&zZ1*yY4", "pP4@tT7!bB9",
  "rR9$vV2#mM5", "fF6^cC1%hH8", "yY3*wW5&zZ7", "kK1!mM4@bB9", "hH7#fF9$cC2",
  "tT5%pP8^rR6", "vV2&wW1*yY4", "mM4@bB7!kK9", "cC9$hH2#fF5", "bB6^mM1%pP8",
  "zZ3*yY5&wW7", "rR1!tT4@vV9", "fF7#cC9$hH2", "kK5%mM8^bB6", "pP2&tT1*rR4"
];

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

// AQUÍ ESTÁ LA CORRECCIÓN MÁGICA
function getIP(req) {
  try {
    let ip = req.headers['x-forwarded-for'];
    if (Array.isArray(ip)) return ip.trim();
    if (typeof ip === 'string') return ip.split(',').trim();
    return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'desconocido';
  } catch (e) {
    return 'desconocido';
  }
}

// ─── Main Handler (AHORA ES ASÍNCRONO PARA LA BASE DE DATOS) ─────
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  const action = req.query.action;
  const ip = getIP(req);

  try {
    switch (action) {
      case 'start':  return await handleStart(req, res, ip);
      case 'stop':   return await handleStop(req, res, ip);
      case 'ping':   return res.status(200).json({ serverTime: Date.now(), ok: true });
      case 'audit':  return await handleAudit(req, res);
      default:       return res.status(400).json({ error: 'Acción no válida' });
    }
  } catch (error) {
    console.error("Error en la DB:", error);
    return res.status(500).json({ error: 'Error interno de la base de datos.' });
  }
};

// ─── START: Verificar clave, quemarla e iniciar sesión ───────────
async function handleStart(req, res, ip) {
  const body = req.body || {};
  const playerKey = body.key;

  // 1. Validar si la clave existe en la lista oficial
  if (!playerKey || !VALID_KEYS.includes(playerKey)) {
    return res.status(403).json({ error: 'Clave de acceso inválida.' });
  }

  // 2. Comprobar en la Base de Datos si ya fue usada
  const isUsed = await kv.sismember('used_keys', playerKey);
  if (isUsed) {
    return res.status(403).json({ error: 'Esta clave ya fue utilizada.' });
  }

  // 3. Quemar la clave en la Base de Datos para que nadie más la use
  await kv.sadd('used_keys', playerKey);

  const sessionId = crypto.randomUUID();
  const startTime = Date.now();
  
  const token = signPayload({
    sid: sessionId, st: startTime, ip: ip, key: playerKey,
    ua: (req.headers['user-agent'] || 'desconocido').substring(0, 200)
  });

  return res.status(200).json({ sessionId, token, serverTime: startTime });
}

// ─── STOP: Calcular resultado y guardar en BD permanente ────────
async function handleStop(req, res, ip) {
  const stopTime = Date.now();
  const body = req.body || {};
  const { token, isTrusted, clientElapsed } = body;

  if (!token) return res.status(400).json({ error: 'Token requerido.' });

  const session = verifyPayload(token);
  if (!session) return res.status(403).json({ error: 'Token inválido.' });

  const serverElapsed = stopTime - session.st;
  const diff = Math.abs(serverElapsed - TARGET_MS);
  const isWithinTolerance = diff <= TOLERANCE_MS;
  const isSuspicious = isTrusted === false || (clientElapsed && Math.abs(serverElapsed - clientElapsed) > 500);
  
  const status = isSuspicious ? 'SOSPECHOSO' : (isWithinTolerance ? 'PENDIENTE_REVISION' : 'LIMPIO');

  // Guardar en la Base de Datos (Vercel KV)
  const entry = {
    sessionId: session.sid,
    playerKey: session.key, // Guardamos qué clave usó
    ip: session.ip,
    serverElapsed, diff, isWinner: isWithinTolerance && !isSuspicious,
    status, isTrustedEvent: isTrusted, clientDrift: clientElapsed ? Math.abs(serverElapsed - clientElapsed) : null,
    timestamp: new Date(stopTime).toISOString()
  };

  await kv.lpush('auditLog', entry);
  await kv.ltrim('auditLog', 0, MAX_AUDIT_ENTRIES - 1); // Mantener solo los últimos 500

  return res.status(200).json({
    sessionId: session.sid, serverElapsed, diff, isWinner: entry.isWinner, status,
    message: entry.isWinner ? '🏆 ¡Posible ganador!' : `❌ Diferencia de ${diff}ms.`
  });
}

// ─── AUDIT: Leer historial desde la BD ───────────────────────────
async function handleAudit(req, res) {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'Clave incorrecta.' });

  // Leer la lista completa desde la Base de Datos
  let entries = await kv.lrange('auditLog', 0, -1);
  if (!entries) entries = [];

  const filter = req.query.filter;
  if (filter === 'winners') entries = entries.filter(e => e.isWinner);
  else if (filter === 'suspicious') entries = entries.filter(e => e.status === 'SOSPECHOSO');
  else if (filter === 'pending') entries = entries.filter(e => e.status === 'PENDIENTE_REVISION');

  return res.status(200).json({ total: entries.length, entries });
}
