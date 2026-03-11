# Reto 10 Segundos — Guía de Despliegue

## ¿Qué es esto?

Una aplicación web donde los usuarios intentan detener un cronómetro en exactamente **10.000 segundos**. El sistema valida todo del lado del servidor para evitar trampas.

### Características de Seguridad:
- Cálculo 100% server-side — El navegador NO decide si ganaste
- Tokens firmados con HMAC-SHA256 — No se puede manipular el tiempo de inicio
- Validación isTrusted — Detecta clics automáticos (bots)
- Detección de Speed Hack — Compara reloj del cliente vs servidor
- Rate Limiting — Máximo 10 intentos cada 30 segundos por IP
- Panel de Auditoría — Revisa cada intento antes de pagar
- Verificación de IP — El token solo funciona desde la IP que lo generó

### Tolerancia: Objetivo 10,000ms | Rango ganador: 9,900ms — 10,100ms

---

## Despliegue en Vercel (GRATIS) — Paso a Paso

### Paso 1: Crear cuenta en GitHub
1. Ve a https://github.com y crea una cuenta gratuita
2. Verifica tu correo electrónico

### Paso 2: Crear un repositorio
1. Clic en el botón verde "New" (o ve a https://github.com/new)
2. Nombre: `reto-10-segundos`
3. Déjalo como Public o Private
4. NO marques "Add a README file"
5. Clic en "Create repository"

### Paso 3: Subir los archivos
**Desde el navegador (más fácil):**
1. En tu nuevo repositorio, clic en "uploading an existing file"
2. Arrastra TODOS los archivos y carpetas del proyecto
3. Clic en "Commit changes"

### Paso 4: Crear cuenta en Vercel
1. Ve a https://vercel.com
2. Clic en "Sign Up" → "Continue with GitHub"
3. Autoriza a Vercel

### Paso 5: Importar el proyecto
1. En Vercel, clic en "Add New..." → "Project"
2. Selecciona tu repositorio → "Import"
3. Framework Preset: "Other"
4. Abre "Environment Variables" y agrega:
   - SESSION_SECRET = (inventa una clave larga)
   - ADMIN_KEY = (tu contraseña para el panel admin)
5. Clic en "Deploy"

¡LISTO! Vercel te da una URL como: https://reto-10-segundos.vercel.app

---

## Panel de Administración
1. Abre tu sitio → toca "Admin" en la barra inferior
2. Ingresa tu ADMIN_KEY
3. Filtra por: Todos | Ganadores | Pendientes | Sospechosos

### Qué buscar al auditar:
- Drift alto (>500ms) = reloj manipulado
- Trust = ❌ = clic no humano
- IP repetida con intentos exactos = posible bot

---

## Configuración (api/game.js)
- TARGET_MS = 10000 (objetivo en ms)
- TOLERANCE_MS = 100 (tolerancia ±100ms)
- RATE_LIMIT_MAX = 10 (intentos por ventana)

## Estructura
```
├── api/game.js        ← Backend
├── public/index.html  ← Frontend
├── vercel.json        ← Config Vercel
├── package.json       ← Config proyecto
└── README.md          ← Este archivo
```

## Costo: $0/mes (Vercel free tier)
