import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';

dotenv.config();
const app = express();

// 1. TRUST PROXY: Vital para Cloudflare/Proxies
app.set('trust proxy', 1); 

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN DE CRIPTOGRAFÍA ---
// Necesitas añadir MASTER_ENCRYPTION_KEY (32 hex chars) a tu .env
if (!process.env.MASTER_ENCRYPTION_KEY) {
    console.error("⚠️ ADVERTENCIA: Falta MASTER_ENCRYPTION_KEY. La encriptación no funcionará.");
}
const ENCRYPTION_KEY = process.env.MASTER_ENCRYPTION_KEY 
    ? Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex') 
    : crypto.randomBytes(32); // Fallback temporal solo para que no crashee en dev
const IV_LENGTH = 16;

// Funciones para proteger credenciales de satélites en la DB
function encrypt(text) {
    if (!text) return null;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return null;
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// --- DOMINIOS PERMITIDOS ---
const SATELLITE_URL = process.env.SATELLITE_URL || "https://api-clinica.vintex.net.br";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";
const ALLOWED_ORIGINS = [FRONTEND_URL, 'https://vintex.net.br', 'http://localhost:5173'];

// --- SEGURIDAD: MIDDLEWARES ---

// 1. Helmet con CSP Estricta
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// 2. CORS Robusto
app.use(cors({
    origin: (origin, callback) => {
        // Permitir solicitudes sin origen (como apps móviles o curl) o dominios permitidos
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Bloqueado por CORS'));
        }
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret'], // Añadido header interno
    credentials: true
}));

app.use(express.json({ limit: '10kb' })); // Anti-DoS Body Size

// 3. Rate Limiting General
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 150, // Aumentado ligeramente para uso normal
    message: { error: "Demasiadas peticiones." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// 4. Rate Limiting Específico para Auth (Anti Brute-Force)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20, 
    message: { error: "Demasiados intentos de autenticación." }
});

// 5. Logger Sanitizado
const sanitizeLog = (obj) => {
    if (!obj) return obj;
    const copy = { ...obj };
    const sensitiveKeys = ['password', 'token', 'access_token', 'session', 'secret', 'dni', 'credit_card', 'cvv', 'phone', 'telefono', 'email', 'supab_service_key', 'jwt_secret'];
    Object.keys(copy).forEach(key => {
        if (sensitiveKeys.includes(key.toLowerCase())) {
            copy[key] = '***REDACTED***';
        } else if (typeof copy[key] === 'object' && copy[key] !== null) {
            copy[key] = sanitizeLog(copy[key]);
        }
    });
    return copy;
};

app.use((req, res, next) => {
    console.log(`\n🔵 [REQUEST] ${req.method} ${req.url}`);
    if (req.body && Object.keys(req.body).length > 0) {
        // Solo loguear body en dev o debug, sanitizado
        if (process.env.NODE_ENV !== 'production') {
             console.log('   Payload:', JSON.stringify(sanitizeLog(req.body), null, 2));
        }
    }
    next();
});

// --- SUPABASE MASTER ---
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ FALTA CONFIGURACIÓN: SUPABASE_URL o SUPABASE_SERVICE_KEY.");
    process.exit(1);
}

const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- SCHEMAS DE VALIDACIÓN (ZOD) ---
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8, "Contraseña insegura"),
    full_name: z.string().min(2)
});

const trialSchema = z.object({
    email: z.string().email(),
    fullName: z.string().min(2),
    phone: z.string().min(8)
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string()
});

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// =================================================================
// RUTAS DE NEGOCIO (Usuarios, Auth)
// =================================================================

app.post('/api/register', authLimiter, validate(registerSchema), async (req, res) => {
  const { email, password, full_name } = req.body;
  try {
    const { data: authData, error: authError } = await masterSupabase.auth.signUp({
      email,
      password,
      options: { data: { full_name } }
    });

    if (authError) throw authError;
    if (!authData.user) throw new Error("Error en creación de usuario.");

    const userId = authData.user.id;

    // Transacción implícita (si falla una, idealmente revertir, pero en Supabase JS se hace secuencial)
    const { error: userError } = await masterSupabase.from('users').insert({
        id: userId,
        email: email,
        full_name: full_name,
        role: 'admin',
        created_at: new Date()
    });

    if (userError) throw userError;

    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 14);

    await masterSupabase.from('trials').insert({
        user_id: userId,
        start_date: new Date(),
        end_date: endDate,
        status: 'active'
    });

    await masterSupabase.from('servisi').insert({
        "ID_User": userId,
        web_clinica: false,
        "Bot_clinica": false
    });
      
    res.status(200).json({
      message: 'Usuario registrado correctamente',
      user: { id: authData.user.id, email: authData.user.email },
      session: authData.session 
    });

  } catch (error) {
    console.error("Registro error:", error.message); 
    res.status(400).json({ error: error.message || 'Error al procesar el registro.' });
  }
});

app.post('/api/start-trial', authLimiter, validate(trialSchema), async (req, res) => {
    const { email, fullName, phone } = req.body;
    // Generar password temporal seguro
    const tempPassword = crypto.randomBytes(16).toString('hex') + "V!1";

    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email,
            password: tempPassword,
            options: { data: { full_name: fullName, phone } }
        });

        if (authError) throw authError;
        const userId = authData.user.id;

        await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: fullName,
            phone: phone,
            role: 'admin'
        });

        await masterSupabase.from('servisi').insert({
            "ID_User": userId,
            web_clinica: false, 
            "Bot_clinica": false
        });

        console.log(`[INFO] Usuario Trial creado: ${email}`); 
        // TODO: Enviar email con sendgrid/resend con la tempPassword
        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });

    } catch (error) {
        console.error("Trial error:", error.message);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/login', authLimiter, validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
        
        if (error || !data.user) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        return res.json({
            success: true,
            session: data.session,
            user: { id: data.user.id, email: data.user.email }
        });
    } catch (e) {
        console.error("Error Login:", e.message);
        return res.status(500).json({ error: 'Error interno de autenticación.' });
    }
});

// =================================================================
// RUTAS DE INFRAESTRUCTURA (Conexión Frontend & Satélites)
// =================================================================

// 1. Endpoint para el Frontend (Cliente)
// Devuelve SOLO la URL y la Anon Key. Nunca la Service Key.
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

    const token = authHeader.split(' ')[1];
    try {
        // Verificar token real con Supabase
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });

        // Buscar configuración de clínica
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_ANON_KEY') // SOLO claves públicas
            .eq('ID_USER', user.id)
            .single();
        
        if (!config) {
             return res.status(200).json({ hasClinic: false });
        }

        return res.json({
            hasClinic: true,
            backendUrl: SATELLITE_URL,
            supabaseUrl: config.SUPABASE_URL,
            supabaseAnonKey: config.SUPABASE_ANON_KEY 
        });
    } catch (e) {
        console.error("Error Init Session:", e.message);
        return res.status(500).json({ error: 'Error recuperando configuración.' });
    }
});

// 2. Endpoint INTERNO para el Backend Satélite (Server-to-Server)
// Devuelve la SERVICE KEY para que el satélite pueda administrar su DB.
// Protegido por una clave secreta interna compartida.
app.post('/api/internal/get-clinic-credentials', async (req, res) => {
    const internalSecret = req.headers['x-internal-secret'];
    
    // Validación estricta de secreto interno
    if (!internalSecret || internalSecret !== process.env.INTERNAL_SECRET_KEY) {
        console.warn(`[SECURITY] Intento de acceso no autorizado a credenciales internas desde IP: ${req.ip}`);
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID requerido' });

    try {
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY')
            .eq('ID_USER', userId)
            .single();

        if (!config) return res.status(404).json({ error: 'Configuración no encontrada' });

        // Si guardamos la clave encriptada en DB (RECOMENDADO), aquí la desencriptamos
        // const serviceKey = decrypt(config.SUPABASE_SERVICE_KEY);
        // Por ahora, asumimos que viene de la DB (asegúrate de encriptar al guardar en el futuro)
        const serviceKey = config.SUPABASE_SERVICE_KEY;

        res.json({
            url: config.SUPABASE_URL,
            key: serviceKey
        });
    } catch (e) {
        console.error("Error Internal Credentials:", e.message);
        res.status(500).json({ error: 'Internal Error' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER SECURED (api-master.vintex.net.br) en puerto ${PORT}`);
});