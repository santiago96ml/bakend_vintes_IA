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

// 1. TRUST PROXY: Vital para que Cloudflare/Proxies funcionen correctamente
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN DE CRIPTOGRAFÍA ---
// Necesitas añadir MASTER_ENCRYPTION_KEY (32 hex chars) a tu .env
if (!process.env.MASTER_ENCRYPTION_KEY) {
    console.error("⚠️ ADVERTENCIA: Falta MASTER_ENCRYPTION_KEY. La encriptación no funcionará correctamente.");
}

const ENCRYPTION_KEY = process.env.MASTER_ENCRYPTION_KEY
    ? Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex')
    : crypto.randomBytes(32); // Fallback temporal
const IV_LENGTH = 16;

// Funciones para proteger credenciales (opcional si decides guardar claves encriptadas)
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

// --- CONFIGURACIÓN DE DOMINIOS ---
const SATELLITE_URL = process.env.SATELLITE_URL || "https://api-clinica.vintex.net.br";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";
const ALLOWED_ORIGINS = [FRONTEND_URL, 'https://vintex.net.br', 'http://localhost:5173'];

// --- SEGURIDAD: HELMET & CORS ---
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
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret'],
    credentials: true
}));

app.use(express.json({ limit: '10kb' })); // Anti-DoS Body Size

// --- RATE LIMITING ---
// 3. Limitador General
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    limit: 150,
    message: { error: "Demasiadas peticiones." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// 4. Limitador Específico para Auth (Anti Brute-Force)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    message: { error: "Demasiados intentos de autenticación." }
});

// --- LOGGER SANITIZADO ---
const sanitizeLog = (obj) => {
    if (!obj) return obj;
    const copy = { ...obj };
    const sensitiveKeys = ['password', 'token', 'access_token', 'session', 'secret', 'dni', 'credit_card', 'cvv', 'phone', 'telefono', 'email', 'supab_service_key', 'jwt_secret'];
    Object.keys(copy).forEach(key => {
        if (sensitiveKeys.includes(key.toLowerCase())) {
            copy[key] = '***REDACTED***';
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
    full_name: z.string().min(2, "Nombre requerido")
});

const trialSchema = z.object({
    email: z.string().email(),
    fullName: z.string().min(2),
    phone: z.string().optional()
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string()
});

// Middleware de Validación
const validate = (schema) => (req, res, next) => {
    try {
        req.body = schema.parse(req.body);
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
        // 1. Crear usuario en Auth de Supabase
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email,
            password,
            options: { data: { full_name } }
        });

        if (authError) throw authError;
        if (!authData.user) throw new Error("No se pudo crear el usuario");

        const userId = authData.user.id;

        // 2. Crear registro en tabla pública 'users'
        const { error: userError } = await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: full_name,
            role: 'owner', // Rol por defecto para quien se registra
            subscription_status: 'trial'
        });

        if (userError) {
            // Nota: Si esto falla, idealmente deberíamos borrar el usuario de Auth (rollback manual)
            console.error("Error creando perfil público:", userError);
            throw userError;
        }

        res.status(201).json({ success: true, userId });

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
        // Lógica simplificada de trial
        // Aquí podrías reutilizar la lógica de registro o invocar una función específica
        console.log(`[INFO] Usuario Trial solicitado: ${email}`);
        
        // TODO: Implementar lógica real de creación de usuario trial
        // Por ahora, simulamos éxito
        res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });

    } catch (error) {
        console.error("Trial error:", error);
        res.status(500).json({ error: 'Error interno.' });
    }
});

app.post('/api/login', authLimiter, validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(401).json({ error: 'Credenciales inválidas.' });
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

    constHvtoken = authHeader.split(' ')[1];
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
            // Usuario registrado pero sin clínica asignada aún
            return res.json({ hasClinic: false });
        }

        return res.json({
            hasClinic: true,
            backendUrl: SATELLITE_URL, // https://api-clinica.vintex.net.br
            supabaseUrl: config.SUPABASE_URL,
            supabaseAnonKey: config.SUPABASE_ANON_KEY
        });
    } catch (e) {
        console.error("Init Session Error:", e);
        res.status(500).json({ error: 'Error de servidor' });
    }
});

// 2. Endpoint INTERNO para el Backend Satélite (Server-to-Server)
// Devuelve la SERVICE KEY para que el satélite pueda administrar su DB.
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

        res.json({
            url: config.SUPABASE_URL,
            key: config.SUPABASE_SERVICE_KEY // Ojo: Asegurar que esto viaja por HTTPS y red privada si es posible
        });
    } catch (e) {
        console.error("Error Internal Credentials:", e.message);
        res.status(500).json({ error: 'Internal Error' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 MASTER SERVER (api-master.vintex.net.br) en puerto ${PORT}`);
});