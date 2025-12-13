import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';
import OpenAI from 'openai'; 

dotenv.config();
const app = express();

// 1. TRUST PROXY
app.set('trust proxy', 1); 

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN CRIPTOGRAFÍA ---
if (!process.env.MASTER_ENCRYPTION_KEY) {
    console.warn("⚠️ ADVERTENCIA: Falta MASTER_ENCRYPTION_KEY. Usando clave temporal insegura.");
}
const ENCRYPTION_KEY = process.env.MASTER_ENCRYPTION_KEY 
    ? Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex') 
    : crypto.randomBytes(32); 
const IV_LENGTH = 16;

// Funciones Auxiliares Crypto
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

// --- CONFIGURACIÓN OPENROUTER (DEEPSEEK) ---
let openai;
if (process.env.OPENROUTER_API_KEY) {
    openai = new OpenAI({ 
        apiKey: process.env.OPENROUTER_API_KEY,
        baseURL: "https://openrouter.ai/api/v1", 
        defaultHeaders: {
            "HTTP-Referer": process.env.FRONTEND_URL || "https://vintex.net.br",
            "X-Title": "Vintex AI",
        }
    });
} else {
    console.error("❌ FALTA OPENROUTER_API_KEY en .env");
}

// --- DOMINIOS PERMITIDOS ---
const SATELLITE_URL = process.env.SATELLITE_URL || "https://api-clinica.vintex.net.br";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";
const ALLOWED_ORIGINS = [FRONTEND_URL, 'https://vintex.net.br', 'http://localhost:5173', 'http://localhost:3000'];

// --- MIDDLEWARES SEGURIDAD ---

// 1. Helmet
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

// 2. CORS (Limpiamos cabeceras de WhatsApp)
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`Bloqueo CORS para origen: ${origin}`);
            callback(new Error('Bloqueado por CORS'));
        }
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret'], // Quitamos x-hub-signature-256
    credentials: true
}));

// 3. Body Parser (Simplificado, ya no necesitamos rawBody)
app.use(express.json({ limit: '10kb' }));

// 4. Rate Limits
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300, 
    message: { error: "Demasiadas peticiones." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50, 
    message: { error: "Demasiados intentos de autenticación." }
});

const chatLimiter = rateLimit({
    windowMs: 3 * 60 * 60 * 1000, 
    limit: 100, 
    message: { error: "Límite de chat excedido." },
    standardHeaders: true,
    legacyHeaders: false,
});

// 5. Logger Sanitizado
const sanitizeLog = (obj) => {
    if (!obj) return obj;
    const copy = { ...obj };
    const sensitiveKeys = ['password', 'token', 'access_token', 'session', 'secret', 'dni', 'credit_card', 'cvv', 'phone', 'telefono', 'email', 'supab_service_key', 'jwt_secret', 'messages'];
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
    if (req.body && Object.keys(req.body).length > 0 && process.env.NODE_ENV !== 'production') {
         console.log('   Payload:', JSON.stringify(sanitizeLog(req.body), null, 2));
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

// --- SCHEMAS ZOD ---
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8, "Contraseña insegura"),
    full_name: z.string().min(2)
});

// ✅ RECUPERADO: Schema para Trial
const trialSchema = z.object({
    email: z.string().email(),
    fullName: z.string().min(2),
    phone: z.string().min(8)
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string()
});

const chatSchema = z.object({
    message: z.string().min(1).max(2000),
    threadId: z.string().optional() 
});

const onboardingSchema = z.object({
    companyName: z.string().min(2, "Nombre de empresa muy corto"),
    description: z.string().min(10, "Describe mejor tu empresa para la IA"),
    requirements: z.string().optional()
});

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- MIDDLEWARE AUTENTICACIÓN ---
const requireAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    
    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });
        req.user = user;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'No autorizado' });
    }
};

// --- ANTI PROMPT INJECTION ---
const detectPromptInjection = (text) => {
    const patterns = [
        /ignore previous instructions/i, /ignora tus instrucciones/i,
        /system prompt/i, /act as a/i, /actúa como/i, /reset instructions/i
    ];
    return patterns.some(pattern => pattern.test(text));
};

// =================================================================
// RUTAS DE NEGOCIO
// =================================================================

app.post('/api/register', authLimiter, validate(registerSchema), async (req, res) => {
  const { email, password, full_name } = req.body;
  try {
    const { data: authData, error: authError } = await masterSupabase.auth.signUp({
      email, password, options: { data: { full_name } }
    });
    if (authError) throw authError;
    if (!authData.user) throw new Error("Error en creación de usuario.");
    const userId = authData.user.id;

    const { error: userError } = await masterSupabase.from('users').insert({
        id: userId, email, full_name, role: 'admin', created_at: new Date()
    });
    
    if (userError) console.error("Error insertando user profile:", userError);

    await masterSupabase.from('servisi').insert({
        "ID_User": userId, web_clinica: false, "Bot_clinica": false
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

// ✅ RECUPERADA: Ruta para Start Trial
app.post('/api/start-trial', authLimiter, validate(trialSchema), async (req, res) => {
    const { email, fullName, phone } = req.body;
    const tempPassword = crypto.randomBytes(16).toString('hex') + "V!1";
    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email, password: tempPassword, options: { data: { full_name: fullName, phone } }
        });
        if (authError) throw authError;
        const userId = authData.user.id;
        await masterSupabase.from('users').insert({
            id: userId, email, full_name, phone, role: 'admin'
        });
        await masterSupabase.from('servisi').insert({
            "ID_User": userId, web_clinica: false, "Bot_clinica": false
        });
        console.log(`[INFO] Usuario Trial creado: ${email}`); 
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
// RUTA DE AUTOMATIZACIÓN (Onboarding + n8n)
// =================================================================

app.post('/api/onboarding/complete', requireAuth, validate(onboardingSchema), async (req, res) => {
    const { companyName, description } = req.body;
    const user = req.user;
    const N8N_URL = process.env.N8N_DEPLOY_WEBHOOK_URL; 

    if (!N8N_URL) {
        console.error("❌ ERROR CRÍTICO: Faltan N8N_DEPLOY_WEBHOOK_URL en .env");
        return res.status(500).json({ error: "Error de configuración del sistema." });
    }

    try {
        console.log(`🚀 [AUTOMATION] Iniciando despliegue para Usuario: ${user.id}`);

        const { error: updateError } = await masterSupabase.from('users').update({ 
            subscription_status: 'active',
            plan_type: 'pro',
            last_payment_date: new Date(),
        }).eq('id', user.id);

        if (updateError) console.warn("Advertencia al actualizar usuario:", updateError.message);

        const payload = {
            userId: user.id,
            email: user.email,
            companyName: companyName,
            description: description,
            source: "web_onboarding"
        };

        fetch(N8N_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(response => {
            if (!response.ok) console.error(`⚠️ n8n respondió con error: ${response.status}`);
            else console.log("✅ Webhook n8n entregado correctamente.");
        })
        .catch(err => console.error("🔥 Error contactando a n8n:", err.message));

        res.json({ success: true, message: "Despliegue iniciado." });

    } catch (error) {
        console.error("Error Fatal en Onboarding:", error);
        res.status(500).json({ error: "Error procesando el despliegue." });
    }
});

// =================================================================
// 🧠 RUTA CHAT IA (OpenRouter / DeepSeek)
// =================================================================

app.post('/chat', requireAuth, chatLimiter, validate(chatSchema), async (req, res) => {
    const { message } = req.body; 
    const userId = req.user.id;

    if (detectPromptInjection(message)) {
        console.warn(`[SECURITY] Prompt Injection detectado User: ${userId}`);
        return res.status(400).json({ error: "Entrada no permitida." });
    }

    try {
        const completion = await openai.chat.completions.create({
            model: "tngtech/deepseek-r1t2-chimera:free", 
            messages: [
                { 
                    role: "system", 
                    content: "Eres Vintex AI, un asistente experto en gestión de clínicas y negocios. Responde de forma breve, profesional y útil." 
                },
                { role: "user", content: message }
            ],
            temperature: 0.7,
            max_tokens: 1000,
        });

        const responseText = completion.choices[0]?.message?.content || "No pude generar una respuesta.";

        res.json({ response: responseText });

    } catch (e) {
        console.error("Error Chat OpenRouter:", e);
        res.status(503).json({ error: "El servicio de IA está ocupado, intenta de nuevo." });
    }
});

// =================================================================
// RUTAS INFRAESTRUCTURA
// =================================================================

app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });
        
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_ANON_KEY')
            .eq('ID_USER', user.id)
            .single();
            
        if (!config) return res.status(200).json({ hasClinic: false });
        
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

app.post('/api/internal/get-clinic-credentials', async (req, res) => {
    const internalSecret = req.headers['x-internal-secret'];
    if (!internalSecret || internalSecret !== process.env.INTERNAL_SECRET_KEY) {
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
        
        res.json({ url: config.SUPABASE_URL, key: config.SUPABASE_SERVICE_KEY });
    } catch (e) {
        console.error("Error Internal Credentials:", e.message);
        res.status(500).json({ error: 'Internal Error' });
    }
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER SECURED (api-master.vintex.net.br) en puerto ${PORT}`);
});
server.setTimeout(30000);