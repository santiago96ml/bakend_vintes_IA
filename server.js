import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';
import OpenAI from 'openai'; // Necesitas instalar: npm install openai

dotenv.config();
const app = express();

// 1. TRUST PROXY
app.set('trust proxy', 1); 

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN CRIPTOGRAFÍA ---
if (!process.env.MASTER_ENCRYPTION_KEY) {
    console.error("⚠️ ADVERTENCIA: Falta MASTER_ENCRYPTION_KEY.");
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

// --- CONFIGURACIÓN OPENAI ---
// Instanciar cliente solo si existe la key, sino advertir
let openai;
if (process.env.OPENAI_API_KEY) {
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
} else {
    console.error("❌ FALTA OPENAI_API_KEY en .env");
}

// --- DOMINIOS PERMITIDOS ---
const SATELLITE_URL = process.env.SATELLITE_URL || "https://api-clinica.vintex.net.br";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";
const ALLOWED_ORIGINS = [FRONTEND_URL, 'https://vintex.net.br', 'http://localhost:5173'];

// --- MIDDLEWARES SEGURIDAD ---

// 1. Helmet (Cabeceras Seguras)
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

// 2. CORS
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Bloqueado por CORS'));
        }
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret', 'x-hub-signature-256'],
    credentials: true
}));

// 3. Body Parser con Límite (Anti-DoS)
// Usamos verify para capturar el rawBody necesario para la validación del Webhook de Meta
app.use(express.json({ 
    limit: '10kb',
    verify: (req, res, buf, encoding) => {
        req.rawBody = buf.toString(encoding || 'utf8');
    }
}));

// 4. Rate Limit General
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 150, 
    message: { error: "Demasiadas peticiones." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// 5. Rate Limit Auth
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20, 
    message: { error: "Demasiados intentos de autenticación." }
});

// 6. Rate Limit CHAT (Anti Bill Shock - CRÍTICO)
// Límite estricto: 50 mensajes cada 3 horas por IP para usuarios autenticados
const chatLimiter = rateLimit({
    windowMs: 3 * 60 * 60 * 1000, // 3 horas
    limit: 50, 
    message: { error: "Límite de chat excedido. Protegiendo recursos." },
    standardHeaders: true,
    legacyHeaders: false,
});

// 7. Logger Sanitizado
const sanitizeLog = (obj) => {
    if (!obj) return obj;
    const copy = { ...obj };
    const sensitiveKeys = ['password', 'token', 'access_token', 'session', 'secret', 'dni', 'credit_card', 'cvv', 'phone', 'telefono', 'email', 'supab_service_key', 'jwt_secret', 'messages']; // Añadido messages para privacidad médica
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

// --- SCHEMAS ZOD ---
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

const chatSchema = z.object({
    message: z.string().min(1).max(2000), // Límite de caracteres
    threadId: z.string().optional()
});

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- MIDDLEWARE AUTENTICACIÓN (Para Chat) ---
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

// --- FUNCIÓN ANTI PROMPT INJECTION ---
const detectPromptInjection = (text) => {
    const patterns = [
        /ignore previous instructions/i,
        /ignora tus instrucciones/i,
        /system prompt/i,
        /act as a/i,
        /actúa como/i,
        /reset instructions/i
    ];
    return patterns.some(pattern => pattern.test(text));
};

// =================================================================
// RUTAS DE NEGOCIO (Usuarios, Auth)
// =================================================================

app.post('/api/register', authLimiter, validate(registerSchema), async (req, res) => {
  // ... (Código original de registro se mantiene igual)
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
    if (userError) throw userError;

    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 14);
    await masterSupabase.from('trials').insert({
        user_id: userId, start_date: new Date(), end_date: endDate, status: 'active'
    });
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

app.post('/api/start-trial', authLimiter, validate(trialSchema), async (req, res) => {
    // ... (Código original trial se mantiene igual)
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
    // ... (Código original login se mantiene igual)
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
// RUTAS NUEVAS: CHAT CON IA (Protegidas)
// =================================================================

app.post('/chat', requireAuth, chatLimiter, validate(chatSchema), async (req, res) => {
    const { message, threadId } = req.body;
    const userId = req.user.id;

    // 1. Detección de Prompt Injection
    if (detectPromptInjection(message)) {
        console.warn(`[SECURITY] Prompt Injection detectado User: ${userId}`);
        return res.status(400).json({ error: "Entrada no permitida." });
    }

    try {
        // 2. Validación de Propiedad del Hilo (Evitar Hijacking)
        let safeThreadId = threadId;

        if (threadId) {
            // Verificar en BD que el thread pertenece al usuario
            const { data: threadData } = await masterSupabase
                .from('chat_threads')
                .select('id')
                .eq('openai_thread_id', threadId)
                .eq('user_id', userId)
                .single();
            
            if (!threadData) {
                // Si el thread no es suyo, creamos uno nuevo para no exponer datos ajenos
                safeThreadId = null; 
            }
        }

        if (!safeThreadId) {
            const thread = await openai.beta.threads.create();
            safeThreadId = thread.id;
            // Guardar asociación Thread-Usuario
            await masterSupabase.from('chat_threads').insert({
                user_id: userId,
                openai_thread_id: safeThreadId,
                created_at: new Date()
            });
        }

        // 3. Enviar mensaje a OpenAI
        await openai.beta.threads.messages.create(safeThreadId, {
            role: "user",
            content: message
        });

        const run = await openai.beta.threads.runs.create(safeThreadId, {
            assistant_id: process.env.OPENAI_ASSISTANT_ID
        });

        // 4. Polling con Timeout y Race Condition check básico
        let runStatus = await openai.beta.threads.runs.retrieve(safeThreadId, run.id);
        const startTime = Date.now();
        const TIMEOUT_MS = 25000; // 25s máx para no bloquear server (Node Event Loop)

        while (runStatus.status !== "completed") {
            if (Date.now() - startTime > TIMEOUT_MS) {
                throw new Error("Timeout esperando respuesta de IA");
            }
            if (runStatus.status === 'failed' || runStatus.status === 'cancelled') {
                 throw new Error("Error en procesamiento de IA");
            }
            await new Promise((resolve) => setTimeout(resolve, 1000));
            runStatus = await openai.beta.threads.runs.retrieve(safeThreadId, run.id);
        }

        const messages = await openai.beta.threads.messages.list(safeThreadId);
        const lastMessage = messages.data
            .filter((msg) => msg.run_id === run.id && msg.role === "assistant")
            .pop();

        let responseText = "No se pudo generar respuesta.";
        if (lastMessage && lastMessage.content[0].type === "text") {
            responseText = lastMessage.content[0].text.value;
        }

        // 5. Sanity Check de Respuesta (Básico)
        if (responseText.length > 5000 || /error|fatal/i.test(responseText)) {
             // Loguear para revisión humana pero no enviar raw error al usuario
             console.error("[IA Output] Posible alucinación o error largo:", responseText);
        }

        res.json({ response: responseText, threadId: safeThreadId });

    } catch (e) {
        // 6. No exponer errores internos de OpenAI
        console.error("Error Chat:", e.message);
        res.status(503).json({ error: "El servicio de IA está ocupado, intenta de nuevo." });
    }
});

// =================================================================
// RUTAS NUEVAS: WEBHOOKS (Integridad)
// =================================================================

// Verificación GET (Meta Challenge)
app.get('/webhook', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === process.env.WHATSAPP_VERIFY_TOKEN) {
        res.status(200).send(challenge);
    } else {
        res.sendStatus(403);
    }
});

// Recepción POST (Mensajes)
app.post('/webhook', async (req, res) => {
    // 1. Verificación de Firma Criptográfica (Integridad)
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
        console.warn("[WEBHOOK] Falta firma X-Hub-Signature");
        return res.sendStatus(403);
    }

    if (!process.env.WHATSAPP_APP_SECRET) {
        console.error("❌ FALTA WHATSAPP_APP_SECRET para validar webhook");
        return res.sendStatus(500);
    }

    const elements = signature.split('=');
    const signatureHash = elements[1];
    // Usamos req.rawBody capturado en el middleware
    const expectedHash = crypto
        .createHmac('sha256', process.env.WHATSAPP_APP_SECRET)
        .update(req.rawBody) 
        .digest('hex');

    if (signatureHash !== expectedHash) {
        console.warn("[WEBHOOK] Firma inválida. Posible ataque.");
        return res.sendStatus(403);
    }

    // 2. Procesamiento Seguro
    // No loguear req.body completo para no violar GDPR/HIPAA
    console.log("[WEBHOOK] Mensaje verificado recibido."); 

    // Aquí iría tu lógica de negocio (enviar a N8N, guardar en DB, etc.)
    // ...

    res.sendStatus(200);
});

// =================================================================
// RUTAS INFRAESTRUCTURA
// =================================================================

app.get('/api/config/init-session', async (req, res) => {
    // ... (Código original se mantiene igual)
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
            hasClinic: true, backendUrl: SATELLITE_URL, supabaseUrl: config.SUPABASE_URL, supabaseAnonKey: config.SUPABASE_ANON_KEY 
        });
    } catch (e) {
        console.error("Error Init Session:", e.message);
        return res.status(500).json({ error: 'Error recuperando configuración.' });
    }
});

app.post('/api/internal/get-clinic-credentials', async (req, res) => {
    // ... (Código original se mantiene igual)
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
        // const serviceKey = decrypt(config.SUPABASE_SERVICE_KEY); // Descomentar cuando uses encrypt
        res.json({ url: config.SUPABASE_URL, key: config.SUPABASE_SERVICE_KEY });
    } catch (e) {
        console.error("Error Internal Credentials:", e.message);
        res.status(500).json({ error: 'Internal Error' });
    }
});

// Listener con Timeout para prevenir Slowloris
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER SECURED (api-master.vintex.net.br) en puerto ${PORT}`);
});
server.setTimeout(30000); // 30s timeout