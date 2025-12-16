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

// 1. TRUST PROXY (Importante para Rate Limits tras proxys como Easypanel/Cloudflare)
app.set('trust proxy', 1); 

const PORT = process.env.PORT || 3000;

// --- 🔒 SEGURIDAD: CONFIGURACIÓN CRIPTOGRAFÍA ---
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

// --- CONFIGURACIÓN OPENROUTER (IA) ---
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

// --- 🔒 SEGURIDAD: DOMINIOS PERMITIDOS (CORS ESTRICTO) ---
const SATELLITE_URL = process.env.SATELLITE_URL || "https://api-clinica.vintex.net.br";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";
const HOSTINGER_URL = "https://webs-de-vintex-login-web.1kh9sk.easypanel.host";

const ALLOWED_ORIGINS = [
    FRONTEND_URL, 
    HOSTINGER_URL,
    'https://vintex.net.br', 
    'http://localhost:5173', // Desarrollo Local
    'http://localhost:3000'
];

// --- MIDDLEWARES SEGURIDAD ---

// 1. Helmet (Cabeceras HTTP seguras)
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

// 2. CORS (Modo Estricto)
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`[CORS SECURITY] Bloqueo para origen no autorizado: ${origin}`);
            callback(new Error('Bloqueado por CORS')); 
        }
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret'], 
    credentials: true
}));

// 3. Body Parser (LÍMITE AUMENTADO PARA CHAT LARGO)
app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 4. Rate Limits (Protección contra DDOS y Fuerza Bruta)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300, 
    message: { error: "Demasiadas peticiones. Intenta más tarde." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50, 
    message: { error: "Demasiados intentos de autenticación. Seguridad activada." }
});

const chatLimiter = rateLimit({
    windowMs: 3 * 60 * 60 * 1000, 
    limit: 100, 
    message: { error: "Límite de chat excedido por seguridad." },
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

// --- SCHEMAS ZOD (Validación de Datos) ---
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
    message: z.string().min(1).max(2000),
    threadId: z.string().optional() 
});

const onboardingChatSchema = z.object({
    messages: z.array(z.object({
        role: z.enum(['user', 'assistant', 'system']),
        content: z.string()
    }))
});

const onboardingCompleteSchema = z.object({
    conversationSummary: z.string().min(10),
    schemaConfig: z.any().optional()
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

// --- 🔒 SEGURIDAD: ANTI PROMPT INJECTION ---
const detectPromptInjection = (text) => {
    const patterns = [
        /ignore previous instructions/i, /ignora tus instrucciones/i,
        /system prompt/i, /act as a/i, /actúa como/i, /reset instructions/i,
        /eres un bot/i, /your core directive/i
    ];
    if (typeof text === 'string') {
        return patterns.some(pattern => pattern.test(text));
    } else if (Array.isArray(text)) {
        return text.some(msg => patterns.some(pattern => pattern.test(msg.content || "")));
    }
    return false;
};

// =================================================================
// RUTAS DE NEGOCIO
// =================================================================

// 1. REGISTRO
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
        "ID_User": userId, 
        web_clinica: true, 
        "Bot_clinica": true 
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

// 2. START TRIAL
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
            "ID_User": userId, web_clinica: true, "Bot_clinica": true 
        });
        console.log(`[INFO] Usuario Trial creado: ${email}`); 
        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });
    } catch (error) {
        console.error("Trial error:", error.message);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// 3. LOGIN
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

// 4. CHAT ARQUITECTO (Onboarding)
app.post('/api/onboarding/chat', requireAuth, validate(onboardingChatSchema), async (req, res) => {
    const { messages } = req.body;
    const userId = req.user.id;

    if (detectPromptInjection(messages)) {
        console.warn(`[SECURITY] Prompt Injection detectado en Onboarding. User: ${userId}`);
        return res.status(400).json({ error: "Entrada no permitida por políticas de seguridad." });
    }
    
    const systemPrompt = `Eres "Vintex Architect", un Consultor de Producto experto en diseñar aplicaciones de gestión estilo Airtable/No-Code.
TU OBJETIVO: Entrevistar al usuario para definir su modelo de negocio y, CRÍTICAMENTE, cómo quiere VISUALIZAR sus datos.

REGLAS DE INTERACCIÓN:
1.  Haz UNA sola pregunta a la vez.
2.  Mantén un tono profesional pero cercano.
3.  Tu objetivo final es generar un "RESUMEN TÉCNICO" que servirá de input para un sistema automático.

FASES DE LA ENTREVISTA:

FASE 1: EL NEGOCIO
- Pregunta: "¡Hola! Vamos a construir tu app. Primero, ¿cuál es el nombre de tu proyecto y a qué se dedica principalmente?"
- Objetivo: Identificar el rubro (Clínica, Taller, Tienda, etc.).

FASE 2: LOS DATOS (ENTIDADES)
- Basado en el rubro, sugiere las entidades principales.
- Pregunta: "Para gestionar [Negocio], necesitaremos registrar cosas. Por ejemplo: Clientes, Pedidos, Inventario. ¿Cuáles son las 3 cosas más importantes que necesitas controlar?"

FASE 3: VISTAS Y EXPERIENCIA (CRÍTICO PARA UI)
- Aquí debes definir el diseño.
- PREGUNTA OBLIGATORIA: "Hablemos de cómo quieres trabajar. Para tus datos principales (como [Entidad mencionada]), ¿te gustaría verlos en un CALENDARIO (para fechas), en un TABLERO KANBAN (para mover tarjetas por etapas como 'Pendiente' -> 'Listo'), o prefieres una lista simple?"
- Si eligen Kanban: Pregunta "¿Qué estados debería tener? (Ej: Pendiente, En Proceso, Finalizado)".
- Si eligen Calendario: Confirma qué fecha es la importante (Ej: Fecha de Cita, Fecha de Entrega).

FASE 4: CAMPOS ESPECIALES
- Pregunta: "¿Necesitas guardar archivos adjuntos (fotos/PDFs) o cobrar a través de la app?"

CIERRE Y GENERACIÓN:
- Cuando tengas todo claro, di: "Perfecto, tengo la estructura lista. Procedo a generar tu configuración."
- IMPORTANTE: Tu último mensaje DEBE incluir un bloque llamado "MEMORIA TÉCNICA" con este formato exacto (para que la IA de backend lo lea):

--- MEMORIA TÉCNICA ---
NEGOCIO: [Nombre]
RUBRO: [Rubro]
TABLAS PRINCIPALES: [Lista de tablas]
VISTA PREFERIDA: [CALENDARIO / KANBAN / LISTA / GALERÍA]
ESTADOS KANBAN: [Lista de estados o N/A]
FUNCIONALIDADES EXTRA: [Pagos, Archivos, etc.]
RESUMEN: [Breve descripción de 2 líneas del flujo completo]
-----------------------`;

    try {
        const completion = await openai.chat.completions.create({
            model: "nvidia/nemotron-3-nano-30b-a3b:free", 
            messages: [
                { role: "system", content: systemPrompt },
                ...messages
            ],
            temperature: 0.5,
            max_tokens: 600,
        });

        res.json({ response: completion.choices[0]?.message?.content });
    } catch (e) {
        console.error("Error Arquitecto:", e);
        res.status(503).json({ error: "El arquitecto está pensando... reintenta." });
    }
});

// 5. COMPLETAR ONBOARDING (MODIFICADO: CON FALLBACK DE USUARIO)
app.post('/api/onboarding/complete', requireAuth, validate(onboardingCompleteSchema), async (req, res) => {
    const { conversationSummary, schemaConfig } = req.body;
    const user = req.user;
    const N8N_URL = process.env.N8N_DEPLOY_WEBHOOK_URL; 

    if (!N8N_URL) {
        return res.status(500).json({ error: "Error de configuración del sistema." });
    }

    try {
        console.log(`🚀 [AUTOMATION] Iniciando despliegue para Usuario: ${user.id}`);

        // --- 🛡️ PASO DE SEGURIDAD: VERIFICAR/CREAR USUARIO ---
        // Verificamos si el usuario ya tiene perfil en la tabla 'users'
        const { data: existingUser } = await masterSupabase
            .from('users')
            .select('id')
            .eq('id', user.id)
            .single();

        if (!existingUser) {
            console.log(`⚠️ Usuario ${user.id} no encontrado en tabla pública. Creándolo ahora...`);
            
            // Lo creamos manualmente usando los datos del Token (Google)
            const { error: insertError } = await masterSupabase.from('users').insert({
                id: user.id,
                email: user.email,
                // Intentamos sacar el nombre de los metadatos de Google, o usamos el email
                full_name: user.user_metadata?.full_name || user.email.split('@')[0],
                role: 'admin',
                created_at: new Date()
            });

            if (insertError) {
                console.error("❌ Error creando usuario fallback:", insertError);
                throw new Error("No se pudo crear el perfil del usuario.");
            }
        }
        // -----------------------------------------------------

        // Ahora sí, actualizamos el estado (Ya es seguro porque el usuario existe)
        const { error: updateError } = await masterSupabase.from('users').update({ 
            subscription_status: 'active',
            plan_type: 'pro',
            last_payment_date: new Date(),
        }).eq('id', user.id);

        if (updateError) console.warn("Advertencia al actualizar usuario:", updateError.message);

        // Disparamos n8n
        const payload = {
            userId: user.id,
            email: user.email,
            companyName: schemaConfig?.appName || "Mi Negocio",
            description: conversationSummary, 
            source: "chat_onboarding_architect"
        };

        fetch(N8N_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).catch(err => console.error("🔥 Error contactando a n8n:", err.message));

        // Placeholders DB
        const { error: dbError } = await masterSupabase
            .from('web_clinica')
            .upsert({ 
                "ID_USER": user.id,
                "SUPABASE_URL": "https://building.vintex.ai",
                "SUPABASE_ANON_KEY": "building",
                "SUPABASE_SERVICE_KEY": "building",
                "JWT_SECRET": "building",
                "url_backend": "https://building.vintex.ai",
                "status": "building" // Marcamos que se está construyendo
            }, { onConflict: "ID_USER" });

        if (dbError) throw dbError;

        res.json({ success: true, message: "Despliegue iniciado." });

    } catch (error) {
        console.error("Error Fatal en Onboarding:", error);
        res.status(500).json({ error: "Error procesando el despliegue." });
    }
});

// 6. CHAT GENERAL
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
                    content: "Eres Vintex AI, un asistente experto en gestión de clínicas y negocios." 
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
// RUTAS INFRAESTRUCTURA (Configuración Dinámica)
// =================================================================

app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.split(' ')[1];
    
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });
        
        // --- MODIFICACIÓN CLAVE PARA SERVER-DRIVEN UI ---
        // Ahora seleccionamos también 'ui_config'
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_ANON_KEY, ui_config')
            .eq('ID_USER', user.id)
            .single();
            
        if (!config) return res.status(200).json({ hasClinic: false });
        
        return res.json({
            hasClinic: true, 
            backendUrl: SATELLITE_URL, 
            supabaseUrl: config.SUPABASE_URL, 
            supabaseAnonKey: config.SUPABASE_ANON_KEY,
            uiConfig: config.ui_config 
        });
    } catch (e) {
        console.error("Error Init Session:", e.message);
        return res.status(500).json({ error: 'Error recuperando configuración.' });
    }
});

// Ruta interna para n8n u otros servicios
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