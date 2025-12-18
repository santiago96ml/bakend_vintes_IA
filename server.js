import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import rateLimit from 'express-rate-limit'; // Corregido: importación por defecto suele ser mejor aquí
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';
import OpenAI from 'openai';
import multer from 'multer';
import * as xlsx from 'xlsx'; // Corregido: Importación compatible con ESM
import { Readable } from 'stream';
import pg from 'pg';

dotenv.config();
const app = express();

// 1. TRUST PROXY
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN POOL DE BASE DE DATOS (Para crear tablas) ---
if (!process.env.DATABASE_URL) {
    console.warn("⚠️ ADVERTENCIA: Falta DATABASE_URL. La construcción automática de tablas fallará.");
}
const dbPool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

// Manejo de errores del pool para evitar caídas
dbPool.on('error', (err) => {
    console.error('🔥 Error inesperado en el cliente PG inactivo', err);
});

// --- SEGURIDAD Y CONFIGURACIÓN GENERAL ---
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
    try {
        let textParts = text.split(':');
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error("Error desencriptando:", error);
        return null;
    }
}

// Configuración OpenRouter (IA)
let openai;
if (process.env.OPENROUTER_API_KEY) {
    openai = new OpenAI({
        apiKey: process.env.OPENROUTER_API_KEY,
        baseURL: "[https://openrouter.ai/api/v1](https://openrouter.ai/api/v1)",
        defaultHeaders: {
            "HTTP-Referer": process.env.FRONTEND_URL || "[https://vintex.net.br](https://vintex.net.br)",
            "X-Title": "Vintex AI",
        }
    });
} else {
    console.error("❌ FALTA OPENROUTER_API_KEY en .env");
}

const SATELLITE_URL = process.env.SATELLITE_URL || "[https://api-clinica.vintex.net.br](https://api-clinica.vintex.net.br)";
const FRONTEND_URL = process.env.FRONTEND_URL || "[https://vintex.net.br](https://vintex.net.br)";
const HOSTINGER_URL = "[https://webs-de-vintex-login-web.1kh9sk.easypanel.host](https://webs-de-vintex-login-web.1kh9sk.easypanel.host)";

const ALLOWED_ORIGINS = [
    FRONTEND_URL,
    HOSTINGER_URL,
    '[https://vintex.net.br](https://vintex.net.br)',
    'http://localhost:5173',
    'http://localhost:3000'
];

// --- MIDDLEWARES ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], upgradeInsecureRequests: [] },
    },
    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) { callback(null, true); } 
        else { console.warn(`[CORS] Bloqueo: ${origin}`); callback(new Error('Bloqueado por CORS')); }
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret'],
    credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// Rate Limits
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300 });
app.use(limiter);
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 50 });
const chatLimiter = rateLimit({ windowMs: 3 * 60 * 60 * 1000, limit: 100 });

// Logger
app.use((req, res, next) => {
    console.log(`\n🔵 [REQUEST] ${req.method} ${req.url}`);
    next();
});

// --- SUPABASE MASTER ---
const masterSupabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- SCHEMAS ZOD ---
const loginSchema = z.object({ email: z.string().email(), password: z.string() });
const registerSchema = z.object({ email: z.string().email(), password: z.string().min(8), full_name: z.string().min(2) });
const trialSchema = z.object({ email: z.string().email(), fullName: z.string().min(2), phone: z.string().min(8) });
const chatSchema = z.object({ message: z.string().min(1).max(2000), threadId: z.string().optional() });
const onboardingCompleteSchema = z.object({ conversationSummary: z.string().min(10), schemaConfig: z.any().optional() });
const onboardingChatSchema = z.object({ messages: z.array(z.any()) });

const validate = (schema) => (req, res, next) => {
    try { schema.parse(req.body); next(); } 
    catch (e) { return res.status(400).json({ error: 'Datos inválidos', details: e.errors }); }
};

// Middleware Auth
const requireAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });
        req.user = user;
        next();
    } catch (e) { return res.status(401).json({ error: 'No autorizado' }); }
};

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

// --- 🧠 FUNCIÓN MAESTRA: CONSTRUCTOR DE SISTEMAS (Reemplaza a n8n) ---
async function buildSystemWithAI(userId, summary) {
    console.log(`🏗️ [CONSTRUCTOR] Iniciando obra para usuario: ${userId}`);
    
    if (!openai) {
        console.error("🔥 Error: OpenAI no inicializado. Abortando construcción.");
        return;
    }

    const dbClient = await dbPool.connect(); 

    try {
        const systemPrompt = `
        ERES UN INGENIERO DE BASES DE DATOS POSTGRESQL EXPERTO.
        TU TAREA: Generar un script SQL ejecutable basado en los requisitos del usuario.
        
        REQUISITOS DEL USUARIO:
        "${summary}"
        
        REGLAS CRÍTICAS DE SEGURIDAD Y DISEÑO:
        1.  TODAS las tablas deben tener RLS (Row Level Security) activado.
        2.  TODAS las tablas deben tener una columna "user_id" tipo UUID que referencie a 'auth.users(id)'.
        3.  Crea una política RLS para cada tabla que permita al usuario ver/editar SOLO sus filas:
            Example: CREATE POLICY "Users can manage own data" ON table_name USING (auth.uid() = user_id);
        4.  Usa tipos de datos adecuados (TEXT, BOOLEAN, TIMESTAMPTZ, NUMERIC).
        5.  NO borres tablas existentes (usa CREATE TABLE IF NOT EXISTS).
        6.  Devuelve SOLO el código SQL, sin explicaciones ni markdown (nada de \`\`\`sql).
        `;

        const completion = await openai.chat.completions.create({
            model: "meta-llama/llama-3.3-70b-instruct:free", 
            messages: [{ role: "system", content: systemPrompt }],
            temperature: 0.2,
        });

        let sqlCode = completion.choices[0].message.content;
        
        // Limpieza robusta del SQL (Elimina bloques de markdown si existen)
        const sqlMatch = sqlCode.match(/```sql([\s\S]*?)```/) || sqlCode.match(/```([\s\S]*?)```/);
        if (sqlMatch) {
            sqlCode = sqlMatch[1].trim();
        } else {
            sqlCode = sqlCode.trim();
        }
        
        // Limpiar palabras clave peligrosas muy básicas (opcional, pero recomendado)
        if (sqlCode.toLowerCase().includes('drop table') || sqlCode.toLowerCase().includes('drop database')) {
             console.warn("⚠️ ALERTA: La IA intentó borrar tablas. Se bloqueará la ejecución.");
             throw new Error("Código SQL inseguro detectado.");
        }

        console.log(`📜 SQL Generado (Preview): ${sqlCode.substring(0, 100)}...`);

        await dbClient.query('BEGIN'); 
        await dbClient.query(sqlCode);

        const defaultUiConfig = {
            theme: { primary: "#00E599", mode: "dark" },
            generatedAt: new Date().toISOString()
        };

        await dbClient.query(`
            UPDATE public.web_clinica 
            SET status = 'active', 
                ui_config = $1 
            WHERE "ID_USER" = $2
        `, [JSON.stringify(defaultUiConfig), userId]);

        await dbClient.query('COMMIT');
        console.log(`✅ [CONSTRUCTOR] Sistema desplegado con éxito para ${userId}`);

    } catch (error) {
        await dbClient.query('ROLLBACK');
        console.error("🔥 [CONSTRUCTOR ERROR]:", error);
    } finally {
        dbClient.release();
    }
}

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

    // Verificar si el usuario ya existe en public.users para evitar duplicados si auth falló a medias
    const { error: userError } = await masterSupabase.from('users').upsert({
        id: userId, email, full_name, role: 'admin', created_at: new Date()
    }, { onConflict: 'id' });
    
    if (userError) console.error("Error insertando user profile:", userError);

    await masterSupabase.from('servisi').upsert({
        "ID_User": userId, web_clinica: true, "Bot_clinica": true 
    }, { onConflict: 'ID_User' });

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
        await masterSupabase.from('users').upsert({
            id: userId, email, full_name: fullName, phone, role: 'admin'
        });
        await masterSupabase.from('servisi').upsert({ 
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

// 4. CHAT ARQUITECTO (Onboarding Interactivo)
app.post('/api/onboarding/interactive', requireAuth, upload.single('file'), async (req, res) => {
    const { message } = req.body;
    const file = req.file;
    const userId = req.user.id;

    if (!openai) return res.status(503).json({ error: "IA no disponible" });

    try {
        let { data: session } = await masterSupabase.from('onboarding_session').select('*').eq('user_id', userId).maybeSingle();
        if (!session) {
            const { data: newS } = await masterSupabase.from('onboarding_session').insert({ user_id: userId, extracted_context: {} }).select().single();
            session = newS;
        }

        let fileContext = "";
        if (file && (file.mimetype.includes('csv') || file.mimetype.includes('spreadsheet'))) {
            const workbook = xlsx.read(file.buffer, { type: 'buffer' });
            const sheet = workbook.Sheets[workbook.SheetNames[0]];
            const dataPreview = xlsx.utils.sheet_to_json(sheet, { header: 1 }).slice(0, 10);
            fileContext = `[ARCHIVO ADJUNTO] El usuario subió datos. Estructura: ${JSON.stringify(dataPreview)}`;
        }

        const systemPrompt = `
        Eres Vintex Architect. Entrevista al usuario para crear su software.
        Memoria: ${JSON.stringify(session.extracted_context)}
        Responde JSON: { "reply": "...", "updated_context": {...}, "is_ready": boolean }
        `;

        const completion = await openai.chat.completions.create({
            model: "meta-llama/llama-3.3-70b-instruct:free",
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: `User: ${message}. ${fileContext}` }
            ],
            response_format: { type: "json_object" }
        });

        const aiData = JSON.parse(completion.choices[0].message.content);

        // Validar que conversation_history sea array
        const history = Array.isArray(session.conversation_history) ? session.conversation_history : [];

        await masterSupabase.from('onboarding_session').update({
            conversation_history: [...history, { user: message, bot: aiData.reply }],
            extracted_context: aiData.updated_context,
            analysis_status: aiData.is_ready ? 'ready' : 'listening'
        }).eq('session_id', session.session_id);

        res.json(aiData);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Error pensando..." });
    }
});

// 5. COMPLETAR ONBOARDING (¡AHORA SIN N8N!) 🚀
app.post('/api/onboarding/complete', requireAuth, validate(onboardingCompleteSchema), async (req, res) => {
    const { conversationSummary } = req.body;
    const user = req.user;

    try {
        console.log(`🚀 Iniciando despliegue LOCAL para Usuario: ${user.id}`);

        // --- AUTO-REPARACIÓN (UPSERT) ---
        await masterSupabase.from('users').upsert({
            id: user.id,
            email: user.email,
            full_name: user.email.split('@')[0],
            role: 'admin',
            created_at: new Date()
        }, { onConflict: 'id', ignoreDuplicates: true });

        await masterSupabase.from('servisi').upsert({
            "ID_User": user.id, web_clinica: true, "Bot_clinica": true
        }, { onConflict: "ID_User", ignoreDuplicates: true });

        // --- ESTADO INICIAL: BUILDING ---
        const { error: dbError } = await masterSupabase.from('web_clinica').upsert({ 
            "ID_USER": user.id,
            "SUPABASE_URL": "[https://building.vintex.ai](https://building.vintex.ai)",
            "SUPABASE_ANON_KEY": "building",
            "SUPABASE_SERVICE_KEY": "building",
            "JWT_SECRET": "building",
            "status": "building" 
        }, { onConflict: "ID_USER" });

        if (dbError) throw dbError;

        // --- 🔥 EL REEMPLAZO DE N8N 🔥 ---
        // Se ejecuta sin await para no bloquear la respuesta HTTP
        buildSystemWithAI(user.id, conversationSummary).catch(err => 
            console.error("🔥 Error asíncrono en constructor:", err)
        );

        res.json({ success: true, message: "Arquitecto trabajando en segundo plano..." });

    } catch (error) {
        console.error("Error Onboarding:", error);
        res.status(500).json({ error: "Error iniciando construcción." });
    }
});

// 6. CHAT GENERAL (Legacy)
app.post('/chat', requireAuth, chatLimiter, validate(chatSchema), async (req, res) => {
    const { message } = req.body; 
    const userId = req.user.id;

    if (detectPromptInjection(message)) {
        console.warn(`[SECURITY] Prompt Injection detectado User: ${userId}`);
        return res.status(400).json({ error: "Entrada no permitida." });
    }

    if (!openai) return res.status(503).json({ error: "Servicio de IA no disponible" });

    try {
        const completion = await openai.chat.completions.create({
            model: "tngtech/deepseek-r1t2-chimera:free", 
            messages: [
                { role: "system", content: "Eres Vintex AI, un asistente experto en gestión." },
                { role: "user", content: message }
            ],
            temperature: 0.7,
            max_tokens: 1000,
        });

        const responseText = completion.choices[0]?.message?.content || "No pude generar una respuesta.";
        res.json({ response: responseText });

    } catch (e) {
        console.error("Error Chat OpenRouter:", e);
        res.status(503).json({ error: "El servicio de IA está ocupado." });
    }
});

// 7. INSTANCIADOR DE PLANTILLAS
app.post('/api/templates/instantiate', requireAuth, async (req, res) => {
    const { templateId } = req.body;
    const userId = req.user.id;

    try {
        const { data: template } = await masterSupabase.from('templates').select('*').eq('id', templateId).single();
        if (!template) return res.status(404).json({ error: "Plantilla no encontrada" });

        await masterSupabase.from('web_clinica').upsert({
            ID_USER: userId,
            ui_config: template.ui_config_template, 
            status: 'preview_template' 
        }, { onConflict: 'ID_USER' });

        res.json({ success: true, message: "Plantilla cargada" });
    } catch (error) {
        console.error("Error instanciando plantilla:", error);
        res.status(500).json({ error: "Error al cargar la plantilla" });
    }
});

// 8. INTERNAL CREDENTIALS (Uso interno)
app.post('/api/internal/get-clinic-credentials', async (req, res) => {
    const internalSecret = req.headers['x-internal-secret'];
    if (!internalSecret || internalSecret !== process.env.INTERNAL_SECRET_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { userId } = req.body;
    try {
        const { data: config } = await masterSupabase.from('web_clinica').select('SUPABASE_URL, SUPABASE_SERVICE_KEY').eq('ID_USER', userId).single();
        if (!config) return res.status(404).json({ error: 'No config' });
        res.json({ url: config.SUPABASE_URL, key: config.SUPABASE_SERVICE_KEY });
    } catch (e) { res.status(500).json({ error: 'Internal Error' }); }
});

// 9. INIT SESSION (CON AUTO-REPARACIÓN BLINDADA)
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(authHeader.split(' ')[1]);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });

        // AUTO-REPAIR
        await masterSupabase.from('users').upsert({
            id: user.id, email: user.email, full_name: user.email.split('@')[0], role: 'admin', created_at: new Date()
        }, { onConflict: 'id', ignoreDuplicates: true });

        await masterSupabase.from('servisi').upsert({
            "ID_User": user.id, web_clinica: true, "Bot_clinica": true
        }, { onConflict: "ID_User", ignoreDuplicates: true });

        // BUSCAR CONFIG
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_ANON_KEY, ui_config')
            .eq('ID_USER', user.id)
            .maybeSingle();
            
        if (!config) return res.status(200).json({ hasClinic: false });
        
        return res.json({
            hasClinic: true, 
            backendUrl: SATELLITE_URL, 
            supabaseUrl: config.SUPABASE_URL, 
            supabaseAnonKey: config.SUPABASE_ANON_KEY,
            uiConfig: config.ui_config 
        });

    } catch (e) {
        console.error("Error Init:", e);
        res.status(500).json({ error: 'Error interno' });
    }
});

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 VINTEX ENGINE (NODE+AI) en puerto ${PORT}`);
});
// Aumentamos el timeout para operaciones largas de IA
server.setTimeout(60000);