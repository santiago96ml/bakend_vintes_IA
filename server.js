import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv'; // Corregido el typo
import { createClient } from '@supabase/supabase-js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';
import OpenAI from 'openai';
import multer from 'multer';
import * as xlsx from 'xlsx';
import { Readable } from 'stream';
import pg from 'pg';

dotenv.config();
const app = express();

// 1. TRUST PROXY
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN POOL DE BASE DE DATOS ---
if (!process.env.DATABASE_URL) {
    console.warn("⚠️ ADVERTENCIA: Falta DATABASE_URL.");
}
const dbPool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

dbPool.on('error', (err) => {
    console.error('🔥 Error inesperado en el cliente PG inactivo', err);
});

// --- SEGURIDAD (Encriptación restaurada) ---
const ENCRYPTION_KEY = process.env.MASTER_ENCRYPTION_KEY 
    ? Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex') 
    : crypto.randomBytes(32);
const IV_LENGTH = 16;

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

// --- CONFIGURACIÓN OPENROUTER (DeepSeek R1) ---
let openai;
const AI_MODEL = "deepseek/deepseek-r1:free"; // Modelo potente y gratuito

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

const SATELLITE_URL = process.env.SATELLITE_URL || "https://api-clinica.vintex.net.br";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";
const HOSTINGER_URL = "https://webs-de-vintex-login-web.1kh9sk.easypanel.host";

const ALLOWED_ORIGINS = [
    FRONTEND_URL,
    HOSTINGER_URL,
    'https://vintex.net.br',
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
        else { callback(null, true); } 
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

// --- 🔧 UTILIDAD DE LIMPIEZA PARA DEEPSEEK R1 ---
function cleanDeepSeekResponse(content) {
    if (!content) return "";
    
    // 1. Eliminar el proceso de pensamiento <think>...</think>
    let clean = content.replace(/<think>[\s\S]*?<\/think>/g, '').trim();

    // 2. Intentar extraer JSON de bloques de código markdown ```json ... ```
    const jsonMatch = clean.match(/```json([\s\S]*?)```/);
    if (jsonMatch) return jsonMatch[1].trim();

    // 3. Intentar extraer SQL de bloques ```sql ... ```
    const sqlMatch = clean.match(/```sql([\s\S]*?)```/);
    if (sqlMatch) return sqlMatch[1].trim();

    // 4. Si no hay markdown, buscar el primer '{' y el último '}' para JSON
    const braceMatch = clean.match(/\{[\s\S]*\}/);
    if (braceMatch) return braceMatch[0];

    return clean;
}

// --- SCHEMAS ZOD ---
const registerSchema = z.object({ email: z.string().email(), password: z.string().min(8), full_name: z.string().min(2) });
const loginSchema = z.object({ email: z.string().email(), password: z.string() });
const trialSchema = z.object({ email: z.string().email(), fullName: z.string().min(2), phone: z.string().min(8) });
const chatSchema = z.object({ message: z.string().min(1).max(2000), threadId: z.string().optional() });
const onboardingCompleteSchema = z.object({ conversationSummary: z.string().min(10), schemaConfig: z.any().optional() });

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
        /system prompt/i, /act as a/i, /actúa como/i, /reset instructions/i
    ];
    if (typeof text === 'string') return patterns.some(pattern => pattern.test(text));
    return false;
};

// --- 🧠 CONSTRUCTOR DE SISTEMAS CON DEEPSEEK R1 ---
async function buildSystemWithAI(userId, summary) {
    console.log(`🏗️ [CONSTRUCTOR] Iniciando obra para usuario: ${userId}`);
    
    if (!openai) return;
    const dbClient = await dbPool.connect(); 

    try {
        const systemPrompt = `
        ERES UN INGENIERO DE BASES DE DATOS POSTGRESQL EXPERTO.
        TU TAREA: Generar un script SQL para: "${summary}"
        
        REGLAS:
        1. Tablas con RLS activado.
        2. Columna "user_id" (UUID) en todas las tablas que referencie a auth.users.
        3. CREATE POLICY "Manage own data" ON table USING (auth.uid() = user_id);
        4. Devuelve SOLO el código SQL dentro de un bloque markdown.
        `;

        const completion = await openai.chat.completions.create({
            model: AI_MODEL, 
            messages: [{ role: "system", content: systemPrompt }],
            temperature: 0.1, 
        });

        // Limpieza específica para R1
        let rawContent = completion.choices[0].message.content;
        let sqlCode = cleanDeepSeekResponse(rawContent);

        // Limpieza extra por seguridad
        if (sqlCode.startsWith('```')) sqlCode = sqlCode.replace(/```sql|```/g, '');
        
        console.log(`📜 SQL Generado: ${sqlCode.substring(0, 50)}...`);

        await dbClient.query('BEGIN'); 
        await dbClient.query(sqlCode);

        const defaultUiConfig = {
            theme: { primary: "#00E599", mode: "dark" },
            generatedAt: new Date().toISOString()
        };

        await dbClient.query(`
            UPDATE public.web_clinica 
            SET status = 'active', ui_config = $1 WHERE "ID_USER" = $2
        `, [JSON.stringify(defaultUiConfig), userId]);

        await dbClient.query('COMMIT');
        console.log(`✅ [CONSTRUCTOR] Sistema listo para ${userId}`);

    } catch (error) {
        await dbClient.query('ROLLBACK');
        console.error("🔥 [CONSTRUCTOR ERROR]:", error);
    } finally {
        dbClient.release();
    }
}

// =================================================================
// RUTAS
// =================================================================

// 1. REGISTER
app.post('/api/register', authLimiter, validate(registerSchema), async (req, res) => {
    const { email, password, full_name } = req.body;
    try {
        const { data, error } = await masterSupabase.auth.signUp({ email, password, options: { data: { full_name } } });
        
        if (error) return res.status(400).json({ error: error.message });
        
        // Upsert perfil para consistencia
        await masterSupabase.from('users').upsert({ id: data.user.id, email, full_name, role: 'admin' }, { onConflict: 'id' });
        await masterSupabase.from('servisi').upsert({ "ID_User": data.user.id, web_clinica: true, "Bot_clinica": true }, { onConflict: 'ID_User' });

        res.json({ user: data.user, session: data.session });
    } catch (error) {
        console.error("Error Registro:", error);
        res.status(400).json({ error: "Error procesando registro" });
    }
});

// 2. START TRIAL (Restaurado)
app.post('/api/start-trial', authLimiter, validate(trialSchema), async (req, res) => {
    const { email, fullName, phone } = req.body;
    const tempPassword = crypto.randomBytes(16).toString('hex') + "V!1";
    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email, password: tempPassword, options: { data: { full_name: fullName, phone } }
        });
        if (authError) throw authError;
        const userId = authData.user.id;
        
        await masterSupabase.from('users').upsert({ id: userId, email, full_name: fullName, phone, role: 'admin' });
        await masterSupabase.from('servisi').upsert({ "ID_User": userId, web_clinica: true, "Bot_clinica": true });
        
        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });
    } catch (error) {
        console.error("Trial error:", error.message);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// 3. LOGIN
app.post('/api/login', authLimiter, validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: 'Credenciales inválidas' });
    return res.json({ success: true, session: data.session, user: { id: data.user.id, email: data.user.email } });
});

// 4. CHAT ARQUITECTO (Onboarding Interactivo con DeepSeek R1 y Excel)
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
        // Restaurada lógica de Excel para dar contexto a la IA
        if (file && (file.mimetype.includes('csv') || file.mimetype.includes('spreadsheet'))) {
            const workbook = xlsx.read(file.buffer, { type: 'buffer' });
            const sheet = workbook.Sheets[workbook.SheetNames[0]];
            const dataPreview = xlsx.utils.sheet_to_json(sheet, { header: 1 }).slice(0, 10);
            fileContext = `[ARCHIVO ADJUNTO] El usuario subió datos. Estructura: ${JSON.stringify(dataPreview)}`;
        } else if (file) {
            fileContext = "[Archivo recibido]";
        }

        const systemPrompt = `
        Eres Vintex Architect. Entrevista al usuario.
        Memoria actual: ${JSON.stringify(session.extracted_context)}
        
        OBJETIVO: Obtener detalles para construir el software.
        
        FORMATO DE RESPUESTA REQUERIDO (JSON PURO):
        { 
            "reply": "Tu respuesta al usuario...", 
            "updated_context": { ...datos extraídos... }, 
            "is_ready": boolean (true si ya tienes toda la info básica) 
        }
        NO escribas nada fuera del JSON.
        `;

        const completion = await openai.chat.completions.create({
            model: AI_MODEL, // DeepSeek R1 Free
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: `User: ${message}. ${fileContext}` }
            ],
            // response_format ELIMINADO para compatibilidad
        });

        // ✅ LIMPIEZA DEEPSEEK
        let rawContent = completion.choices[0].message.content;
        let cleanContent = cleanDeepSeekResponse(rawContent);

        console.log("IA Clean:", cleanContent.substring(0, 100)); 

        let aiData;
        try {
            aiData = JSON.parse(cleanContent);
        } catch (e) {
            console.error("Error parseando JSON IA:", cleanContent);
            aiData = { 
                reply: "Estoy procesando esa información, ¿podrías darme más detalles?", 
                updated_context: session.extracted_context, 
                is_ready: false 
            };
        }

        const history = Array.isArray(session.conversation_history) ? session.conversation_history : [];

        await masterSupabase.from('onboarding_session').update({
            conversation_history: [...history, { user: message, bot: aiData.reply }],
            extracted_context: aiData.updated_context,
            analysis_status: aiData.is_ready ? 'ready' : 'listening'
        }).eq('session_id', session.session_id);

        res.json(aiData);
    } catch (e) {
        console.error("Error en Onboarding:", e);
        res.status(500).json({ error: "Error en el cerebro digital." });
    }
});

// 5. COMPLETAR ONBOARDING (Restaurados campos críticos)
app.post('/api/onboarding/complete', requireAuth, validate(onboardingCompleteSchema), async (req, res) => {
    const { conversationSummary } = req.body;
    const user = req.user;

    try {
        // Auto-reparación antes de construir
        await masterSupabase.from('users').upsert({ id: user.id, email: user.email, role: 'admin' }, { onConflict: 'id', ignoreDuplicates: true });
        
        await masterSupabase.from('web_clinica').upsert({ 
            "ID_USER": user.id,
            "SUPABASE_URL": "[https://building.vintex.ai](https://building.vintex.ai)",
            "SUPABASE_ANON_KEY": "building", // Restaurado
            "SUPABASE_SERVICE_KEY": "building", // Restaurado
            "JWT_SECRET": "building", // Restaurado
            "status": "building" 
        }, { onConflict: "ID_USER" });

        // Trigger Async Construction
        buildSystemWithAI(user.id, conversationSummary).catch(e => console.error("Async build error:", e));

        res.json({ success: true, message: "Construyendo..." });
    } catch (error) {
        res.status(500).json({ error: "Error iniciando construcción." });
    }
});

// 6. CHAT GENERAL (Restaurado con DeepSeek R1)
app.post('/chat', requireAuth, chatLimiter, validate(chatSchema), async (req, res) => {
    const { message } = req.body; 
    
    if (detectPromptInjection(message)) {
        return res.status(400).json({ error: "Entrada no permitida." });
    }

    try {
        const completion = await openai.chat.completions.create({
            model: AI_MODEL, // DeepSeek R1
            messages: [
                { role: "system", content: "Eres Vintex AI, un asistente experto en gestión." },
                { role: "user", content: message }
            ],
            temperature: 0.7,
            max_tokens: 1000,
        });

        const raw = completion.choices[0]?.message?.content || "";
        res.json({ response: cleanDeepSeekResponse(raw) });

    } catch (e) {
        res.status(503).json({ error: "El servicio de IA está ocupado." });
    }
});

// 7. INSTANCIADOR DE PLANTILLAS (Restaurado)
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
        res.status(500).json({ error: "Error al cargar la plantilla" });
    }
});

// 8. INTERNAL CREDENTIALS (Restaurado)
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

// 9. INIT SESSION (Con Auto-Reparación Restaurada)
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    
    try {
        const { data: { user } } = await masterSupabase.auth.getUser(authHeader.split(' ')[1]);
        if (!user) return res.status(401).json({ error: 'Sesión inválida' });

        // AUTO-REPAIR (Restaurado para robustez)
        await masterSupabase.from('users').upsert({
            id: user.id, email: user.email, full_name: user.email.split('@')[0], role: 'admin'
        }, { onConflict: 'id', ignoreDuplicates: true });

        await masterSupabase.from('servisi').upsert({
            "ID_User": user.id, web_clinica: true, "Bot_clinica": true
        }, { onConflict: "ID_User", ignoreDuplicates: true });

        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('*')
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
    console.log(`🚀 VINTEX ENGINE con DEEPSEEK R1 en puerto ${PORT}`);
});
server.setTimeout(60000);