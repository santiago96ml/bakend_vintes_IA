import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';
import OpenAI from 'openai';
import multer from 'multer';
import * as xlsx from 'xlsx';
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

// --- SEGURIDAD (Encriptación) ---
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

// --- CONFIGURACIÓN OPENROUTER (DeepSeek R1 oficial y estable) ---
let openai;
const AI_MODEL = "tngtech/deepseek-r1t2-chimera:free"; // Modelo oficial recomendado

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
        else { callback(null, true); } // Nota: en producción, considerar restringir más
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

// --- UTILIDADES DE IA ---
function cleanDeepSeekResponse(content) {
    if (!content) return "";
    let clean = content.replace(/<think>[\s\S]*?<\/think>/g, '').trim();

    const jsonMatch = clean.match(/```json([\s\S]*?)```/);
    if (jsonMatch) return jsonMatch[1].trim();

    const sqlMatch = clean.match(/```sql([\s\S]*?)```/);
    if (sqlMatch) return sqlMatch[1].trim();

    const braceMatch = clean.match(/\{[\s\S]*\}/);
    if (braceMatch) return braceMatch[0];

    return clean;
}

function shouldStream(chunk, isThinking) {
    if (chunk.includes('<think>')) return { emit: false, thinking: true };
    if (chunk.includes('</think>')) return { emit: false, thinking: false };
    return { emit: !isThinking, thinking: isThinking };
}

// --- MEJOR LECTURA DE EXCEL/CSV: Resumen inteligente ---
function analyzeExcelFile(buffer) {
    try {
        const workbook = xlsx.read(buffer, { type: 'buffer' });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet, { header: 1, defval: null });

        if (jsonData.length === 0) return "[ARCHIVO VACÍO]";

        const headers = jsonData[0];
        const dataRows = jsonData.slice(1);
        const sampleRows = dataRows.slice(0, 8); // Máximo 8 filas de ejemplo
        const totalRows = dataRows.length;

        // Inferir tipos básicos por columna
        const columnTypes = headers.map((header, i) => {
            const values = dataRows.map(row => row[i]).filter(v => v !== null && v !== undefined);
            if (values.length === 0) return "vacío";
            if (values.every(v => typeof v === 'number')) return "número";
            if (values.every(v => typeof v === 'string' && !isNaN(Date.parse(v)))) return "fecha";
            return "texto";
        });

        return `
[ARCHIVO EXCEL/CSV ANALIZADO]
Hoja: "${sheetName}"
Columnas (${headers.length}): ${headers.join(', ')}
Tipos aproximados: ${columnTypes.join(', ')}
Total filas de datos: ${totalRows}
Ejemplos (primeras ${sampleRows.length} filas):
${JSON.stringify(sampleRows, null, 2)}
`.trim();
    } catch (error) {
        console.error("Error analizando Excel:", error);
        return "[ERROR AL LEER ARCHIVO]";
    }
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
    const patterns = [/ignore previous instructions/i, /ignora tus instrucciones/i, /system prompt/i, /act as a/i, /actúa como/i, /reset instructions/i];
    return typeof text === 'string' && patterns.some(pattern => pattern.test(text));
};

// --- 🧠 CONSTRUCTOR DE SISTEMAS (Prompt mejorado del Código 1) ---
async function buildSystemWithAI(userId, summary) {
    console.log(`🏗️ [CONSTRUCTOR] Iniciando construcción para usuario: ${userId}`);
    
    if (!openai) return;

    const dbClient = await dbPool.connect(); 

    try {
        const systemPrompt = `
        ERES UN INGENIERO DE BASES DE DATOS POSTGRESQL EXPERTO.
        TU TAREA: Generar un script SQL completo para: "${summary}"
        
        REGLAS OBLIGATORIAS:
        1. Todas las tablas deben tener RLS activado (ENABLE ROW LEVEL SECURITY).
        2. Todas las tablas que contengan datos del usuario deben tener una columna "user_id" UUID que referencie auth.users(id).
        3. Crear políticas: CREATE POLICY "Manage own data" ON tabla USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
        4. Incluir políticas para SELECT, INSERT, UPDATE, DELETE si aplica.
        5. Usar tipos adecuados (timestamptz, jsonb cuando sea útil).
        6. Incluir índices útiles en columnas de búsqueda frecuente.
        
        Devuelve SOLO el código SQL dentro de un bloque markdown \`\`\`sql ... \`\`\`
        NO agregues explicaciones, ni texto fuera del bloque.
        `;

        const completion = await openai.chat.completions.create({
            model: AI_MODEL, 
            messages: [{ role: "system", content: systemPrompt }],
            temperature: 0.1, 
        });

        let rawContent = completion.choices[0].message.content;
        let sqlCode = cleanDeepSeekResponse(rawContent);

        // Limpieza extra de seguridad
        if (sqlCode.startsWith('```')) sqlCode = sqlCode.replace(/```sql|```/g, '').trim();
        
        console.log(`📜 SQL Generado (primeros 100 chars): ${sqlCode.substring(0, 100)}...`);

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
        console.log(`✅ [CONSTRUCTOR] Sistema construido con éxito para ${userId}`);

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

app.post('/api/register', authLimiter, validate(registerSchema), async (req, res) => {
    const { email, password, full_name } = req.body;
    try {
        const { data, error } = await masterSupabase.auth.signUp({ email, password, options: { data: { full_name } } });
        if (error) return res.status(400).json({ error: error.message });
        
        await masterSupabase.from('users').upsert({ id: data.user.id, email, full_name, role: 'admin' }, { onConflict: 'id', ignoreDuplicates: true });
        await masterSupabase.from('servisi').upsert({ "ID_User": data.user.id, web_clinica: true, "Bot_clinica": true }, { onConflict: 'ID_User', ignoreDuplicates: true });

        res.json({ user: data.user, session: data.session });
    } catch (error) {
        console.error("Error Registro:", error);
        res.status(400).json({ error: "Error procesando registro" });
    }
});

app.post('/api/start-trial', authLimiter, validate(trialSchema), async (req, res) => {
    const { email, fullName, phone } = req.body;
    const tempPassword = crypto.randomBytes(16).toString('hex') + "V!1";
    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email, password: tempPassword, options: { data: { full_name: fullName, phone } }
        });
        if (authError) throw authError;
        const userId = authData.user.id;
        
        await masterSupabase.from('users').upsert({ id: userId, email, full_name: fullName, phone, role: 'admin' }, { onConflict: 'id', ignoreDuplicates: true });
        await masterSupabase.from('servisi').upsert({ "ID_User": userId, web_clinica: true, "Bot_clinica": true }, { onConflict: 'ID_User', ignoreDuplicates: true });
        
        return res.status(201).json({ success: true, message: 'Usuario creado exitosamente. Revisa tu email para ingresar.' });
    } catch (error) {
        console.error("Trial error:", error.message);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/login', authLimiter, validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: 'Credenciales inválidas' });
    return res.json({ success: true, session: data.session, user: { id: data.user.id, email: data.user.email } });
});

// CHAT ARQUITECTO CON STREAMING + ANÁLISIS INTELIGENTE DE EXCEL
app.post('/api/onboarding/interactive', requireAuth, upload.single('file'), async (req, res) => {
    const { message } = req.body;
    const file = req.file;
    const userId = req.user.id;

    if (!openai) return res.status(503).json({ error: "IA no disponible" });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    try {
        let { data: session } = await masterSupabase.from('onboarding_session').select('*').eq('user_id', userId).maybeSingle();
        if (!session) {
            const { data: newS } = await masterSupabase.from('onboarding_session').insert({ user_id: userId, extracted_context: {} }).select().single();
            session = newS;
        }

        let fileContext = "";
        if (file && (file.mimetype.includes('csv') || file.mimetype.includes('spreadsheet') || file.originalname.endsWith('.xlsx') || file.originalname.endsWith('.xls'))) {
            fileContext = analyzeExcelFile(file.buffer);
        } else if (file) {
            fileContext = `[Archivo recibido: ${file.originalname} (${file.mimetype})]`;
        }

        const systemPrompt = `
        Eres Vintex Architect, un experto en diseño de software médico y de gestión.
        Tu objetivo es entrevistar al usuario para entender sus necesidades y extraer requisitos claros.
        Memoria actual del proyecto: ${JSON.stringify(session.extracted_context)}
        
        FORMATO DE RESPUESTA OBLIGATORIO (JSON PURO, nada más):
        { 
            "reply": "Respuesta natural y amigable al usuario...", 
            "updated_context": { ...datos extraídos y acumulados... }, 
            "is_ready": true/false (true solo si ya tienes información suficiente para construir el sistema)
        }
        NO escribas nada fuera del JSON. NO uses markdown.
        `;

        const stream = await openai.chat.completions.create({
            model: AI_MODEL,
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: `Usuario: ${message}\n${fileContext}` }
            ],
            stream: true
        });

        let fullResponse = "";
        let isThinking = false;

        for await (const chunk of stream) {
            const content = chunk.choices[0]?.delta?.content || "";
            fullResponse += content;

            const status = shouldStream(content, isThinking);
            isThinking = status.thinking;

            if (status.emit && content) {
                res.write(`data: ${JSON.stringify({ chunk: content })}\n\n`);
            }
        }

        const cleanJson = cleanDeepSeekResponse(fullResponse);
        let aiData;
        try {
            aiData = JSON.parse(cleanJson);
        } catch (e) {
            console.error("Error parseando JSON de IA:", cleanJson);
            aiData = { 
                reply: "Entendido. ¿Podrías darme más detalles sobre eso?", 
                updated_context: session.extracted_context, 
                is_ready: false 
            };
        }

        const history = Array.isArray(session.conversation_history) ? session.conversation_history : [];
        await masterSupabase.from('onboarding_session').update({
            conversation_history: [...history, { user: message, bot: aiData.reply }].slice(-20), // Guardar más historia
            extracted_context: aiData.updated_context,
            analysis_status: aiData.is_ready ? 'ready' : 'listening'
        }).eq('session_id', session.session_id);

        res.write(`data: ${JSON.stringify({ final: true, ...aiData })}\n\n`);
        res.end();

    } catch (e) {
        console.error("Error en onboarding:", e);
        res.write(`data: ${JSON.stringify({ error: "Error temporal en el asistente." })}\n\n`);
        res.end();
    }
});

app.post('/api/onboarding/complete', requireAuth, validate(onboardingCompleteSchema), async (req, res) => {
    const { conversationSummary } = req.body;
    const user = req.user;

    try {
        await masterSupabase.from('users').upsert({ id: user.id, email: user.email, role: 'admin' }, { onConflict: 'id', ignoreDuplicates: true });
        
        await masterSupabase.from('web_clinica').upsert({ 
            "ID_USER": user.id,
            "SUPABASE_URL": "[https://building.vintex.ai](https://building.vintex.ai)",
            "SUPABASE_ANON_KEY": "building",
            "SUPABASE_SERVICE_KEY": "building",
            "JWT_SECRET": "building",
            "status": "building" 
        }, { onConflict: "ID_USER" });

        buildSystemWithAI(user.id, conversationSummary).catch(e => console.error("Error async build:", e));

        res.json({ success: true, message: "¡Construcción iniciada! Te avisaremos cuando esté listo." });
    } catch (error) {
        console.error("Error completando onboarding:", error);
        res.status(500).json({ error: "Error iniciando construcción." });
    }
});

// CHAT GENERAL CON STREAMING
app.post('/chat', requireAuth, chatLimiter, validate(chatSchema), async (req, res) => {
    const { message } = req.body; 
    
    if (detectPromptInjection(message)) {
        return res.status(400).json({ error: "Entrada no permitida." });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');

    try {
        const stream = await openai.chat.completions.create({
            model: AI_MODEL,
            messages: [
                { role: "system", content: "Eres Vintex AI, un asistente experto, amable y profesional en gestión de clínicas y negocios." },
                { role: "user", content: message }
            ],
            stream: true,
            temperature: 0.7,
        });

        for await (const chunk of stream) {
            const content = chunk.choices[0]?.delta?.content || "";
            if (content) res.write(`data: ${JSON.stringify({ chunk: content })}\n\n`);
        }
        res.end();
    } catch (e) {
        console.error("Error en chat:", e);
        res.write(`data: ${JSON.stringify({ error: "Servicio temporalmente no disponible." })}\n\n`);
        res.end();
    }
});

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

        res.json({ success: true, message: "Plantilla cargada correctamente" });
    } catch (error) {
        res.status(500).json({ error: "Error al cargar la plantilla" });
    }
});

app.post('/api/internal/get-clinic-credentials', async (req, res) => {
    const internalSecret = req.headers['x-internal-secret'];
    if (!internalSecret || internalSecret !== process.env.INTERNAL_SECRET_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { userId } = req.body;
    try {
        const { data: config } = await masterSupabase.from('web_clinica').select('SUPABASE_URL, SUPABASE_SERVICE_KEY').eq('ID_USER', userId).single();
        if (!config) return res.status(404).json({ error: 'Configuración no encontrada' });
        res.json({ url: config.SUPABASE_URL, key: config.SUPABASE_SERVICE_KEY });
    } catch (e) { 
        res.status(500).json({ error: 'Error interno' }); 
    }
});

app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    
    try {
        const { data: { user } } = await masterSupabase.auth.getUser(authHeader.split(' ')[1]);
        if (!user) return res.status(401).json({ error: 'Sesión inválida' });

        // Auto-reparación robusta
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
    console.log(`🚀 VINTEX ENGINE MEJORADO - Streaming + Excel Inteligente + Seguridad RLS en puerto ${PORT}`);
});

server.setTimeout(600000); // 10 minutos