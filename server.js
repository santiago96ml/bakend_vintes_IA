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

// --- 📊 LOGGER ESTRUCTURADO ---
const logger = {
    info: (msg, data = '') => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, data),
    error: (msg, err = '') => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, err),
    warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`)
};

// --- CONFIGURACIÓN POOL DE BASE DE DATOS ---
const dbPool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

dbPool.on('error', (err) => logger.error('Error PG Pool Inactivo:', err));

// --- SEGURIDAD (Encriptación de credenciales satélite) ---
const ENCRYPTION_KEY = process.env.MASTER_ENCRYPTION_KEY 
    ? Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex') 
    : crypto.randomBytes(32);
const IV_LENGTH = 16;

function encrypt(text) {
    if (!text) return null;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return null;
    try {
        let parts = text.split(':');
        let iv = Buffer.from(parts.shift(), 'hex');
        let encryptedText = Buffer.from(parts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        return Buffer.concat([decipher.update(encryptedText), decipher.final()]).toString();
    } catch (e) { return null; }
}

// --- CONFIGURACIÓN OPENROUTER (ARQUITECTURA DE NODOS 2025) ---
let openai;
const MODEL_ORQUESTADOR = "meta-llama/llama-3.1-405b-instruct:free"; 
const MODEL_ANALISTA = "meta-llama/llama-3.2-3b-instruct:free";
const MODEL_VISION = "qwen/qwen-2.5-vl-7b-instruct:free";

if (process.env.OPENROUTER_API_KEY) {
    openai = new OpenAI({
        apiKey: process.env.OPENROUTER_API_KEY,
        baseURL: "https://openrouter.ai/api/v1",
        defaultHeaders: {
            "HTTP-Referer": process.env.FRONTEND_URL || "https://vintex.net.br",
            "X-Title": "Vintex AI PRO",
        }
    });
}

// --- MIDDLEWARES PROFESIONALES ---
app.use(helmet({ contentSecurityPolicy: false }));

const ALLOWED_ORIGINS = [
    process.env.FRONTEND_URL,
    "https://vintex.net.br",
    "http://localhost:5173",
    "http://localhost:3000"
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin) || process.env.NODE_ENV !== 'production') {
            callback(null, true);
        } else {
            logger.warn(`Bloqueado por CORS: ${origin}`);
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const upload = multer({ 
    storage: multer.memoryStorage(), 
    limits: { fileSize: 20 * 1024 * 1024 } // 20MB
});

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300 });
app.use(limiter);

// --- SUPABASE MASTER ---
const masterSupabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// --- 🛡️ SEGURIDAD Y LIMPIEZA ---
function isSafeSQL(sql) {
    const forbidden = [/drop\s+/i, /truncate\s+/i, /delete\s+(?!.*where)/i, /grant\s+/i, /revoke\s+/i];
    return !forbidden.some(pattern => pattern.test(sql));
}

function cleanIAContent(content) {
    if (!content) return "";
    let clean = content.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    const jsonMatch = clean.match(/```json([\s\S]*?)```/);
    if (jsonMatch) return jsonMatch[1].trim();
    const braceMatch = clean.match(/\{[\s\S]*\}/);
    return braceMatch ? braceMatch[0] : clean;
}

function detectPromptInjection(text) {
    const patterns = [/ignore previous instructions/i, /ignora tus instrucciones/i, /system prompt/i, /act as a/i, /actúa como/i];
    return typeof text === 'string' && patterns.some(pattern => pattern.test(text));
}

// --- 🤖 AGENTES ESPECIALIZADOS (NODOS) ---

async function nodoAnalistaExcel(files) {
    if (!files || files.length === 0) return "Sin archivos de datos.";
    try {
        const summaries = files.map(file => {
            const workbook = xlsx.read(file.buffer, { type: 'buffer' });
            const sheet = workbook.Sheets[workbook.SheetNames[0]];
            const rawData = xlsx.utils.sheet_to_json(sheet, { header: 1 });
            return {
                name: file.originalname,
                structure: rawData.slice(0, 15),
                rows: rawData.length
            };
        });
        const completion = await openai.chat.completions.create({
            model: MODEL_ANALISTA,
            messages: [{ role: "system", content: "Analista de datos. Describe el esquema y tendencias." },
                       { role: "user", content: JSON.stringify(summaries) }]
        });
        return completion.choices[0].message.content;
    } catch (e) { return "Error analizando datos."; }
}

async function nodoVision(files) {
    if (!files || files.length === 0) return "Sin imágenes.";
    try {
        const imagePrompts = files.map(file => ({
            type: "image_url",
            image_url: { url: `data:${file.mimetype};base64,${file.buffer.toString('base64')}` }
        }));
        const completion = await openai.chat.completions.create({
            model: MODEL_VISION,
            messages: [{ role: "user", content: [{ type: "text", text: "Extrae texto y datos de estas imágenes (OCR)." }, ...imagePrompts] }]
        });
        return completion.choices[0].message.content;
    } catch (e) { return "Error analizando visión."; }
}

// --- 🧠 CONSTRUCTOR CON SANDBOX SQL ---
async function buildSystemWithAI(userId, summary) {
    logger.info(`Construyendo sistema para: ${userId}`);
    const client = await dbPool.connect();
    try {
        const completion = await openai.chat.completions.create({
            model: MODEL_ORQUESTADOR,
            messages: [{ role: "system", content: "Ingeniero SQL. Genera tablas PostgreSQL con RLS para: " + summary }],
            temperature: 0.1
        });
        let sql = cleanIAContent(completion.choices[0].message.content).replace(/```sql|```/g, '');

        if (!isSafeSQL(sql)) throw new Error("SQL generado no es seguro");

        await client.query('BEGIN');
        await client.query(sql);
        const config = { theme: { primary: "#00E599", mode: "dark" } };
        await client.query(`UPDATE public.web_clinica SET status = 'active', ui_config = $1 WHERE "ID_USER" = $2`, [JSON.stringify(config), userId]);
        await client.query('COMMIT');
        logger.info("Construcción exitosa.");
    } catch (e) {
        await client.query('ROLLBACK');
        logger.error("Error en build:", e.message);
    } finally { client.release(); }
}

// --- MIDDLEWARE AUTH ---
const requireAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No autorizado' });
    try {
        const { data: { user } } = await masterSupabase.auth.getUser(authHeader.split(' ')[1]);
        if (!user) throw new Error();
        req.user = user;
        next();
    } catch (e) { res.status(401).json({ error: 'Sesión inválida' }); }
};

// =================================================================
// RUTAS
// =================================================================

// 4. ONBOARDING (NODOS + DISPATCHER + STREAMING)
app.post('/api/onboarding/interactive', requireAuth, upload.array('files', 5), async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    try {
        const { message } = req.body;
        const files = req.files || [];
        const userId = req.user.id;

        let { data: session } = await masterSupabase.from('onboarding_session').select('*').eq('user_id', userId).maybeSingle();
        if (!session) {
            const { data: newS } = await masterSupabase.from('onboarding_session').insert({ user_id: userId, extracted_context: {} }).select().single();
            session = newS;
        }

        res.write(`data: ${JSON.stringify({ status: "analyzing", chunk: "🔍 Vintex Nodes: Procesando archivos...\n" })}\n\n`);

        const [reporteExcel, reporteVision] = await Promise.all([
            nodoAnalistaExcel(files.filter(f => f.originalname.match(/\.(xlsx|csv)$/i))),
            nodoVision(files.filter(f => f.mimetype.includes('image')))
        ]);

        res.write(`data: ${JSON.stringify({ status: "thinking", chunk: "🧠 Orquestador: Generando respuesta...\n" })}\n\n`);

        const stream = await openai.chat.completions.create({
            model: MODEL_ORQUESTADOR,
            messages: [
                { role: "system", content: `Orquestador Maestro. Reporte Datos: ${reporteExcel}. Reporte Visión: ${reporteVision}. Memoria: ${JSON.stringify(session.extracted_context)}. Devuelve JSON puro.` },
                { role: "user", content: message }
            ],
            stream: true
        });

        let full = "";
        let thinking = false;
        for await (const chunk of stream) {
            const content = chunk.choices[0]?.delta?.content || "";
            full += content;
            if (content.includes("<think>")) thinking = true;
            if (content.includes("</think>")) thinking = false;
            if (!thinking && content && !content.includes("</think>")) {
                res.write(`data: ${JSON.stringify({ chunk: content })}\n\n`);
            }
        }

        const data = JSON.parse(cleanIAContent(full));
        await masterSupabase.from('onboarding_session').update({
            conversation_history: [...(session.conversation_history || []), { user: message, bot: data.reply }].slice(-10),
            extracted_context: data.updated_context,
            analysis_status: data.is_ready ? 'ready' : 'listening'
        }).eq('user_id', userId);

        res.write(`data: ${JSON.stringify({ final: true, ...data })}\n\n`);
        res.end();
    } catch (e) {
        res.write(`data: ${JSON.stringify({ error: "Error en el cerebro digital" })}\n\n`);
        res.end();
    }
});

// RUTAS AUTH
app.post('/api/register', async (req, res) => {
    const { email, password, full_name } = req.body;
    const { data, error } = await masterSupabase.auth.signUp({ email, password, options: { data: { full_name } } });
    if (error) return res.status(400).json({ error: error.message });
    await masterSupabase.from('users').upsert({ id: data.user.id, email, full_name, role: 'admin' });
    await masterSupabase.from('servisi').upsert({ "ID_User": data.user.id, web_clinica: true, "Bot_clinica": true });
    res.json({ success: true, user: data.user });
});

app.post('/api/start-trial', async (req, res) => {
    const { email, fullName, phone } = req.body;
    const pwd = crypto.randomBytes(12).toString('hex') + "V!";
    try {
        const { data: auth } = await masterSupabase.auth.signUp({ email, password: pwd, options: { data: { full_name: fullName, phone } } });
        await masterSupabase.from('users').upsert({ id: auth.user.id, email, full_name: fullName, phone, role: 'admin' });
        await masterSupabase.from('servisi').upsert({ "ID_User": auth.user.id, web_clinica: true, "Bot_clinica": true });
        res.status(201).json({ success: true });
    } catch (e) { res.status(500).json({ error: "Fallo trial" }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: "Fallo login" });
    res.json({ success: true, session: data.session });
});

// CHAT GENERAL (Streaming)
app.post('/chat', requireAuth, async (req, res) => {
    const { message } = req.body;
    if (detectPromptInjection(message)) return res.status(400).end();
    res.setHeader('Content-Type', 'text/event-stream');
    try {
        const stream = await openai.chat.completions.create({
            model: MODEL_ORQUESTADOR,
            messages: [{ role: "system", content: "Asistente Vintex." }, { role: "user", content: message }],
            stream: true
        });
        for await (const chunk of stream) {
            const content = chunk.choices[0]?.delta?.content || "";
            if (content) res.write(`data: ${JSON.stringify({ chunk: content })}\n\n`);
        }
        res.end();
    } catch (e) { res.end(); }
});

// OTROS ENDPOINTS
app.post('/api/onboarding/complete', requireAuth, async (req, res) => {
    const { conversationSummary } = req.body;
    await masterSupabase.from('web_clinica').upsert({ ID_USER: req.user.id, status: "building" });
    buildSystemWithAI(req.user.id, conversationSummary).catch(e => logger.error("Async build error", e));
    res.json({ success: true });
});

app.post('/api/templates/instantiate', requireAuth, async (req, res) => {
    const { templateId } = req.body;
    const { data: t } = await masterSupabase.from('templates').select('*').eq('id', templateId).single();
    await masterSupabase.from('web_clinica').upsert({ ID_USER: req.user.id, ui_config: t.ui_config_template, status: 'preview' });
    res.json({ success: true });
});

app.get('/api/config/init-session', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).end();
    const { data: { user } } = await masterSupabase.auth.getUser(auth.split(' ')[1]);
    const { data: c } = await masterSupabase.from('web_clinica').select('*').eq('ID_USER', user.id).maybeSingle();
    res.json({ hasClinic: !!c, uiConfig: c?.ui_config });
});

app.use((err, req, res, next) => {
    logger.error("Error Global:", err.message);
    res.status(500).json({ error: "Error interno" });
});

const server = app.listen(PORT, '0.0.0.0', () => logger.info(`VINTEX ENGINE PRO ON: ${PORT}`));
server.setTimeout(600000); // 10 Minutos