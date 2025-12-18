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

app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const logger = {
    info: (msg, data = '') => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, data),
    error: (msg, err = '') => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, err),
    warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`)
};

const dbPool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

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

// --- CONFIGURACIÓN OPENROUTER (MODELOS SOLICITADOS) ---
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

app.use(helmet({ contentSecurityPolicy: false }));
const ALLOWED_ORIGINS = [process.env.FRONTEND_URL, "https://vintex.net.br", "http://localhost:5173", "http://localhost:3000"];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin) || process.env.NODE_ENV !== 'production') {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const upload = multer({ 
    storage: multer.memoryStorage(), 
    limits: { fileSize: 20 * 1024 * 1024 } 
});

const masterSupabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

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

// --- 🤖 AGENTES ESPECIALIZADOS (MEJORA: MULTI-HOJA) ---
async function nodoAnalistaExcel(files) {
    if (!files || files.length === 0) return "Sin archivos de datos.";
    try {
        const allSheetsSummary = [];
        for (const file of files) {
            const workbook = xlsx.read(file.buffer, { type: 'buffer' });
            const fileSheets = workbook.SheetNames.map(sheetName => {
                const sheet = workbook.Sheets[sheetName];
                const rawData = xlsx.utils.sheet_to_json(sheet, { header: 1 });
                return {
                    fileName: file.originalname,
                    sheetName: sheetName,
                    structure: rawData.slice(0, 15),
                    rows: rawData.length
                };
            });
            allSheetsSummary.push(...fileSheets);
        }

        const completion = await openai.chat.completions.create({
            model: MODEL_ANALISTA,
            messages: [
                { role: "system", content: "Analista de datos experto. Describe esquemas, relaciones entre hojas y tendencias." },
                { role: "user", content: `Analiza estos datos (múltiples hojas): ${JSON.stringify(allSheetsSummary)}` }
            ]
        });
        return completion.choices[0].message.content;
    } catch (e) { 
        logger.error("Error analizando Excel:", e);
        return "Error al procesar la estructura de los archivos."; 
    }
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
            messages: [{ role: "user", content: [{ type: "text", text: "Extrae texto y datos detallados de estas imágenes (OCR)." }, ...imagePrompts] }]
        });
        return completion.choices[0].message.content;
    } catch (e) { return "Error analizando visión."; }
}

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
        if (!isSafeSQL(sql)) throw new Error("SQL inseguro");
        await client.query('BEGIN');
        await client.query(sql);
        const config = { theme: { primary: "#00E599", mode: "dark" } };
        await client.query(`UPDATE public.web_clinica SET status = 'active', ui_config = $1 WHERE "ID_USER" = $2`, [JSON.stringify(config), userId]);
        await client.query('COMMIT');
    } catch (e) {
        await client.query('ROLLBACK');
        logger.error("Error en build:", e.message);
    } finally { client.release(); }
}

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

// --- RUTA ONBOARDING INTERACTIVO ---
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

        res.write(`data: ${JSON.stringify({ status: "analyzing", chunk: "🔍 Procesando archivos y hojas...\n" })}\n\n`);

        const excelFiles = files.filter(f => f.originalname.match(/\.(xlsx|csv|xls)$/i));
        const imageFiles = files.filter(f => f.mimetype.includes('image'));

        const [reporteExcel, reporteVision] = await Promise.all([
            nodoAnalistaExcel(excelFiles),
            nodoVision(imageFiles)
        ]);

        const stream = await openai.chat.completions.create({
            model: MODEL_ORQUESTADOR,
            messages: [
                { role: "system", content: `Orquestador. Reporte Datos: ${reporteExcel}. Reporte Visión: ${reporteVision}. Memoria: ${JSON.stringify(session.extracted_context)}. Responde JSON puro.` },
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
        res.write(`data: ${JSON.stringify({ error: "Error en el sistema de nodos" })}\n\n`);
        res.end();
    }
});

// ... (Resto de rutas: register, start-trial, login, complete, templates, init-session se mantienen igual)
app.post('/api/register', async (req, res) => {
    const { email, password, full_name } = req.body;
    const { data, error } = await masterSupabase.auth.signUp({ email, password, options: { data: { full_name } } });
    if (error) return res.status(400).json({ error: error.message });
    await masterSupabase.from('users').upsert({ id: data.user.id, email, full_name, role: 'admin' });
    await masterSupabase.from('servisi').upsert({ "ID_User": data.user.id, web_clinica: true, "Bot_clinica": true });
    res.json({ success: true, user: data.user });
});

app.post('/api/onboarding/complete', requireAuth, async (req, res) => {
    const { conversationSummary } = req.body;
    await masterSupabase.from('web_clinica').upsert({ ID_USER: req.user.id, status: "building" });
    buildSystemWithAI(req.user.id, conversationSummary).catch(e => logger.error("Async build error", e));
    res.json({ success: true });
});

app.get('/api/config/init-session', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).end();
    const { data: { user } } = await masterSupabase.auth.getUser(auth.split(' ')[1]);
    const { data: c } = await masterSupabase.from('web_clinica').select('*').eq('ID_USER', user.id).maybeSingle();
    res.json({ hasClinic: !!c, uiConfig: c?.ui_config });
});

const server = app.listen(PORT, '0.0.0.0', () => logger.info(`VINTEX Engine PRO en puerto ${PORT}`));
server.setTimeout(600000);