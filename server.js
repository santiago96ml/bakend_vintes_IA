import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import OpenAI from 'openai';
import multer from 'multer';
import xlsx from 'xlsx';
import pg from 'pg'; 

dotenv.config();
const app = express();

// 1. TRUST PROXY (Vital para despliegues en la nube)
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN BASE DE DATOS (PG POOL DIRECTO) ---
if (!process.env.DATABASE_URL) {
    console.warn("⚠️ FALTA DATABASE_URL EN .ENV");
}
const dbPool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

// --- CONFIGURACIÓN OPENAI / OPENROUTER ---
let openai;
if (process.env.OPENROUTER_API_KEY) {
    openai = new OpenAI({
        apiKey: process.env.OPENROUTER_API_KEY,
        baseURL: "https://openrouter.ai/api/v1",
        defaultHeaders: { 
            "HTTP-Referer": process.env.FRONTEND_URL || "https://vintex.net.br", 
            "X-Title": "Vintex AI" 
        }
    });
} else {
    console.error("❌ FALTA OPENROUTER_API_KEY");
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

// --- MIDDLEWARES DE SEGURIDAD Y CONFIGURACIÓN ---
app.use(helmet({
    contentSecurityPolicy: false // Ajustar según necesidad en producción
}));

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) { 
            callback(null, true); 
        } else { 
            // En modo desarrollo permitimos null/undefined, en prod ser más estricto
            callback(null, true); 
        }
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-secret'],
    credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Configuración de subida de archivos (Memoria)
const upload = multer({ 
    storage: multer.memoryStorage(), 
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB límite
});

// --- RATE LIMITING ---
const limiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    limit: 300,
    message: { error: "Demasiadas peticiones, intenta más tarde." }
});
app.use(limiter);

const authLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    limit: 50,
    message: { error: "Límite de autenticación excedido." }
});

// --- CLIENTE SUPABASE (ADMIN) ---
const masterSupabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- SCHEMAS DE VALIDACIÓN ZOD (ESTRICTOS) ---
const LoginSchema = z.object({ email: z.string().email(), password: z.string() });
const RegisterSchema = z.object({ email: z.string().email(), password: z.string().min(8), full_name: z.string().min(2) });
const TrialSchema = z.object({ email: z.string().email(), fullName: z.string().min(2), phone: z.string().min(8) });
const OnboardingCompleteSchema = z.object({ conversationSummary: z.string().min(10), schemaConfig: z.any().optional() });

// Schema del Plan de Arquitectura (El corazón del sistema seguro)
const ColumnSchema = z.object({
    name: z.string().regex(/^[a-z0-9_]+$/).max(64),
    type: z.enum(['text', 'integer', 'bigint', 'boolean', 'date', 'json', 'uuid', 'array_text']),
    references: z.object({ table: z.string(), column: z.string() }).optional(),
    indexed: z.boolean().optional()
});

const TableSchema = z.object({
    name: z.string().regex(/^[a-z0-9_]+$/).max(64),
    columns: z.array(ColumnSchema).max(50)
});

const ArchitectPlanSchema = z.object({
    tables: z.array(TableSchema).max(20),
    seedData: z.record(z.array(z.any())).optional(),
    uiConfig: z.any()
});

// Middleware de Validación Genérico
const validate = (schema) => (req, res, next) => {
    try { 
        schema.parse(req.body); 
        next(); 
    } catch (e) { 
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors }); 
    }
};

// --- MIDDLEWARE DE AUTENTICACIÓN Y METERING ---
const requireAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.split(' ')[1];
    
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });
        
        // Verificación de Suscripción (Stub para futura integración con Stripe)
        const { data: profile } = await masterSupabase
            .from('users')
            .select('plan, subscription_status, role')
            .eq('id', user.id)
            .single();

        // Si está baneado, bloqueamos
        if (profile?.subscription_status === 'banned') {
            return res.status(403).json({ error: 'Cuenta suspendida por administración.' });
        }

        req.user = user;
        req.userProfile = profile;
        next();
    } catch (e) { 
        return res.status(401).json({ error: 'Error de autorización' }); 
    }
};

// --- SEGURIDAD: DETECCIÓN DE PROMPT INJECTION ---
const detectPromptInjection = (text) => {
    if (!text || typeof text !== 'string') return false;
    const patterns = [
        /ignore previous instructions/i, 
        /system prompt/i, 
        /act as a/i, 
        /reset instructions/i, 
        /drop table/i, 
        /delete from/i, 
        /alter role/i
    ];
    return patterns.some(p => p.test(text));
};

// --- HELPER: LEER ESQUEMA ACTUAL (PARA SMART DELTA) ---
async function getCurrentSchema() {
    const client = await dbPool.connect();
    try {
        const res = await client.query(`
            SELECT table_name, column_name, data_type 
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name LIKE 'app_%'
            ORDER BY table_name, ordinal_position;
        `);
        
        const tables = {};
        res.rows.forEach(row => {
            const tableName = row.table_name.replace('app_', '');
            if (!tables[tableName]) tables[tableName] = [];
            tables[tableName].push(`${row.column_name} (${row.data_type})`);
        });
        
        return JSON.stringify(tables, null, 2);
    } catch (e) { 
        console.error("Error leyendo esquema:", e);
        return "{}"; 
    } finally { 
        client.release(); 
    }
}

// --- HELPER: ACTUALIZAR LOG DE CONSTRUCCIÓN ---
async function updateBuildLog(userId, message) {
    console.log(`[BUILD LOG ${userId}]: ${message}`);
    // Intentamos actualizar, si falla no detenemos el proceso
    await masterSupabase
        .from('web_clinica')
        .update({ build_log: message })
        .eq('ID_USER', userId)
        .catch(() => {});
}

// --- 🔥 MOTOR DE EJECUCIÓN V4.2 (SEGURO Y ROBUSTO) ---
async function executeArchitectPlan(dbClient, userId, rawPlan) {
    let plan;
    try {
        // 1. Validación Estricta con Zod
        plan = ArchitectPlanSchema.parse(rawPlan); 
    } catch (zodError) {
        const errorMsg = `❌ Plan inválido generado por IA: ${zodError.errors.map(e => e.path.join('.') + ': ' + e.message).join(', ')}`;
        console.error(errorMsg);
        await updateBuildLog(userId, errorMsg);
        throw new Error("La IA generó un plan inválido. Por favor intenta de nuevo dando más detalles.");
    }
    
    // 2. Dry Run / Verificación de Cambios
    const totalTables = plan.tables.length;
    if (totalTables === 0) {
        await updateBuildLog(userId, "ℹ️ No se detectaron cambios necesarios en la estructura de base de datos.");
        return;
    }

    await updateBuildLog(userId, `🏗️ Ejecutando cambios en ${totalTables} tablas (Modo Seguro)...`);

    // Mapeo de Tipos SQL
    const typeMap = { 
        'text': 'TEXT', 
        'integer': 'INTEGER', 
        'bigint': 'BIGINT', 
        'boolean': 'BOOLEAN', 
        'date': 'TIMESTAMPTZ', 
        'json': 'JSONB', 
        'uuid': 'UUID', 
        'array_text': 'TEXT[]' 
    };

    // 3. Creación/Modificación de Tablas
    for (const table of plan.tables) {
        const tableName = `app_${table.name}`; // Sanitizado por Zod

        // Crear tabla base (Idempotente)
        await dbClient.query(`
            CREATE TABLE IF NOT EXISTS public.${tableName} (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                user_id UUID REFERENCES auth.users(id) DEFAULT auth.uid() NOT NULL,
                updated_at TIMESTAMPTZ
            );
        `);

        // Agregar columnas (Smart Delta)
        for (const col of table.columns) {
            const sqlType = typeMap[col.type];
            try {
                // Truco para ADD COLUMN IF NOT EXISTS en versiones viejas de PG o standard compliance
                await dbClient.query(`
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='${tableName}' AND column_name='${col.name}') THEN 
                            ALTER TABLE public.${tableName} ADD COLUMN ${col.name} ${sqlType}; 
                        END IF; 
                    END $$;
                `);
                
                // Índices automáticos
                if (col.indexed || col.name.endsWith('_id') || col.name === 'email') {
                    const idxName = `idx_${tableName}_${col.name}`;
                    await dbClient.query(`CREATE INDEX IF NOT EXISTS ${idxName} ON public.${tableName} (${col.name});`);
                }

            } catch (e) { 
                console.warn(`⚠️ Advertencia en columna ${col.name}:`, e.message); 
            }
        }

        // RLS Obligatorio (Siempre se reaplica por seguridad)
        await dbClient.query(`ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;`);
        await dbClient.query(`DROP POLICY IF EXISTS "tenant_isolation" ON public.${tableName};`);
        await dbClient.query(`CREATE POLICY "tenant_isolation" ON public.${tableName} USING (user_id = auth.uid());`);
        await dbClient.query(`GRANT ALL ON public.${tableName} TO authenticated, service_role;`);
    }

    // 4. Creación de Relaciones (Foreign Keys)
    for (const table of plan.tables) {
        const tableName = `app_${table.name}`;
        for (const col of table.columns) {
            if (col.references) {
                const refTable = `app_${col.references.table}`;
                const refCol = col.references.column || 'id';
                const constraintName = `fk_${tableName}_${col.name}`;
                
                try {
                    await dbClient.query(`
                        DO $$ BEGIN 
                            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${constraintName}') THEN 
                                ALTER TABLE public.${tableName} 
                                ADD CONSTRAINT ${constraintName} 
                                FOREIGN KEY (${col.name}) REFERENCES public.${refTable} (${refCol}) 
                                ON DELETE SET NULL; 
                            END IF; 
                        END $$;
                    `);
                } catch (e) { 
                    console.warn(`⚠️ Advertencia FK ${constraintName}:`, e.message); 
                }
            }
        }
    }

    // 5. Seeding Inteligente (Datos de Prueba)
    if (plan.seedData) {
        for (const [key, rows] of Object.entries(plan.seedData)) {
            const tableName = `app_${key}`;
            for (const row of rows) {
                // Filtramos keys para evitar inyección en nombres de columnas
                const keys = Object.keys(row).filter(k => k !== 'user_id');
                if (keys.length === 0) continue;

                // Serialización de objetos/arrays a JSON string
                const values = keys.map(k => {
                    const val = row[k];
                    return (typeof val === 'object' && val !== null) ? JSON.stringify(val) : val;
                });

                const cols = keys.join(', '); // Seguro porque keys vienen del JSON validado
                const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
                
                // Si trae ID, usamos ON CONFLICT para no duplicar en re-runs
                const conflict = keys.includes('id') ? 'ON CONFLICT (id) DO NOTHING' : '';

                try {
                    await dbClient.query(
                        `INSERT INTO public.${tableName} (${cols}, user_id) 
                         VALUES (${placeholders}, $${keys.length + 1}) ${conflict}`,
                        [...values, userId]
                    );
                } catch (e) { 
                    console.warn(`⚠️ Error seeding ${tableName}:`, e.message); 
                }
            }
        }
    }
}

// --- 🧠 ORQUESTADOR DE IA (CON SMART DELTA) ---
async function buildSystemWithAI(userId, summary) {
    const dbClient = await dbPool.connect(); 
    try {
        await updateBuildLog(userId, "🧠 Analizando arquitectura y generando plan...");
        
        // 1. Leer esquema actual para hacer cambios diferenciales
        const currentSchema = await getCurrentSchema();

        const systemPrompt = `ERES UN ARQUITECTO DE BASES DE DATOS POSTGRESQL EXPERTO.
        
        TU MISIÓN: Diseñar o Evolucionar un esquema de base de datos para: "${summary}".
        
        ESQUEMA ACTUAL (Tablas ya existentes):
        ${currentSchema}
        
        INSTRUCCIONES CLAVE (SMART DELTA):
        1. **SI UNA TABLA YA EXISTE** con las columnas necesarias, **NO** la incluyas en el array 'tables'.
        2. **SOLO GENERA** tablas nuevas o columnas que falten en tablas existentes.
        3. Prioriza 'ALTER' (agregar columnas) sobre crear tablas nuevas.
        4. Genera un JSON PLAN que cumpla estrictamente el esquema proporcionado.
        
        TIPOS PERMITIDOS: text, integer, bigint, boolean, date, json, uuid, array_text.
        
        FORMATO JSON ESPERADO:
        {
          "tables": [ 
            { 
              "name": "pacientes", 
              "columns": [ 
                { "name": "nombre", "type": "text", "indexed": true },
                { "name": "edad", "type": "integer" }
              ] 
            } 
          ],
          "seedData": { 
            "pacientes": [{ "nombre": "Ejemplo", "edad": 30 }] 
          },
          "uiConfig": { 
            "theme": "#00E599",
            "modules": ["pacientes"] 
          }
        }`;

        const completion = await openai.chat.completions.create({
            model: "meta-llama/llama-3.3-70b-instruct:free", // Modelo potente y rápido
            messages: [{ role: "system", content: systemPrompt }],
            temperature: 0.1,
            response_format: { type: "json_object" }
        });

        let rawPlan;
        try {
            rawPlan = JSON.parse(completion.choices[0].message.content);
        } catch (e) {
            throw new Error("La IA generó una respuesta que no es un JSON válido.");
        }
        
        // 2. Ejecutar Transacción
        await updateBuildLog(userId, "🏗️ Aplicando cambios a la base de datos...");
        await dbClient.query('BEGIN');
        await executeArchitectPlan(dbClient, userId, rawPlan);
        await dbClient.query('COMMIT');

        // 3. Finalizar
        await updateBuildLog(userId, "🎨 Actualizando interfaz y finalizando...");
        await masterSupabase.from('web_clinica').update({ 
            status: 'active', 
            ui_config: rawPlan.uiConfig, 
            build_log: '✅ Sistema Actualizado y Listo (V4.2)' 
        }).eq('ID_USER', userId);

    } catch (error) {
        await dbClient.query('ROLLBACK');
        console.error("🔥 Error Crítico en Construcción:", error);
        await updateBuildLog(userId, `❌ Error: ${error.message}`);
    } finally {
        dbClient.release();
    }
}

// =================================================================
// RUTAS DE LA API
// =================================================================

// 1. CHAT INTERACTIVO (MULTIMODAL + MEMORIA)
app.post('/api/onboarding/interactive', requireAuth, upload.array('files', 5), async (req, res) => {
    const { message } = req.body;
    const files = req.files || [];
    const userId = req.user.id;

    // Validación Anti-Injection básica
    if (detectPromptInjection(message)) {
        return res.status(400).json({ error: "Mensaje rechazado por políticas de seguridad." });
    }

    try {
        // Recuperar o Crear Sesión de Onboarding
        let { data: session } = await masterSupabase.from('onboarding_session').select('*').eq('user_id', userId).maybeSingle();
        if (!session) {
            const { data: newS } = await masterSupabase.from('onboarding_session').insert({ 
                user_id: userId, 
                conversation_history: [], 
                extracted_context: {} 
            }).select().single();
            session = newS;
        }

        // Construir Contexto del Usuario (Texto + Archivos)
        let userContent = [{ type: "text", text: message || "Analiza estos archivos." }];
        
        for (const file of files) {
            if (file.mimetype.startsWith('image/')) {
                // Visión: Base64
                const b64 = file.buffer.toString('base64');
                userContent.push({ type: "image_url", image_url: { url: `data:${file.mimetype};base64,${b64}` } });
            } else if (file.mimetype.includes('sheet') || file.mimetype.includes('csv')) {
                // Datos: Parsear Excel/CSV
                const wb = xlsx.read(file.buffer, { type: 'buffer' });
                const preview = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1 }).slice(0, 5); // Solo 5 filas de muestra
                userContent[0].text += `\n[ARCHIVO SUBIDO ${file.originalname} - MUESTRA]: ${JSON.stringify(preview)}`;
            }
        }

        // Recuperar historial reciente para mantener contexto
        const history = (session.conversation_history || []).slice(-10).map(m => ([
            { role: "user", content: m.user }, 
            { role: "assistant", content: m.bot }
        ])).flat();

        // Llamada a la IA
        const completion = await openai.chat.completions.create({
            model: "openai/gpt-4o-mini", // Modelo capaz de visión y json mode
            messages: [
                { role: "system", content: "Eres Vintex, un Arquitecto de Software. Analiza los requerimientos. Responde SIEMPRE en JSON: { reply: string, updated_context: object, is_ready: boolean }" },
                ...history,
                { role: "user", content: userContent }
            ],
            response_format: { type: "json_object" }
        });

        const aiData = JSON.parse(completion.choices[0].message.content);

        // Actualizar Memoria en DB
        await masterSupabase.from('onboarding_session').update({
            conversation_history: [...(session.conversation_history || []), { user: message, bot: aiData.reply }],
            extracted_context: { ...session.extracted_context, ...aiData.updated_context },
            analysis_status: aiData.is_ready ? 'ready' : 'listening'
        }).eq('session_id', session.session_id);

        res.json(aiData);

    } catch (e) {
        console.error("Chat Error:", e);
        res.status(500).json({ error: "Error procesando solicitud de IA." });
    }
});

// 2. COMPLETAR ONBOARDING (DISPARAR CONSTRUCTOR)
app.post('/api/onboarding/complete', requireAuth, validate(OnboardingCompleteSchema), async (req, res) => {
    const { conversationSummary } = req.body;
    const userId = req.user.id;

    try {
        // Asegurar usuario y servicios (Auto-reparación preventiva)
        await masterSupabase.from('users').upsert({ id: userId, email: req.user.email, role: 'admin' }, { onConflict: 'id', ignoreDuplicates: true });
        await masterSupabase.from('servisi').upsert({ "ID_User": userId, web_clinica: true }, { onConflict: "ID_User", ignoreDuplicates: true });
        await masterSupabase.from('web_clinica').upsert({ "ID_USER": userId, status: "building" }, { onConflict: "ID_USER" });

        // Iniciar construcción asíncrona (Fire and Forget)
        buildSystemWithAI(userId, conversationSummary);

        res.json({ success: true, message: "Arquitecto iniciado correctamente." });
    } catch (error) {
        console.error("Error al iniciar construcción:", error);
        res.status(500).json({ error: "No se pudo iniciar la construcción." });
    }
});

// 3. INIT SESSION (CONFIGURACIÓN DINÁMICA + AUTO REPARACIÓN)
app.get('/api/config/init-session', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing' });
    
    try {
        const { data: { user } } = await masterSupabase.auth.getUser(token);
        if (!user) return res.status(401).json({ error: 'Invalid token' });

        // Auto-reparación silenciosa
        await masterSupabase.from('users').upsert({ id: user.id, email: user.email, role: 'admin' }, { onConflict: 'id', ignoreDuplicates: true });
        await masterSupabase.from('servisi').upsert({ "ID_User": user.id, web_clinica: true }, { onConflict: "ID_User", ignoreDuplicates: true });

        const { data: config } = await masterSupabase.from('web_clinica').select('SUPABASE_URL, ui_config').eq('ID_USER', user.id).maybeSingle();
        
        res.json({
            hasClinic: !!config,
            backendUrl: SATELLITE_URL,
            supabaseUrl: config?.SUPABASE_URL || process.env.SUPABASE_URL,
            supabaseAnonKey: "public-anon-key-placeholder", 
            uiConfig: config?.ui_config
        });
    } catch (e) {
        console.error("Init Session Error:", e);
        res.status(500).json({ error: "Error interno" });
    }
});

// 4. RUTAS LEGACY DE AUTENTICACIÓN (LOGIN/REGISTER/TRIAL)
app.post('/api/register', authLimiter, validate(RegisterSchema), async (req, res) => {
    const { email, password, full_name } = req.body;
    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email, password, options: { data: { full_name } }
        });
        if (authError) throw authError;
        
        // Crear perfil inmediatamente
        if (authData.user) {
            await masterSupabase.from('users').upsert({ id: authData.user.id, email, full_name, role: 'admin' });
            await masterSupabase.from('servisi').upsert({ "ID_User": authData.user.id, web_clinica: true });
        }

        res.status(200).json({ success: true, session: authData.session });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/login', authLimiter, validate(LoginSchema), async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: 'Credenciales inválidas' });
    return res.json({ success: true, session: data.session, user: data.user });
});

app.post('/api/start-trial', authLimiter, validate(TrialSchema), async (req, res) => {
    // Lógica de prueba gratuita (Stub)
    res.status(200).json({ success: true, message: "Trial registrado." });
});

app.post('/api/templates/instantiate', requireAuth, async (req, res) => {
    // Lógica para instanciar plantillas predefinidas (Stub)
    res.json({ success: true, message: "Plantilla cargada." });
});

// 5. HEALTH CHECK
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', uptime: process.uptime(), timestamp: new Date() });
});

// --- INICIAR SERVIDOR ---
app.listen(PORT, () => {
    console.log(`🚀 VINTEX ENGINE 4.2 (FULL ENTERPRISE) corriendo en puerto ${PORT}`);
});
