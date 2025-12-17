import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';
import OpenAI from 'openai';
import multer from 'multer';
import xlsx from 'xlsx';
import { Readable } from 'stream';

dotenv.config();
const app = express();

// 1. TRUST PROXY
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

// 2. CORS
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

// 3. Body Parser
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Configuración de Multer (Memoria temporal para archivos)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB Límite
});

// 4. Rate Limits
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

// 4. CHAT ARQUITECTO INTERACTIVO (Onboarding con Archivos y Memoria) - NUEVO 🚀
app.post('/api/onboarding/interactive', requireAuth, upload.single('file'), async (req, res) => {
    const { message, sessionId } = req.body; // Mensaje del usuario
    const file = req.file; // Archivo adjunto (si hay)
    const userId = req.user.id;

    try {
        // 1. RECUPERAR MEMORIA (Simulando Redis)
        let { data: session } = await masterSupabase
            .from('onboarding_session')
            .select('*')
            .eq('user_id', userId)
            .maybeSingle();

        // Si no existe sesión, creamos una
        if (!session) {
            const { data: newSession } = await masterSupabase
                .from('onboarding_session')
                .insert({ user_id: userId, extracted_context: {} })
                .select()
                .single();
            session = newSession;
        }

        // 2. PROCESAR ARCHIVOS (Ojos del Bot) 👁️
        let fileContext = "";
        if (file) {
            console.log(`📂 Procesando archivo: ${file.originalname}`);

            if (file.mimetype.includes('csv') || file.mimetype.includes('spreadsheet')) {
                // Leer Excel/CSV
                const workbook = xlsx.read(file.buffer, { type: 'buffer' });
                const sheetName = workbook.SheetNames[0];
                const sheet = workbook.Sheets[sheetName];
                // Convertimos a JSON (Solo las primeras 20 filas para no saturar a la IA)
                const dataPreview = xlsx.utils.sheet_to_json(sheet, { header: 1 }).slice(0, 20);
                fileContext = `EL USUARIO SUBIÓ UN ARCHIVO DE DATOS (${file.originalname}). 
                ESTA ES UNA MUESTRA DE LA ESTRUCTURA:\n${JSON.stringify(dataPreview)}`;
            } else if (file.mimetype.startsWith('image/')) {
                // Aquí podrías usar GPT-4o Vision para describir la imagen (placeholder)
                fileContext = `[IMAGEN RECIBIDA: ${file.originalname} - Análisis de visión pendiente]`;
            }
        }

        // 3. PENSAMIENTO DE LA IA (El Consultor Experto "Vintex Architect") 🧠
        // Reemplazo del prompt genérico por el Prompt Experto de Consultoría No-Code
        const systemPrompt = `
        Eres "Vintex Architect", un Consultor de Producto experto en diseñar aplicaciones de gestión estilo Airtable/No-Code.
        
        MEMORIA ACTUAL DEL USUARIO: ${JSON.stringify(session.extracted_context)}

        TU OBJETIVO: Entrevistar al usuario para definir su modelo de negocio y, CRÍTICAMENTE, cómo quiere VISUALIZAR sus datos.
        
        REGLAS DE INTERACCIÓN:
        1. Analiza lo que dice el usuario y los archivos que sube.
        2. Haz UNA sola pregunta a la vez. Sé conciso.
        3. Si suben un Excel, deduce las tablas basándote en las columnas.
        4. Decide si sugieres una plantilla existente o sigues preguntando.

        FASES DE LA ENTREVISTA (Guía interna):
        - FASE 1 (NEGOCIO): Identificar rubro.
        - FASE 2 (DATOS): Sugerir entidades (Clientes, Pedidos, etc).
        - FASE 3 (VISTAS): ¿Calendario, Kanban o Lista? Si es Kanban, pedir estados.
        - FASE 4 (EXTRAS): Archivos, cobros.

        DEVUELVE SOLO JSON:
        {
            "reply": "Tu respuesta al usuario (usando el tono de Vintex Architect)",
            "updated_context": { ...datos extraídos actualizados... },
            "suggested_template_id": (null o ID si encaja perfecto con una plantilla de la BD),
            "is_ready": (true/false si ya tienes suficiente info para construir)
        }
        `;

        const userContent = `Usuario dice: "${message || ''}". \n ${fileContext}`;

        const completion = await openai.chat.completions.create({
            model: "meta-llama/llama-3.3-70b-instruct:free", // Modelo potente
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userContent }
            ],
            response_format: { type: "json_object" }
        });

        const aiThinking = JSON.parse(completion.choices[0].message.content);

        // 4. ACTUALIZAR MEMORIA (Guardar estado)
        await masterSupabase
            .from('onboarding_session')
            .update({
                conversation_history: [...session.conversation_history, { role: 'user', content: message }, { role: 'assistant', content: aiThinking.reply }],
                extracted_context: aiThinking.updated_context,
                suggested_template_id: aiThinking.suggested_template_id,
                analysis_status: aiThinking.is_ready ? 'ready' : 'listening'
            })
            .eq('session_id', session.session_id);

        res.json(aiThinking);

    } catch (e) {
        console.error("Error en Interactive Onboarding:", e);
        res.status(500).json({ error: "Error procesando tu solicitud." });
    }
});

// 5. COMPLETAR ONBOARDING (FINALIZAR Y DESPLEGAR)
app.post('/api/onboarding/complete', requireAuth, validate(onboardingCompleteSchema), async (req, res) => {
    const { conversationSummary, schemaConfig } = req.body;
    const user = req.user;
    const N8N_URL = process.env.N8N_DEPLOY_WEBHOOK_URL;

    if (!N8N_URL) {
        return res.status(500).json({ error: "Error de configuración del sistema." });
    }

    try {
        console.log(`🚀 [AUTOMATION] Iniciando despliegue para Usuario: ${user.id}`);

        // --- 🛡️ PASO DE SEGURIDAD: VERIFICAR/CREAR USUARIO (Fallback) ---
        const { data: existingUser } = await masterSupabase
            .from('users')
            .select('id')
            .eq('id', user.id)
            .single();

        if (!existingUser) {
            console.log(`⚠️ Usuario ${user.id} no encontrado en tabla pública. Creándolo ahora...`);
            const { error: insertError } = await masterSupabase.from('users').insert({
                id: user.id,
                email: user.email,
                full_name: user.user_metadata?.full_name || user.email.split('@')[0],
                role: 'admin',
                created_at: new Date()
            });

            if (insertError) {
                console.error("❌ Error creando usuario fallback:", insertError);
                throw new Error("No se pudo crear el perfil del usuario.");
            }
        }

        // Actualizar suscripción
        const { error: updateError } = await masterSupabase.from('users').update({
            subscription_status: 'active',
            plan_type: 'pro',
            last_payment_date: new Date(),
        }).eq('id', user.id);

        if (updateError) console.warn("Advertencia al actualizar usuario:", updateError.message);

        // Disparar n8n
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

        // DB Placeholders
        const { error: dbError } = await masterSupabase
            .from('web_clinica')
            .upsert({
                "ID_USER": user.id,
                "SUPABASE_URL": "https://building.vintex.ai",
                "SUPABASE_ANON_KEY": "building",
                "SUPABASE_SERVICE_KEY": "building",
                "JWT_SECRET": "building",
                "url_backend": "https://building.vintex.ai",
                "status": "building"
            }, { onConflict: "ID_USER" });

        if (dbError) throw dbError;

        res.json({ success: true, message: "Despliegue iniciado." });

    } catch (error) {
        console.error("Error Fatal en Onboarding:", error);
        res.status(500).json({ error: "Error procesando el despliegue." });
    }
});

// 6. CHAT GENERAL (Legacy / Uso General)
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

// --- RUTA NUEVA: INSTANCIADOR DE PLANTILLAS (Tipo Airtable) ---
app.post('/api/templates/instantiate', requireAuth, async (req, res) => {
    const { templateId } = req.body;
    const userId = req.user.id;

    try {
        // 1. Buscamos la plantilla maestra
        const { data: template, error: tError } = await masterSupabase
            .from('templates')
            .select('*')
            .eq('id', templateId)
            .single();

        if (tError || !template) return res.status(404).json({ error: "Plantilla no encontrada" });

        // 2. "Clonamos" la configuración visual al usuario (Preview Instantáneo)
        const { error: updateError } = await masterSupabase
            .from('web_clinica')
            .upsert({
                ID_USER: userId,
                ui_config: template.ui_config_template, // Copiamos el diseño
                source_template_id: template.id,
                status: 'preview_template' // Estado especial "Previsualizando"
            }, { onConflict: 'ID_USER' });

        if (updateError) throw updateError;

        res.json({
            success: true,
            message: "Plantilla cargada en modo previsualización",
            uiConfig: template.ui_config_template,
            systemPrompt: template.ai_system_prompt
        });

    } catch (error) {
        console.error("Error instanciando plantilla:", error);
        res.status(500).json({ error: "Error al cargar la plantilla" });
    }
});

// =================================================================
// RUTAS INFRAESTRUCTURA (Configuración Dinámica + Auto-Reparación V2)
// =================================================================

app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.split(' ')[1];
    
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });
        
        // --- 🛡️ AUTO-REPARACIÓN A PRUEBA DE FALLOS ---
        // Usamos UPSERT con ignoreDuplicates:true (en lógica) para asegurar que existan
        // sin sobrescribir datos si ya existen.
        
        // 1. Asegurar Usuario en tabla pública
        await masterSupabase.from('users').upsert({
            id: user.id,
            email: user.email,
            full_name: user.user_metadata?.full_name || user.email.split('@')[0],
            role: 'admin',
            created_at: new Date()
        }, { onConflict: 'id', ignoreDuplicates: true });

        // 2. Asegurar Servicios (CRÍTICO: Si esto falta, el usuario es zombie)
        await masterSupabase.from('servisi').upsert({
            "ID_User": user.id, 
            web_clinica: true, 
            "Bot_clinica": true
        }, { onConflict: "ID_User", ignoreDuplicates: true });

        // ------------------------------------------------

        // 3. Buscar configuración de la Clínica
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