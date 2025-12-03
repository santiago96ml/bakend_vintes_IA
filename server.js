import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import crypto from 'crypto';

dotenv.config();
const app = express();
app.set('trust proxy', 1); // CORRECCIÓN: Necesario para Rate Limit detrás de proxy
const PORT = process.env.PORT || 3000;

const SATELLITE_URL = process.env.SATELLITE_URL || "https://webs-de-vintex-bakend-de-clinica.1kh9sk.easypanel.host/";
const FRONTEND_URL = process.env.FRONTEND_URL;

// --- 1. SEGURIDAD ---
app.use(helmet());
app.use(cors({
    origin: FRONTEND_URL ? [FRONTEND_URL, 'http://localhost:5173'] : 'http://localhost:5173',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.json({ limit: '10kb' })); // DoS Protection JSON

// Rate Limit
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    message: { error: "Demasiadas peticiones." }
});
app.use(limiter);

// Logger Sanitizado
const sanitizeLog = (obj) => {
    if (!obj) return obj;
    const copy = { ...obj };
    // CORRECCIÓN: Lista ampliada con PII (dni, telefono, email, etc.)
    const sensitiveKeys = ['password', 'token', 'access_token', 'session', 'secret', 'dni', 'credit_card', 'cvv', 'phone', 'telefono', 'email'];
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
        console.log('   Payload:', JSON.stringify(sanitizeLog(req.body), null, 2));
    }
    next();
});

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ FALTA CONFIGURACIÓN: SUPABASE_URL o SUPABASE_SERVICE_KEY.");
    process.exit(1);
}

const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// Esquemas Zod
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

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// RUTAS

app.post('/api/register', validate(registerSchema), async (req, res) => {
  const { email, password, full_name } = req.body;
  try {
    const { data: authData, error: authError } = await masterSupabase.auth.signUp({
      email,
      password,
      options: { data: { full_name } }
    });

    if (authError) throw authError;
    if (!authData.user) throw new Error("Error en creación de usuario.");

    const userId = authData.user.id;

    const { error: userError } = await masterSupabase.from('users').insert({
        id: userId,
        email: email,
        full_name: full_name,
        role: 'admin',
        created_at: new Date()
    });

    if (userError) throw userError;

    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 14);

    await masterSupabase.from('trials').insert({
        user_id: userId,
        start_date: new Date(),
        end_date: endDate,
        status: 'active'
    });

    await masterSupabase.from('servisi').insert({
        "ID_User": userId,
        web_clinica: false,
        "Bot_clinica": false
    });
      
    res.status(200).json({
      message: 'Usuario registrado correctamente',
      user: { id: authData.user.id, email: authData.user.email },
      session: authData.session 
    });

  } catch (error) {
    console.error("Registro error:", error.message); 
    res.status(400).json({ error: 'Error al procesar el registro.' });
  }
});

app.post('/api/start-trial', validate(trialSchema), async (req, res) => {
    const { email, fullName, phone } = req.body;
    // Crypto Safe Random Password
    const tempPassword = crypto.randomBytes(16).toString('hex') + "V!1";

    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email,
            password: tempPassword,
            options: { data: { full_name: fullName, phone } }
        });

        if (authError) throw authError;
        const userId = authData.user.id;

        await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: fullName,
            phone: phone,
            role: 'admin'
        });

        await masterSupabase.from('servisi').insert({
            "ID_User": userId,
            web_clinica: false, 
            "Bot_clinica": false
        });

        console.log(`[INFO] Usuario Trial creado: ${email}`); 
        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });

    } catch (error) {
        console.error("Trial error:", error.message);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// Login con User Enumeration Protection
app.post('/api/login', validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
        
        // Mensaje GENÉRICO para evitar enumeración
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

app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });

        // SOLUCIÓN CRÍTICA: Devolver ANON KEY, no Service Key.
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_ANON_KEY') 
            .eq('ID_USER', user.id)
            .single();
        
        if (!config) {
             return res.status(200).json({ hasClinic: false });
        }

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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER SECURE en puerto ${PORT}`);
});