import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// URL DEL SATÉLITE
const SATELLITE_URL = "https://webs-de-vintex-bakend-de-clinica.1kh9sk.easypanel.host/";
// URL DEL FRONTEND (Asegúrate de poner la URL real de tu frontend aquí)
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tu-dominio-frontend.com";

// --- 1. SEGURIDAD: HELMET & CORS ---
app.use(helmet()); // Headers de seguridad HTTP
app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:5173'], // Solo permite tu frontend y localhost para dev
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10kb' })); // Limita el tamaño del body para evitar DoS

// --- 2. SEGURIDAD: RATE LIMITING ---
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    limit: 100, // Máximo 100 peticiones por IP
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: "Demasiadas peticiones, intenta más tarde." }
});
app.use(limiter);

// --- 3. LOGGER SANITIZADO ---
app.use((req, res, next) => {
    console.log(`\n🔵 [REQUEST] ${req.method} ${req.url}`);
    
    if (req.body && Object.keys(req.body).length > 0) {
        // Clonamos el body para no modificar el original
        const sanitizedBody = { ...req.body };
        // Ocultamos datos sensibles
        if (sanitizedBody.password) sanitizedBody.password = '********';
        if (sanitizedBody.token) sanitizedBody.token = '********';
        console.log('   Payload:', JSON.stringify(sanitizedBody, null, 2));
    }

    next();
});

// Verificación de variables de entorno
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ FALTA CONFIGURACIÓN: SUPABASE_URL o SUPABASE_SERVICE_KEY.");
    process.exit(1);
}

const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- ESQUEMAS DE VALIDACIÓN ZOD ---
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
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

// Middleware de Validación
const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- RUTAS ---

// 1. REGISTRO
app.post('/api/register', validate(registerSchema), async (req, res) => {
  const { email, password, full_name } = req.body;

  try {
    const { data: authData, error: authError } = await masterSupabase.auth.signUp({
      email,
      password,
      options: { data: { full_name } }
    });

    if (authError) throw authError;
    if (!authData.user) throw new Error("No se pudo crear el usuario en Auth.");

    const userId = authData.user.id;

    const { error: userError } = await masterSupabase.from('users').insert({
        id: userId,
        email: email,
        full_name: full_name,
        role: 'admin',
        created_at: new Date()
    });

    if (userError) throw userError;

    // Inicializar Trial y Servicios (Lógica original mantenida)
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
      user: authData.user,
      session: authData.session 
    });

  } catch (error) {
    console.error("Error REAL en registro:", error); // Logueamos el error real
    // Respondemos genérico al cliente
    res.status(400).json({ error: 'Error al procesar el registro.' });
  }
});

// 2. START TRIAL
app.post('/api/start-trial', validate(trialSchema), async (req, res) => {
    const { email, fullName, phone } = req.body;
    const tempPassword = Math.random().toString(36).slice(-8) + "V!1";

    try {
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email,
            password: tempPassword,
            options: { data: { full_name: fullName, phone } }
        });

        if (authError) throw authError;
        if (!authData.user) throw new Error('No se pudo crear el usuario.');

        const userId = authData.user.id;

        const { error: dbError } = await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: fullName,
            phone: phone,
            role: 'admin'
        });

        if (dbError) throw dbError;

        await masterSupabase.from('servisi').insert({
            "ID_User": userId,
            web_clinica: false, 
            "Bot_clinica": false
        });

        // OJO: Aquí deberías enviar el email real, no loguear la password en prod
        console.log(`[INFO] Usuario Trial creado: ${email}`); 

        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });

    } catch (error) {
        console.error("Error REAL trial:", error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// 3. LOGIN
app.post('/api/login', validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
        if (error || !data.user) return res.status(401).json({ error: 'Credenciales inválidas' });

        return res.json({
            success: true,
            session: data.session,
            user: data.user
        });
    } catch (e) {
        console.error("Error Login:", e);
        return res.status(500).json({ error: 'Error interno de autenticación.' });
    }
});

// 4. INIT SESSION
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });

        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('*')
            .eq('ID_USER', user.id)
            .single();
        
        if (!config) {
             return res.status(200).json({ hasClinic: false });
        }

        return res.json({
            hasClinic: true,
            backendUrl: SATELLITE_URL, 
            supabaseUrl: config.SUPABASE_URL,
            supabaseAnonKey: config.SUPABASE_SERVICE_KEY 
        });
    } catch (e) {
        console.error("Error Init Session:", e);
        return res.status(500).json({ error: 'Error recuperando configuración.' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER SECURE en puerto ${PORT}`);
});