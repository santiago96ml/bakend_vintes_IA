import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// URL DEL SATÉLITE (Proporcionada por ti)
const SATELLITE_URL = "https://webs-de-vintex-bakend-de-clinica.1kh9sk.easypanel.host/";

app.use(cors({ origin: '*' }));
app.use(express.json());

// --- LOGGER MIDDLEWARE (NUEVO) ---
// Muestra en consola todas las peticiones entrantes y las respuestas salientes
app.use((req, res, next) => {
    // 1. Loguear la petición (Request)
    console.log(`\n🔵 [REQUEST] ${req.method} ${req.url}`);
    if (req.body && Object.keys(req.body).length > 0) {
        console.log('   Payload:', JSON.stringify(req.body, null, 2));
    } else {
        console.log('   Payload: (vacío)');
    }

    // 2. Interceptar la respuesta (Response)
    const originalJson = res.json;
    res.json = function (body) {
        console.log(`fq [RESPONSE] Status: ${res.statusCode}`);
        if (body) {
            console.log('   Body:', JSON.stringify(body, null, 2));
        }
        return originalJson.call(this, body);
    };

    next();
});
// ---------------------------------

// Verificación de variables de entorno
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ FALTA CONFIGURACIÓN: SUPABASE_URL o SUPABASE_SERVICE_KEY en Master.");
    process.exit(1);
}

// Cliente Maestro
const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- RUTAS ---

// 1. RUTA DE REGISTRO COMPLETA (Corregida)
app.post('/api/register', async (req, res) => {
  const { email, password, full_name } = req.body;

  try {
    // A. Crear usuario en Supabase Auth (Usando masterSupabase)
    const { data: authData, error: authError } = await masterSupabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name } // Guardamos el nombre en los metadatos
      }
    });

    if (authError) throw authError;
    if (!authData.user) throw new Error("No se pudo crear el usuario en Auth.");

    const userId = authData.user.id;

    // B. Guardar en tabla 'users' (Gestión del SaaS)
    const { error: userError } = await masterSupabase
      .from('users')
      .insert({
        id: userId,
        email: email,
        full_name: full_name,
        role: 'admin', // El que se registra es admin de su clínica
        created_at: new Date()
      });

    if (userError) throw userError;

    // C. Inicializar Trial (Prueba Gratuita)
    const startDate = new Date();
    const endDate = new Date();
    endDate.setDate(startDate.getDate() + 14); // 14 días de prueba

    const { error: trialError } = await masterSupabase
      .from('trials')
      .insert({
        user_id: userId,
        start_date: startDate,
        end_date: endDate,
        status: 'active'
      });

    if (trialError) console.error("Error creando trial:", trialError.message);

    // D. Inicializar Servicios (Tabla 'servisi')
    const { error: serviceError } = await masterSupabase
      .from('servisi')
      .insert({
        "ID_User": userId,
        web_clinica: false,
        "Bot_clinica": false
      });
      
    if (serviceError) console.error("Error servicios:", serviceError.message);

    // E. Responder con éxito y la sesión
    res.status(200).json({
      message: 'Usuario registrado correctamente',
      user: authData.user,
      session: authData.session 
    });

  } catch (error) {
    console.error("Error en registro:", error.message);
    res.status(400).json({ error: error.message });
  }
});

// 2. START TRIAL (Registro alternativo rápido)
app.post('/api/start-trial', async (req, res) => {
    const { email, fullName, phone } = req.body;
    // Generamos password temporal
    const tempPassword = Math.random().toString(36).slice(-8) + "V!1";

    try {
        // A. Crear Auth User
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email,
            password: tempPassword,
            options: { data: { full_name: fullName, phone } }
        });

        if (authError) return res.status(400).json({ error: authError.message });
        if (!authData.user) return res.status(400).json({ error: 'No se pudo crear el usuario.' });

        const userId = authData.user.id;

        // B. Insertar en tabla users
        const { error: dbError } = await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: fullName,
            phone: phone,
            role: 'admin'
        });

        if (dbError) throw dbError;

        // C. Crear servicios por defecto
        await masterSupabase.from('servisi').insert({
            "ID_User": userId,
            web_clinica: false, 
            "Bot_clinica": false
        });

        console.log(`Usuario creado (Trial): ${email} | Pass: ${tempPassword}`);

        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// 3. LOGIN
app.post('/api/login', async (req, res) => {
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
        return res.status(500).json({ error: e.message });
    }
});

// 4. INIT SESSION (Ruteo Inteligente)
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });

        // Buscar config de la clínica en Master DB
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('*')
            .eq('ID_USER', user.id)
            .single();
        
        if (!config) {
             // Si no tiene clínica configurada, no devolvemos backendUrl
             return res.status(200).json({ hasClinic: false });
        }

        return res.json({
            hasClinic: true,
            backendUrl: SATELLITE_URL, 
            supabaseUrl: config.SUPABASE_URL,
            supabaseAnonKey: config.SUPABASE_SERVICE_KEY 
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER en puerto ${PORT}`);
});