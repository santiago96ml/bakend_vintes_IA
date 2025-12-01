import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// URL DEL SATÉLITE (Proporcionada por ti)
const SATELLITE_URL = "https://webs-de-vintex-bakend-de-clinica.1kh9sk.easypanel.host";

app.use(cors({ origin: '*' }));
app.use(express.json());

// Verificación de variables de entorno (Configúralas en Easypanel)
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

// 1. REGISTRO (StartTrial)
app.post('/api/start-trial', async (req, res) => {
    const { email, fullName, phone } = req.body;
    // Generamos password temporal para el trial
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

        // B. Insertar en tabla public.users (Master DB)
        const { error: dbError } = await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: fullName,
            phone: phone,
            role: 'admin' // Dueño de la clínica
        });

        if (dbError) throw dbError;

        // C. Crear servicios por defecto
        await masterSupabase.from('servisi').insert({
            "ID_User": userId,
            web_clinica: false, 
            "Bot_clinica": false
        });

        // NOTA: Aquí deberías enviar un email real con la password temporal
        console.log(`Usuario creado: ${email} | Pass: ${tempPassword}`);

        return res.status(201).json({ success: true, message: 'Usuario registrado. Revisa tu email.' });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// 2. REGISTRO COMPLETO (Desde /register)
app.post('/api/register', async (req, res) => {
    const { email, password, fullName } = req.body;
    
    try {
        const { data, error } = await masterSupabase.auth.signUp({
            email,
            password,
            options: { data: { full_name: fullName } }
        });
        
        if (error) return res.status(400).json({ error: error.message });
        
        // Crear en tabla users
        if (data.user) {
             await masterSupabase.from('users').insert({
                id: data.user.id,
                email: email,
                full_name: fullName,
                role: 'admin'
            });
        }

        res.status(201).json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
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

// 4. INIT SESSION (El cerebro del ruteo)
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
            // AQUÍ ESTÁ LA CLAVE: Devolvemos la URL del Satélite al Frontend
            backendUrl: SATELLITE_URL, 
            supabaseUrl: config.SUPABASE_URL,
            supabaseAnonKey: config.SUPABASE_SERVICE_KEY // Usamos service key como anon temporalmente o configúralo en DB
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MASTER SERVER en puerto ${PORT}`);
});