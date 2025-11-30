import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Configuración CORS
app.use(cors({ origin: '*' }));
app.use(express.json());

// Verificación de credenciales
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan variables de entorno.");
    process.exit(1);
}

// Cliente Maestro (VINTEX AI)
const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// =============================================================================
// 1. ENDPOINT: REGISTRO (Crear Cuenta Email/Pass) [NUEVO]
// =============================================================================
app.post('/api/register', async (req, res) => {
    const { email, password, fullName } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Faltan datos requeridos.' });
    }

    try {
        // A. Crear usuario en Supabase Auth
        const { data: authData, error: authError } = await masterSupabase.auth.signUp({
            email,
            password,
            options: { data: { full_name: fullName } }
        });

        if (authError) return res.status(400).json({ error: authError.message });
        if (!authData.user) return res.status(400).json({ error: 'No se pudo crear el usuario.' });

        const userId = authData.user.id;

        // B. Crear entrada en tabla 'users'
        await masterSupabase.from('users').insert({
            id: userId,
            email: email,
            full_name: fullName || '',
            role_admin: false
        });

        // C. Crear servicios por defecto (Desactivados)
        await masterSupabase.from('servisi').insert({
            ID_User: userId,
            web_clinica: false,
            Bot_clinica: false
        });

        return res.status(201).json({ 
            success: true, 
            message: 'Usuario registrado correctamente. Por favor verifica tu email.' 
        });

    } catch (error) {
        console.error("Error en Registro:", error);
        // Si falla por duplicado (código 23505 de Postgres), avisar
        if (error.code === '23505') return res.status(400).json({ error: 'El usuario ya existe.' });
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// =============================================================================
// 2. ENDPOINT: LOGIN (Email y Contraseña)
// =============================================================================
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data, error } = await masterSupabase.auth.signInWithPassword({ email, password });
        if (error || !data.user) return res.status(401).json({ error: 'Credenciales inválidas' });

        // Obtener configuración de clínica si la tiene
        const config = await getClinicConfig(data.user.id);
        
        return res.json({
            success: true,
            session: data.session,
            user: data.user,
            satelliteConfig: config
        });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// 3. ENDPOINT: LOGIN CON GOOGLE
// =============================================================================
app.post('/api/auth/google', async (req, res) => {
  const { googleAccessToken } = req.body; 

  if (!googleAccessToken) return res.status(400).json({ error: 'Falta token.' });

  try {
    const { data: { user }, error } = await masterSupabase.auth.getUser(googleAccessToken);
    if (error || !user) return res.status(401).json({ error: 'Token inválido.' });

    // Sincronizar usuario (Upsert maneja si ya existe o no)
    await masterSupabase.from('users').upsert({
        id: user.id, 
        email: user.email, 
        full_name: user.user_metadata.full_name
    }, { onConflict: 'id' });

    // Asegurar que tenga fila de servicios
    const { data: s } = await masterSupabase.from('servisi').select('id').eq('ID_User', user.id).single();
    if (!s) {
        await masterSupabase.from('servisi').insert({ ID_User: user.id, web_clinica: false, Bot_clinica: false });
    }

    const config = await getClinicConfig(user.id);

    return res.json({
      success: true,
      session: { access_token: googleAccessToken, user },
      satelliteConfig: config
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// =============================================================================
// 4. ENDPOINT: INICIALIZAR SESIÓN (Para Dashboard)
// =============================================================================
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await masterSupabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Sesión inválida' });

        const config = await getClinicConfig(user.id);
        
        if (!config) {
             return res.status(200).json({ hasClinic: false });
        }

        return res.json({
            hasClinic: true,
            backendUrl: config.url_backend,
            supabaseUrl: config.SUPABASE_URL,
            // Nota: Si no guardaste supabase_anon_key en la tabla web_clinica, esto vendrá null.
            // Asegúrate de agregarlo a la tabla si el frontend lo necesita.
            supabaseAnonKey: config.supabase_anon_key || null 
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// 5. ENDPOINT: BOOT CONFIG (Para Servidor Satélite - Opcional pero Seguro) [NUEVO]
// =============================================================================
// Este endpoint permite que la clínica pregunte sus credenciales sin tener la MASTER_KEY
app.post('/api/internal/boot-config', async (req, res) => {
    const { clinicUserId } = req.body;
    if (!clinicUserId) return res.status(400).json({ error: 'ID requerido' });

    try {
        // Verificar servicio activo
        const { data: servicio } = await masterSupabase
            .from('servisi')
            .select('web_clinica')
            .eq('ID_User', clinicUserId)
            .single();

        if (!servicio || !servicio.web_clinica) {
            return res.status(403).json({ error: 'Servicio no autorizado' });
        }

        // Devolver secretos
        const { data: config } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET')
            .eq('ID_USER', clinicUserId)
            .single();

        if (!config) return res.status(404).json({ error: 'Config no encontrada' });

        return res.json({
            supabaseUrl: config.SUPABASE_URL,
            supabaseServiceKey: config.SUPABASE_SERVICE_KEY,
            jwtSecret: config.JWT_SECRET
        });

    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

// --- FUNCIONES AUXILIARES ---

async function getClinicConfig(userId) {
    // 1. Chequear servicio
    const { data: s } = await masterSupabase.from('servisi').select('web_clinica').eq('ID_User', userId).single();
    
    if (s && s.web_clinica) {
        // 2. Buscar datos técnicos
        const { data: w } = await masterSupabase
            .from('web_clinica')
            .select('*') // Trae todo: url, keys, backend_url
            .eq('ID_USER', userId)
            .single();
        return w; 
    }
    return null;
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SERVIDOR VINTEX CENTRAL ACTIVO EN PUERTO ${PORT}`);
});