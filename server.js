import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Configuración CORS (Permite peticiones desde tu Frontend)
app.use(cors({ origin: '*' }));
app.use(express.json());

// Verificación de variables de entorno
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan variables de entorno SUPABASE_URL o SUPABASE_SERVICE_KEY");
    process.exit(1);
}

// Conexión a DB Maestra (VINTEX AI) con permisos de Admin
const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { 
      auth: { 
          autoRefreshToken: false, 
          persistSession: false 
      } 
  }
);

// =============================================================================
// 1. ENDPOINT: LOGIN (Email y Contraseña)
// =============================================================================
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Autenticar con Supabase Auth
        const { data: authData, error: authError } = await masterSupabase.auth.signInWithPassword({
            email,
            password
        });

        if (authError || !authData.user) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const userId = authData.user.id;

        // 2. Obtener configuración de clínica (Si existe)
        const satelliteConfig = await getClinicConfig(userId);

        // 3. Responder al Frontend
        return res.status(200).json({
            success: true,
            session: authData.session, // Token para el Frontend
            user: authData.user,
            satelliteConfig: satelliteConfig // URL del backend clínica (si tiene)
        });

    } catch (error) {
        console.error("Error en Login:", error);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// =============================================================================
// 2. ENDPOINT: LOGIN CON GOOGLE
// =============================================================================
app.post('/api/auth/google', async (req, res) => {
  const { googleAccessToken } = req.body; 

  if (!googleAccessToken) {
      return res.status(400).json({ error: 'Falta el token de acceso.' });
  }

  try {
    // Validar token de Google
    const { data: { user }, error: authError } = await masterSupabase.auth.getUser(googleAccessToken);

    if (authError || !user) {
      return res.status(401).json({ error: 'Token inválido o sesión expirada.' });
    }

    const userId = user.id; 

    // Sincronizar usuario en tabla 'users'
    await masterSupabase.from('users').upsert({
        id: userId,
        email: user.email,
        full_name: user.user_metadata.full_name,
        updated_at: new Date().toISOString()
    }, { onConflict: 'id' });

    // Asegurar entrada en 'servisi'
    await ensureServicesExist(userId);

    // Obtener configuración
    const satelliteConfig = await getClinicConfig(userId);

    return res.status(200).json({
      success: true,
      session: { access_token: googleAccessToken, user: { id: userId, email: user.email } },
      satelliteConfig
    });

  } catch (err) {
    console.error("Error Google Auth:", err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// =============================================================================
// 3. ENDPOINT: INICIALIZAR SESIÓN (Para el Dashboard)
// =============================================================================
app.get('/api/config/init-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado' });
  
    const token = authHeader.split(' ')[1];
  
    try {
      // 1. Verificar identidad
      const { data: { user }, error: authError } = await masterSupabase.auth.getUser(token);
  
      if (authError || !user) {
        return res.status(401).json({ error: 'Sesión inválida' });
      }
  
      // 2. Buscar configuración en web_clinica
      const { data: config, error: configError } = await masterSupabase
        .from('web_clinica')
        .select('url_backend, SUPABASE_URL, supabase_anon_key') 
        .eq('ID_USER', user.id)
        .single();
  
      if (configError || !config) {
        // Si no tiene clínica, devolvemos null (El frontend mostrará "Sin servicios")
        return res.status(200).json({ hasClinic: false });
      }
  
      // 3. Devolver configuración pública
      return res.status(200).json({
        hasClinic: true,
        backendUrl: config.url_backend,        // https://webs-de-vintex-bakend-de-clinica...
        supabaseUrl: config.SUPABASE_URL,      
        supabaseAnonKey: config.supabase_anon_key // Opcional, si lo usas
      });
  
    } catch (error) {
      console.error('Error en init-session:', error);
      return res.status(500).json({ error: 'Error recuperando configuración' });
    }
});

// --- FUNCIONES AUXILIARES ---

async function ensureServicesExist(userId) {
    const { data } = await masterSupabase.from('servisi').select('id').eq('ID_User', userId).single();
    if (!data) {
        await masterSupabase.from('servisi').insert({ ID_User: userId, web_clinica: false, Bot_clinica: false });
    }
}

async function getClinicConfig(userId) {
    // Verificar si tiene servicio activo
    const { data: servicio } = await masterSupabase
        .from('servisi')
        .select('web_clinica')
        .eq('ID_User', userId)
        .single();

    if (servicio && servicio.web_clinica) {
        const { data: webData } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY, url_backend')
            .eq('ID_USER', userId)
            .single();
            
        if (webData) {
            return {
                MASTER_SUPABASE_URL: webData.SUPABASE_URL,
                url_backend: webData.url_backend,
                clinic_id: userId
            };
        }
    }
    return null;
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SERVIDOR VINTEX CENTRAL ACTIVO EN PUERTO ${PORT}`);
});