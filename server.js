// src/server.js
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de CORS más robusta para producción
app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST', 'OPTIONS']
}));
app.use(express.json());

// Verificación de variables de entorno críticas
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan variables de entorno SUPABASE_URL o SUPABASE_SERVICE_KEY");
    process.exit(1);
}

// Conexión a DB Maestra (VINTEX AI)
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
// 1. ENDPOINT: LOGIN / REGISTRO
// =============================================================================
app.post('/api/auth/google', async (req, res) => {
  const { googleAccessToken } = req.body; 

  if (!googleAccessToken) {
      return res.status(400).json({ error: 'Falta el token de acceso.' });
  }

  try {
    // A. Validar el token con Supabase Auth
    // OJO: Esto espera un JWT de Supabase, no el token raw de Google API.
    const { data: { user }, error: authError } = await masterSupabase.auth.getUser(googleAccessToken);

    if (authError || !user) {
      console.error("Error auth:", authError);
      return res.status(401).json({ error: 'Token inválido o sesión expirada.' });
    }

    const email = user.email;
    const userId = user.id; 
    const fullName = user.user_metadata.full_name || 'Usuario Google';

    // B. Sincronizar tabla 'users' (Upsert)
    const { error: upsertError } = await masterSupabase
      .from('users')
      .upsert({
        id: userId,
        email: email,
        full_name: fullName,
        updated_at: new Date().toISOString()
      }, { onConflict: 'id' });

    if (upsertError) {
      console.error('Error DB User:', upsertError);
      return res.status(500).json({ error: 'Error al registrar usuario en base de datos.' });
    }

    // C. Verificar/Crear Servicios
    let { data: servicios, error: servError } = await masterSupabase
      .from('servisi')
      .select('web_clinica, Bot_clinica')
      .eq('ID_User', userId)
      .single();

    if (!servicios && !servError) {
       // Crear servicios por defecto si no existen
       const { data: newService, error: createError } = await masterSupabase
         .from('servisi')
         .insert({ ID_User: userId, web_clinica: false, Bot_clinica: false })
         .select()
         .single();
         
       if (createError) throw createError;
       servicios = newService;
    }

    // D. Lógica Web Clínica
    let clinicConfig = null;

    if (servicios && servicios.web_clinica === true) {
      const { data: webData } = await masterSupabase
        .from('web_clinica')
        .select('SUPABASE_URL, SUPABASE_SERVICE_KEY')
        .eq('ID_USER', userId)
        .single();

      if (webData) {
        clinicConfig = {
            MASTER_SUPABASE_URL: webData.SUPABASE_URL, 
            MASTER_SUPABASE_SERVICE_KEY: webData.SUPABASE_SERVICE_KEY,
            CLINIC_USER_ID: userId 
        };
      }
    }

    // E. Respuesta
    return res.status(200).json({
      success: true,
      session: {
        access_token: googleAccessToken, 
        user: { id: userId, email: email }
      },
      servicios: {
          web_clinica: servicios?.web_clinica || false,
          bot_clinica: servicios?.Bot_clinica || false
      },
      satelliteConfig: clinicConfig 
    });

  } catch (err) {
    console.error("Error interno:", err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SERVIDOR VINTEX_API ACTIVO EN PUERTO ${PORT}`);
});