import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
app.use(express.json());

// --- CONEXIÓN A LA BASE DE DATOS MAESTRA (Usuarios y Permisos) ---
const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- 1. LOGIN & ORQUESTACIÓN DE MICROSERVICIOS ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // A. Autenticación Básica (Identity Provider)
    const { data: authData, error: authError } = await masterSupabase.auth.signInWithPassword({ 
      email, 
      password 
    });

    if (authError) return res.status(401).json({ error: 'Credenciales inválidas' });

    const userId = authData.user.id;

    // B. Verificación de Permisos (Microservicio de Cuentas)
    // Buscamos en 'servisi' usando el ID del usuario autenticado
    const { data: servicios, error: servError } = await masterSupabase
      .from('servisi')
      .select('*')
      .eq('ID_User', userId)
      .single();

    if (servError || !servicios) {
      return res.status(403).json({ error: 'No tienes servicios activos asociados a esta cuenta.' });
    }

    // C. Enrutamiento de Servicios (Service Mesh Logic)
    let clinicConfig = null;
    let botConfig = null;

    // 1. Si tiene el servicio WEB_CLINICA activo
    if (servicios.web_clinica === true) {
      // Buscamos las credenciales específicas de SU instancia en la tabla web_clinica
      // Asumimos que la tabla web_clinica tiene una FK al usuario o a la empresa
      const { data: webData } = await masterSupabase
        .from('web_clinica')
        .select('supabase_url, supabase_anon_key, jwt_secret')
        .eq('user_id', userId) // O la relación que tengas definida
        .single();
        
      if (webData) {
        clinicConfig = {
          url: webData.supabase_url,
          key: webData.supabase_anon_key,
          // No enviamos el secret al frontend por seguridad, solo lo necesario
        };
      }
    }

    // 2. Si tiene el servicio BOT_CLINICA activo (n8n)
    if (servicios.Bot_clinica === true) {
      const { data: webhookData } = await masterSupabase
        .from('n8n_webhook')
        .select('n8n_webhook_id')
        .eq('user_id', userId) // Asumiendo relación
        .single();
        
      botConfig = webhookData;
    }

    // D. Respuesta Unificada
    return res.status(200).json({
      success: true,
      user: {
        id: userId,
        email: authData.user.email,
        role: 'user', // Esto vendría de tu tabla 'users' -> 'role'
      },
      session: { 
        access_token: authData.session.access_token 
      },
      // Aquí entregamos las llaves para que el Frontend se conecte al backend correcto
      config: {
        clinic: clinicConfig, // URL y Key de la BBDD de la clínica específica
        bot: botConfig
      }
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error interno del orquestador' });
  }
});

// --- 2. REGISTRO (Crea la estructura en la DB Maestra) ---
app.post('/api/register', async (req, res) => {
    // Lógica existente de registro, asegurando crear la entrada en 'servisi' por defecto en FALSE
    // ... (código similar al anterior pero insertando en 'servisi')
});

app.listen(PORT, () => {
  console.log(`🚀 ORQUESTADOR VINTEX_IA ACTIVO EN PUERTO ${PORT}`);
});