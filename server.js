// src/server.js
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
app.use(express.json());

// Conexión a DB Maestra (VINTEX AI)
const masterSupabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// =============================================================================
// 1. ENDPOINT: LOGIN / REGISTRO CON GOOGLE (Unificado)
// =============================================================================
// Este endpoint recibe el 'access_token' de Google desde el Frontend
app.post('/api/auth/google', async (req, res) => {
  const { googleAccessToken } = req.body; // Token que te da Google en el frontend

  try {
    // A. Validar el token de Google con Supabase Auth
    const { data: { user }, error: authError } = await masterSupabase.auth.getUser(googleAccessToken);

    if (authError || !user) {
      return res.status(401).json({ error: 'Token de Google inválido o expirado.' });
    }

    const email = user.email;
    const userId = user.id; // ID único generado por Supabase Auth
    const fullName = user.user_metadata.full_name || 'Usuario Google';

    // B. Sincronizar tabla 'public.users' (Lógica de "Crear Cuenta" implícita)
    // Usamos 'upsert' para crear si no existe, o actualizar si ya existe.
    const { error: upsertError } = await masterSupabase
      .from('users')
      .upsert({
        id: userId,
        email: email,
        full_name: fullName,
        // role: 'user' (o FALSE según tu esquema) se pone por default en la DB
        // created_at se pone solo
      }, { onConflict: 'id' });

    if (upsertError) {
      console.error('Error upsert users:', upsertError);
      return res.status(500).json({ error: 'Error al registrar usuario en base de datos.' });
    }

    // C. Verificar Servicios (Tabla 'servisi')
    // Buscamos las filas 'web_clinica' y 'Bot_clinica'
    let { data: servicios, error: servError } = await masterSupabase
      .from('servisi')
      .select('web_clinica, Bot_clinica')
      .eq('ID_User', userId)
      .single();

    // Si no existe entrada en servisi (usuario nuevo), la creamos por defecto en FALSE
    if (!servicios) {
       const { data: newService } = await masterSupabase
         .from('servisi')
         .insert({ ID_User: userId, web_clinica: false, Bot_clinica: false })
         .select()
         .single();
       servicios = newService;
    }

    // D. Lógica de Configuración Web Clínica
    let clinicConfig = null;

    // Si web_clinica es TRUE
    if (servicios && servicios.web_clinica === true) {
      
      // Buscamos en la tabla 'web_clinica' usando el ID del usuario
      const { data: webData, error: webError } = await masterSupabase
        .from('web_clinica')
        .select('SUPABASE_URL, SUPABASE_SERVICE_KEY') // Lo que pediste
        .eq('ID_USER', userId)
        .single();

      if (webData) {
        // Preparamos el objeto para mandar al Backend de la Clínica
        clinicConfig = {
            // Mapeo específico solicitado en tu prompt:
            MASTER_SUPABASE_URL: webData.SUPABASE_URL, 
            MASTER_SUPABASE_SERVICE_KEY: webData.SUPABASE_SERVICE_KEY,
            CLINIC_USER_ID: userId // "ID_USER" a "CLINIC_USER_ID"
        };
      }
    }

    // E. Respuesta Final al Frontend
    // El frontend recibirá esto y decidirá si redirigir al Dashboard o mostrar "Sin Servicios"
    return res.status(200).json({
      success: true,
      session: {
        access_token: googleAccessToken, // O un nuevo JWT propio si prefieres
        user: {
            id: userId,
            email: email,
            role_admin: false // O lo que leas de la DB
        }
      },
      servicios: {
          web_clinica: servicios.web_clinica,
          bot_clinica: servicios.Bot_clinica
      },
      // Esta configuración NO se debe guardar en LocalStorage del navegador por seguridad
      // Se debe enviar al backend satélite en el paso de "boot-config"
      satelliteConfig: clinicConfig 
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Endpoint auxiliar para que el Servidor Satélite pida sus credenciales (como vimos antes)
// Esto es más seguro que enviar las keys al frontend.
app.post('/api/internal/get-clinic-credentials', async (req, res) => {
    const { userId } = req.body;
    // ... Lógica para leer web_clinica y devolver SUPABASE_URL y SERVICE_KEY ...
    // (Similar al bloque D de arriba, pero autenticado con un API KEY interna entre servidores)
});

app.listen(PORT, () => {
  console.log(`🚀 ORQUESTADOR VINTEX_IA ACTIVO EN PUERTO ${PORT}`);
});