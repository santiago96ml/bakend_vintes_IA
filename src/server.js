import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL || '', 
  process.env.SUPABASE_SERVICE_KEY || '', 
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// Token de Calendly (simulado) - En producción esto iría en .env
const CALENDLY_TOKEN = process.env.CALENDLY_TOKEN || "token_simulado";

app.get('/', (req, res) => res.json({ status: 'online' }));

// --- 1. AGENDAR REUNIÓN (/api/schedule) ---
app.post('/api/schedule', async (req, res) => {
  const { firstName, lastName, email, phone, date, time } = req.body;
  console.log(`📅 Nueva reunión: ${email} - ${date} ${time}`);

  try {
    // Aquí podrías guardar el lead en una tabla 'leads' o 'meetings' en Supabase
    // O integrarte con la API real de Calendly usando el token.
    
    // Simulación de éxito
    return res.status(200).json({ 
      success: true, 
      message: 'Reunión pre-agendada.' 
    });

  } catch (error) {
    console.error('Error scheduling:', error);
    return res.status(500).json({ error: 'Error al agendar' });
  }
});

// --- 2. REGISTRO DE CUENTA (/api/register) ---
// Este endpoint crea la cuenta real en Supabase Auth
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body; // Recibimos password real
  console.log('📝 Creando cuenta para:', email);

  try {
    // Crear usuario en Auth
    const { data: authUser, error: authError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName } // Guardamos el nombre en metadata
    });

    if (authError) return res.status(400).json({ error: authError.message });

    // Guardar en DB pública 'users'
    const { error: dbError } = await supabase.from('users').insert({
      id: authUser.user.id,
      email,
      full_name: fullName || 'Usuario Nuevo',
      role: 'user'
    });

    if (dbError) console.error("Error DB:", dbError);

    return res.status(201).json({ success: true, message: 'Cuenta creada.' });

  } catch (error) {
    console.error('❌ Error Registro:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// --- 3. LOGIN (/api/login) ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: 'Credenciales inválidas' });

    return res.status(200).json({
      success: true,
      user: { id: data.user.id, email: data.user.email },
      session: { token: data.session.access_token }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 SERVIDOR ACTIVO EN PUERTO ${PORT}`);
});