import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';

// Configuración
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors()); // Permite peticiones desde el Frontend (localhost:5173)
app.use(express.json());

// Conexión a Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY; // ¡Usar la SERVICE_ROLE key, no la anon!

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ Error: Faltan variables de entorno de Supabase');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Esquema de Validación (Zod)
const trialSchema = z.object({
  fullName: z.string().min(3, "El nombre es muy corto"),
  email: z.string().email("Email inválido"),
  phone: z.string().min(8, "Teléfono inválido"),
});

// --- ENDPOINTS ---

// Health Check
app.get('/health', (req, res) => {
  res.json({ status: 'online', system: 'VINTEX AI API v1.0' });
});

// POST: Iniciar Prueba Gratuita
app.post('/api/start-trial', async (req, res) => {
  try {
    // 1. Validar datos entrantes
    const data = trialSchema.parse(req.body);
    console.log(`⚡ Nueva solicitud de trial: ${data.email}`);

    // 2. Verificar si el usuario ya existe
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', data.email)
      .single();

    if (existingUser) {
      return res.status(409).json({ error: 'Este email ya tiene una cuenta registrada.' });
    }

    // 3. Crear Usuario en DB
    const { data: newUser, error: userError } = await supabase
      .from('users')
      .insert({
        full_name: data.fullName,
        email: data.email,
        phone: data.phone,
        role: 'user'
      })
      .select()
      .single();

    if (userError) throw userError;

    // 4. Crear Registro de Trial (15 días)
    const startDate = new Date();
    const endDate = new Date();
    endDate.setDate(startDate.getDate() + 15);

    const { error: trialError } = await supabase
      .from('trials')
      .insert({
        user_id: newUser.id,
        start_date: startDate,
        end_date: endDate,
        status: 'active'
      });

    if (trialError) throw trialError;

    // 5. (FASE 4) Disparar Webhook de Automatización (n8n)
    // Aquí iría el fetch() al webhook de n8n para enviar el email de bienvenida
    // await fetch(process.env.N8N_WEBHOOK_URL, { method: 'POST', body: JSON.stringify(newUser) });

    console.log(`✅ Trial creado exitosamente para: ${newUser.id}`);
    
    return res.status(201).json({ 
      success: true, 
      message: 'Prueba iniciada correctamente. Revisa tu correo.',
      trialEnd: endDate
    });

  } catch (error) {
    console.error('❌ Error en /api/start-trial:', error);
    
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Datos inválidos', details: error.errors });
    }

    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Iniciar Servidor
app.listen(PORT, () => {
  console.log(`
  🚀 VINTEX AI Backend
  --------------------
  📡 Server running on port ${PORT}
  🔗 Endpoint: http://localhost:${PORT}/api/start-trial
  `);
});