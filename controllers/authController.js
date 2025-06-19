import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../models/db.js'; // Cambié 'db' por 'pool' si estás usando pg.Pool

export const register = async (req, res) => {
  const {
    name,
    apellido_paterno,
    apellido_materno,
    fecha_nacimiento,
    edad,
    telefono,
    especialidades,
    email,
    password
  } = req.body;

  const hash = await bcrypt.hash(password, 10);
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 días

  const especialidadesArray = Array.isArray(especialidades) ? especialidades : [especialidades];

  try {
    const result = await pool.query(
      `INSERT INTO users 
      (name, apellido_paterno, apellido_materno, fecha_nacimiento, edad, telefono, especialidades, email, password, created_at, trial_expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING id, email`,
      [
        name,
        apellido_paterno,
        apellido_materno,
        fecha_nacimiento,
        edad,
        telefono || null,
        especialidadesArray,
        email,
        hash,
        createdAt,
        expiresAt
      ]
    );

    res.status(201).json({ user: result.rows[0], message: 'Usuario registrado con éxito' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Credenciales inválidas' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const now = new Date();
    const expired = now > user.trial_expires_at;

    const token = jwt.sign({ userId: user.id, expired }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    res.json({ token, expired });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
};
