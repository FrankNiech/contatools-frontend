import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../models/db.js';

export const register = async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 días

  try {
    const result = await db.query(
      'INSERT INTO users (name, email, password, created_at, trial_expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, email',
      [name, email, hash, createdAt, expiresAt]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciales inválidas' });

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
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
};
