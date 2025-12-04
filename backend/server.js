// ========== IMPORTS ==========
require('dotenv').config();
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const pool = require('./database');

const app = express();

// ========== CONFIGURATION ==========
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_for_dev_only';
const PORT = process.env.PORT || 3001;

// ========== LOGGER (Winston) ==========
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'guardia-api' },
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'error.log'), level: 'error', maxsize: 5242880, maxFiles: 5 }),
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'combined.log'), maxsize: 5242880, maxFiles: 5 }),
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'security.log'), level: 'warn', maxsize: 5242880, maxFiles: 10 }),
    new winston.transports.Console({ format: winston.format.combine(winston.format.colorize(), winston.format.simple()) })
  ]
});

// ========== RATE LIMITING ==========
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Trop de requêtes, veuillez réessayer plus tard',
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Trop de tentatives de connexion, veuillez réessayer dans 15 minutes',
  skipSuccessfulRequests: true,
});

// ========== HEADERS DE SECURITE ==========
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  frameguard: { action: 'deny' }
}));

// ========== CORS SECURISE ==========
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://votre-domaine.com'] 
    : ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:5500', 'http://127.0.0.1:5501', 'https://localhost:3001'],
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// ========== MIDDLEWARES ==========
app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== VALIDATIONS ==========
const registerValidation = [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Nom invalide'),
  body('email').isEmail().normalizeEmail().withMessage('Email invalide'),
  body('student_id').trim().notEmpty().isLength({ max: 50 }).withMessage('Numéro étudiant invalide'),
  body('password').isLength({ min: 6, max: 100 }).withMessage('Mot de passe minimum 6 caractères'),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Email invalide'),
  body('password').notEmpty().withMessage('Mot de passe requis'),
];

const eventValidation = [
  body('title').trim().isLength({ min: 3, max: 200 }).withMessage('Titre invalide'),
  body('type').trim().notEmpty().withMessage('Type requis'),
  body('date').isISO8601().withMessage('Date invalide'),
  body('location').trim().isLength({ min: 3, max: 200 }).withMessage('Lieu invalide'),
  body('capacity').isInt({ min: 1, max: 10000 }).withMessage('Capacité invalide'),
];

// ========== MIDDLEWARES D'AUTHENTIFICATION ==========
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn('Tentative d\'accès sans token', { ip: req.ip, path: req.path });
    return res.status(401).json({ message: 'Token manquant' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn('Token invalide détecté', { ip: req.ip, error: err.message });
      return res.status(403).json({ message: 'Token invalide' });
    }
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    logger.warn('Tentative d\'accès admin non autorisée', { userId: req.user.userId, ip: req.ip });
    return res.status(403).json({ message: 'Accès réservé aux administrateurs' });
  }
  next();
}

// ========== ROUTES D'AUTHENTIFICATION ==========
app.post('/api/auth/register', authLimiter, registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Inscription - Validation échouée', { email: req.body.email, ip: req.ip });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, student_id, password } = req.body;

    const [existingUsers] = await pool.query(
      'SELECT id FROM users WHERE email = ? OR student_id = ?',
      [email, student_id]
    );

    if (existingUsers.length > 0) {
      logger.warn('Inscription - Email/ID étudiant déjà utilisé', { email, student_id, ip: req.ip });
      return res.status(400).json({ message: 'Email ou numéro étudiant déjà utilisé' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, student_id, password, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, student_id, hashedPassword, 'user']
    );

    logger.info('Nouveau compte créé', { userId: result.insertId, email, ip: req.ip });

    res.status(201).json({
      message: 'Compte créé avec succès',
      userId: result.insertId
    });

  } catch (error) {
    logger.error('Erreur inscription', { error: error.message, ip: req.ip });
    res.status(500).json({ message: 'Erreur lors de la création du compte' });
  }
});

app.post('/api/auth/login', authLimiter, loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login - Validation échouée', { email: req.body.email, ip: req.ip });
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      logger.warn('Tentative login - Email inexistant', { email, ip: req.ip });
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      logger.warn('Tentative login - Mot de passe incorrect', { email, userId: user.id, ip: req.ip });
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    logger.info('Login réussi', { userId: user.id, email: user.email, ip: req.ip });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        studentId: user.student_id,
        role: user.role
      }
    });

  } catch (error) {
    logger.error('Erreur connexion', { error: error.message, ip: req.ip });
    res.status(500).json({ message: 'Erreur lors de la connexion' });
  }
});

app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, student_id, role FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }

    res.json({
      user: {
        id: users[0].id,
        name: users[0].name,
        email: users[0].email,
        studentId: users[0].student_id,
        role: users[0].role
      }
    });

  } catch (error) {
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// ========== ROUTES ADMIN ==========
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT
        u.id,
        u.name,
        u.email,
        u.student_id,
        u.role,
        u.created_at,
        COUNT(DISTINCT r.event_id) as events_registered
      FROM users u
      LEFT JOIN registrations r ON u.id = r.user_id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);

    res.json(users);
  } catch (error) {
    logger.error('Erreur récupération utilisateurs', { error: error.message });
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs' });
  }
});

app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [userCount] = await pool.query('SELECT COUNT(*) as total FROM users');
    const [eventCount] = await pool.query('SELECT COUNT(*) as total FROM events');
    const [regCount] = await pool.query('SELECT COUNT(*) as total FROM registrations');

    const [fillRate] = await pool.query(`
      SELECT
        SUM(e.capacity) as total_capacity,
        COUNT(r.id) as total_registered
      FROM events e
      LEFT JOIN registrations r ON e.id = r.event_id
    `);

    const [popularEvents] = await pool.query(`
      SELECT
        e.title,
        e.type,
        e.capacity,
        COUNT(r.id) as registered_count,
        ROUND((COUNT(r.id) / e.capacity) * 100, 2) as fill_rate
      FROM events e
      LEFT JOIN registrations r ON e.id = r.event_id
      GROUP BY e.id
      ORDER BY registered_count DESC
      LIMIT 10
    `);

    res.json({
      overview: {
        totalUsers: userCount[0].total,
        totalEvents: eventCount[0].total,
        totalRegistrations: regCount[0].total,
        globalFillRate: fillRate[0].total_capacity > 0
          ? ((fillRate[0].total_registered / fillRate[0].total_capacity) * 100).toFixed(2)
          : 0
      },
      popularEvents
    });

  } catch (error) {
    logger.error('Erreur récupération stats', { error: error.message });
    res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    if (req.params.id == req.user.userId) {
      return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
    }

    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    logger.info('Utilisateur supprimé par admin', { deletedUserId: req.params.id, adminId: req.user.userId });
    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (error) {
    logger.error('Erreur suppression utilisateur', { error: error.message });
    res.status(500).json({ error: 'Erreur lors de la suppression' });
  }
});

app.patch('/api/admin/users/:id/role', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { role } = req.body;

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Rôle invalide' });
    }

    const [result] = await pool.query(
      'UPDATE users SET role = ? WHERE id = ?',
      [role, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    logger.info('Rôle modifié par admin', { userId: req.params.id, newRole: role, adminId: req.user.userId });
    res.json({ message: 'Rôle modifié avec succès' });
  } catch (error) {
    logger.error('Erreur modification rôle', { error: error.message });
    res.status(500).json({ error: 'Erreur lors de la modification' });
  }
});

// ========== ROUTES ÉVÉNEMENTS ==========
app.get('/api/test', (req, res) => {
  res.json({ message: 'API Node.js opérationnelle !' });
});

app.get('/api/events', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        e.id,
        e.title,
        e.type,
        e.date,
        e.location,
        e.capacity,
        e.description,
        e.organizer,
        e.created_at,
        e.created_by,
        COUNT(r.id) as registered_count,
        u.name as creator_name
      FROM events e
      LEFT JOIN registrations r ON e.id = r.event_id
      LEFT JOIN users u ON e.created_by = u.id
      GROUP BY e.id, e.title, e.type, e.date, e.location, e.capacity, e.description, e.organizer, e.created_at, e.created_by, u.name
      ORDER BY e.date ASC
    `);

    res.json(rows);
  } catch (err) {
    logger.error('Erreur récupération événements', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la récupération des événements' });
  }
});

app.post('/api/events', authenticateToken, eventValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, type, date, location, capacity, description, organizer } = req.body;

    const [result] = await pool.query(`
      INSERT INTO events (title, type, date, location, capacity, description, organizer, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [title, type, date, location, capacity, description || '', organizer || '', req.user.userId]);

    logger.info('Événement créé', { eventId: result.insertId, title, userId: req.user.userId });

    res.status(201).json({
      message: 'Événement créé avec succès',
      id: result.insertId
    });

  } catch (err) {
    logger.error('Erreur création événement', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la création de l\'événement' });
  }
});

app.put('/api/events/:id', authenticateToken, eventValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const eventId = req.params.id;
    const { title, type, date, location, capacity, description, organizer } = req.body;

    const [events] = await pool.query(
      'SELECT created_by FROM events WHERE id = ?',
      [eventId]
    );

    if (events.length === 0) {
      return res.status(404).json({ error: 'Événement non trouvé' });
    }

    if (events[0].created_by !== req.user.userId && req.user.role !== 'admin') {
      logger.warn('Tentative modification événement non autorisée', { eventId, userId: req.user.userId });
      return res.status(403).json({ error: 'Vous n\'avez pas la permission de modifier cet événement' });
    }

    const [result] = await pool.query(`
      UPDATE events
      SET title = ?, type = ?, date = ?, location = ?, capacity = ?, description = ?, organizer = ?
      WHERE id = ?
    `, [title, type, date, location, capacity, description || '', organizer || '', eventId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Événement non trouvé' });
    }

    logger.info('Événement modifié', { eventId, userId: req.user.userId });
    res.json({ message: 'Événement modifié avec succès' });

  } catch (err) {
    logger.error('Erreur modification événement', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la modification de l\'événement' });
  }
});

app.post('/api/events/:id/register', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const userId = req.user.userId;
    const { phone } = req.body;

    const [events] = await pool.query(`
      SELECT e.capacity, COUNT(r.id) as registered_count
      FROM events e
      LEFT JOIN registrations r ON e.id = r.event_id
      WHERE e.id = ?
      GROUP BY e.id
    `, [eventId]);

    if (events.length === 0) {
      return res.status(404).json({ error: 'Événement non trouvé' });
    }

    if (events[0].registered_count >= events[0].capacity) {
      return res.status(400).json({ error: 'Événement complet' });
    }

    const [existing] = await pool.query(
      'SELECT id FROM registrations WHERE event_id = ? AND user_id = ?',
      [eventId, userId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Vous êtes déjà inscrit à cet événement' });
    }

    const [result] = await pool.query(
      'INSERT INTO registrations (event_id, user_id, phone) VALUES (?, ?, ?)',
      [eventId, userId, phone || '']
    );

    logger.info('Inscription événement', { eventId, userId, registrationId: result.insertId });

    res.status(201).json({ 
      message: 'Inscription réussie',
      registrationId: result.insertId 
    });

  } catch (err) {
    logger.error('Erreur inscription événement', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});

app.get('/api/users/:userId/events', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;
    const [events] = await pool.query(`
      SELECT e.* FROM events e
      INNER JOIN registrations r ON e.id = r.event_id
      WHERE r.user_id = ?
    `, [userId]);
    res.json(events);
  } catch (error) {
    logger.error('Erreur récupération événements utilisateur', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/events/:id/participants', authenticateToken, async (req, res) => {
  try {
    const [participants] = await pool.query(`
      SELECT
        r.id,
        u.name,
        u.email,
        u.student_id,
        r.phone,
        r.registered_at
      FROM registrations r
      JOIN users u ON r.user_id = u.id
      WHERE r.event_id = ?
      ORDER BY r.registered_at DESC
    `, [req.params.id]);

    res.json(participants);
  } catch (err) {
    logger.error('Erreur récupération participants', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la récupération des participants' });
  }
});

app.delete('/api/events/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM events WHERE id = ?', [req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Événement non trouvé' });
    }

    logger.info('Événement supprimé', { eventId: req.params.id, adminId: req.user.userId });
    res.json({ message: 'Événement supprimé avec succès' });
  } catch (err) {
    logger.error('Erreur suppression événement', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la suppression' });
  }
});

app.delete('/api/events/:eventId/participants/:participantId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [result] = await pool.query(
      'DELETE FROM registrations WHERE id = ? AND event_id = ?',
      [req.params.participantId, req.params.eventId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Participant non trouvé' });
    }

    logger.info('Participant retiré', { participantId: req.params.participantId, eventId: req.params.eventId });
    res.json({ message: 'Participant retiré avec succès' });
  } catch (err) {
    logger.error('Erreur retrait participant', { error: err.message });
    res.status(500).json({ error: 'Erreur lors du retrait' });
  }
});

app.delete('/api/events/:id/unregister', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const userId = req.user.userId;

    const [result] = await pool.query(
      'DELETE FROM registrations WHERE event_id = ? AND user_id = ?',
      [eventId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Inscription non trouvée' });
    }

    logger.info('Désinscription événement', { eventId, userId });
    res.json({ message: 'Désinscription réussie' });
  } catch (err) {
    logger.error('Erreur désinscription', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la désinscription' });
  }
});

app.get('/api/user/registrations', authenticateToken, async (req, res) => {
  try {
    const [registrations] = await pool.query(`
      SELECT
        e.id,
        e.title,
        e.type,
        e.date,
        e.location,
        e.capacity,
        e.description,
        e.organizer,
        COUNT(r.id) as registered_count,
        r.registered_at as user_registered_at
      FROM events e
      INNER JOIN registrations r ON e.id = r.event_id
      WHERE r.user_id = ?
      ORDER BY e.date ASC
    `, [req.user.userId]);

    res.json(registrations);
  } catch (err) {
    logger.error('Erreur récupération inscriptions utilisateur', { error: err.message });
    res.status(500).json({ error: 'Erreur lors de la récupération des inscriptions' });
  }
});

// ========== DEMARRAGE SERVEUR AVEC HTTPS ==========
const startServer = () => {
  // Créer le dossier logs s'il n'existe pas
  const logsDir = path.join(__dirname, 'logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  // Tenter de démarrer en HTTPS
  if (process.env.ENABLE_HTTPS === 'true') {
    try {
      const sslPath = path.join(__dirname, 'ssl');
      const keyPath = path.join(sslPath, 'key.pem');
      const certPath = path.join(sslPath, 'cert.pem');

      if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        const sslOptions = {
          key: fs.readFileSync(keyPath),
          cert: fs.readFileSync(certPath)
        };

        https.createServer(sslOptions, app).listen(PORT, () => {
          console.log(`🔒 Serveur HTTPS lancé sur https://localhost:${PORT}`);
          console.log(`✅ Sécurité complète activée : HTTPS + Helmet + Rate Limiting + Logs`);
          logger.info('Serveur HTTPS démarré', { port: PORT });
        });

        // Redirection HTTP vers HTTPS
        http.createServer((req, res) => {
          res.writeHead(301, { "Location": "https://" + req.headers['host'].replace('3000', PORT) + req.url });
          res.end();
        }).listen(3000, () => {
          console.log('🔄 Redirection HTTP:3000 → HTTPS:' + PORT);
        });
      } else {
        console.warn('⚠️  Certificats SSL non trouvés, démarrage en HTTP');
        startHTTP();
      }
    } catch (error) {
      console.error('❌ Erreur HTTPS:', error.message);
      console.log('🔄 Basculement en HTTP...');
      startHTTP();
    }
  } else {
    startHTTP();
  }
};

const startHTTP = () => {
  app.listen(PORT, () => {
    console.log(`🚀 Serveur HTTP lancé sur http://localhost:${PORT}`);
    console.log(`🔒 Sécurité activée : Helmet + Rate Limiting + Validation + Logs`);
    logger.info('Serveur HTTP démarré', { port: PORT });
  });
};

startServer();

module.exports = app;
