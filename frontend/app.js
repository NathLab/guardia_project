const express = require('express');
const pool = require('./database');
const app = express();

app.use(express.json());

// Importer les routes de server.js
require('./server');

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(401).json({error: 'Email ou mot de passe incorrect'});

    if (rows[0].password !== password)
      return res.status(401).json({error: 'Email ou mot de passe incorrect'});

    res.json({user: {id: rows[0].id, name: rows[0].name, role: rows[0].role }});
  } catch (err) {
    res.status(500).json({error: 'Erreur serveur'});
  }
});

app.listen(3001, () => console.log('API sur http://localhost:3001'));

module.exports = app;
