const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',          // Par défaut sous XAMPP
    password: '',          // Vide par défaut sous XAMPP (si tu n’as rien mis)
    database: 'guardia_project'
});

module.exports = pool.promise();
