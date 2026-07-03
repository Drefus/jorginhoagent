// Arquivo de teste com vulnerabilidades JavaScript
const express = require('express');
const app = express();
const mysql = require('mysql');

// SQL Injection
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// Command Injection
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 4 ' + host, (err, stdout) => {
        res.send(stdout);
    });
});

// XSS
app.get('/search', (req, res) => {
    const term = req.query.q;
    res.send('<h1>Results for: ' + term + '</h1>');
});

// Hardcoded credentials
const DB_PASSWORD = "admin123";
const API_KEY = "sk-1234567890abcdef";

// Eval injection
app.post('/calc', (req, res) => {
    const expression = req.body.expr;
    const result = eval(expression);
    res.json({ result });
});

// Insecure crypto
const crypto = require('crypto');
const hash = crypto.createHash('md5').update('password').digest('hex');

app.listen(3000);
