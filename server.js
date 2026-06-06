const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Simple hardcoded admin password (in a real app, use environment variables and hashing)
const ADMIN_PASSWORD = 'admin';

// Initialize Database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        db.run(`CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_string TEXT UNIQUE,
            app_name TEXT,
            status TEXT DEFAULT 'active',
            hwid TEXT,
            last_ip TEXT,
            last_used DATETIME
        )`);
        console.log('Database initialized.');
    }
});

// Middleware for Admin Auth
function adminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader === `Bearer ${ADMIN_PASSWORD}`) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

// =======================
// CLIENT API ENDPOINTS
// =======================

app.post('/api/check_key', (req, res) => {
    const { key, hwid } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!key || !hwid) {
        return res.status(400).json({ valid: false, message: 'Missing key or hwid' });
    }

    db.get('SELECT * FROM keys WHERE key_string = ?', [key], (err, row) => {
        if (err) {
            return res.status(500).json({ valid: false, message: 'Server error' });
        }

        if (!row) {
            return res.status(404).json({ valid: false, message: 'Key not found' });
        }

        if (row.status !== 'active') {
            return res.status(403).json({ valid: false, message: `Key is ${row.status}` });
        }

        // HWID Binding Logic
        if (!row.hwid) {
            // First time use, bind HWID
            db.run('UPDATE keys SET hwid = ?, last_ip = ?, last_used = CURRENT_TIMESTAMP WHERE id = ?', [hwid, ip, row.id]);
            return res.json({ valid: true, status: 'active', message: 'Key bound and authenticated' });
        } else if (row.hwid !== hwid) {
            return res.status(403).json({ valid: false, message: 'Invalid HWID (bound to another machine)' });
        } else {
            // Valid and matches HWID
            db.run('UPDATE keys SET last_ip = ?, last_used = CURRENT_TIMESTAMP WHERE id = ?', [ip, row.id]);
            return res.json({ valid: true, status: 'active', message: 'Authenticated successfully' });
        }
    });
});

// =======================
// ADMIN API ENDPOINTS
// =======================

// Generate a new key matching FiveWare-XXX-XXXX-XXX
function generateKey() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const randomStr = (len) => Array.from({length: len}, () => charset[Math.floor(Math.random() * charset.length)]).join('');
    return `FiveWare-${randomStr(3)}-${randomStr(4)}-${randomStr(3)}`;
}

app.get('/api/admin/keys', adminAuth, (req, res) => {
    db.all('SELECT * FROM keys ORDER BY id DESC', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/api/admin/keys', adminAuth, (req, res) => {
    const { app_name } = req.body;
    const newKey = generateKey();
    
    db.run('INSERT INTO keys (key_string, app_name) VALUES (?, ?)', [newKey, app_name || 'FiveWare Spoofer'], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID, key_string: newKey, app_name: app_name || 'FiveWare Spoofer', status: 'active' });
    });
});

app.put('/api/admin/keys/:id', adminAuth, (req, res) => {
    const { status, hwid } = req.body;
    const id = req.params.id;

    if (status) {
        db.run('UPDATE keys SET status = ? WHERE id = ?', [status, id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
        });
    }

    // Pass hwid as null to reset it
    if (hwid === null || hwid === '') {
        db.run('UPDATE keys SET hwid = NULL WHERE id = ?', [id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
        });
    }

    res.json({ message: 'Key updated successfully' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
