const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Admin password (Set this in Vercel Environment Variables later)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

// Initialize PostgreSQL Connection Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Initialize Database Table
pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
        id SERIAL PRIMARY KEY,
        key_string TEXT UNIQUE,
        app_name TEXT,
        status TEXT DEFAULT 'active',
        hwid TEXT,
        last_ip TEXT,
        last_used TIMESTAMP
    )
`).then(() => console.log('Database initialized.'))
  .catch(err => console.error('Error initializing database:', err.message));

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

app.post('/api/check_key', async (req, res) => {
    const { key, hwid } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!key || !hwid) {
        return res.status(400).json({ valid: false, message: 'Missing key or hwid' });
    }

    try {
        const result = await pool.query('SELECT * FROM keys WHERE key_string = $1', [key]);
        const row = result.rows[0];

        if (!row) {
            return res.status(404).json({ valid: false, message: 'Key not found' });
        }

        if (row.status !== 'active') {
            return res.status(403).json({ valid: false, message: `Key is ${row.status}` });
        }

        // HWID Binding Logic
        if (!row.hwid) {
            // First time use, bind HWID
            await pool.query('UPDATE keys SET hwid = $1, last_ip = $2, last_used = CURRENT_TIMESTAMP WHERE id = $3', [hwid, ip, row.id]);
            return res.json({ valid: true, status: 'active', message: 'Key bound and authenticated' });
        } else if (row.hwid !== hwid) {
            return res.status(403).json({ valid: false, message: 'Invalid HWID (bound to another machine)' });
        } else {
            // Valid and matches HWID
            await pool.query('UPDATE keys SET last_ip = $1, last_used = CURRENT_TIMESTAMP WHERE id = $2', [ip, row.id]);
            return res.json({ valid: true, status: 'active', message: 'Authenticated successfully' });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ valid: false, message: 'Server error' });
    }
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

app.get('/api/admin/keys', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM keys ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/keys', async (req, res) => {
    const { app_name } = req.body;
    const newKey = generateKey();
    
    try {
        const result = await pool.query(
            'INSERT INTO keys (key_string, app_name) VALUES ($1, $2) RETURNING id',
            [newKey, app_name || 'FiveWare Spoofer']
        );
        res.json({ id: result.rows[0].id, key_string: newKey, app_name: app_name || 'FiveWare Spoofer', status: 'active' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/keys/:id', async (req, res) => {
    const { status, hwid } = req.body;
    const id = req.params.id;

    try {
        if (status) {
            await pool.query('UPDATE keys SET status = $1 WHERE id = $2', [status, id]);
        }

        // Pass hwid as null to reset it
        if (hwid === null || hwid === '') {
            await pool.query('UPDATE keys SET hwid = NULL WHERE id = $1', [id]);
        }

        res.json({ message: 'Key updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// For local testing
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

// Export the Express app so Vercel can run it serverlessly
module.exports = app;
