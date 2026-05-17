require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const { AccessToken } = require('livekit-server-sdk');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretkey123',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY || 'devkey';
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET || 'secret';
const LIVEKIT_URL = process.env.LIVEKIT_URL;
const MAX_ROOM_SIZE = 5;

let queue = [];

// Init DB tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      avatar TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  console.log('DB ready');
}
initDB();

// ─── AUTH ──────────────────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username too short' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short (min 6)' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, avatar',
      [username, hash]
    );
    const user = result.rows[0];
    req.session.user = { id: user.id, username: user.username, avatar: user.avatar };
    res.json({ ok: true, user: req.session.user });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Username already taken' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Wrong username or password' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Wrong username or password' });
    req.session.user = { id: user.id, username: user.username, avatar: user.avatar };
    res.json({ ok: true, user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// ─── MATCHMAKING ───────────────────────────────────────────────────────

app.post('/api/join', requireAuth, async (req, res) => {
  const user = req.session.user;
  queue = queue.filter(u => u.id !== user.id);
  queue.push({ ...user, joinedAt: Date.now() });
  console.log(`${user.username} joined queue. Size: ${queue.length}`);

  if (queue.length >= 2) {
    const roomUsers = queue.splice(0, MAX_ROOM_SIZE);
    const roomName = `room-${Date.now()}`;

    // Generate Livekit token for the requesting user
    const token = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
      identity: String(user.id),
      name: user.username,
      ttl: '1h',
    });
    token.addGrant({
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canSubscribe: true,
    });
    const jwt = await token.toJwt();

    return res.json({
      matched: true,
      roomName,
      token: jwt,
      livekitUrl: LIVEKIT_URL,
      roomUsers,
    });
  }

  res.json({ matched: false, queuePosition: queue.length });
});

app.get('/api/status', (req, res) => {
  res.json({ queueSize: queue.length });
});

app.post('/api/leave', requireAuth, (req, res) => {
  queue = queue.filter(u => u.id !== req.session.user.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
