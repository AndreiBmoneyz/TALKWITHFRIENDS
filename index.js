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

// rooms: { [roomName]: { users: [...], createdAt } }
let rooms = {};

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
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', (req, res) => { res.json({ user: req.session.user || null }); });

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// ─── ROOM LOGIC ────────────────────────────────────────────────────────

async function generateToken(user, roomName) {
  const token = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
    identity: String(user.id),
    name: user.username,
    ttl: '1h',
  });
  token.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  return await token.toJwt();
}

function findBestRoom(userId) {
  // Find room with most people but still has a free seat
  // exclude rooms where this user already is
  let best = null;
  let bestCount = -1;
  for (const [roomName, room] of Object.entries(rooms)) {
    const alreadyIn = room.users.some(u => u.id === userId);
    if (alreadyIn) continue;
    if (room.users.length < MAX_ROOM_SIZE && room.users.length > bestCount) {
      best = roomName;
      bestCount = room.users.length;
    }
  }
  return best;
}

app.post('/api/join', requireAuth, async (req, res) => {
  const user = req.session.user;

  // Find best existing room or create new one
  let roomName = findBestRoom(user.id);

  if (!roomName) {
    // No room available, create a new one
    roomName = `room-${Date.now()}`;
    rooms[roomName] = { users: [], createdAt: Date.now() };
    console.log(`Created new room: ${roomName}`);
  }

  // Add user to room
  rooms[roomName].users.push({ ...user, joinedAt: Date.now() });
  console.log(`${user.username} joined ${roomName}. Users: ${rooms[roomName].users.length}`);

  // Generate token
  const token = await generateToken(user, roomName);

  res.json({
    ok: true,
    roomName,
    token,
    livekitUrl: LIVEKIT_URL,
    roomUsers: rooms[roomName].users,
  });
});

app.post('/api/leave', requireAuth, (req, res) => {
  const user = req.session.user;
  for (const [roomName, room] of Object.entries(rooms)) {
    room.users = room.users.filter(u => u.id !== user.id);
    if (room.users.length === 0) {
      delete rooms[roomName];
      console.log(`Deleted empty room: ${roomName}`);
    }
  }
  res.json({ ok: true });
});

// Clean up empty rooms every 60 seconds
setInterval(() => {
  for (const [roomName, room] of Object.entries(rooms)) {
    if (room.users.length === 0) delete rooms[roomName];
  }
}, 60000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
