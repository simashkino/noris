import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Папки
const uploadDir = path.join(__dirname, 'uploads');
['', '/avatars', '/files', '/stickers', '/voice', '/video'].forEach(folder => {
  const dir = path.join(uploadDir, folder);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = '/files';
    if (file.fieldname === 'avatar') folder = '/avatars';
    else if (file.fieldname === 'sticker') folder = '/stickers';
    else if (file.mimetype?.startsWith('audio/')) folder = '/voice';
    else if (file.mimetype?.startsWith('video/')) folder = '/video';
    cb(null, path.join(uploadDir, folder));
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// ========== БАЗА ДАННЫХ ==========
let db;
const initDB = async () => {
  db = await open({ filename: './noris.db', driver: sqlite3.Database });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE, password TEXT,
      firstName TEXT, lastName TEXT, username TEXT UNIQUE,
      avatar TEXT, isOnline INTEGER DEFAULT 0, lastSeen TEXT
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, chatId TEXT, senderId TEXT, receiverId TEXT,
      type TEXT, content TEXT, fileUrl TEXT, fileName TEXT, duration INTEGER,
      isSticker INTEGER DEFAULT 0, replyTo TEXT, pinned INTEGER DEFAULT 0,
      read INTEGER DEFAULT 0, createdAt TEXT
    );
    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY, name TEXT, description TEXT, avatar TEXT,
      creatorId TEXT, inviteLink TEXT, createdAt TEXT
    );
    CREATE TABLE IF NOT EXISTS group_members (groupId TEXT, userId TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY, name TEXT, description TEXT, avatar TEXT,
      creatorId TEXT, username TEXT UNIQUE, inviteLink TEXT, createdAt TEXT
    );
    CREATE TABLE IF NOT EXISTS channel_subscribers (channelId TEXT, userId TEXT);
    CREATE TABLE IF NOT EXISTS contacts (userId TEXT, contactId TEXT);
    CREATE TABLE IF NOT EXISTS sticker_packs (
      id TEXT PRIMARY KEY, name TEXT, creatorId TEXT, inviteLink TEXT, createdAt TEXT
    );
    CREATE TABLE IF NOT EXISTS stickers (id TEXT PRIMARY KEY, packId TEXT, imageUrl TEXT, emoji TEXT);
    CREATE TABLE IF NOT EXISTS user_sticker_packs (userId TEXT, packId TEXT);
    CREATE TABLE IF NOT EXISTS pinned_chats (userId TEXT, chatId TEXT);
    CREATE TABLE IF NOT EXISTS deleted_chats (userId TEXT, chatId TEXT);
  `);
  console.log('✅ База готова');
};
await initDB();

// ========== AUTH ==========
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.get('SELECT id, email, username, firstName, lastName, avatar FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

app.post('/api/auth/register', async (req, res) => {
  const { email, password, firstName, lastName, username } = req.body;
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Никнейм только латиница' });
  const existing = await db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
  if (existing) return res.status(400).json({ error: 'Email или никнейм занят' });
  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();
  await db.run('INSERT INTO users (id, email, password, firstName, lastName, username, lastSeen) VALUES (?,?,?,?,?,?,?)', 
    [id, email, hashed, firstName, lastName, username, new Date().toISOString()]);
  res.json({ userId: id });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Неверные данные' });
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  await db.run('UPDATE users SET isOnline = 1, lastSeen = ? WHERE id = ?', [new Date().toISOString(), user.id]);
  res.json({ token, user: { id: user.id, username: user.username, firstName: user.firstName, lastName: user.lastName, avatar: user.avatar } });
});

app.get('/api/users/me', auth, (req, res) => res.json({ user: req.user }));
app.get('/api/users/search', auth, async (req, res) => {
  const users = await db.all('SELECT id, username, firstName, lastName, avatar FROM users WHERE username LIKE ? AND id != ? LIMIT 20', [`%${req.query.q}%`, req.user.id]);
  res.json(users);
});
app.post('/api/users/contact', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO contacts VALUES (?, ?)', [req.user.id, req.body.contactId]);
  res.json({ success: true });
});
app.get('/api/users/contacts', auth, async (req, res) => {
  const contacts = await db.all('SELECT u.id, u.username, u.firstName, u.lastName, u.avatar, u.isOnline FROM contacts c JOIN users u ON c.contactId = u.id WHERE c.userId = ?', [req.user.id]);
  res.json(contacts);
});
app.put('/api/users/profile', auth, async (req, res) => {
  const { firstName, lastName, username } = req.body;
  await db.run('UPDATE users SET firstName = ?, lastName = ?, username = ? WHERE id = ?', [firstName, lastName, username, req.user.id]);
  res.json({ success: true });
});
app.post('/api/upload/avatar', auth, upload.single('avatar'), async (req, res) => {
  const url = `${req.protocol}://${req.get('host')}/uploads/avatars/${req.file.filename}`;
  await db.run('UPDATE users SET avatar = ? WHERE id = ?', [url, req.user.id]);
  res.json({ url });
});

app.get('/api/chats', auth, async (req, res) => {
  const deleted = await db.all('SELECT chatId FROM deleted_chats WHERE userId = ?', [req.user.id]);
  const deletedIds = new Set(deleted.map(d => d.chatId));
  const contacts = await db.all('SELECT u.id, u.username as name, "user" as type, u.avatar FROM contacts c JOIN users u ON c.contactId = u.id WHERE c.userId = ?', [req.user.id]);
  const groups = await db.all('SELECT g.id, g.name, "group" as type, g.avatar FROM groups g JOIN group_members gm ON g.id = gm.groupId WHERE gm.userId = ?', [req.user.id]);
  const channels = await db.all('SELECT c.id, c.name, "channel" as type, c.avatar FROM channels c JOIN channel_subscribers cs ON c.id = cs.channelId WHERE cs.userId = ?', [req.user.id]);
  const all = [...contacts, ...groups, ...channels].filter(c => !deletedIds.has(c.id));
  const pinned = await db.all('SELECT chatId FROM pinned_chats WHERE userId = ?', [req.user.id]);
  const pinnedIds = new Set(pinned.map(p => p.chatId));
  all.sort((a, b) => (pinnedIds.has(b.id) ? 1 : 0) - (pinnedIds.has(a.id) ? 1 : 0));
  res.json(all);
});

app.get('/api/messages/:chatId', auth, async (req, res) => {
  const messages = await db.all('SELECT * FROM messages WHERE chatId = ? ORDER BY createdAt ASC LIMIT 100', [req.params.chatId]);
  res.json(messages);
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  await db.run('DELETE FROM messages WHERE id = ? AND senderId = ?', [req.params.id, req.user.id]);
  res.json({ success: true });
});
app.post('/api/messages/:id/pin', auth, async (req, res) => {
  await db.run('UPDATE messages SET pinned = 1 WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});
app.post('/api/pinned-chats', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO pinned_chats VALUES (?, ?)', [req.user.id, req.body.chatId]);
  res.json({ success: true });
});
app.delete('/api/pinned-chats/:chatId', auth, async (req, res) => {
  await db.run('DELETE FROM pinned_chats WHERE userId = ? AND chatId = ?', [req.user.id, req.params.chatId]);
  res.json({ success: true });
});
app.post('/api/deleted-chats', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO deleted_chats VALUES (?, ?)', [req.user.id, req.body.chatId]);
  res.json({ success: true });
});

app.post('/api/groups', auth, async (req, res) => {
  const id = uuidv4();
  const inviteLink = uuidv4().slice(0, 8);
  await db.run('INSERT INTO groups (id, name, description, avatar, creatorId, inviteLink, createdAt) VALUES (?,?,?,?,?,?,?)', 
    [id, req.body.name, req.body.description || '', req.body.avatar || '', req.user.id, inviteLink, new Date().toISOString()]);
  await db.run('INSERT INTO group_members VALUES (?, ?, ?)', [id, req.user.id, 'creator']);
  for (const member of (req.body.members || [])) {
    await db.run('INSERT OR IGNORE INTO group_members VALUES (?, ?, ?)', [id, member, 'member']);
  }
  res.json({ id, name: req.body.name, inviteLink });
});
app.post('/api/groups/:id/add', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO group_members VALUES (?, ?, ?)', [req.params.id, req.body.userId, 'member']);
  res.json({ success: true });
});
app.get('/api/groups', auth, async (req, res) => {
  const groups = await db.all('SELECT g.* FROM groups g JOIN group_members gm ON g.id = gm.groupId WHERE gm.userId = ?', [req.user.id]);
  res.json(groups);
});

app.post('/api/channels', auth, async (req, res) => {
  const id = uuidv4();
  const inviteLink = uuidv4().slice(0, 8);
  await db.run('INSERT INTO channels (id, name, description, avatar, creatorId, username, inviteLink, createdAt) VALUES (?,?,?,?,?,?,?,?)',
    [id, req.body.name, req.body.description || '', req.body.avatar || '', req.user.id, req.body.username, inviteLink, new Date().toISOString()]);
  await db.run('INSERT INTO channel_subscribers VALUES (?, ?)', [id, req.user.id]);
  res.json({ id, name: req.body.name, username: req.body.username, inviteLink });
});
app.post('/api/channels/:id/join', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO channel_subscribers VALUES (?, ?)', [req.params.id, req.user.id]);
  res.json({ success: true });
});
app.get('/api/channels', auth, async (req, res) => {
  const channels = await db.all('SELECT c.* FROM channels c JOIN channel_subscribers cs ON c.id = cs.channelId WHERE cs.userId = ?', [req.user.id]);
  res.json(channels);
});

app.post('/api/sticker-packs', auth, async (req, res) => {
  const id = uuidv4();
  const inviteLink = uuidv4().slice(0, 8);
  await db.run('INSERT INTO sticker_packs (id, name, creatorId, inviteLink, createdAt) VALUES (?,?,?,?,?)', [id, req.body.name, req.user.id, inviteLink, new Date().toISOString()]);
  await db.run('INSERT INTO user_sticker_packs VALUES (?, ?)', [req.user.id, id]);
  res.json({ id, name: req.body.name, inviteLink });
});
app.post('/api/sticker-packs/:id/add-sticker', auth, upload.single('sticker'), async (req, res) => {
  const url = `${req.protocol}://${req.get('host')}/uploads/stickers/${req.file.filename}`;
  const stickerId = uuidv4();
  await db.run('INSERT INTO stickers (id, packId, imageUrl) VALUES (?,?,?)', [stickerId, req.params.id, url]);
  res.json({ id: stickerId, url });
});
app.get('/api/sticker-packs', auth, async (req, res) => {
  const packs = await db.all('SELECT sp.*, (SELECT imageUrl FROM stickers WHERE packId = sp.id LIMIT 1) as coverSticker FROM sticker_packs sp JOIN user_sticker_packs usp ON sp.id = usp.packId WHERE usp.userId = ?', [req.user.id]);
  for (const pack of packs) {
    pack.stickers = await db.all('SELECT * FROM stickers WHERE packId = ?', [pack.id]);
  }
  res.json(packs);
});
app.post('/api/sticker-packs/:id/add', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO user_sticker_packs VALUES (?, ?)', [req.user.id, req.params.id]);
  res.json({ success: true });
});

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  let folder = '/files';
  if (req.file.mimetype?.startsWith('audio/')) folder = '/voice';
  else if (req.file.mimetype?.startsWith('video/')) folder = '/video';
  const url = `${req.protocol}://${req.get('host')}/uploads${folder}/${req.file.filename}`;
  res.json({ url, filename: req.file.originalname, duration: req.body.duration || 0 });
});

// ========== SOCKET.IO ==========
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch { next(new Error('Invalid token')); }
});

io.on('connection', async (socket) => {
  console.log('✅ User connected:', socket.userId);
  await db.run('UPDATE users SET isOnline = 1 WHERE id = ?', [socket.userId]);
  socket.join(`user:${socket.userId}`);
  io.emit('user_status', { userId: socket.userId, isOnline: true });

  socket.on('send_message', async (data) => {
    const messageId = uuidv4();
    await db.run(`INSERT INTO messages (id, chatId, senderId, receiverId, type, content, fileUrl, fileName, duration, isSticker, replyTo, createdAt)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [messageId, data.chatId, socket.userId, data.receiverId, data.type, data.content, data.fileUrl, data.fileName, data.duration || 0, data.isSticker ? 1 : 0, data.replyTo || null, new Date().toISOString()]);
    const message = await db.get('SELECT * FROM messages WHERE id = ?', [messageId]);
    if (data.receiverId) io.to(`user:${data.receiverId}`).emit('new_message', message);
    if (data.chatId && !data.receiverId) io.to(data.chatId).emit('new_message', message);
    socket.emit('message_sent', message);
  });

  socket.on('join_chat', (chatId) => socket.join(chatId));
  socket.on('typing', (data) => {
    if (data.receiverId) socket.to(`user:${data.receiverId}`).emit('user_typing', { userId: socket.userId, chatId: data.chatId });
  });

  socket.on('disconnect', async () => {
    console.log('❌ User disconnected:', socket.userId);
    await db.run('UPDATE users SET isOnline = 0, lastSeen = ? WHERE id = ?', [new Date().toISOString(), socket.userId]);
    io.emit('user_status', { userId: socket.userId, isOnline: false });
  });
});

server.listen(process.env.PORT || 10000, () => console.log(`🚀 Noris running on port ${process.env.PORT || 10000}`));
