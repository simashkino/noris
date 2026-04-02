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
const io = new Server(server, {
  cors: { origin: "*", credentials: true }
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Создаём папки для файлов
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(path.join(uploadDir, 'avatars'))) fs.mkdirSync(path.join(uploadDir, 'avatars'));
if (!fs.existsSync(path.join(uploadDir, 'files'))) fs.mkdirSync(path.join(uploadDir, 'files'));
if (!fs.existsSync(path.join(uploadDir, 'stickers'))) fs.mkdirSync(path.join(uploadDir, 'stickers'));

// Multer настройка
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'avatar') cb(null, path.join(uploadDir, 'avatars'));
    else if (file.fieldname === 'sticker') cb(null, path.join(uploadDir, 'stickers'));
    else cb(null, path.join(uploadDir, 'files'));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// ==================== БАЗА ДАННЫХ SQLITE ====================
let db;
const initDB = async () => {
  db = await open({
    filename: './noris.db',
    driver: sqlite3.Database
  });

  // Пользователи
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT,
      firstName TEXT,
      lastName TEXT,
      username TEXT UNIQUE,
      avatar TEXT,
      isOnline INTEGER DEFAULT 0,
      lastSeen TEXT
    )
  `);

  // Сообщения
  await db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      chatId TEXT,
      senderId TEXT,
      receiverId TEXT,
      type TEXT,
      content TEXT,
      fileUrl TEXT,
      fileName TEXT,
      isSticker INTEGER DEFAULT 0,
      replyTo TEXT,
      pinned INTEGER DEFAULT 0,
      read INTEGER DEFAULT 0,
      createdAt TEXT
    )
  `);

  // Группы
  await db.exec(`
    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      avatar TEXT,
      creatorId TEXT,
      type TEXT DEFAULT 'group',
      isPublic INTEGER DEFAULT 0,
      inviteLink TEXT,
      createdAt TEXT
    )
  `);

  // Участники групп
  await db.exec(`
    CREATE TABLE IF NOT EXISTS group_members (
      groupId TEXT,
      userId TEXT,
      role TEXT DEFAULT 'member',
      PRIMARY KEY (groupId, userId)
    )
  `);

  // Каналы
  await db.exec(`
    CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      avatar TEXT,
      creatorId TEXT,
      username TEXT UNIQUE,
      isPublic INTEGER DEFAULT 1,
      inviteLink TEXT,
      createdAt TEXT
    )
  `);

  // Подписчики каналов
  await db.exec(`
    CREATE TABLE IF NOT EXISTS channel_subscribers (
      channelId TEXT,
      userId TEXT,
      PRIMARY KEY (channelId, userId)
    )
  `);

  // Контакты
  await db.exec(`
    CREATE TABLE IF NOT EXISTS contacts (
      userId TEXT,
      contactId TEXT,
      PRIMARY KEY (userId, contactId)
    )
  `);

  // Стикерпаки
  await db.exec(`
    CREATE TABLE IF NOT EXISTS sticker_packs (
      id TEXT PRIMARY KEY,
      name TEXT,
      creatorId TEXT,
      coverSticker TEXT,
      inviteLink TEXT,
      createdAt TEXT
    )
  `);

  // Стикеры
  await db.exec(`
    CREATE TABLE IF NOT EXISTS stickers (
      id TEXT PRIMARY KEY,
      packId TEXT,
      imageUrl TEXT,
      emoji TEXT,
      createdAt TEXT
    )
  `);

  // Пользовательские стикерпаки
  await db.exec(`
    CREATE TABLE IF NOT EXISTS user_sticker_packs (
      userId TEXT,
      packId TEXT,
      PRIMARY KEY (userId, packId)
    )
  `);

  // Закреплённые чаты
  await db.exec(`
    CREATE TABLE IF NOT EXISTS pinned_chats (
      userId TEXT,
      chatId TEXT,
      PRIMARY KEY (userId, chatId)
    )
  `);

  console.log('✅ SQLite база готова');
};
await initDB();

// ==================== MIDDLEWARE AUTH ====================
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.get('SELECT id, email, username, firstName, lastName, avatar FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ==================== API РОУТЫ ====================
app.post('/api/auth/register', async (req, res) => {
  const { email, password, firstName, lastName, username } = req.body;
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Никнейм только латиница, цифры, _' });
  const existing = await db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
  if (existing) return res.status(400).json({ error: 'Email или никнейм занят' });
  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();
  await db.run('INSERT INTO users (id, email, password, firstName, lastName, username, isOnline, lastSeen) VALUES (?, ?, ?, ?, ?, ?, 0, ?)', [id, email, hashed, firstName, lastName, username, new Date().toISOString()]);
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

app.get('/api/users/me', auth, async (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/users/search', auth, async (req, res) => {
  const { q } = req.query;
  const users = await db.all('SELECT id, username, firstName, lastName, avatar FROM users WHERE username LIKE ? AND id != ? LIMIT 20', [`%${q}%`, req.user.id]);
  res.json(users);
});

app.post('/api/users/contact', auth, async (req, res) => {
  const { contactId } = req.body;
  await db.run('INSERT OR IGNORE INTO contacts (userId, contactId) VALUES (?, ?)', [req.user.id, contactId]);
  res.json({ success: true });
});

app.get('/api/users/contacts', auth, async (req, res) => {
  const contacts = await db.all('SELECT u.id, u.username, u.firstName, u.lastName, u.avatar, u.isOnline FROM contacts c JOIN users u ON c.contactId = u.id WHERE c.userId = ?', [req.user.id]);
  res.json(contacts);
});

app.get('/api/chats', auth, async (req, res) => {
  const contacts = await db.all('SELECT u.id, u.username as name, "user" as type, u.avatar FROM contacts c JOIN users u ON c.contactId = u.id WHERE c.userId = ?', [req.user.id]);
  const groups = await db.all('SELECT g.id, g.name, "group" as type, g.avatar FROM groups g JOIN group_members gm ON g.id = gm.groupId WHERE gm.userId = ?', [req.user.id]);
  const channels = await db.all('SELECT c.id, c.name, "channel" as type, c.avatar FROM channels c JOIN channel_subscribers cs ON c.id = cs.channelId WHERE cs.userId = ?', [req.user.id]);
  res.json([...contacts, ...groups, ...channels]);
});

app.get('/api/messages/:chatId', auth, async (req, res) => {
  const messages = await db.all('SELECT * FROM messages WHERE chatId = ? ORDER BY createdAt ASC LIMIT 100', [req.params.chatId]);
  res.json(messages);
});

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.fieldname === 'avatar' ? 'avatars' : req.file.fieldname === 'sticker' ? 'stickers' : 'files'}/${req.file.filename}`;
  res.json({ url: fileUrl, filename: req.file.filename });
});

app.post('/api/upload/avatar', auth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/avatars/${req.file.filename}`;
  await db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatarUrl, req.user.id]);
  res.json({ url: avatarUrl });
});

// Группы
app.post('/api/groups', auth, async (req, res) => {
  const { name, description, avatar, members } = req.body;
  const id = uuidv4();
  await db.run('INSERT INTO groups (id, name, description, avatar, creatorId, type, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)', [id, name, description, avatar, req.user.id, 'group', new Date().toISOString()]);
  await db.run('INSERT INTO group_members (groupId, userId, role) VALUES (?, ?, ?)', [id, req.user.id, 'creator']);
  for (const member of (members || [])) {
    await db.run('INSERT OR IGNORE INTO group_members (groupId, userId, role) VALUES (?, ?, ?)', [id, member, 'member']);
  }
  res.json({ id, name });
});

app.get('/api/groups/:id/members', auth, async (req, res) => {
  const members = await db.all('SELECT u.id, u.username, u.firstName, u.lastName, u.avatar, gm.role FROM group_members gm JOIN users u ON gm.userId = u.id WHERE gm.groupId = ?', [req.params.id]);
  res.json(members);
});

app.post('/api/groups/:id/add', auth, async (req, res) => {
  const { userId } = req.body;
  await db.run('INSERT OR IGNORE INTO group_members (groupId, userId, role) VALUES (?, ?, ?)', [req.params.id, userId, 'member']);
  res.json({ success: true });
});

// Каналы
app.post('/api/channels', auth, async (req, res) => {
  const { name, description, avatar, username, isPublic } = req.body;
  const id = uuidv4();
  const inviteLink = `${uuidv4().slice(0, 8)}`;
  await db.run('INSERT INTO channels (id, name, description, avatar, creatorId, username, isPublic, inviteLink, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [id, name, description, avatar, req.user.id, username, isPublic ? 1 : 0, inviteLink, new Date().toISOString()]);
  await db.run('INSERT INTO channel_subscribers (channelId, userId) VALUES (?, ?)', [id, req.user.id]);
  res.json({ id, name, inviteLink });
});

app.get('/api/channels/:username', auth, async (req, res) => {
  const channel = await db.get('SELECT * FROM channels WHERE username = ?', [req.params.username]);
  if (!channel) return res.status(404).json({ error: 'Канал не найден' });
  res.json(channel);
});

app.post('/api/channels/:id/join', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO channel_subscribers (channelId, userId) VALUES (?, ?)', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// Стикерпаки
app.post('/api/sticker-packs', auth, async (req, res) => {
  const { name } = req.body;
  const id = uuidv4();
  const inviteLink = `${uuidv4().slice(0, 8)}`;
  await db.run('INSERT INTO sticker_packs (id, name, creatorId, inviteLink, createdAt) VALUES (?, ?, ?, ?, ?)', [id, name, req.user.id, inviteLink, new Date().toISOString()]);
  await db.run('INSERT INTO user_sticker_packs (userId, packId) VALUES (?, ?)', [req.user.id, id]);
  res.json({ id, name, inviteLink });
});

app.post('/api/sticker-packs/:id/add-sticker', auth, upload.single('sticker'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const packId = req.params.id;
  const stickerUrl = `${req.protocol}://${req.get('host')}/uploads/stickers/${req.file.filename}`;
  const stickerId = uuidv4();
  await db.run('INSERT INTO stickers (id, packId, imageUrl, createdAt) VALUES (?, ?, ?, ?)', [stickerId, packId, stickerUrl, new Date().toISOString()]);
  res.json({ id: stickerId, url: stickerUrl });
});

app.get('/api/sticker-packs', auth, async (req, res) => {
  const packs = await db.all('SELECT sp.*, (SELECT imageUrl FROM stickers WHERE packId = sp.id LIMIT 1) as coverSticker FROM sticker_packs sp JOIN user_sticker_packs usp ON sp.id = usp.packId WHERE usp.userId = ?', [req.user.id]);
  res.json(packs);
});

app.get('/api/sticker-packs/:id', auth, async (req, res) => {
  const pack = await db.get('SELECT * FROM sticker_packs WHERE id = ?', [req.params.id]);
  if (!pack) return res.status(404).json({ error: 'Not found' });
  const stickers = await db.all('SELECT * FROM stickers WHERE packId = ?', [req.params.id]);
  res.json({ ...pack, stickers });
});

app.post('/api/sticker-packs/:id/add', auth, async (req, res) => {
  await db.run('INSERT OR IGNORE INTO user_sticker_packs (userId, packId) VALUES (?, ?)', [req.user.id, req.params.id]);
  res.json({ success: true });
});

// Управление чатами
app.post('/api/pinned-chats', auth, async (req, res) => {
  const { chatId } = req.body;
  await db.run('INSERT OR IGNORE INTO pinned_chats (userId, chatId) VALUES (?, ?)', [req.user.id, chatId]);
  res.json({ success: true });
});

app.delete('/api/pinned-chats/:chatId', auth, async (req, res) => {
  await db.run('DELETE FROM pinned_chats WHERE userId = ? AND chatId = ?', [req.user.id, req.params.chatId]);
  res.json({ success: true });
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  await db.run('DELETE FROM messages WHERE id = ? AND senderId = ?', [req.params.id, req.user.id]);
  res.json({ success: true });
});

app.post('/api/messages/:id/pin', auth, async (req, res) => {
  await db.run('UPDATE messages SET pinned = 1 WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ==================== SOCKET.IO ====================
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
    const { chatId, content, type, receiverId, fileUrl, fileName, replyTo, isSticker } = data;
    await db.run(`INSERT INTO messages (id, chatId, senderId, receiverId, type, content, fileUrl, fileName, isSticker, replyTo, createdAt)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [messageId, chatId, socket.userId, receiverId, type, content, fileUrl, fileName, isSticker ? 1 : 0, replyTo, new Date().toISOString()]);
    
    const message = await db.get('SELECT * FROM messages WHERE id = ?', [messageId]);
    
    // Отправляем получателю (если есть)
    if (receiverId) {
      io.to(`user:${receiverId}`).emit('new_message', message);
    }
    // Отправляем в группу/канал
    if (chatId && !receiverId) {
      io.to(chatId).emit('new_message', message);
    }
    // Подтверждение отправителю
    socket.emit('message_sent', message);
  });

  socket.on('join_chat', (chatId) => {
    socket.join(chatId);
  });

  socket.on('typing', (data) => {
    if (data.receiverId) {
      socket.to(`user:${data.receiverId}`).emit('user_typing', { userId: socket.userId, chatId: data.chatId });
    }
  });

  socket.on('disconnect', async () => {
    console.log('❌ User disconnected:', socket.userId);
    await db.run('UPDATE users SET isOnline = 0, lastSeen = ? WHERE id = ?', [new Date().toISOString(), socket.userId]);
    io.emit('user_status', { userId: socket.userId, isOnline: false });
  });
});

server.listen(process.env.PORT || 10000, () => {
  console.log(`🚀 Noris Backend running on port ${process.env.PORT || 10000}`);
});
