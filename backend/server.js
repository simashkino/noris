import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';
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
app.use(express.json({ limit: '100mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Создаем папки
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(path.join(uploadDir, 'avatars'))) fs.mkdirSync(path.join(uploadDir, 'avatars'));
if (!fs.existsSync(path.join(uploadDir, 'files'))) fs.mkdirSync(path.join(uploadDir, 'files'));

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'avatar') {
      cb(null, path.join(uploadDir, 'avatars'));
    } else {
      cb(null, path.join(uploadDir, 'files'));
    }
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// ============ SQLite БАЗА ДАННЫХ ============
let db;

const initDB = async () => {
  db = await open({
    filename: './noris.db',
    driver: sqlite3.Database
  });

  // Таблица пользователей
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT,
      firstName TEXT,
      lastName TEXT,
      username TEXT UNIQUE,
      avatar TEXT,
      emailVerified INTEGER DEFAULT 0,
      verificationCode TEXT,
      isOnline INTEGER DEFAULT 0,
      lastSeen TEXT,
      createdAt TEXT
    )
  `);

  // Таблица сообщений
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
      read INTEGER DEFAULT 0,
      timestamp TEXT
    )
  `);

  // Таблица групп
  await db.exec(`
    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      name TEXT,
      photo TEXT,
      creatorId TEXT,
      type TEXT DEFAULT 'group',
      createdAt TEXT
    )
  `);

  // Таблица участников групп
  await db.exec(`
    CREATE TABLE IF NOT EXISTS group_members (
      groupId TEXT,
      userId TEXT
    )
  `);

  // Таблица контактов
  await db.exec(`
    CREATE TABLE IF NOT EXISTS contacts (
      userId TEXT,
      contactId TEXT
    )
  `);

  console.log('✅ SQLite база данных готова');
};

// ============ ПОЧТА ============
let transporter;
const setupMailer = async () => {
  const testAccount = await nodemailer.createTestAccount();
  transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: { user: testAccount.user, pass: testAccount.pass }
  });
  console.log('📧 Тестовая почта готова!');
  console.log(`📧 Логин: ${testAccount.user}`);
  console.log(`📧 Пароль: ${testAccount.pass}`);
};

// ============ MIDDLEWARE ============
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.get('SELECT id, email, username, firstName, lastName, avatar, isOnline FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Не авторизован' });
  }
};

// ============ API РОУТЫ ============

// Регистрация
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, username } = req.body;
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ error: 'Никнейм только латиница, цифры, _' });
    }
    
    const existing = await db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
    if (existing) return res.status(400).json({ error: 'Email или никнейм занят' });
    
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = Date.now().toString();
    
    await db.run(
      'INSERT INTO users (id, email, password, firstName, lastName, username, verificationCode, emailVerified, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)',
      [id, email, hashedPassword, firstName, lastName, username, code, new Date().toISOString()]
    );
    
    const info = await transporter.sendMail({
      from: '"Noris" <noreply@noris.com>',
      to: email,
      subject: 'Код подтверждения Noris',
      html: `<h2>Ваш код: <strong>${code}</strong></h2><p>Введите его для подтверждения email.</p>`
    });
    
    console.log(`📧 Письмо отправлено! Превью: ${nodemailer.getTestMessageUrl(info)}`);
    res.json({ message: 'Код отправлен', userId: id, testEmailUrl: nodemailer.getTestMessageUrl(info) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Подтверждение кода
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { userId, code } = req.body;
    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user || user.verificationCode !== code) return res.status(400).json({ error: 'Неверный код' });
    
    await db.run('UPDATE users SET emailVerified = 1, verificationCode = NULL WHERE id = ?', [userId]);
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, firstName: user.firstName, lastName: user.lastName, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Вход
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    await db.run('UPDATE users SET isOnline = 1, lastSeen = ? WHERE id = ?', [new Date().toISOString(), user.id]);
    res.json({ token, user: { id: user.id, username: user.username, firstName: user.firstName, lastName: user.lastName, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить текущего пользователя
app.get('/api/users/me', auth, async (req, res) => {
  res.json({ user: req.user });
});

// Поиск пользователей
app.get('/api/users/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    const users = await db.all(
      'SELECT id, username, firstName, lastName, avatar FROM users WHERE username LIKE ? AND id != ? LIMIT 20',
      [`%${q}%`, req.user.id]
    );
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Добавить в контакты
app.post('/api/users/contact', auth, async (req, res) => {
  try {
    const { contactId } = req.body;
    await db.run('INSERT OR IGNORE INTO contacts (userId, contactId) VALUES (?, ?)', [req.user.id, contactId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить контакты
app.get('/api/users/contacts', auth, async (req, res) => {
  try {
    const contacts = await db.all(
      'SELECT u.id, u.username, u.firstName, u.lastName, u.avatar, u.isOnline FROM contacts c JOIN users u ON c.contactId = u.id WHERE c.userId = ?',
      [req.user.id]
    );
    res.json(contacts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Загрузка файла
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.fieldname === 'avatar' ? 'avatars' : 'files'}/${req.file.filename}`;
    res.json({ url: fileUrl, filename: req.file.filename });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Загрузка аватарки
app.post('/api/upload/avatar', auth, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/avatars/${req.file.filename}`;
    await db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatarUrl, req.user.id]);
    res.json({ url: avatarUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Создать группу
app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, members } = req.body;
    const id = Date.now().toString();
    await db.run('INSERT INTO groups (id, name, creatorId, type, createdAt) VALUES (?, ?, ?, ?, ?)', [id, name, req.user.id, 'group', new Date().toISOString()]);
    await db.run('INSERT INTO group_members (groupId, userId) VALUES (?, ?)', [id, req.user.id]);
    for (const member of (members || [])) {
      await db.run('INSERT INTO group_members (groupId, userId) VALUES (?, ?)', [id, member]);
    }
    res.json({ id, name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить чаты
app.get('/api/chats', auth, async (req, res) => {
  try {
    const contacts = await db.all(
      'SELECT u.id, u.username, u.firstName, u.lastName, u.avatar FROM contacts c JOIN users u ON c.contactId = u.id WHERE c.userId = ?',
      [req.user.id]
    );
    const groups = await db.all(
      'SELECT g.id, g.name, g.photo FROM groups g JOIN group_members gm ON g.id = gm.groupId WHERE gm.userId = ?',
      [req.user.id]
    );
    const chats = [
      ...contacts.map(c => ({ id: c.id, name: c.username, type: 'user', avatar: c.avatar })),
      ...groups.map(g => ({ id: g.id, name: g.name, type: 'group', avatar: g.photo }))
    ];
    res.json(chats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить историю сообщений
app.get('/api/messages/:chatId', auth, async (req, res) => {
  try {
    const messages = await db.all(
      'SELECT * FROM messages WHERE chatId = ? ORDER BY timestamp ASC LIMIT 100',
      [req.params.chatId]
    );
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ SOCKET.IO ============
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Нет токена"));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (err) {
    next(new Error("Неверный токен"));
  }
});

io.on('connection', async (socket) => {
  console.log('✅ Пользователь подключился:', socket.userId);
  
  await db.run('UPDATE users SET isOnline = 1, lastSeen = ? WHERE id = ?', [new Date().toISOString(), socket.userId]);
  socket.join(`user_${socket.userId}`);
  io.emit('user_status', { userId: socket.userId, isOnline: true });
  
  socket.on('send_message', async (data) => {
    try {
      const id = Date.now().toString() + Math.random().toString(36).substr(2, 4);
      await db.run(
        'INSERT INTO messages (id, chatId, senderId, receiverId, type, content, fileUrl, fileName, read, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [id, data.chatId, socket.userId, data.receiverId, data.type || 'text', data.content, data.fileUrl, data.fileName, 0, new Date().toISOString()]
      );
      
      const message = await db.get('SELECT * FROM messages WHERE id = ?', [id]);
      
      if (data.receiverId) {
        io.to(`user_${data.receiverId}`).emit('new_message', message);
      }
      if (data.chatId && !data.receiverId) {
        io.to(data.chatId).emit('new_message', message);
      }
      socket.emit('message_sent', message);
    } catch (err) {
      socket.emit('message_error', { error: err.message });
    }
  });
  
  socket.on('typing', (data) => {
    if (data.receiverId) {
      socket.to(`user_${data.receiverId}`).emit('user_typing', { userId: socket.userId, chatId: data.chatId });
    }
  });
  
  socket.on('join_group', (groupId) => {
    socket.join(groupId);
  });
  
  socket.on('disconnect', async () => {
    console.log('❌ Пользователь отключился:', socket.userId);
    await db.run('UPDATE users SET isOnline = 0, lastSeen = ? WHERE id = ?', [new Date().toISOString(), socket.userId]);
    io.emit('user_status', { userId: socket.userId, isOnline: false });
  });
});

// ============ ЗАПУСК ============
const start = async () => {
  await initDB();
  await setupMailer();
  server.listen(process.env.PORT || 10000, () => {
    console.log(`🚀 Noris сервер запущен на порту ${process.env.PORT || 10000}`);
  });
};

start();
