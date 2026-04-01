import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:3000", credentials: true }
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Создаем папку для загрузок
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(path.join(uploadDir, 'avatars'))) fs.mkdirSync(path.join(uploadDir, 'avatars'));
if (!fs.existsSync(path.join(uploadDir, 'files'))) fs.mkdirSync(path.join(uploadDir, 'files'));

// Настройка multer для загрузки файлов (локальное хранилище)
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

// ============ МОДЕЛИ MONGODB ============
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  firstName: String,
  lastName: String,
  username: { type: String, unique: true, required: true, match: /^[a-zA-Z0-9_]+$/ },
  avatar: String,
  emailVerified: { type: Boolean, default: false },
  verificationCode: String,
  contacts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isOnline: { type: Boolean, default: false },
  lastSeen: Date
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  chatId: String,
  senderId: String,
  receiverId: String,
  type: { type: String, default: 'text' },
  content: String,
  fileUrl: String,
  fileName: String,
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});

const groupSchema = new mongoose.Schema({
  name: String,
  photo: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  creatorId: String,
  type: { type: String, default: 'group' },
  username: { type: String, unique: true, sparse: true },
  isPublic: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);

// ============ НАСТРОЙКА ПОЧТЫ (тестовый аккаунт, регистрация не нужна) ============
let transporter;
const setupMailer = async () => {
  // Создаем тестовый аккаунт Ethereal автоматически (не нужна регистрация)
  const testAccount = await nodemailer.createTestAccount();
  transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: { user: testAccount.user, pass: testAccount.pass }
  });
  console.log('📧 Тестовая почта готова! Письма смотреть тут: https://ethereal.email/login');
  console.log(`📧 Логин: ${testAccount.user}`);
  console.log(`📧 Пароль: ${testAccount.pass}`);
};
setupMailer();

// ============ MIDDLEWARE ============
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
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
    
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ error: 'Email или никнейм занят' });
    
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({ 
      email, password: hashedPassword, firstName, lastName, username, 
      verificationCode: code, emailVerified: false 
    });
    await user.save();
    
    // Отправляем письмо (через тестовую почту)
    const info = await transporter.sendMail({
      from: '"Noris" <noreply@noris.com>',
      to: email,
      subject: 'Код подтверждения Noris',
      html: `<h2>Ваш код: <strong>${code}</strong></h2><p>Введите его для подтверждения email.</p>`
    });
    
    console.log(`📧 Письмо отправлено! Превью: ${nodemailer.getTestMessageUrl(info)}`);
    
    res.json({ message: 'Код отправлен', userId: user._id, testEmailUrl: nodemailer.getTestMessageUrl(info) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Подтверждение кода
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { userId, code } = req.body;
    const user = await User.findById(userId);
    if (!user || user.verificationCode !== code) return res.status(400).json({ error: 'Неверный код' });
    
    user.emailVerified = true;
    user.verificationCode = null;
    await user.save();
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username: user.username, firstName: user.firstName, lastName: user.lastName, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Вход
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    user.isOnline = true;
    await user.save();
    res.json({ token, user: { id: user._id, username: user.username, firstName: user.firstName, lastName: user.lastName, avatar: user.avatar } });
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
    const users = await User.find({ 
      username: { $regex: q, $options: 'i' },
      _id: { $ne: req.user._id }
    }).limit(20).select('username firstName lastName avatar');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Добавить в контакты
app.post('/api/users/contact', auth, async (req, res) => {
  try {
    const { contactId } = req.body;
    await User.findByIdAndUpdate(req.user._id, { $addToSet: { contacts: contactId } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить контакты
app.get('/api/users/contacts', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('contacts', 'username firstName lastName avatar isOnline');
    res.json(user.contacts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Загрузка файла (локально)
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
    await User.findByIdAndUpdate(req.user._id, { avatar: avatarUrl });
    res.json({ url: avatarUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Создать группу
app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, members } = req.body;
    const group = new Group({ 
      name, 
      members: [req.user._id, ...(members || [])], 
      creatorId: req.user._id 
    });
    await group.save();
    res.json(group);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить чаты (диалоги и группы)
app.get('/api/chats', auth, async (req, res) => {
  try {
    // Получаем последние сообщения для каждого чата
    const privateChats = await User.find({ _id: { $in: req.user.contacts } }).select('username firstName lastName avatar');
    const groups = await Group.find({ members: req.user._id });
    
    const chats = [
      ...privateChats.map(u => ({ id: u._id, name: u.username, type: 'user', avatar: u.avatar })),
      ...groups.map(g => ({ id: g._id, name: g.name, type: 'group', avatar: g.photo }))
    ];
    res.json(chats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить историю сообщений
app.get('/api/messages/:chatId', auth, async (req, res) => {
  try {
    const messages = await Message.find({ chatId: req.params.chatId })
      .sort({ timestamp: -1 })
      .limit(50)
      .populate('senderId', 'username firstName lastName avatar');
    res.json(messages.reverse());
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
  
  // Обновляем статус онлайн
  await User.findByIdAndUpdate(socket.userId, { isOnline: true, lastSeen: new Date() });
  socket.join(`user_${socket.userId}`);
  io.emit('user_status', { userId: socket.userId, isOnline: true });
  
  // Отправка сообщения
  socket.on('send_message', async (data) => {
    try {
      const message = new Message({
        chatId: data.chatId,
        senderId: socket.userId,
        receiverId: data.receiverId,
        type: data.type || 'text',
        content: data.content,
        fileUrl: data.fileUrl,
        fileName: data.fileName
      });
      await message.save();
      
      const populated = await Message.findById(message._id).populate('senderId', 'username firstName lastName avatar');
      
      // Отправляем получателю
      if (data.receiverId) {
        io.to(`user_${data.receiverId}`).emit('new_message', populated);
      }
      // Если это группа
      if (data.chatId && !data.receiverId) {
        io.to(data.chatId).emit('new_message', populated);
      }
      // Подтверждаем отправителю
      socket.emit('message_sent', populated);
    } catch (err) {
      socket.emit('message_error', { error: err.message });
    }
  });
  
  // Печатает
  socket.on('typing', (data) => {
    if (data.receiverId) {
      socket.to(`user_${data.receiverId}`).emit('user_typing', { userId: socket.userId, chatId: data.chatId });
    }
  });
  
  // Присоединение к группе
  socket.on('join_group', (groupId) => {
    socket.join(groupId);
  });
  
  socket.on('disconnect', async () => {
    console.log('❌ Пользователь отключился:', socket.userId);
    await User.findByIdAndUpdate(socket.userId, { isOnline: false, lastSeen: new Date() });
    io.emit('user_status', { userId: socket.userId, isOnline: false });
  });
});

// ============ ЗАПУСК ============
mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log('✅ MongoDB подключена');
  server.listen(process.env.PORT || 5000, () => {
    console.log(`🚀 Noris сервер запущен: http://localhost:${process.env.PORT || 5000}`);
  });
}).catch(err => {
  console.error('❌ Ошибка MongoDB:', err.message);
});