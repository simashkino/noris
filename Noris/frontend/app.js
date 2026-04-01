import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import toast, { Toaster } from 'react-hot-toast';
import './App.css';

function App() {
  const [step, setStep] = useState('login');
  const [formData, setFormData] = useState({ email: '', password: '', firstName: '', lastName: '', username: '' });
  const [code, setCode] = useState('');
  const [userId, setUserId] = useState('');
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  const [socket, setSocket] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageText, setMessageText] = useState('');
  const [chats, setChats] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [typing, setTyping] = useState(false);
  const messagesEndRef = useRef(null);
  
  const api = axios.create({
    baseURL: process.env.REACT_APP_API_URL + '/api',
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });
  
  useEffect(() => {
    if (token) {
      fetchUser();
    }
  }, [token]);
  
  useEffect(() => {
    if (socket && activeChat) {
      socket.emit('join_group', activeChat.id);
    }
  }, [socket, activeChat]);
  
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);
  
  const fetchUser = async () => {
    try {
      const { data } = await api.get('/users/me');
      setUser(data.user);
      fetchChats();
      fetchContacts();
      initSocket();
      setStep('main');
    } catch (err) {
      localStorage.removeItem('token');
      setToken(null);
      setStep('login');
    }
  };
  
  const initSocket = () => {
    const newSocket = io(process.env.REACT_APP_API_URL, { auth: { token } });
    setSocket(newSocket);
    
    newSocket.on('new_message', (msg) => {
      setMessages(prev => [...prev, msg]);
      if (msg.senderId._id !== user?.id) {
        toast(`📩 ${msg.senderId.username}: ${msg.content}`, { duration: 3000 });
      }
    });
    
    newSocket.on('user_typing', (data) => {
      if (activeChat?.id === data.userId) setTyping(true);
      setTimeout(() => setTyping(false), 2000);
    });
    
    newSocket.on('message_sent', (msg) => {
      setMessages(prev => [...prev, msg]);
    });
  };
  
  const fetchChats = async () => {
    const { data } = await api.get('/chats');
    setChats(data);
  };
  
  const fetchContacts = async () => {
    const { data } = await api.get('/users/contacts');
    setContacts(data);
  };
  
  const fetchMessages = async (chatId) => {
    const { data } = await api.get(`/messages/${chatId}`);
    setMessages(data);
  };
  
  const handleRegister = async () => {
    try {
      const { data } = await api.post('/auth/register', formData);
      setUserId(data.userId);
      toast.success('Код отправлен! Проверьте email');
      setStep('verify');
    } catch (err) {
      toast.error(err.response?.data?.error || 'Ошибка');
    }
  };
  
  const handleVerify = async () => {
    try {
      const { data } = await api.post('/auth/verify', { userId, code });
      localStorage.setItem('token', data.token);
      setToken(data.token);
      setUser(data.user);
      setStep('main');
      toast.success('Добро пожаловать в Noris!');
    } catch (err) {
      toast.error('Неверный код');
    }
  };
  
  const handleLogin = async () => {
    try {
      const { data } = await api.post('/auth/login', { email: formData.email, password: formData.password });
      localStorage.setItem('token', data.token);
      setToken(data.token);
      setUser(data.user);
      setStep('main');
      toast.success('Вход выполнен!');
    } catch (err) {
      toast.error('Неверный email или пароль');
    }
  };
  
  const searchUsers = async () => {
    if (!searchQuery) return;
    const { data } = await api.get(`/users/search?q=${searchQuery}`);
    setSearchResults(data);
  };
  
  const addContact = async (contactId) => {
    await api.post('/users/contact', { contactId });
    toast.success('Контакт добавлен');
    fetchContacts();
  };
  
  const openChat = (chat) => {
    setActiveChat(chat);
    fetchMessages(chat.id);
  };
  
  const sendMessage = async () => {
    if (!messageText.trim() && !activeChat?.fileUrl) return;
    
    const messageData = {
      chatId: activeChat.id,
      content: messageText,
      type: 'text',
      receiverId: activeChat.type === 'user' ? activeChat.id : null
    };
    
    socket.emit('send_message', messageData);
    setMessageText('');
  };
  
  const sendTyping = () => {
    if (activeChat?.type === 'user') {
      socket.emit('typing', { receiverId: activeChat.id, chatId: activeChat.id });
    }
  };
  
  const uploadFile = async (file, type = 'file') => {
    const formData = new FormData();
    formData.append(type, file);
    const { data } = await api.post('/upload', formData);
    return data.url;
  };
  
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    const url = await uploadFile(file);
    socket.emit('send_message', {
      chatId: activeChat.id,
      content: url,
      type: 'file',
      fileName: file.name,
      receiverId: activeChat.type === 'user' ? activeChat.id : null
    });
  };
  
  // СТРАНИЦЫ
  if (step === 'login') {
    return (
      <div className="auth">
        <div className="auth-card">
          <h1>✨ Noris</h1>
          <input placeholder="Email" onChange={e => setFormData({...formData, email: e.target.value})} />
          <input type="password" placeholder="Пароль" onChange={e => setFormData({...formData, password: e.target.value})} />
          <button onClick={handleLogin}>Войти</button>
          <button className="secondary" onClick={() => setStep('register')}>Создать аккаунт</button>
        </div>
        <Toaster />
      </div>
    );
  }
  
  if (step === 'register') {
    return (
      <div className="auth">
        <div className="auth-card">
          <h1>Регистрация Noris</h1>
          <input placeholder="Email" onChange={e => setFormData({...formData, email: e.target.value})} />
          <input type="password" placeholder="Пароль (мин 6)" onChange={e => setFormData({...formData, password: e.target.value})} />
          <input placeholder="Имя" onChange={e => setFormData({...formData, firstName: e.target.value})} />
          <input placeholder="Фамилия" onChange={e => setFormData({...formData, lastName: e.target.value})} />
          <input placeholder="Никнейм (англ буквы, цифры, _)" onChange={e => setFormData({...formData, username: e.target.value})} />
          <button onClick={handleRegister}>Зарегистрироваться</button>
          <button className="secondary" onClick={() => setStep('login')}>Назад</button>
        </div>
        <Toaster />
      </div>
    );
  }
  
  if (step === 'verify') {
    return (
      <div className="auth">
        <div className="auth-card">
          <h1>Подтверждение</h1>
          <p>Введите код из письма</p>
          <input placeholder="Код" onChange={e => setCode(e.target.value)} />
          <button onClick={handleVerify}>Подтвердить</button>
        </div>
        <Toaster />
      </div>
    );
  }
  
  // ГЛАВНЫЙ ЭКРАН
  return (
    <div className="app">
      <div className="sidebar">
        <div className="profile">
          <img src={user?.avatar || `https://ui-avatars.com/api/?name=${user?.firstName}+${user?.lastName}&background=2b5278&color=fff`} alt="avatar" />
          <div>
            <strong>{user?.firstName} {user?.lastName}</strong>
            <span>@{user?.username}</span>
          </div>
        </div>
        
        <div className="search-box">
          <input 
            placeholder="Поиск по никнейму..." 
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyPress={e => e.key === 'Enter' && searchUsers()}
          />
          <button onClick={searchUsers}>🔍</button>
        </div>
        
        {searchResults.length > 0 && (
          <div className="search-results">
            {searchResults.map(u => (
              <div key={u._id} className="contact-item" onClick={() => addContact(u._id)}>
                <img src={u.avatar || `https://ui-avatars.com/api/?name=${u.username}&background=2b5278&color=fff`} alt="" />
                <span>@{u.username}</span>
                <button>+</button>
              </div>
            ))}
          </div>
        )}
        
        <div className="chats">
          <h3>Чаты</h3>
          {chats.map(chat => (
            <div key={chat.id} className={`chat-item ${activeChat?.id === chat.id ? 'active' : ''}`} onClick={() => openChat(chat)}>
              <img src={chat.avatar || `https://ui-avatars.com/api/?name=${chat.name}&background=2b5278&color=fff`} alt="" />
              <span>{chat.name}</span>
            </div>
          ))}
        </div>
        
        <div className="contacts">
          <h3>Контакты</h3>
          {contacts.map(c => (
            <div key={c._id} className="contact-item" onClick={() => openChat({ id: c._id, name: c.username, type: 'user', avatar: c.avatar })}>
              <img src={c.avatar || `https://ui-avatars.com/api/?name=${c.username}&background=2b5278&color=fff`} alt="" />
              <div>
                <span>{c.firstName} {c.lastName}</span>
                <small>@{c.username}</small>
              </div>
              <span className={`status ${c.isOnline ? 'online' : 'offline'}`}></span>
            </div>
          ))}
        </div>
      </div>
      
      <div className="chat-area">
        {activeChat ? (
          <>
            <div className="chat-header">
              <img src={activeChat.avatar || `https://ui-avatars.com/api/?name=${activeChat.name}&background=2b5278&color=fff`} alt="" />
              <div>
                <strong>{activeChat.name}</strong>
                {typing && <small className="typing">печатает...</small>}
              </div>
            </div>
            
            <div className="messages">
              {messages.map((msg, i) => (
                <div key={i} className={`message ${msg.senderId?._id === user?.id ? 'mine' : 'theirs'}`}>
                  <img src={msg.senderId?.avatar || `https://ui-avatars.com/api/?name=${msg.senderId?.username}&background=2b5278&color=fff`} alt="" />
                  <div className="message-content">
                    <strong>{msg.senderId?.username}</strong>
                    {msg.type === 'file' ? (
                      <a href={msg.content} target="_blank" rel="noreferrer">📎 {msg.fileName || 'Файл'}</a>
                    ) : (
                      <p>{msg.content}</p>
                    )}
                    <small>{new Date(msg.timestamp).toLocaleTimeString()}</small>
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
            
            <div className="input-area">
              <label className="file-btn">
                📎
                <input type="file" onChange={handleFileUpload} style={{ display: 'none' }} />
              </label>
              <input 
                value={messageText}
                onChange={e => setMessageText(e.target.value)}
                onKeyPress={e => e.key === 'Enter' && sendMessage()}
                onFocus={sendTyping}
                placeholder="Сообщение..."
              />
              <button onClick={sendMessage}>➤</button>
            </div>
          </>
        ) : (
          <div className="placeholder">
            <h2>✨ Noris Messenger</h2>
            <p>Выберите чат или найдите друга по никнейму</p>
          </div>
        )}
      </div>
      <Toaster />
    </div>
  );
}

export default App;