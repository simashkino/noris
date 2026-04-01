package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/gorilla/websocket"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}

var clients = make(map[*websocket.Conn]int)
var clientsMu sync.Mutex

type User struct {
    ID        int       `json:"id"`
    Email     string    `json:"email"`
    Nickname  string    `json:"nickname"`
    IsAdmin   bool      `json:"is_admin"`
    CreatedAt time.Time `json:"created_at"`
}

type Message struct {
    ID        int       `json:"id"`
    FromID    int       `json:"from_id"`
    FromNick  string    `json:"from_nick"`
    ToID      int       `json:"to_id"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
}

type RegisterRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
    Nickname string `json:"nickname"`
}

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type LoginResponse struct {
    Token    string `json:"token"`
    UserID   int    `json:"user_id"`
    Nickname string `json:"nickname"`
    IsAdmin  bool   `json:"is_admin"`
}

type SendMessageRequest struct {
    ToID    int    `json:"to_id"`
    Content string `json:"content"`
}

var forbiddenWords = []string{
    "хуй", "хуи", "хуя", "пизда", "пиздец", "бля", "блять", "блядь",
    "xui", "xyu", "blyat", "pizdec", "suka", "cyka", "debil", "idiot",
    "fuck", "shit", "ass", "cock", "dick",
}

func containsForbiddenWord(s string) bool {
    lower := strings.ToLower(s)
    for _, word := range forbiddenWords {
        if strings.Contains(lower, word) {
            return true
        }
    }
    return false
}

func initDB() {
    var err error
    db, err = sql.Open("sqlite3", "./noris.db")
    if err != nil {
        log.Fatal(err)
    }

    db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        nickname TEXT UNIQUE NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)

    db.Exec(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_id INTEGER NOT NULL,
        to_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_id) REFERENCES users(id),
        FOREIGN KEY(to_id) REFERENCES users(id)
    )`)

    var count int
    db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
    if count == 0 {
        hashedPass, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
        db.Exec("INSERT INTO users (email, password, nickname, is_admin) VALUES (?, ?, ?, ?)",
            "alexey-worke@bk.ru", string(hashedPass), "noris_admin", true)
        log.Println("Admin created: alexey-worke@bk.ru / admin123")
    }
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    var req RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", 400)
        return
    }

    if len(req.Nickname) < 3 {
        http.Error(w, "Nickname min 3 chars", 400)
        return
    }

    for _, c := range req.Nickname {
        if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            http.Error(w, "Only latin letters and digits", 400)
            return
        }
    }

    if containsForbiddenWord(req.Nickname) {
        http.Error(w, "Nickname contains forbidden words", 400)
        return
    }

    hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

    _, err := db.Exec("INSERT INTO users (email, password, nickname) VALUES (?, ?, ?)",
        req.Email, string(hashedPass), req.Nickname)
    if err != nil {
        if strings.Contains(err.Error(), "UNIQUE") {
            http.Error(w, "Email or nickname already taken", 409)
            return
        }
        http.Error(w, "Server error", 500)
        return
    }

    w.WriteHeader(201)
    json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", 400)
        return
    }

    var user struct {
        ID       int
        Password string
        Nickname string
        IsAdmin  bool
    }
    err := db.QueryRow("SELECT id, password, nickname, is_admin FROM users WHERE email = ?", req.Email).
        Scan(&user.ID, &user.Password, &user.Nickname, &user.IsAdmin)
    if err != nil {
        http.Error(w, "Invalid email or password", 401)
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
        http.Error(w, "Invalid email or password", 401)
        return
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id":  user.ID,
        "nickname": user.Nickname,
        "is_admin": user.IsAdmin,
        "exp":      time.Now().Add(time.Hour * 24 * 7).Unix(),
    })

    tokenString, _ := token.SignedString([]byte("noris-secret-key"))

    json.NewEncoder(w).Encode(LoginResponse{
        Token:    tokenString,
        UserID:   user.ID,
        Nickname: user.Nickname,
        IsAdmin:  user.IsAdmin,
    })
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Unauthorized", 401)
            return
        }

        tokenString = strings.TrimPrefix(tokenString, "Bearer ")
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return []byte("noris-secret-key"), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", 401)
            return
        }

        claims := token.Claims.(jwt.MapClaims)
        r.Header.Set("X-User-ID", fmt.Sprintf("%.0f", claims["user_id"].(float64)))
        r.Header.Set("X-Is-Admin", fmt.Sprintf("%v", claims["is_admin"]))
        next(w, r)
    }
}

func searchUsersHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    if query == "" {
        http.Error(w, "Query required", 400)
        return
    }

    rows, err := db.Query("SELECT id, nickname FROM users WHERE nickname LIKE ? LIMIT 20", "%"+query+"%")
    if err != nil {
        http.Error(w, "Server error", 500)
        return
    }
    defer rows.Close()

    var users []struct {
        ID       int    `json:"id"`
        Nickname string `json:"nickname"`
    }
    for rows.Next() {
        var u struct {
            ID       int
            Nickname string
        }
        rows.Scan(&u.ID, &u.Nickname)
        users = append(users, u)
    }
    json.NewEncoder(w).Encode(users)
}

func messagesHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Header.Get("X-User-ID")
    otherID := r.URL.Query().Get("with")

    rows, err := db.Query(`
        SELECT id, from_id, to_id, content, created_at FROM messages
        WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
        ORDER BY created_at ASC LIMIT 100`,
        userID, otherID, otherID, userID)
    if err != nil {
        http.Error(w, "Server error", 500)
        return
    }
    defer rows.Close()

    var messages []Message
    for rows.Next() {
        var m Message
        var fromID, toID int
        rows.Scan(&m.ID, &fromID, &toID, &m.Content, &m.CreatedAt)
        m.FromID = fromID
        m.ToID = toID
        rows2, err := db.Query("SELECT nickname FROM users WHERE id = ?", fromID)
        if err == nil {
            if rows2.Next() {
                rows2.Scan(&m.FromNick)
            }
            rows2.Close()
        }
        messages = append(messages, m)
    }
    json.NewEncoder(w).Encode(messages)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        http.Error(w, "Unauthorized", 401)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("WebSocket upgrade error:", err)
        return
    }
    defer conn.Close()

    clientsMu.Lock()
    clients[conn] = parseInt(userID)
    clientsMu.Unlock()

    defer func() {
        clientsMu.Lock()
        delete(clients, conn)
        clientsMu.Unlock()
    }()

    for {
        var msg SendMessageRequest
        err := conn.ReadJSON(&msg)
        if err != nil {
            break
        }

        fromID := parseInt(userID)
        result, err := db.Exec("INSERT INTO messages (from_id, to_id, content) VALUES (?, ?, ?)",
            fromID, msg.ToID, msg.Content)
        if err != nil {
            log.Println("DB insert error:", err)
            continue
        }

        msgID, _ := result.LastInsertId()
        var fromNick string
        db.QueryRow("SELECT nickname FROM users WHERE id = ?", fromID).Scan(&fromNick)

        fullMsg := Message{
            ID:        int(msgID),
            FromID:    fromID,
            FromNick:  fromNick,
            ToID:      msg.ToID,
            Content:   msg.Content,
            CreatedAt: time.Now(),
        }

        clientsMu.Lock()
        for conn, uid := range clients {
            if uid == msg.ToID {
                conn.WriteJSON(fullMsg)
            }
            if uid == fromID {
                conn.WriteJSON(fullMsg)
            }
        }
        clientsMu.Unlock()
    }
}

func parseInt(s string) int {
    var i int
    fmt.Sscanf(s, "%d", &i)
    return i
}

func serveFrontend(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Noris</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        :root {
            --lavender: #E6E6FA;
            --lavender-dark: #D4D4F0;
            --purple: #9370DB;
            --dark-purple: #7B68EE;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 30px;
            animation: fadeIn 0.5s ease;
            max-width: 400px;
            margin: 50px auto;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        input, button {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border-radius: 10px;
            border: 1px solid #ddd;
            font-size: 16px;
            transition: all 0.3s;
        }
        input:focus {
            outline: none;
            border-color: var(--purple);
            box-shadow: 0 0 0 3px rgba(147,112,219,0.1);
        }
        button {
            background: linear-gradient(135deg, var(--purple), var(--dark-purple));
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
            margin-top: 15px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(147,112,219,0.4);
        }
        .chat-container {
            display: flex;
            height: 80vh;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .sidebar {
            width: 300px;
            background: var(--lavender);
            border-right: 1px solid rgba(0,0,0,0.1);
            padding: 20px;
            overflow-y: auto;
        }
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }
        .message {
            margin-bottom: 15px;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .message.sent { text-align: right; }
        .message-bubble {
            display: inline-block;
            padding: 10px 15px;
            border-radius: 18px;
            max-width: 70%;
            word-wrap: break-word;
        }
        .message.received .message-bubble {
            background: var(--lavender);
            color: #333;
        }
        .message.sent .message-bubble {
            background: linear-gradient(135deg, var(--purple), var(--dark-purple));
            color: white;
        }
        .message-nick {
            font-size: 12px;
            color: #666;
            margin-bottom: 4px;
        }
        .input-area {
            padding: 20px;
            border-top: 1px solid #eee;
            display: flex;
            gap: 10px;
        }
        .input-area input {
            flex: 1;
            margin: 0;
        }
        .input-area button {
            width: auto;
            padding: 12px 24px;
            margin: 0;
        }
        .user-item {
            padding: 12px;
            margin: 5px 0;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .user-item:hover {
            background: rgba(147,112,219,0.1);
        }
        .user-item.active {
            background: var(--purple);
            color: white;
        }
        .search-box {
            margin-bottom: 15px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: var(--purple);
            font-size: 2em;
        }
        .link {
            color: var(--purple);
            cursor: pointer;
            text-align: center;
            margin-top: 15px;
        }
        .link:hover {
            text-decoration: underline;
        }
        .error {
            color: #e74c3c;
            font-size: 14px;
            margin-top: 5px;
            text-align: center;
        }
        .success {
            color: #27ae60;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container" id="app"></div>
    <script>
        let token = localStorage.getItem('token');
        let currentUser = null;
        let currentChat = null;
        let ws = null;
        let messagesCache = {};

        function render() {
            if (!token) renderAuth();
            else renderChat();
        }

        async function renderAuth() {
            const app = document.getElementById('app');
            app.innerHTML = `
                <div class="card">
                    <div class="logo">
                        <h1>Noris</h1>
                        <p style="color: var(--purple);">Secure messenger</p>
                    </div>
                    <div id="auth-form">
                        <input type="email" id="email" placeholder="Email" autocomplete="off">
                        <input type="text" id="nickname" placeholder="Nickname (latin, 3+ chars)">
                        <input type="password" id="password" placeholder="Password">
                        <button onclick="register()">Register</button>
                        <div class="link" onclick="showLogin()">Already have account? Login</div>
                    </div>
                    <div id="error-msg" class="error"></div>
                </div>
            `;
        }

        function showLogin() {
            const form = document.getElementById('auth-form');
            form.innerHTML = `
                <input type="email" id="email" placeholder="Email">
                <input type="password" id="password" placeholder="Password">
                <button onclick="login()">Login</button>
                <div class="link" onclick="renderAuth()">No account? Register</div>
            `;
        }

        async function register() {
            const email = document.getElementById('email').value;
            const nickname = document.getElementById('nickname').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error-msg');

            try {
                const res = await fetch('/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password, nickname})
                });
                const data = await res.text();
                if (res.ok) {
                    errorDiv.className = 'success';
                    errorDiv.innerText = 'Registration successful! Please login.';
                    setTimeout(() => showLogin(), 1500);
                } else {
                    errorDiv.innerText = data;
                }
            } catch(e) {
                errorDiv.innerText = 'Connection error';
            }
        }

        async function login() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error-msg');

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password})
                });
                const data = await res.json();
                if (res.ok) {
                    token = data.token;
                    currentUser = data;
                    localStorage.setItem('token', token);
                    localStorage.setItem('user', JSON.stringify(data));
                    render();
                } else {
                    errorDiv.innerText = data;
                }
            } catch(e) {
                errorDiv.innerText = 'Connection error';
            }
        }

        async function renderChat() {
            if (!currentUser) {
                const saved = localStorage.getItem('user');
                if (saved) currentUser = JSON.parse(saved);
            }
            const app = document.getElementById('app');
            app.innerHTML = `
                <div class="chat-container">
                    <div class="sidebar">
                        <h3 style="margin-bottom: 15px;">Noris</h3>
                        <div class="search-box">
                            <input type="text" id="search" placeholder="Search by nickname..." oninput="searchUsers()">
                        </div>
                        <div id="users-list"></div>
                    </div>
                    <div class="chat-area">
                        <div class="messages" id="messages"></div>
                        <div class="input-area">
                            <input type="text" id="message-input" placeholder="Message..." onkeypress="if(event.key==='Enter') sendMessage()">
                            <button onclick="sendMessage()">Send</button>
                        </div>
                    </div>
                </div>
            `;
            loadUsers();
            connectWebSocket();
        }

        async function searchUsers() {
            const query = document.getElementById('search').value;
            if (query.length < 2) {
                loadUsers();
                return;
            }
            const res = await fetch('/api/users/search?q=' + encodeURIComponent(query), {
                headers: {'Authorization': 'Bearer ' + token}
            });
            const users = await res.json();
            renderUsersList(users);
        }

        async function loadUsers() {
            const res = await fetch('/api/users/search?q=', {
                headers: {'Authorization': 'Bearer ' + token}
            });
            const users = await res.json();
            renderUsersList(users);
        }

        function renderUsersList(users) {
            const container = document.getElementById('users-list');
            if (!container) return;
            container.innerHTML = users.filter(u => u.id !== currentUser.user_id).map(u => `
                <div class="user-item ${currentChat === u.id ? 'active' : ''}" onclick="openChat(${u.id}, '${u.nickname}')">
                    <strong>${escapeHtml(u.nickname)}</strong>
                </div>
            `).join('');
        }

        async function openChat(userId, nickname) {
            currentChat = {id: userId, nickname};
            document.getElementById('messages').innerHTML = '<div style="text-align:center; color:#888;">Loading...</div>';
            const res = await fetch('/api/messages?with=' + userId, {
                headers: {'Authorization': 'Bearer ' + token}
            });
            const messages = await res.json();
            messagesCache[userId] = messages;
            renderMessages();
            document.querySelectorAll('.user-item').forEach(el => {
                el.classList.remove('active');
                if (el.innerText.includes(nickname)) el.classList.add('active');
            });
        }

        function renderMessages() {
            const container = document.getElementById('messages');
            if (!container || !currentChat) return;
            const messages = messagesCache[currentChat.id] || [];
            container.innerHTML = messages.map(msg => `
                <div class="message ${msg.from_id === currentUser.user_id ? 'sent' : 'received'}">
                    <div class="message-nick">${escapeHtml(msg.from_nick || (msg.from_id === currentUser.user_id ? 'You' : currentChat.nickname))}</div>
                    <div class="message-bubble">${escapeHtml(msg.content)}</div>
                </div>
            `).join('');
            container.scrollTop = container.scrollHeight;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function sendMessage() {
            const input = document.getElementById('message-input');
            const content = input.value.trim();
            if (!content || !currentChat) return;
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({to_id: currentChat.id, content: content}));
                input.value = '';
            }
        }

        function connectWebSocket() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + location.host + '/ws');
            ws.onopen = () => console.log('WebSocket connected');
            ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                if (!messagesCache[msg.from_id]) messagesCache[msg.from_id] = [];
                messagesCache[msg.from_id].push(msg);
                if (currentChat && currentChat.id === msg.from_id) renderMessages();
            };
            ws.onerror = (error) => console.log('WebSocket error:', error);
        }

        render();
    </script>
</body>
</html>`)
}

func main() {
    initDB()
    defer db.Close()

    r := http.NewServeMux()
    r.HandleFunc("/", serveFrontend)
    r.HandleFunc("/api/register", registerHandler)
    r.HandleFunc("/api/login", loginHandler)
    r.HandleFunc("/api/users/search", authMiddleware(searchUsersHandler))
    r.HandleFunc("/api/messages", authMiddleware(messagesHandler))
    r.HandleFunc("/ws", authMiddleware(wsHandler))

    log.Println("Noris started on http://localhost:8080")
    log.Println("Admin: alexey-worke@bk.ru / admin123")
    log.Fatal(http.ListenAndServe(":8080", r))
}
