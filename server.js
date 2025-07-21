// server.js

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const SESSION_SECRET = 'bloxstudios_secret_key_12345';
const siteName = 'Blox Studios';

// Load users and messages from JSON file or create default data
let data = {
  users: {
    admin: {
      passwordHash: null,
      role: 'admin',
      banned: false,
      warned: false,
      profile: { name: 'Administrator', email: 'admin@blox.com' },
      sessions: []
    },
    staff1: {
      passwordHash: null,
      role: 'staff',
      banned: false,
      warned: false,
      profile: { name: 'Staff One', email: '' },
      sessions: []
    },
    staff2: {
      passwordHash: null,
      role: 'staff',
      banned: false,
      warned: false,
      profile: { name: 'Staff Two', email: '' },
      sessions: []
    }
  },
  secretInfo: "Welcome to Blox Studios' secret area.",
  messages: [] // { from, to, text, timestamp }
};

function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

try {
  if (fs.existsSync(DATA_FILE)) {
    const loaded = JSON.parse(fs.readFileSync(DATA_FILE));
    data = loaded;
  } else {
    // For first time, hash admin's default password
    bcrypt.hash('adminpass', 10).then(hash => {
      data.users.admin.passwordHash = hash;
      saveData();
    });
  }
} catch (e) {
  console.error('Error loading data:', e);
}

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Serve static for client-side socket.io scripts
app.use('/socket.io', express.static(path.join(__dirname, 'node_modules/socket.io/client-dist')));

function isLoggedIn(req) {
  return req.session.user && data.users[req.session.user] && !data.users[req.session.user].banned;
}

function isAdmin(req) {
  return isLoggedIn(req) && data.users[req.session.user].role === 'admin';
}

function isStaffOrAdmin(req) {
  return isLoggedIn(req) && (data.users[req.session.user].role === 'staff' || data.users[req.session.user].role === 'admin');
}

function authRequired(req, res, next) {
  if (isLoggedIn(req)) return next();
  res.redirect('/login');
}

function adminRequired(req, res, next) {
  if (isAdmin(req)) return next();
  res.status(403).send('Admin access required.');
}

function staffOrAdminRequired(req, res, next) {
  if (isStaffOrAdmin(req)) return next();
  res.status(403).send('Staff or Admin access required.');
}

// Track sessions
function trackSession(username, sessionID) {
  if (!data.users[username].sessions.includes(sessionID)) {
    data.users[username].sessions.push(sessionID);
    saveData();
  }
}

function untrackSession(username, sessionID) {
  data.users[username].sessions = data.users[username].sessions.filter(sid => sid !== sessionID);
  saveData();
}

// ---- Routes ----

// Home redirect
app.get('/', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/secret');
  res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
  const error = req.query.error || '';
  res.send(`
  <!DOCTYPE html>
  <html lang="en"><head><meta charset="UTF-8" />
  <title>${siteName} - Login</title>
  <style>
    body { font-family: Arial; background: #f7f7f7; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
    .box { background:#fff; padding:20px; border-radius:8px; box-shadow:0 0 10px #aaa; width:300px; }
    input { width:100%; padding:10px; margin:10px 0; border-radius:5px; border:1px solid #ccc; }
    button { width:100%; padding:10px; background:#0078d7; color:#fff; border:none; border-radius:5px; cursor:pointer; }
    button:hover { background:#005fa3; }
    p.error { color:red; font-weight:bold; text-align:center; }
  </style>
  </head><body>
    <div class="box">
      <h2>${siteName} Login</h2>
      ${error ? `<p class="error">${error}</p>` : ''}
      <form method="POST" action="/login">
        <input name="username" placeholder="Username" required autofocus />
        <input type="password" name="password" placeholder="Password or New Password" required />
        <button type="submit">Log In</button>
      </form>
    </div>
  </body></html>`);
});

// Login handler
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = data.users[username];
  if (!user) {
    return res.redirect('/login?error=Invalid username or password');
  }
  if (user.banned) {
    return res.send(`<h1>${siteName} - Access Denied</h1><p>Your account is banned. Contact admin.</p>`);
  }

  if (!user.passwordHash) {
    // First time password set
    if (password.length < 4) {
      return res.redirect('/login?error=Password too short');
    }
    const hash = await bcrypt.hash(password, 10);
    user.passwordHash = hash;
    req.session.user = username;
    trackSession(username, req.sessionID);
    saveData();
    return res.redirect('/secret');
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.redirect('/login?error=Invalid username or password');
  }

  req.session.user = username;
  trackSession(username, req.sessionID);
  saveData();
  res.redirect('/secret');
});

// Logout
app.get('/logout', (req, res) => {
  if (req.session.user) untrackSession(req.session.user, req.sessionID);
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Secret info - staff+admin only
app.get('/secret', staffOrAdminRequired, (req, res) => {
  const user = data.users[req.session.user];
  res.send(`
  <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
  <title>${siteName} - Secret Info</title>
  <style>
    body { font-family: Arial; margin: 40px; background: #eef2f7; }
    a { color: #0078d7; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .warn { color: red; font-weight: bold; }
  </style>
  </head><body>
  <h1>${siteName} Secret Info</h1>
  <p>Welcome, <b>${req.session.user}</b> (${user.role})!</p>
  ${user.warned ? '<p class="warn">⚠️ You have a warning from admin.</p>' : ''}
  <p>${data.secretInfo}</p>
  ${user.role === 'admin' ? `<p><a href="/admin">Admin Panel</a></p>` : ''}
  <p><a href="/profile">Edit Profile</a></p>
  <p><a href="/chat">Chat (DM)</a></p>
  <p><a href="/logout">Logout</a></p>
  </body></html>
  `);
});

// Profile edit page
app.get('/profile', authRequired, (req, res) => {
  const user = data.users[req.session.user];
  res.send(`
  <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
  <title>${siteName} - Edit Profile</title>
  <style>
    body { font-family: Arial; margin: 40px; background: #f9f9f9; }
    input, textarea { width: 300px; padding: 8px; margin: 5px 0; border-radius: 5px; border: 1px solid #ccc; }
    button { padding: 10px 20px; background: #0078d7; color: white; border: none; border-radius: 5px; cursor: pointer; }
    button:hover { background: #005fa3; }
    label { display: block; margin-top: 10px; }
    a { color: #0078d7; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
  </head><body>
  <h1>Edit Profile (${req.session.user})</h1>
  <form method="POST" action="/profile">
    <label>Name:<br/><input name="name" value="${user.profile.name || ''}" required></label>
    <label>Email:<br/><input type="email" name="email" value="${user.profile.email || ''}"></label>
    <label>New Password (leave blank to keep current):<br/><input type="password" name="password" minlength="4"></label>
    <button type="submit">Save</button>
  </form>
  <p><a href="/secret">Back to Secret Info</a></p>
  </body></html>
  `);
});

// Profile edit handler
app.post('/profile', authRequired, async (req, res) => {
  const { name, email, password } = req.body;
  const user = data.users[req.session.user];
  user.profile.name = name;
  user.profile.email = email;
  if (password && password.length >= 4) {
    user.passwordHash = await bcrypt.hash(password, 10);
  }
  saveData();
  res.redirect('/profile');
});

// Admin panel page
app.get('/admin', adminRequired, (req, res) => {
  let usersList = '';
  for (const [uname, u] of Object.entries(data.users)) {
    usersList += `
      <li>
        <b>${uname}</b> (${u.role}) - Banned: ${u.banned ? 'Yes' : 'No'} - Warned: ${u.warned ? 'Yes' : 'No'}<br/>
        <form style="display:inline" method="POST" action="/admin/ban">
          <input type="hidden" name="username" value="${uname}"/>
          <button type="submit">${u.banned ? 'Unban' : 'Ban'}</button>
        </form>
        <form style="display:inline" method="POST" action="/admin/warn">
          <input type="hidden" name="username" value="${uname}"/>
          <button type="submit">${u.warned ? 'Remove Warning' : 'Warn'}</button>
        </form>
        <form style="display:inline" method="POST" action="/admin/delete">
          <input type="hidden" name="username" value="${uname}"/>
          <button type="submit" ${u.role === 'admin' ? 'disabled' : ''}>Delete</button>
        </form>
        <form style="display:inline" method="POST" action="/admin/promote">
          <input type="hidden" name="username" value="${uname}"/>
          <button type="submit" ${u.role === 'admin' ? 'disabled' : ''}>Promote to Admin</button>
        </form>
      </li>
      <hr/>
    `;
  }
  res.send(`
  <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
  <title>${siteName} - Admin Panel</title>
  <style>
    body { font-family: Arial; margin: 40px; background: #f0f4f8; }
    ul { list-style:none; padding:0; }
    li { margin-bottom: 15px; }
    button { margin-left: 5px; }
    form { display: inline; }
    a { color: #0078d7; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
  </head><body>
    <h1>Admin Panel</h1>
    <h3>Secret Info</h3>
    <form method="POST" action="/admin/editSecret">
      <textarea name="secret" rows="4" cols="60" required>${data.secretInfo}</textarea><br/>
      <button type="submit">Update Secret Info</button>
    </form>
    <h3>User Management</h3>
    <ul>${usersList}</ul>
    <p><a href="/secret">Back to Secret Info</a></p>
    <p><a href="/logout">Logout</a></p>
  </body></html>
  `);
});

// Admin edit secret info
app.post('/admin/editSecret', adminRequired, (req, res) => {
  const secret = req.body.secret;
  if (secret && secret.trim().length > 0) {
    data.secretInfo = secret.trim();
    saveData();
  }
  res.redirect('/admin');
});

// Admin ban user
app.post('/admin/ban', adminRequired, (req, res) => {
  const username = req.body.username;
  if (username !== 'admin' && data.users[username]) {
    data.users[username].banned = !data.users[username].banned;
    saveData();
  }
  res.redirect('/admin');
});

// Admin warn user
app.post('/admin/warn', adminRequired, (req, res) => {
  const username = req.body.username;
  if (username !== 'admin' && data.users[username]) {
    data.users[username].warned = !data.users[username].warned;
    saveData();
  }
  res.redirect('/admin');
});

// Admin delete user
app.post('/admin/delete', adminRequired, (req, res) => {
  const username = req.body.username;
  if (username !== 'admin' && data.users[username]) {
    delete data.users[username];
    saveData();
  }
  res.redirect('/admin');
});

// Admin promote user to admin
app.post('/admin/promote', adminRequired, (req, res) => {
  const username = req.body.username;
  if (username !== 'admin' && data.users[username]) {
    data.users[username].role = 'admin';
    saveData();
  }
  res.redirect('/admin');
});

// --------------------
// Real-time Chat (DM) with Socket.io

const onlineUsers = new Map(); // sessionID -> username

io.use((socket, next) => {
  const sessionID = socket.handshake.auth.sessionID;
  if (!sessionID) return next(new Error("No session ID"));
  // find username by sessionID
  let userFound = null;
  for (const [username, user] of Object.entries(data.users)) {
    if (user.sessions.includes(sessionID)) {
      userFound = username;
      break;
    }
  }
  if (!userFound) return next(new Error("Unauthorized"));
  socket.username = userFound;
  next();
});

io.on('connection', socket => {
  onlineUsers.set(socket.id, socket.username);

  // Send online users list to client
  io.emit('onlineUsers', [...onlineUsers.values()]);

  // Send last 50 messages to client
  socket.emit('chatHistory', data.messages.slice(-50));

  socket.on('sendMessage', ({ to, text }) => {
    if (!text || typeof text !== 'string' || text.trim() === '') return;
    if (!to || !data.users[to]) return;

    // Only staff and admin can chat
    const fromUser = data.users[socket.username];
    if (!fromUser || (fromUser.role !== 'staff' && fromUser.role !== 'admin')) return;

    const msg = {
      from: socket.username,
      to,
      text: text.trim(),
      timestamp: Date.now()
    };
    data.messages.push(msg);
    saveData();

    // Emit to sender and receiver only
    for (const [id, username] of onlineUsers.entries()) {
      if (username === to || username === socket.username) {
        io.to(id).emit('newMessage', msg);
      }
    }
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.id);
    io.emit('onlineUsers', [...onlineUsers.values()]);
  });
});

// Chat page
app.get('/chat', staffOrAdminRequired, (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="en"><head><meta charset="UTF-8" />
  <title>${siteName} - Chat</title>
  <style>
    body { font-family: Arial; margin: 0; background: #f0f2f5; }
    #chat { max-width: 800px; margin: 40px auto; background: white; border-radius: 8px; box-shadow: 0 0 10px #ccc; display: flex; flex-direction: column; height: 80vh; }
    #online { border-bottom: 1px solid #ddd; padding: 10px; background: #0078d7; color: white; font-weight: bold; }
    #messages { flex-grow: 1; padding: 10px; overflow-y: auto; border-bottom: 1px solid #ddd; }
    #inputForm { display: flex; padding: 10px; }
    select, input[type="text"] { padding: 10px; margin-right: 10px; font-size: 16px; border-radius: 5px; border: 1px solid #ccc; }
    button { padding: 10px 20px; background: #0078d7; color: white; border: none; border-radius: 5px; cursor: pointer; }
    button:hover { background: #005fa3; }
    .message { margin-bottom: 10px; }
    .message b { font-weight: bold; }
    .timestamp { font-size: 0.8em; color: #666; }
    a { color: #0078d7; text-decoration: none; margin: 10px; display: inline-block; }
    a:hover { text-decoration: underline; }
  </style>
  </head><body>
    <div id="chat">
      <div id="online">Online Users: <span id="onlineUsers"></span></div>
      <div id="messages"></div>
      <form id="inputForm">
        <select id="userSelect" required></select>
        <input type="text" id="messageInput" placeholder="Type message" autocomplete="off" required />
        <button type="submit">Send</button>
      </form>
    </div>
    <p style="text-align:center;"><a href="/secret">Back to Secret Info</a></p>

    <script src="/socket.io/socket.io.js"></script>
    <script>
      const socket = io({
        auth: { sessionID: "${req.sessionID}" }
      });

      const onlineUsersElem = document.getElementById('onlineUsers');
      const userSelect = document.getElementById('userSelect');
      const messagesDiv = document.getElementById('messages');
      const inputForm = document.getElementById('inputForm');
      const messageInput = document.getElementById('messageInput');

      let onlineUsers = [];

      function renderOnlineUsers(users) {
        onlineUsers = users.filter(u => u !== "${req.session.user}");
        onlineUsersElem.textContent = onlineUsers.join(', ') || 'No one online';
        userSelect.innerHTML = '';
        if(onlineUsers.length === 0) {
          const option = document.createElement('option');
          option.text = 'No one online';
          option.value = '';
          userSelect.add(option);
          userSelect.disabled = true;
        } else {
          userSelect.disabled = false;
          onlineUsers.forEach(u => {
            const option = document.createElement('option');
            option.text = u;
            option.value = u;
            userSelect.add(option);
          });
        }
      }

      socket.on('onlineUsers', renderOnlineUsers);

      function addMessage(msg) {
        const div = document.createElement('div');
        div.className = 'message';
        const date = new Date(msg.timestamp);
        div.innerHTML = '<b>' + msg.from + '</b> to <b>' + msg.to + '</b>: ' + 
          escapeHTML(msg.text) + ' <span class="timestamp">(' + date.toLocaleTimeString() + ')</span>';
        messagesDiv.appendChild(div);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
      }

      socket.on('chatHistory', history => {
        messagesDiv.innerHTML = '';
        history.forEach(addMessage);
      });

      socket.on('newMessage', addMessage);

      inputForm.addEventListener('submit', e => {
        e.preventDefault();
        const to = userSelect.value;
        const text = messageInput.value.trim();
        if(!to || !text) return;
        socket.emit('sendMessage', { to, text });
        messageInput.value = '';
      });

      function escapeHTML(str) {
        return str.replace(/[&<>"']/g, function(m) {
          return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];
        });
      }
    </script>
  </body></html>
  `);
});

// Start server
server.listen(PORT, () => {
  console.log(`${siteName} running on http://localhost:${PORT}`);
});
