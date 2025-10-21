// index.js
// Dépendances : express, express-session, bcrypt, helmet
// npm i express express-session bcrypt helmet

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set('trust proxy', 1); // si derrière un reverse-proxy (ex: nginx) - permet cookie.secure correct

// --------- Session config ---------
const isProd = process.env.NODE_ENV === 'production';
if (!process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET non défini — utilisez une valeur forte en production.');
}

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'change_me_for_demo',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,     // true en production (HTTPS requis)
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 // 1 heure
  }
}));

// --------- Example users (in-memory) ---------
// Passwords hashed with bcrypt for demo:
// admin / adminpass
// user  / userpass
const users = [];
(async () => {
  const adminHash = await bcrypt.hash('adminpass', 10);
  const userHash = await bcrypt.hash('userpass', 10);
  users.push({ id: 1, username: 'admin', passwordHash: adminHash, admin: true });
  users.push({ id: 2, username: 'user', passwordHash: userHash, admin: false });
})();

async function findUser(username) {
  return users.find(u => u.username === username) || null;
}

// --------- Middleware ---------
function requireLogin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).send(`
      <h1>401 - Auth required</h1>
      <p>Vous devez être connecté pour accéder à cette page. <a href="/login">Se connecter</a></p>
    `);
  }
  next();
}

// Optionnel : rôle admin
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).send('Authentification requise');
  }
  const user = users.find(u => u.id === req.session.userId);
  if (!user || !user.admin) return res.status(403).send('Accès refusé');
  next();
}

// --------- Routes ---------
app.get('/', (req, res) => {
  res.send(`
    <h1>Intranet RH - Demo</h1>
    <p>Utilisateur connecté: ${req.session.userId ? users.find(u => u.id === req.session.userId).username : 'aucun'}</p>
    <p><a href="/login">/login</a> — <a href="/flag">/flag</a> (protégé)</p>
    <form method="POST" action="/logout" style="display:inline"><button>Logout</button></form>
  `);
});

// Login form
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <label>username: <input name="username" /></label><br/>
      <label>password: <input type="password" name="password" /></label><br/>
      <button>Se connecter</button>
    </form>
  `);
});

// Handle login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('username & password requis');

  const user = await findUser(username);
  if (!user) return res.status(401).send('Identifiants invalides');

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).send('Identifiants invalides');

  // Regenerate session id pour éviter fixation
  req.session.regenerate(err => {
    if (err) {
      console.error('session regenerate error', err);
      return res.status(500).send('Erreur session');
    }
    req.session.userId = user.id;
    req.session.admin = !!user.admin;
    res.send(`<p>Connecté en tant que <strong>${user.username}</strong>. <a href="/">Accueil</a></p>`);
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('sid');
    res.redirect('/');
  });
});

// Protected flag: nécessite connexion (ici je demande aussi rôle admin)
// Choisis requireLogin ou requireAdmin selon ton souhait (ici requireAdmin)
app.get('/flag', requireAdmin, (req, res) => {
  const flagPath = path.join(__dirname, 'public', 'flag.txt');
  if (!fs.existsSync(flagPath)) {
    return res.status(404).send('Flag introuvable (placez public/flag.txt).');
  }
  // Envoi sécurisé du fichier
  res.download(flagPath, 'flag.txt', (err) => {
    if (err) {
      console.error('Erreur download flag:', err);
      res.status(500).send('Erreur lecture flag');
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Intranet demo listening on port ${PORT}`);
  if (!isProd) console.log('Running in development mode (cookie.secure = false). Set NODE_ENV=production + HTTPS in production.');
});
