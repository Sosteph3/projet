// index.js - Intranet RH demo 
// But : fournir une petite appli vulnérable (non destructive)
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Page d'accueil
app.get('/', (req, res) => {
  res.send(`
    <h1>Intranet RH - Demo</h1>
    <p>Bienvenue sur l'intranet de démonstration. Utilisez le formulaire pour rechercher un employé.</p>
    <form method="POST" action="/search">
      <input name="q" placeholder="Nom ou partie du nom" />
      <button>Search</button>
    </form>
    <p>Endpoints utiles : <code>/search</code> (POST), <code>/admin</code> (protected), <code>/flag</code> (secret)</p>
  `);
});

// Route "search" - vulnérable par conception (recherche naïve)
app.post('/search', (req, res) => {
  const q = (req.body.q || '').toLowerCase();
  // Lecture simple du fichier users.txt (pédagogique)
  const users = fs.readFileSync(path.join(__dirname, 'data', 'users.txt'), 'utf8')
                  .split(/\r?\n/).filter(Boolean);
  // Naïve filtering - pas d'échappement ni de limitation
  const hits = users.filter(u => u.toLowerCase().includes(q));
  res.send(`<h2>Résultats</h2><p>Query: <code>${escapeHtml(q)}</code></p><pre>${hits.join('\n') || 'Aucun'}</pre>`);
});

// Endpoint admin - simulation d'un accès protégé par token faible
app.get('/admin', (req, res) => {
  // token transmis en query ? exemple : /admin?token=admintoken
  const token = req.query.token || '';
  // token en clair dans le code (vulnérable volontairement)
  if (token === 'admintoken123') {
    res.send(`<h1>Console Admin</h1><p>Bienvenue, administrateur.</p>`);
  } else {
    res.status(401).send(`<h1>401 Unauthorized</h1><p>Token manquant ou invalide.</p>`);
  }
});

// Endpoint flag (preuve pédagogique)
app.get('/flag', (req, res) => {
  // on sert le fichier flag si demandé
  res.download(path.join(__dirname, 'public', 'flag.txt'), 'flag.txt', (err) => {
    if (err) res.status(500).send('Erreur lecture flag');
  });
});

// Simple helper to avoid XSS in displayed query (very minimal)
function escapeHtml(str) {
  return String(str).replace(/[&<>"'`=\/]/g, s => ({
    '&':'&amp;', '<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;'
  })[s]);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Intranet demo listening on port ${PORT}`));
