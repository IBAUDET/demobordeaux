const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const secretKey = process.env.JWT_SECRET_KEY || "defaultsecretkey";

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "users_db",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connecté à MySQL");
});

const authMiddleware = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: "Accès non autorisé" });
  }
  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token invalide" });
  }
};

app.get("/user", authMiddleware, (req, res) => {
  db.query("SELECT * FROM users WHERE email = ?", [req.query.email], (err, result) => {
    if (err) throw err;
    res.json(result);
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }
    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (!match) {
        return res.status(401).json({ error: "Mot de passe incorrect" });
      }
      const token = jwt.sign({ id: user.id, role: user.role }, secretKey);
      res.json({ token });
    });
  });
});

app.listen(3000, () => console.log("Serveur sécurisé démarré sur le port 3000"));
