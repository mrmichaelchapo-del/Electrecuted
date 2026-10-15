
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("data.sqlite");

db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    blocks TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax"
  }
}));

app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Log in first." });
  }
  next();
}

app.get("/api/health", (req, res) => {
  res.json({ platform: "Electrecuted", online: true });
});

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (
    typeof username !== "string" ||
    !/^[a-zA-Z0-9_]{3,24}$/.test(username) ||
    typeof password !== "string" ||
    password.length < 8 ||
    password.length > 128
  ) {
    return res.status(400).json({ error: "Invalid username or password." });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    ).run(username, hash);

    req.session.userId = Number(result.lastInsertRowid);
    res.status(201).json({ username });
  } catch {
    res.status(409).json({ error: "Username already exists." });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Invalid credentials." });
  }

  req.session.userId = user.id;
  res.json({ username: user.username });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/projects", auth, (req, res) => {
  const projects = db.prepare(
    "SELECT id, title, blocks FROM projects WHERE user_id = ?"
  ).all(req.session.userId);

  res.json(projects.map(p => ({
    ...p,
    blocks: JSON.parse(p.blocks)
  })));
});

app.post("/api/projects", auth, (req, res) => {
  const { title, blocks } = req.body;

  if (
    typeof title !== "string" ||
    !Array.isArray(blocks) ||
    blocks.length > 200
  ) {
    return res.status(400).json({ error: "Invalid project." });
  }

  const result = db.prepare(
    "INSERT INTO projects (user_id, title, blocks) VALUES (?, ?, ?)"
  ).run(
    req.session.userId,
    title.slice(0, 80) || "Untitled project",
    JSON.stringify(blocks)
  );

  res.status(201).json({ id: result.lastInsertRowid });
});

app.delete("/api/projects/:id", auth, (req, res) => {
  const result = db.prepare(
    "DELETE FROM projects WHERE id = ? AND user_id = ?"
  ).run(Number(req.params.id), req.session.userId);

  if (!result.changes) {
    return res.status(404).json({ error: "Project not found." });
  }

  res.json({ success: true });
});

app.listen(3000, () => {
  console.log("Electrecuted: http://localhost:3000");
});
