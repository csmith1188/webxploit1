const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("app.db");

db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL;");

  db.run(`DROP TABLE IF EXISTS users;`);
  db.run(`DROP TABLE IF EXISTS comments;`);

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0
    );
  `);

  db.run(`
    CREATE TABLE comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Intentionally weak: plaintext passwords for the lesson
  const insertUser = db.prepare(
    `INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)`
  );

  insertUser.run("admin", "adminpass", "admin@example.com", 1);
  insertUser.run("alice", "alicepass", "alice@example.com", 0);
  insertUser.run("bob", "bobpass", "bob@example.com", 0);
  insertUser.finalize();

  const insertComment = db.prepare(
    `INSERT INTO comments (author, body) VALUES (?, ?)`
  );

  insertComment.run("alice", "Hello world!");
  insertComment.run("bob", "Nice to meet you.");
  insertComment.finalize();

  console.log("Initialized app.db with sample users/comments.");
});

db.close();
