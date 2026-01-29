const express = require("express");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const db = new sqlite3.Database("app.db");

app.use(express.urlencoded({ extended: true }));

/**
 * Super-minimal “session”:
 * - Not secure; for demo only.
 * - Stores the logged-in username in a cookie-like hidden field workflow is avoided;
 *   instead we use a query param and reflect it back (also not secure).
 *
 * For teaching: you can later replace with real sessions and show improvements.
 */

// Home page
app.get("/", (req, res) => {
  res.send(`
    <h1>Vulnerable Express Lab</h1>
    <ul>
      <li><a href="/login">Login (SQLi vuln)</a></li>
      <li><a href="/comments">Comments (Stored XSS vuln)</a></li>
      <li><a href="/profile/1">Profile #1 (IDOR vuln)</a></li>
    </ul>
    <p><b>Warning:</b> This app is intentionally insecure. Run locally only.</p>
  `);
});

/**
 * -------------- VULN #1: SQL Injection --------------
 * Login builds SQL by string concatenation.
 */
app.get("/login", (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form method="POST" action="/login">
      <label>Username <input name="username" /></label><br/>
      <label>Password <input name="password" type="password" /></label><br/>
      <button type="submit">Login</button>
    </form>
    <p><a href="/">Home</a></p>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // INTENTIONALLY VULNERABLE: concatenating user input into SQL
  const sql =
    "SELECT id, username, email, is_admin FROM users " +
    `WHERE username = '${username}' AND password = '${password}'`;

  db.get(sql, (err, row) => {
    if (err) {
      res.status(500).send(`<pre>DB error:\n${String(err)}</pre><p><a href="/login">Back</a></p>`);
      return;
    }
    if (!row) {
      res.status(401).send(`<p>Login failed.</p><p><a href="/login">Back</a></p>`);
      return;
    }

    // Not real auth: just bounce them to a “dashboard” with the found user id
    res.send(`
      <h2>Welcome, ${row.username}</h2>
      <p>Email: ${row.email}</p>
      <p>Admin: ${row.is_admin ? "yes" : "no"}</p>
      <ul>
        <li><a href="/profile/${row.id}">Go to your profile</a></li>
        <li><a href="/comments?as=${encodeURIComponent(row.username)}">Go to comments as ${row.username}</a></li>
      </ul>
      <p><a href="/">Home</a></p>
    `);
  });
});

/**
 * -------------- VULN #2: Stored XSS --------------
 * Comments are stored in SQLite and rendered without escaping.
 * The rendering below is done via string interpolation, which is unsafe.
 */
app.get("/comments", (req, res) => {
  const asUser = typeof req.query.as === "string" ? req.query.as : "anonymous";

  db.all("SELECT id, author, body, created_at FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) {
      res.status(500).send(`<pre>DB error:\n${String(err)}</pre>`);
      return;
    }

    const list = rows
      .map(
        (c) => `
          <div style="border:1px solid #ccc; padding:8px; margin:8px 0;">
            <div><b>${c.author}</b> <small>${c.created_at}</small></div>
            <!-- INTENTIONALLY VULNERABLE: body inserted raw -->
            <div>${c.body}</div>
          </div>
        `
      )
      .join("");

    res.send(`
      <h2>Comments</h2>
      <p>Posting as: <b>${asUser}</b></p>

      <form method="POST" action="/comments">
        <input type="hidden" name="author" value="${asUser}" />
        <textarea name="body" rows="3" cols="60" placeholder="Write a comment..."></textarea><br/>
        <button type="submit">Post</button>
      </form>

      <hr/>
      ${list}

      <p><a href="/">Home</a></p>
    `);
  });
});

app.post("/comments", (req, res) => {
  const author = req.body.author || "anonymous";
  const body = req.body.body || "";

  // Intentionally not validating/sanitizing
  db.run(
    "INSERT INTO comments (author, body) VALUES (?, ?)",
    [author, body],
    (err) => {
      if (err) {
        res.status(500).send(`<pre>DB error:\n${String(err)}</pre>`);
        return;
      }
      res.redirect(`/comments?as=${encodeURIComponent(author)}`);
    }
  );
});

/**
 * -------------- VULN #3: IDOR (Insecure Direct Object Reference) --------------
 * Anyone can fetch any user's profile by changing the numeric id in the URL.
 * No authentication/authorization check.
 */
app.get("/profile/:id", (req, res) => {
  const id = req.params.id; // intentionally not validated

  db.get(
    "SELECT id, username, email, is_admin FROM users WHERE id = ?",
    [id],
    (err, row) => {
      if (err) {
        res.status(500).send(`<pre>DB error:\n${String(err)}</pre>`);
        return;
      }
      if (!row) {
        res.status(404).send(`<p>User not found.</p><p><a href="/">Home</a></p>`);
        return;
      }

      res.send(`
        <h2>Profile #${row.id}</h2>
        <p>Username: <b>${row.username}</b></p>
        <p>Email: ${row.email}</p>
        <p>Admin: ${row.is_admin ? "yes" : "no"}</p>

        <p style="color:#b00"><b>Note:</b> This endpoint is intentionally vulnerable to IDOR.</p>

        <p><a href="/">Home</a></p>
      `);
    }
  );
});

app.listen(3000, () => {
  console.log("Vulnerable lab server running on http://localhost:3000");
});
