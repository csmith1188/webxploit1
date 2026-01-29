# Exploit Excercise 1

## How to Setup/Run:

- Make sure you have nodeJS installed
- Run the following commands in the root directory
```bash
npm install
npm run init
npm run start
```
- Open `http://localhost:3000`

## Goals
Using nothing but the website as a normal user, achieve the following:
1. Use the website to do a XSS attack, running a javascript `alert()` on the client of any other user who uses the site.
2. Use the login form to perform an SQL Injection attack and log in as another user.
3. Use Insecure Direct Object Reference to access profile pages that aren't yours.

## Secure Vulnerabilities
- Edit the `server.js` to prevent others from achieving these attacks
