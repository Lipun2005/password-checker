# BreachGuard Café

BreachGuard Café is a local password breach checker. It tells you whether a password appears in known breach data, and it can compose memorable variations that have no match in that data.

The password is hashed in the browser with SHA-1. Only the first 5 characters of the hash are sent to the Have I Been Pwned Pwned Passwords range API. The full password and the full hash are never sent.

A result of **no breach match** means the password was not found in the corpus this app checks. It does not guarantee that the password is safe, strong, or unique.

## Windows 11 setup

1. Install the current Node.js LTS, version 18 or newer, from [https://nodejs.org](https://nodejs.org). The installer includes npm. Accept the default options.
2. Open this folder in File Explorer. Click the address bar, type `powershell`, and press Enter. Windows Terminal opens in the project folder.
3. Confirm the install:

   ```powershell
   node -v
   npm -v
   ```

   `node -v` should print `v18` or higher.

4. Install the only dependency, Express:

   ```powershell
   npm install
   ```

   If PowerShell reports that running scripts is disabled, allow local scripts for your user and install again:

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
   npm install
   ```

5. Start the app:

   ```powershell
   npm start
   ```

6. Open [http://localhost:3000](http://localhost:3000) in your browser.

The server listens on this computer only (`127.0.0.1` and `::1`). Stop it with Ctrl+C in the same terminal.

The breach lookup needs an internet connection. The range API does not need an API key.

If port 3000 is already in use:

```powershell
$env:PORT=3001; npm start
```

Then open [http://localhost:3001](http://localhost:3001).

## How a check works

1. The browser encodes the password as UTF-8 and hashes it with SHA-1.
2. The browser sends the first 5 hexadecimal characters to this app's local server, `POST /api/range`.
3. The server requests `https://api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true`.
4. The server returns the matching hash suffixes and their counts. Padding rows with a count of 0 are dropped.
5. The browser compares the other 35 characters locally.

The generator uses `crypto.getRandomValues` to vary letter case, symbol placement, and a short random ending. It keeps your word and your digits intact. Every candidate is checked with the same range lookup. Candidates with a breach match are discarded and are not shown.

## What is not stored

This app does not write passwords, hashes, or personal information to disk, `localStorage`, `sessionStorage`, or the server log. The local server only receives hash prefixes. Refreshing or closing the page drops what you typed. Use **Clear** and **Remove generated passwords** when you are done.

## Project layout

```
BreachGuard_Cafe/
  backend/server.js    Express server and range-API proxy
  frontend/index.html  Page structure
  frontend/styles.css  Coffee, cream, brown, and sage interface
  frontend/app.js      Hashing, checks, and generator
  package.json         Start script and dependency
```

## Privacy note

Check passwords you are allowed to test. Breach data is provided by [Have I Been Pwned](https://haveibeenpwned.com/Passwords), an independent service by Troy Hunt.
