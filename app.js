import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcrypt";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import fs from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: "your_super_secret_session_key",
  resave: false,
  saveUninitialized: false
}));

// --- USER PRIVILEGE CONTROL VIA user.conf ---
let addJobUsers = new Set();
function loadAddJobUsers() {
  try {
    const lines = fs.readFileSync(path.join(__dirname, "user.conf"), "utf8").split(/\r?\n/);
    addJobUsers = new Set(
      lines
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#"))
    );
  } catch (e) {
    addJobUsers = new Set();
  }
}
loadAddJobUsers();
setInterval(loadAddJobUsers, 60000);

// --- REGISTRATION LIMIT VIA urc.conf ---
let maxUserCount = 10;
function loadMaxUserCount() {
  try {
    const lines = fs.readFileSync(path.join(__dirname, "urc.conf"), "utf8").split(/\r?\n/);
    for (const line of lines) {
      if (line.trim().startsWith("max_users")) {
        const val = parseInt(line.split("=")[1]);
        if (!isNaN(val)) maxUserCount = val;
      }
    }
  } catch (e) {
    maxUserCount = 10; // fallback default
  }
}
loadMaxUserCount();
setInterval(loadMaxUserCount, 60000);

function canAddJob(username) {
  return addJobUsers.has(username);
}

function isUserManager(username) {
  return addJobUsers.has(username);
}

// SQLite DB
let db;
async function initDB() {
  db = await open({
    filename: path.join(__dirname, "hrs.db"),
    driver: sqlite3.Database
  });
  await db.exec(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customerName TEXT NOT NULL,
    phoneNumber TEXT NOT NULL,
    deviceName TEXT NOT NULL,
    symptom TEXT NOT NULL,
    technicianNotes TEXT,
    date TEXT NOT NULL
  )`);
  await db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    totp_secret TEXT
  )`);
}
initDB();

// Middleware: restrict routes to logged-in users (except login/register)
function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect("/login");
}

// Registration (one-time for admin/user)
app.get("/register", async (req, res) => {
  const userCount = (await db.all("SELECT COUNT(*) as c FROM users"))[0].c;
  if (userCount >= maxUserCount) return res.render("register", { error: "User registration limit reached." });
  res.render("register", { error: null });
});
app.post("/register", async (req, res) => {
  const userCount = (await db.all("SELECT COUNT(*) as c FROM users"))[0].c;
  if (userCount >= maxUserCount) return res.render("register", { error: "User registration limit reached." });
  const { username, password } = req.body;
  if (!username || !password) return res.render("register", { error: "All fields required" });
  const hash = await bcrypt.hash(password, 10);
  try {
    await db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash]);
    res.redirect("/login");
  } catch {
    res.render("register", { error: "Username already exists" });
  }
});

// Login
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
  if (!user) return res.render("login", { error: "Invalid credentials" });
  if (!(await bcrypt.compare(password, user.password))) return res.render("login", { error: "Invalid credentials" });

  req.session.username = username;

  if (!user.totp_secret) {
    const secret = speakeasy.generateSecret({ name: "HRSApp (" + user.username + ")" });
    await db.run("UPDATE users SET totp_secret = ? WHERE id = ?", [secret.base32, user.id]);
    const otpauth = speakeasy.otpauthURL({ secret: secret.ascii, label: user.username, issuer: "HRSApp" });
    const qr = await QRCode.toDataURL(otpauth);
    req.session.tmpUserId = user.id;
    return res.render("2fa-setup", { qr, secret: secret.base32, error: null, returnToSettings: false });
  } else {
    req.session.tmpUserId = user.id;
    return res.redirect("/2fa");
  }
});

// 2FA setup page (show QR, user enters TOTP)
app.get("/2fa-setup", (req, res) => {
  res.render("2fa-setup", { qr: null, secret: null, error: null, returnToSettings: false });
});
app.post("/2fa-setup", async (req, res) => {
  const { token } = req.body;
  const userId = req.session.tmpUserId;
  const returnToSettings = req.body.returnToSettings === "true";
  if (!userId) return res.redirect("/login");
  const user = await db.get("SELECT * FROM users WHERE id = ?", [userId]);
  if (!user) return res.redirect("/login");
  const verified = speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: "base32",
    token: token,
    window: 1
  });
  if (verified) {
    req.session.userId = user.id;
    req.session.username = user.username;
    delete req.session.tmpUserId;
    if (returnToSettings) return res.redirect("/user/settings");
    return res.redirect("/");
  } else {
    const otpauth = speakeasy.otpauthURL({ secret: speakeasy.base32.decode(user.totp_secret), label: user.username, issuer: "HRSApp" });
    const qr = await QRCode.toDataURL(otpauth);
    return res.render("2fa-setup", { qr, secret: user.totp_secret, error: "Invalid TOTP, try again.", returnToSettings });
  }
});

// 2FA verify login
app.get("/2fa", (req, res) => {
  res.render("2fa", { error: null });
});
app.post("/2fa", async (req, res) => {
  const { token } = req.body;
  const userId = req.session.tmpUserId;
  if (!userId) return res.redirect("/login");
  const user = await db.get("SELECT * FROM users WHERE id = ?", [userId]);
  if (!user) return res.redirect("/login");
  const verified = speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: "base32",
    token: token,
    window: 1
  });
  if (verified) {
    req.session.userId = user.id;
    req.session.username = user.username;
    delete req.session.tmpUserId;
    return res.redirect("/");
  } else {
    return res.render("2fa", { error: "Invalid TOTP, try again." });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// --- User Settings Routes ---
app.get("/user/settings", requireAuth, async (req, res) => {
  const user = await db.get("SELECT * FROM users WHERE id = ?", [req.session.userId]);
  res.render("user-settings", { user, message: null, error: null });
});

app.post("/user/settings", requireAuth, async (req, res) => {
  const action = req.body.action;
  const user = await db.get("SELECT * FROM users WHERE id = ?", [req.session.userId]);
  if (!user) return res.redirect("/login");

  if (action === "disable2fa") {
    await db.run("UPDATE users SET totp_secret=NULL WHERE id=?", [user.id]);
    return res.render("user-settings", { user: { ...user, totp_secret: null }, message: "2FA disabled.", error: null });
  }
  if (action === "enable2fa" || action === "regen2fa") {
    const secret = speakeasy.generateSecret({ name: "HRSApp (" + user.username + ")" });
    await db.run("UPDATE users SET totp_secret=? WHERE id=?", [secret.base32, user.id]);
    const otpauth = speakeasy.otpauthURL({ secret: secret.ascii, label: user.username, issuer: "HRSApp" });
    const qr = await QRCode.toDataURL(otpauth);
    req.session.tmpUserId = user.id;
    return res.render("2fa-setup", { qr, secret: secret.base32, error: null, returnToSettings: true });
  }
  res.render("user-settings", { user, message: null, error: "Unknown action." });
});

// --- USER MANAGEMENT MENU ---
app.get("/user/manage", requireAuth, async (req, res) => {
  if (!isUserManager(req.session.username)) return res.status(403).send("Forbidden");
  const users = await db.all("SELECT id, username, totp_secret FROM users");
  res.render("user-manage", { users, error: null, message: null, sessionUsername: req.session.username, maxUserCount });
});

app.post("/user/manage", requireAuth, async (req, res) => {
  if (!isUserManager(req.session.username)) return res.status(403).send("Forbidden");
  const { action, userid, username, password } = req.body;
  let error = null, message = null;

  if (action === "delete") {
    if (username === req.session.username) {
      error = "Cannot delete yourself.";
    } else {
      await db.run("DELETE FROM users WHERE id = ?", [userid]);
      message = "User deleted.";
    }
  }
  if (action === "add") {
    const userCount = (await db.all("SELECT COUNT(*) as c FROM users"))[0].c;
    if (userCount >= maxUserCount) {
      error = "User registration limit reached.";
    } else if (username && password) {
      try {
        const hash = await bcrypt.hash(password, 10);
        await db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash]);
        message = "User added.";
      } catch {
        error = "Username already exists.";
      }
    } else {
      error = "Username and password required.";
    }
  }
  if (action === "change_pw" && userid && password) {
    await db.run("UPDATE users SET password=? WHERE id=?", [await bcrypt.hash(password,10), userid]);
    message = "Password updated.";
  }
  // --- 2FA enable/disable management ---
  if (action === "disable2fa" && userid) {
    await db.run("UPDATE users SET totp_secret=NULL WHERE id=?", [userid]);
    message = "2FA disabled for user.";
  }
  if (action === "enable2fa" && userid) {
    const user = await db.get("SELECT * FROM users WHERE id=?", [userid]);
    const secret = speakeasy.generateSecret({ name: "HRSApp (" + user.username + ")" });
    await db.run("UPDATE users SET totp_secret=? WHERE id=?", [secret.base32, userid]);
    message = `2FA enabled for user. Secret: ${secret.base32}`;
    // Optionally show QR for admin to send to user, or send secret in message.
  }
  const users = await db.all("SELECT id, username, totp_secret FROM users");
  res.render("user-manage", { users, error, message, sessionUsername: req.session.username, maxUserCount });
});

// --- All below routes require login ---
app.use(requireAuth);

async function getPagedJobs({ page = 1, searchQuery = '', searchBy = ['jobid','name','phone'] }) {
  const PAGE_SIZE = 5;
  let where = [];
  let params = [];
  let totalQuery = "SELECT COUNT(*) AS count FROM jobs";
  let jobsQuery = "SELECT * FROM jobs";
  let order = "ORDER BY id DESC";
  if (searchQuery && searchBy.length > 0) {
    if (searchBy.includes('jobid') && /^\d+$/.test(searchQuery)) {
      where.push("id = ?");
      params.push(parseInt(searchQuery));
    }
    if (searchBy.includes('name')) {
      where.push("customerName LIKE ?");
      params.push('%' + searchQuery + '%');
    }
    if (searchBy.includes('phone')) {
      where.push("phoneNumber LIKE ?");
      params.push('%' + searchQuery + '%');
    }
  }
  if (where.length > 0) {
    jobsQuery += " WHERE " + where.join(" OR ");
    totalQuery += " WHERE " + where.join(" OR ");
  }
  jobsQuery += ` ${order} LIMIT ${PAGE_SIZE} OFFSET ${(page-1)*PAGE_SIZE}`;
  const jobs = await db.all(jobsQuery, params);
  const totalRes = await db.get(totalQuery, params);
  const total = totalRes ? totalRes.count : 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return { jobs, total, totalPages, page };
}

app.get("/", async (req, res) => {
  const { jobs, totalPages } = await getPagedJobs({ page: 1 });
  res.render("jobs", {
    jobs,
    searchQuery: '',
    searchBy: ['jobid','name','phone'],
    page: 1,
    totalPages,
    canAddJob: canAddJob(req.session.username)
  });
});
app.get("/jobs", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const { jobs, totalPages } = await getPagedJobs({ page });
  res.render("jobs", {
    jobs,
    searchQuery: '',
    searchBy: ['jobid','name','phone'],
    page,
    totalPages,
    canAddJob: canAddJob(req.session.username)
  });
});
app.post("/jobs/search", async (req, res) => {
  const { search } = req.body;
  let searchBy = req.body.searchBy;
  let searchQuery = search ? search.trim() : '';
  let page = parseInt(req.body.page) || 1;
  if (!searchBy) searchBy = [];
  if (!Array.isArray(searchBy)) searchBy = [searchBy];

  const { jobs, totalPages } = await getPagedJobs({ page, searchQuery, searchBy });
  res.render("jobs", {
    jobs,
    searchQuery,
    searchBy,
    page,
    totalPages,
    canAddJob: canAddJob(req.session.username)
  });
});
app.get("/jobs/search", async (req, res) => {
  const searchQuery = req.query.search ? req.query.search.trim() : '';
  let searchBy = req.query.searchBy;
  let page = parseInt(req.query.page) || 1;
  if (!searchBy) searchBy = [];
  if (!Array.isArray(searchBy)) searchBy = [searchBy];
  const { jobs, totalPages } = await getPagedJobs({ page, searchQuery, searchBy });
  res.render("jobs", {
    jobs,
    searchQuery,
    searchBy,
    page,
    totalPages,
    canAddJob: canAddJob(req.session.username)
  });
});

// Block non-privileged users from submitting jobs
app.post("/submit", async (req, res) => {
  if (!canAddJob(req.session.username)) {
    return res.status(403).send("You do not have permission to add jobs.");
  }
  const { customerName, phoneNumber, deviceName, symptom, technicianNotes } = req.body;
  const date = new Date().toLocaleString();
  await db.run(
    `INSERT INTO jobs (customerName, phoneNumber, deviceName, symptom, technicianNotes, date)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [customerName, phoneNumber, deviceName, symptom, technicianNotes, date]
  );
  const { jobs, totalPages } = await getPagedJobs({ page: 1 });
  res.render("jobs", {
    jobs,
    searchQuery: '',
    searchBy: ['jobid','name','phone'],
    page: 1,
    totalPages,
    canAddJob: true
  });
});

app.get("/receipt/:id", async (req, res) => {
  const job = await db.get(`SELECT * FROM jobs WHERE id = ?`, [req.params.id]);
  if (!job) return res.status(404).send("Job not found");
  res.render("receipt", { job });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});