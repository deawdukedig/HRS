import express from "express";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import sqlite3 from "sqlite3";
import { open } from "sqlite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// Open SQLite DB
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
}
initDB();

// Helper: get paged jobs, optionally filtered
async function getPagedJobs({ page = 1, searchQuery = '', searchBy = ['jobid','name','phone'] }) {
  const PAGE_SIZE = 5; // Show 5 entries per page
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

// Main page: add + search + list (page 1)
app.get("/", async (req, res) => {
  const { jobs, totalPages } = await getPagedJobs({ page: 1 });
  res.render("jobs", { jobs, searchQuery: '', searchBy: ['jobid','name','phone'], page: 1, totalPages });
});

// Alias for jobs page, supports ?page=N
app.get("/jobs", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const { jobs, totalPages } = await getPagedJobs({ page });
  res.render("jobs", { jobs, searchQuery: '', searchBy: ['jobid','name','phone'], page, totalPages });
});

// Submit new repair
app.post("/submit", async (req, res) => {
  const { customerName, phoneNumber, deviceName, symptom, technicianNotes } = req.body;
  const date = new Date().toLocaleString();
  await db.run(
    `INSERT INTO jobs (customerName, phoneNumber, deviceName, symptom, technicianNotes, date)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [customerName, phoneNumber, deviceName, symptom, technicianNotes, date]
  );
  // After adding, show jobs page page 1
  const { jobs, totalPages } = await getPagedJobs({ page: 1 });
  res.render("jobs", { jobs, searchQuery: '', searchBy: ['jobid','name','phone'], page: 1, totalPages });
});

// Search jobs with checkboxes, supports paging
app.post("/jobs/search", async (req, res) => {
  const { search } = req.body;
  let searchBy = req.body.searchBy;
  let searchQuery = search ? search.trim() : '';
  let page = parseInt(req.body.page) || 1;

  // Normalize searchBy to array
  if (!searchBy) searchBy = [];
  if (!Array.isArray(searchBy)) searchBy = [searchBy];

  const { jobs, totalPages } = await getPagedJobs({ page, searchQuery, searchBy });
  res.render("jobs", { jobs, searchQuery, searchBy, page, totalPages });
});

// Page navigation for search results (using GET, preserves search/filter via hidden fields)
app.get("/jobs/search", async (req, res) => {
  const searchQuery = req.query.search ? req.query.search.trim() : '';
  let searchBy = req.query.searchBy;
  let page = parseInt(req.query.page) || 1;
  if (!searchBy) searchBy = [];
  if (!Array.isArray(searchBy)) searchBy = [searchBy];
  const { jobs, totalPages } = await getPagedJobs({ page, searchQuery, searchBy });
  res.render("jobs", { jobs, searchQuery, searchBy, page, totalPages });
});

// Print receipt
app.get("/receipt/:id", async (req, res) => {
  const job = await db.get(`SELECT * FROM jobs WHERE id = ?`, [req.params.id]);
  if (!job) return res.status(404).send("Job not found");
  res.render("receipt", { job });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});