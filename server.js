/**
 * ScholarHub — School MIS (Class 6–12)
 * Full Stack: Node.js backend + static HTML/CSS/JS frontend
 * Data stored permanently in MongoDB Atlas
 *
 * HOW TO RUN:
 *   npm install
 *   node server.js
 * Then open: http://localhost:3000
 *
 * ADMIN LOGIN:
 *   Username: admin
 *   Password: admin123
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

// ── Config ──────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL || 'mongodb+srv://Schooladmin:schooladmin1234@cluster0.evl6bsz.mongodb.net/scholarhub?retryWrites=true&w=majority&appName=Cluster0';
const SESSION_SECRET = 'scholarhub_secret_key_2024_change_me';
const ADMIN_PASSWORD = 'admin123';
const CLOUD_NAME = process.env.CLOUD_NAME || 'dkrbs8c9a';
const CLOUD_API_KEY = process.env.CLOUD_API_KEY || '628819339173869';
const CLOUD_SECRET = process.env.CLOUD_SECRET || 'ljyaX9qUr90TcA-6Skg5svQJ3uU';

// ── MongoDB Client ────────────────────────────────────────────
const mongoClient = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 10000 });
let dbCol;

// ── Helpers (unchanged from your original) ──────────────────
function hashPass(p) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('hex');
}
function makeToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64');
  return data + '.' + sig;
}
function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const check = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64');
    if (check !== sig) return null;
    return JSON.parse(Buffer.from(data, 'base64').toString());
  } catch { return null; }
}
function getCookie(req, name) {
  const h = req.headers.cookie || '';
  const m = h.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function parseBody(req) {
  return new Promise(res => {
    let b = '';
    req.on('data', d => b += d);
    req.on('end', () => {
      try { res(JSON.parse(b)); } catch { res({}); }
    });
  });
}
function json(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

// ── Multipart Parser ─────────────────────────────────────────
function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const ct = req.headers['content-type'] || '';
      const bm = ct.match(/boundary=(.+)$/);
      if (!bm) { resolve({ fields: {}, files: {} }); return; }
      const boundary = '--' + bm[1];
      const fields = {}, files = {};
      const parts = buf.toString('binary').split(boundary).slice(1, -1);
      for (const part of parts) {
        const idx = part.indexOf('\r\n\r\n');
        if (idx < 0) continue;
        const header = part.slice(0, idx);
        const body = part.slice(idx + 4, part.lastIndexOf('\r\n'));
        const nmMatch = header.match(/name="([^"]+)"/);
        const fnMatch = header.match(/filename="([^"]+)"/);
        if (!nmMatch) continue;
        const name = nmMatch[1];
        if (fnMatch) {
          const ctMatch = header.match(/Content-Type:\s*(.+)/i);
          files[name] = { filename: fnMatch[1], mimetype: ctMatch ? ctMatch[1].trim() : 'application/octet-stream', data: Buffer.from(body, 'binary') };
        } else { fields[name] = body; }
      }
      resolve({ fields, files });
    });
    req.on('error', reject);
  });
}

// ── Cloudinary Upload ────────────────────────────────────────
function cloudinaryUpload(fileBuffer, mimetype, folder) {
  return new Promise((resolve, reject) => {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const paramsToSign = `folder=${folder}&timestamp=${timestamp}`;
    const signature = crypto.createHash('sha1').update(paramsToSign + CLOUD_SECRET).digest('hex');
    const boundary = '----FB' + crypto.randomBytes(8).toString('hex');
    const isRaw = mimetype.includes('pdf');
    const resType = isRaw ? 'raw' : 'image';
    const ext = isRaw ? 'pdf' : mimetype.includes('png') ? 'png' : 'jpg';
    let bodyStr = '';
    const add = (k, v) => { bodyStr += `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`; };
    add('api_key', CLOUD_API_KEY);
    add('timestamp', timestamp);
    add('signature', signature);
    add('folder', folder);
    bodyStr += `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="upload.${ext}"\r\nContent-Type: ${mimetype}\r\n\r\n`;
    const bodyBuf = Buffer.concat([Buffer.from(bodyStr, 'binary'), fileBuffer, Buffer.from(`\r\n--${boundary}--\r\n`, 'binary')]);
    const options = { hostname: 'api.cloudinary.com', path: `/v1_1/${CLOUD_NAME}/${resType}/upload`, method: 'POST', headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': bodyBuf.length } };
    const req = https.request(options, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { const j = JSON.parse(d); resolve(j.secure_url || j.url || null); } catch { reject(new Error('Cloudinary error')); } }); });
    req.on('error', reject);
    req.write(bodyBuf);
    req.end();
  });
}

function authMiddleware(req) {
  const token = getCookie(req, 'sh_token');
  if (!token) return null;
  return verifyToken(token);
}

// ── Database (MongoDB) ───────────────────────────────────────
async function loadData() {
  await mongoClient.connect();
  dbCol = mongoClient.db('scholarhub').collection('data');
  let doc = await dbCol.findOne({ _id: 'main' });
  if (!doc) {
    doc = {
      _id: 'main',
      students: [],
      grades: [],
      attendance: [],
      homework: [],
      notices: [{ id: 1, title: 'Welcome to ScholarHub!', cat: 'General', msg: 'Our school management portal is now live. Students can register and access all their records online.', date: new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) }],
      timetable: [],
      ids: { s: 100, g: 1, a: 1, h: 1, n: 2, t: 1, tc: 1 },
      teachers: [],
      assignments: [],
      adminCredentials: { username: 'admin', password: hashPass(ADMIN_PASSWORD) }
    };
    await dbCol.insertOne(doc);
  }
  return doc;
}
async function saveData(d) {
  const { _id, ...data } = d;
  await dbCol.replaceOne({ _id: 'main' }, { _id: 'main', ...data }, { upsert: true });
}
let DB = {};

// ── API Router (COPY YOUR FULL handleAPI FUNCTION FROM YOUR ORIGINAL server.js HERE) ─────
// ⚠️ IMPORTANT: Paste your entire handleAPI function below. It is too long to repeat here.
// Make sure to include all routes: /api/login, /api/register, /api/upload/photo,
// /api/teacher/..., /api/grades, /api/attendance, etc.
async function handleAPI(req, res) {
  // ... YOUR EXISTING handleAPI CODE ...
  // (It is exactly the same as in your file, starting with "const url = req.url.replace(/\?.*/, '');")
}

function sanitizeStudent(s) {
  const { password, ...safe } = s;
  return safe;
}
function sanitizeTeacher(t) {
  const { password, ...safe } = t;
  return safe;
}

// ── HTTP Server – serve static HTML from public/index.html ──
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // API routes
  if (req.url.startsWith('/api/')) {
    await handleAPI(req, res);
    return;
  }

  // Serve the static HTML file
  const filePath = path.join(__dirname, 'public', 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error – missing public/index.html');
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    }
  });
});

// Start server
loadData().then(data => {
  DB = data;
  server.listen(PORT, () => {
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║   ScholarHub School MIS — Server Running     ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log(`║   Port: ${PORT}                                  ║`);
    console.log('║   Admin login:     admin / admin123          ║');
    console.log('║   Data stored in:  MongoDB Atlas             ║');
    console.log('╚══════════════════════════════════════════════╝\n');
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});
