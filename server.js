/**
 * ╔══════════════════════════════════════════════════════════╗
 *  ScholarHub — School MIS (Class 6–12)
 *  Full Stack: Node.js backend + HTML/CSS/JS frontend
 *  NO npm install needed — uses only Node.js built-ins
 *  Data stored permanently in: school_data.json
 *
 *  HOW TO RUN:
 *    node server.js
 *  Then open: http://localhost:3000
 *
 *  ADMIN LOGIN:
 *    Username: admin
 *    Password: (you set it on first run — see ADMIN_PASSWORD below)
 * ╚══════════════════════════════════════════════════════════╝
 */

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

// ── Config ──────────────────────────────────────────────────
const PORT           = process.env.PORT || 3000;
const MONGO_URL      = process.env.MONGO_URL || 'mongodb+srv://Schooladmin:schooladmin1234@cluster0.evl6bsz.mongodb.net/scholarhub?retryWrites=true&w=majority&appName=Cluster0';
const SESSION_SECRET = 'scholarhub_secret_key_2024_change_me';
const ADMIN_PASSWORD = 'admin123';
const CLOUD_NAME    = process.env.CLOUD_NAME    || 'dkrbs8c9a';
const CLOUD_API_KEY = process.env.CLOUD_API_KEY || '628819339173869';
const CLOUD_SECRET  = process.env.CLOUD_SECRET  || 'ljyaX9qUr90TcA-6Skg5svQJ3uU';

// ── MongoDB Client ────────────────────────────────────────────
const mongoClient = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 10000 });
let dbCol;

// ── Helpers ──────────────────────────────────────────────────
function hashPass(p) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('hex');
}
function makeToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64');
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
      const ct  = req.headers['content-type'] || '';
      const bm  = ct.match(/boundary=(.+)$/);
      if (!bm) { resolve({ fields: {}, files: {} }); return; }
      const boundary = '--' + bm[1];
      const fields = {}, files = {};
      const parts = buf.toString('binary').split(boundary).slice(1, -1);
      for (const part of parts) {
        const idx = part.indexOf('\r\n\r\n');
        if (idx < 0) continue;
        const header = part.slice(0, idx);
        const body   = part.slice(idx + 4, part.lastIndexOf('\r\n'));
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
      students:   [],
      grades:     [],
      attendance: [],
      homework:   [],
      notices:    [{ id: 1, title: 'Welcome to ScholarHub!', cat: 'General', msg: 'Our school management portal is now live. Students can register and access all their records online.', date: new Date().toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'}) }],
      timetable:  [],
      ids:        { s: 100, g: 1, a: 1, h: 1, n: 2, t: 1, tc: 1 },
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

// ── API Router ────────────────────────────────────────────────
async function handleAPI(req, res) {
  const url    = req.url.replace(/\?.*/, '');
  const method = req.method;
  const user   = authMiddleware(req);

  // POST /api/login
  if (url === '/api/login' && method === 'POST') {
    const { username, password, role } = await parseBody(req);
    if (role === 'admin') {
      const ac = DB.adminCredentials || { username: 'admin', password: hashPass(ADMIN_PASSWORD) };
      if (username === ac.username && hashPass(password) === ac.password) {
        const token = makeToken({ role: 'admin', username });
        res.writeHead(200, { 'Set-Cookie': `sh_token=${token}; Path=/; HttpOnly; SameSite=Strict`, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, role: 'admin' }));
      } else { json(res, 401, { ok: false, msg: 'Invalid admin credentials.' }); }
      return;
    }
    // Student login
    const st = DB.students.find(s => s.username === username && s.password === hashPass(password));
    if (!st)      return json(res, 401, { ok: false, msg: 'No account found with these credentials.' });
    if (!st.approved) return json(res, 403, { ok: false, msg: 'Account pending admin approval.' });
    const token = makeToken({ role: 'student', id: st.id });
    res.writeHead(200, { 'Set-Cookie': `sh_token=${token}; Path=/; HttpOnly; SameSite=Strict`, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, role: 'student', student: sanitizeStudent(st) }));
    return;
  }

  // POST /api/logout
  if (url === '/api/logout' && method === 'POST') {
    res.writeHead(200, { 'Set-Cookie': 'sh_token=; Path=/; Max-Age=0', 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // POST /api/register
  if (url === '/api/register' && method === 'POST') {
    const { name, roll, cls, section, username, password } = await parseBody(req);
    if (!name || !roll || !cls || !username || !password) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    if (password.length < 6) return json(res, 400, { ok: false, msg: 'Password must be at least 6 characters.' });
    if (DB.students.find(s => s.username === username)) return json(res, 400, { ok: false, msg: 'Username already taken.' });
    const st = { id: DB.ids.s++, name, roll, cls, section, username, password: hashPass(password), approved: false, photo: '', createdAt: new Date().toISOString() };
    DB.students.push(st);
    saveData(DB);
    json(res, 200, { ok: true, msg: 'Registration successful! Awaiting admin approval.' });
    return;
  }

  // GET /api/me
  if (url === '/api/me' && method === 'GET') {
    if (!user) return json(res, 401, { ok: false });
    if (user.role === 'admin') return json(res, 200, { ok: true, role: 'admin' });
    if (user.role === 'teacher') {
      if (!DB.teachers) DB.teachers = [];
      const t = DB.teachers.find(t => t.id === user.id);
      if (!t) return json(res, 401, { ok: false });
      return json(res, 200, { ok: true, role: 'teacher', teacher: sanitizeTeacher(t) });
    }
    const st = DB.students.find(s => s.id === user.id);
    if (!st) return json(res, 401, { ok: false });
    json(res, 200, { ok: true, role: 'student', student: sanitizeStudent(st) });
    return;
  }


  // POST /api/upload/photo
  if (url === '/api/upload/photo' && method === 'POST') {
    if (!user) return json(res, 401, { ok: false });
    const { files } = await parseMultipart(req);
    const f = files.photo;
    if (!f) return json(res, 400, { ok: false, msg: 'No file.' });
    try {
      const photoUrl = await cloudinaryUpload(f.data, f.mimetype, 'scholarhub/photos');
      if (user.role === 'student') {
        const st = DB.students.find(s => s.id === user.id);
        if (st) { st.photo = photoUrl; await saveData(DB); }
      }
      json(res, 200, { ok: true, url: photoUrl });
    } catch(e) { json(res, 500, { ok: false, msg: 'Upload failed: ' + e.message }); }
    return;
  }

  // POST /api/upload/file
  if (url === '/api/upload/file' && method === 'POST') {
    if (!user) return json(res, 401, { ok: false });
    const { files, fields } = await parseMultipart(req);
    const f = files.file;
    if (!f) return json(res, 400, { ok: false, msg: 'No file.' });
    const folder = fields.folder || 'scholarhub/files';
    try {
      const fileUrl = await cloudinaryUpload(f.data, f.mimetype, folder);
      json(res, 200, { ok: true, url: fileUrl, name: f.filename });
    } catch(e) { json(res, 500, { ok: false, msg: 'Upload failed: ' + e.message }); }
    return;
  }

  // ── ADMIN ONLY ROUTES ────────────────────────────────────

// ── Teacher Routes ───────────────────────────────────────────

  // POST /api/teacher/register
  if (url === '/api/teacher/register' && method === 'POST') {
    const { name, subject, username, password } = await parseBody(req);
    if (!name || !subject || !username || !password) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    if (password.length < 6) return json(res, 400, { ok: false, msg: 'Password min 6 chars.' });
    if (!DB.teachers) DB.teachers = [];
    if (!DB.ids.tc) DB.ids.tc = 1;
    if (DB.teachers.find(t => t.username === username)) return json(res, 400, { ok: false, msg: 'Username taken.' });
    const teacher = { id: DB.ids.tc++, name, subject, username, password: hashPass(password), approved: false, photo: '', createdAt: new Date().toISOString() };
    DB.teachers.push(teacher);
    await saveData(DB);
    json(res, 200, { ok: true, msg: 'Registration successful! Awaiting admin approval.' });
    return;
  }

  // POST /api/teacher/login
  if (url === '/api/teacher/login' && method === 'POST') {
    if (!DB.teachers) DB.teachers = [];
    const { username, password } = await parseBody(req);
    const teacher = DB.teachers.find(t => t.username === username && t.password === hashPass(password));
    if (!teacher) return json(res, 401, { ok: false, msg: 'Invalid credentials.' });
    if (!teacher.approved) return json(res, 403, { ok: false, msg: 'Account pending admin approval.' });
    const token = makeToken({ role: 'teacher', id: teacher.id });
    res.writeHead(200, { 'Set-Cookie': `sh_token=${token}; Path=/; HttpOnly; SameSite=Strict`, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, role: 'teacher', teacher: sanitizeTeacher(teacher) }));
    return;
  }

  if (!user) return json(res, 401, { ok: false, msg: 'Not authenticated.' });


  // POST /api/admin/credentials
  if (url === '/api/admin/credentials' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { username, password } = await parseBody(req);
    if (!username || !password) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    if (password.length < 6) return json(res, 400, { ok: false, msg: 'Password min 6 chars.' });
    DB.adminCredentials = { username, password: hashPass(password) };
    await saveData(DB);
    res.writeHead(200, { 'Set-Cookie': 'sh_token=; Path=/; Max-Age=0', 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, msg: 'Updated! Please login again.' }));
    return;
  }

  // GET /api/admin/credentials
  if (url === '/api/admin/credentials' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    json(res, 200, { ok: true, username: (DB.adminCredentials || { username: 'admin' }).username });
    return;
  }


  // GET /api/teachers (admin only)
  if (url === '/api/teachers' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    if (!DB.teachers) DB.teachers = [];
    json(res, 200, { ok: true, teachers: DB.teachers.map(sanitizeTeacher) });
    return;
  }

  // POST /api/teachers/:id/approve
  const approveTeacherMatch = url.match(/^\/api\/teachers\/(\d+)\/approve$/);
  if (approveTeacherMatch && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    if (!DB.teachers) DB.teachers = [];
    const t = DB.teachers.find(t => t.id === parseInt(approveTeacherMatch[1]));
    if (!t) return json(res, 404, { ok: false });
    t.approved = true;
    await saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/teachers/:id
  const delTeacherMatch = url.match(/^\/api\/teachers\/(\d+)$/);
  if (delTeacherMatch && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.teachers = (DB.teachers || []).filter(t => t.id !== parseInt(delTeacherMatch[1]));
    await saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET /api/teacher/me
  if (url === '/api/teacher/me' && method === 'GET') {
    if (user.role !== 'teacher') return json(res, 403, {});
    if (!DB.teachers) DB.teachers = [];
    const t = DB.teachers.find(t => t.id === user.id);
    if (!t) return json(res, 401, { ok: false });
    json(res, 200, { ok: true, teacher: sanitizeTeacher(t) });
    return;
  }

  // GET /api/students
  if (url === '/api/students' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    json(res, 200, { ok: true, students: DB.students.map(sanitizeStudent) });
    return;
  }

  // POST /api/students/:id/approve
  const approveMatch = url.match(/^\/api\/students\/(\d+)\/approve$/);
  if (approveMatch && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const st = DB.students.find(s => s.id === parseInt(approveMatch[1]));
    if (!st) return json(res, 404, { ok: false });
    st.approved = true;
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/students/:id
  const delStudentMatch = url.match(/^\/api\/students\/(\d+)$/);
  if (delStudentMatch && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    const id = parseInt(delStudentMatch[1]);
    DB.students   = DB.students.filter(s => s.id !== id);
    DB.grades     = DB.grades.filter(g => g.sid !== id);
    DB.attendance = DB.attendance.filter(a => a.sid !== id);
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET/POST /api/grades
  if (url === '/api/grades' && method === 'GET') {
    const sid = user.role === 'student' ? user.id : null;
    const grades = sid ? DB.grades.filter(g => g.sid === sid) : DB.grades;
    json(res, 200, { ok: true, grades });
    return;
  }
  if (url === '/api/grades' && method === 'POST') {
    if (user.role !== 'admin' && user.role !== 'teacher') return json(res, 403, {});
    const { sid, sub, exam, max, obt, fileUrl, fileName } = await parseBody(req);
    if (!sid || !sub || !max || obt === undefined) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    if (obt > max) return json(res, 400, { ok: false, msg: 'Obtained cannot exceed max marks.' });
    DB.grades.push({ id: DB.ids.g++, sid: parseInt(sid), sub, exam, max: parseInt(max), obt: parseInt(obt), fileUrl: fileUrl||'', fileName: fileName||'', createdAt: new Date().toISOString() });
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/grades/:id
  const delGradeMatch = url.match(/^\/api\/grades\/(\d+)$/);
  if (delGradeMatch && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.grades = DB.grades.filter(g => g.id !== parseInt(delGradeMatch[1]));
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET/POST /api/attendance
  if (url === '/api/attendance' && method === 'GET') {
    const sid = user.role === 'student' ? user.id : null;
    const att = sid ? DB.attendance.filter(a => a.sid === sid) : DB.attendance;
    json(res, 200, { ok: true, attendance: att });
    return;
  }
  if (url === '/api/attendance' && method === 'POST') {
    if (user.role !== 'admin' && user.role !== 'teacher') return json(res, 403, {});
    const { sid, sub, tot, pre } = await parseBody(req);
    if (!sid || !sub || !tot || pre === undefined) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    if (parseInt(pre) > parseInt(tot)) return json(res, 400, { ok: false, msg: 'Present cannot exceed total.' });
    DB.attendance.push({ id: DB.ids.a++, sid: parseInt(sid), sub, tot: parseInt(tot), pre: parseInt(pre), createdAt: new Date().toISOString() });
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/attendance/:id
  const delAttMatch = url.match(/^\/api\/attendance\/(\d+)$/);
  if (delAttMatch && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.attendance = DB.attendance.filter(a => a.id !== parseInt(delAttMatch[1]));
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET/POST /api/homework
  if (url === '/api/homework' && method === 'GET') {
    let hw = DB.homework;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      hw = st ? hw.filter(h => h.cls === st.cls || h.cls === 'All') : [];
    }
    json(res, 200, { ok: true, homework: hw });
    return;
  }
  if (url === '/api/homework' && method === 'POST') {
    if (user.role !== 'admin' && user.role !== 'teacher') return json(res, 403, {});
    const { title, sub, cls, due, pri, desc, fileUrl, fileName } = await parseBody(req);
    if (!title || !due) return json(res, 400, { ok: false, msg: 'Title and due date required.' });
    DB.homework.push({ id: DB.ids.h++, title, sub, cls, due, pri, desc, fileUrl: fileUrl||'', fileName: fileName||'', createdAt: new Date().toISOString() });
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }


  // POST /api/homework/:id/submit
  const submitHWMatch = url.match(/^\/api\/homework\/(\d+)\/submit$/);
  if (submitHWMatch && method === 'POST') {
    if (user.role !== 'student') return json(res, 403, {});
    const { fileUrl, fileName } = await parseBody(req);
    const hw = DB.homework.find(h => h.id === parseInt(submitHWMatch[1]));
    if (!hw) return json(res, 404, { ok: false });
    if (!hw.submissions) hw.submissions = [];
    const st = DB.students.find(s => s.id === user.id);
    hw.submissions = hw.submissions.filter(s => s.sid !== user.id);
    hw.submissions.push({ sid: user.id, name: st ? st.name : 'Unknown', fileUrl, fileName, submittedAt: new Date().toISOString() });
    await saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/homework/:id
  const delHWMatch = url.match(/^\/api\/homework\/(\d+)$/);
  if (delHWMatch && method === 'DELETE') {
    if (user.role !== 'admin' && user.role !== 'teacher') return json(res, 403, {});
    DB.homework = DB.homework.filter(h => h.id !== parseInt(delHWMatch[1]));
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET/POST /api/notices
  if (url === '/api/notices' && method === 'GET') {
    json(res, 200, { ok: true, notices: DB.notices });
    return;
  }
  if (url === '/api/notices' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { title, cat, msg } = await parseBody(req);
    if (!title || !msg) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
    DB.notices.unshift({ id: DB.ids.n++, title, cat, msg, date, createdAt: new Date().toISOString() });
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/notices/:id
  const delNotMatch = url.match(/^\/api\/notices\/(\d+)$/);
  if (delNotMatch && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.notices = DB.notices.filter(n => n.id !== parseInt(delNotMatch[1]));
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET/POST /api/timetable
  if (url === '/api/timetable' && method === 'GET') {
    let tt = DB.timetable;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      tt = st ? tt.filter(t => t.cls === st.cls) : [];
    }
    json(res, 200, { ok: true, timetable: tt });
    return;
  }
  if (url === '/api/timetable' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { cls, day, sub, period } = await parseBody(req);
    DB.timetable.push({ id: DB.ids.t++, cls, day, sub, period });
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // DELETE /api/timetable/:id
  const delTTMatch = url.match(/^\/api\/timetable\/(\d+)$/);
  if (delTTMatch && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.timetable = DB.timetable.filter(t => t.id !== parseInt(delTTMatch[1]));
    saveData(DB);
    json(res, 200, { ok: true });
    return;
  }

  // GET /api/stats (admin dashboard)
  if (url === '/api/stats' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    const approved = DB.students.filter(s => s.approved);
    const pending  = DB.students.filter(s => !s.approved);
    const classCounts = {};
    ['Class 6','Class 7','Class 8','Class 9','Class 10','Class 11','Class 12'].forEach(c => classCounts[c] = 0);
    approved.forEach(s => classCounts[s.cls] = (classCounts[s.cls] || 0) + 1);
    json(res, 200, { ok: true, totalStudents: approved.length, pending: pending.length, homework: DB.homework.length, notices: DB.notices.length, assignments: (DB.assignments||[]).length, classCounts });
    return;
  }

  json(res, 404, { ok: false, msg: 'API endpoint not found.' });
}

function sanitizeStudent(s) {
  const { password, ...safe } = s;
  return safe;
}
function sanitizeTeacher(t) {
  const { password, ...safe } = t;
  return safe;
}

// ── HTML Frontend ─────────────────────────────────────────────

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ScholarHub — School MIS (Class 6–12)</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0e1a;--bg2:#111426;--bg3:#181c2e;
  --border:rgba(255,255,255,.07);--border2:rgba(255,255,255,.12);
  --text:#e8eaf6;--text2:#9ca3c9;--text3:#6b7299;
  --primary:#6c63ff;--primary2:#8b84ff;--primary3:#4a42dd;
  --primary-glow:rgba(108,99,255,.25);
  --green:#22d3a0;--green-pale:rgba(34,211,160,.12);
  --amber:#fbbf24;--amber-pale:rgba(251,191,36,.12);
  --rose:#f87171;--rose-pale:rgba(248,113,113,.12);
  --sky:#38bdf8;--sky-pale:rgba(56,189,248,.12);
  --violet:#a78bfa;--violet-pale:rgba(167,139,250,.12);
  --teal:#2dd4bf;--teal-pale:rgba(45,212,191,.12);
  --surface2:#2c3050;--surface3:#353960;
  --sidebar:240px;--r:10px;--r-lg:14px;--r-xl:20px;
  --font:'Plus Jakarta Sans',sans-serif;--mono:'DM Mono',monospace;
  --sh:0 4px 24px rgba(0,0,0,.4);--sh-lg:0 12px 48px rgba(0,0,0,.5);
}
html{scroll-behavior:smooth;}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;line-height:1.6;overflow-x:hidden;}
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-track{background:var(--bg2);}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:99px;}
.screen{display:none;min-height:100vh;}
.screen.active{display:flex;}
#screen-login,#screen-register{align-items:center;justify-content:center;background:var(--bg);position:relative;overflow:hidden;}
.auth-bg{position:absolute;inset:0;overflow:hidden;pointer-events:none;}
.auth-orb{position:absolute;border-radius:50%;filter:blur(80px);animation:orbFloat 8s ease-in-out infinite;}
.orb1{width:500px;height:500px;background:radial-gradient(circle,rgba(108,99,255,.18),transparent 70%);top:-150px;left:-100px;}
.orb2{width:400px;height:400px;background:radial-gradient(circle,rgba(34,211,160,.1),transparent 70%);bottom:-100px;right:-80px;animation-delay:-3s;}
.orb3{width:300px;height:300px;background:radial-gradient(circle,rgba(56,189,248,.08),transparent 70%);top:50%;left:50%;transform:translate(-50%,-50%);animation-delay:-6s;}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1);}33%{transform:translate(30px,-20px) scale(1.05);}66%{transform:translate(-20px,15px) scale(.97);}}
.auth-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.015) 1px,transparent 1px);background-size:48px 48px;}
.auth-wrap{position:relative;z-index:1;width:100%;max-width:480px;padding:20px;}
.auth-box{background:rgba(17,20,38,.92);backdrop-filter:blur(24px);border:1px solid var(--border2);border-radius:var(--r-xl);padding:44px 48px;box-shadow:var(--sh-lg);animation:authIn .5s cubic-bezier(.16,1,.3,1);}
@keyframes authIn{from{opacity:0;transform:translateY(24px) scale(.97);}to{opacity:1;transform:none;}}
.auth-logo{display:flex;align-items:center;gap:12px;margin-bottom:8px;}
.auth-logo-mark{width:44px;height:44px;background:linear-gradient(135deg,var(--primary),var(--primary2));border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 24px var(--primary-glow);position:relative;overflow:hidden;}
.auth-logo-mark::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.2),transparent);}
.auth-logo-mark svg{width:24px;height:24px;fill:white;position:relative;z-index:1;}
.auth-logo-text{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-.5px;}
.auth-logo-text span{color:var(--primary2);}
.auth-tagline{font-size:12.5px;color:var(--text3);margin-bottom:30px;padding-left:56px;}
.auth-head{font-size:19px;font-weight:700;color:var(--text);margin-bottom:4px;}
.auth-sub{font-size:13px;color:var(--text3);margin-bottom:24px;}
.role-tabs{display:flex;background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:4px;gap:4px;margin-bottom:22px;}
.role-tab{flex:1;padding:8px 10px;font-size:12.5px;font-weight:600;font-family:var(--font);border:none;border-radius:7px;cursor:pointer;transition:all .2s;color:var(--text3);background:transparent;}
.role-tab.active{background:var(--surface2);color:var(--primary2);box-shadow:0 1px 6px rgba(0,0,0,.3);}
.f-group{margin-bottom:16px;}
.f-label{font-size:11px;font-weight:700;color:var(--text2);margin-bottom:6px;display:block;letter-spacing:.05em;text-transform:uppercase;}
.f-input,.f-select{width:100%;padding:11px 14px;font-size:13.5px;font-family:var(--font);background:var(--bg3);border:1.5px solid var(--border2);border-radius:9px;color:var(--text);outline:none;transition:all .2s;}
.f-input::placeholder{color:var(--text3);}
.f-input:focus,.f-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
.f-select option{background:var(--bg3);}
.f-row-2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.btn-primary{width:100%;padding:12px;font-size:14px;font-weight:700;font-family:var(--font);background:linear-gradient(135deg,var(--primary),var(--primary2));color:white;border:none;border-radius:10px;cursor:pointer;transition:all .2s;margin-top:4px;position:relative;overflow:hidden;}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px var(--primary-glow);}
.btn-primary:active{transform:none;}
.btn-primary:disabled{opacity:.6;cursor:not-allowed;transform:none;}
.btn-outline{width:100%;padding:11px;font-size:13px;font-family:var(--font);background:transparent;color:var(--text3);border:1.5px solid var(--border2);border-radius:10px;cursor:pointer;transition:all .2s;margin-top:10px;}
.btn-outline:hover{border-color:var(--primary);color:var(--primary2);}
.auth-footer{font-size:13px;text-align:center;color:var(--text3);margin-top:18px;}
.auth-footer a{color:var(--primary2);cursor:pointer;font-weight:600;text-decoration:none;}
.alert{padding:10px 14px;border-radius:8px;font-size:12.5px;margin-bottom:14px;display:none;font-weight:500;}
.alert-err{background:var(--rose-pale);color:var(--rose);border:1px solid rgba(248,113,113,.25);}
.alert-ok{background:var(--green-pale);color:var(--green);border:1px solid rgba(34,211,160,.25);}
#screen-admin,#screen-student{flex-direction:row;}
.sidebar{width:var(--sidebar);background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:100;}
.sb-brand{padding:24px 18px 18px;border-bottom:1px solid var(--border);}
.sb-brand-inner{display:flex;align-items:center;gap:10px;}
.sb-brand-mark{width:34px;height:34px;background:linear-gradient(135deg,var(--primary),var(--primary2));border-radius:9px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 16px var(--primary-glow);}
.sb-brand-mark svg{width:18px;height:18px;fill:white;}
.sb-brand-name{font-size:15px;font-weight:800;color:var(--text);letter-spacing:-.3px;}
.sb-brand-name span{color:var(--primary2);}
.sb-role-pill{margin-top:10px;display:inline-flex;align-items:center;gap:6px;background:var(--bg3);border:1px solid var(--border);border-radius:20px;padding:4px 10px;}
.sb-role-dot{width:6px;height:6px;border-radius:50%;}
.sb-role-text{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.08em;}
.nav{padding:14px 10px;flex:1;overflow-y:auto;}
.nav-section{font-size:9.5px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.1em;padding:10px 8px 4px;margin-top:6px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:9px;cursor:pointer;transition:all .15s;color:var(--text3);font-size:13px;font-weight:500;margin-bottom:2px;user-select:none;position:relative;}
.nav-item:hover{background:var(--bg3);color:var(--text2);}
.nav-item.active{background:rgba(108,99,255,.15);color:var(--primary2);}
.nav-item.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--primary2);border-radius:0 3px 3px 0;}
.nav-item-icon{width:17px;height:17px;flex-shrink:0;}
.nav-badge{margin-left:auto;background:var(--amber);color:#0b0e1a;font-size:9px;font-weight:800;padding:2px 7px;border-radius:10px;font-family:var(--mono);}
.sb-user{padding:14px 16px;border-top:1px solid var(--border);}
.sb-user-info{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
.sb-av{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex-shrink:0;}
.av-p{background:linear-gradient(135deg,var(--primary),var(--primary2));color:white;}
.av-g{background:linear-gradient(135deg,var(--green),#059669);color:white;}
.sb-user-name{font-size:13px;font-weight:600;color:var(--text);}
.sb-user-sub{font-size:11px;color:var(--text3);}
.btn-logout{width:100%;padding:8px;font-size:12px;font-family:var(--font);background:transparent;color:var(--text3);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all .15s;font-weight:500;}
.btn-logout:hover{background:var(--rose-pale);color:var(--rose);border-color:rgba(248,113,113,.3);}
.main{margin-left:var(--sidebar);flex:1;padding:28px 30px;min-height:100vh;background:var(--bg);}
.page{display:none;}
.page.active{display:block;animation:pageIn .3s cubic-bezier(.16,1,.3,1);}
@keyframes pageIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:none;}}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:28px;}
.page-title{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-.5px;}
.page-sub{font-size:13px;color:var(--text3);margin-top:3px;}
.badge{font-size:10.5px;font-weight:700;padding:3px 10px;border-radius:20px;letter-spacing:.03em;display:inline-flex;align-items:center;}
.b-primary{background:var(--primary-glow);color:var(--primary2);}
.b-green{background:var(--green-pale);color:var(--green);}
.b-amber{background:var(--amber-pale);color:var(--amber);}
.b-rose{background:var(--rose-pale);color:var(--rose);}
.b-sky{background:var(--sky-pale);color:var(--sky);}
.b-violet{background:var(--violet-pale);color:var(--violet);}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-lg);padding:18px 20px;position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s;cursor:default;}
.stat-card:hover{transform:translateY(-3px);box-shadow:var(--sh);}
.stat-card::after{content:'';position:absolute;top:0;right:0;width:100px;height:100px;border-radius:50%;opacity:.06;transform:translate(30px,-30px);}
.sc-p::after{background:var(--primary);}
.sc-g::after{background:var(--green);}
.sc-a::after{background:var(--amber);}
.sc-r::after{background:var(--rose);}
.stat-icon{width:36px;height:36px;border-radius:9px;display:flex;align-items:center;justify-content:center;margin-bottom:14px;}
.stat-icon svg{width:17px;height:17px;}
.si-p{background:var(--primary-glow);}
.si-p svg{stroke:var(--primary2);}
.si-g{background:var(--green-pale);}
.si-g svg{stroke:var(--green);}
.si-a{background:var(--amber-pale);}
.si-a svg{stroke:var(--amber);}
.si-r{background:var(--rose-pale);}
.si-r svg{stroke:var(--rose);}
.stat-val{font-size:30px;font-weight:800;font-family:var(--mono);letter-spacing:-1.5px;line-height:1;}
.stat-label{font-size:11.5px;color:var(--text3);margin-top:4px;font-weight:500;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-lg);padding:20px 22px;margin-bottom:16px;}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.card-title{font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.07em;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
.tbl-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border);}
.tbl{width:100%;border-collapse:collapse;font-size:13px;}
.tbl thead tr{background:var(--bg3);}
.tbl th{padding:10px 14px;text-align:left;font-size:10.5px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);}
.tbl td{padding:12px 14px;border-bottom:1px solid var(--border);transition:background .15s;}
.tbl tbody tr:last-child td{border-bottom:none;}
.tbl tbody tr:hover td{background:var(--bg3);}
.tbl-empty{text-align:center;color:var(--text3);padding:32px 0;font-size:13px;}
.form-section{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-lg);padding:22px;margin-bottom:16px;}
.form-section-title{font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.07em;margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--border);}
.f-row{display:grid;gap:14px;margin-bottom:14px;}
.f-row-2{grid-template-columns:1fr 1fr;}
.f-row-3{grid-template-columns:1fr 1fr 1fr;}
.f-row-4{grid-template-columns:1fr 1fr 1fr 1fr;}
.f-grp{display:flex;flex-direction:column;gap:6px;}
.f-lbl{font-size:10.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;}
.fi,.fs,.ft{padding:10px 13px;font-size:13px;font-family:var(--font);background:var(--bg3);border:1.5px solid var(--border2);border-radius:9px;color:var(--text);outline:none;transition:all .2s;}
.fi::placeholder{color:var(--text3);}
.fi:focus,.fs:focus,.ft:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
.fs option{background:var(--bg3);}
.fi[readonly]{color:var(--text3);}
.ft{resize:vertical;}
.btn-save{padding:10px 22px;font-size:13px;font-weight:700;font-family:var(--font);background:linear-gradient(135deg,var(--primary),var(--primary2));color:white;border:none;border-radius:9px;cursor:pointer;transition:all .2s;}
.btn-save:hover{transform:translateY(-1px);box-shadow:0 4px 16px var(--primary-glow);}
.btn-save:disabled{opacity:.6;cursor:not-allowed;transform:none;}
.btn-approve{padding:5px 11px;font-size:10.5px;font-weight:700;font-family:var(--font);background:var(--green-pale);color:var(--green);border:1px solid rgba(34,211,160,.25);border-radius:7px;cursor:pointer;transition:.15s;}
.btn-approve:hover{background:var(--green);color:#0b0e1a;}
.btn-del{padding:5px 11px;font-size:10.5px;font-weight:700;font-family:var(--font);background:var(--rose-pale);color:var(--rose);border:1px solid rgba(248,113,113,.25);border-radius:7px;cursor:pointer;transition:.15s;}
.btn-del:hover{background:var(--rose);color:white;}
.flash{padding:10px 14px;border-radius:9px;font-size:12.5px;font-weight:600;margin-bottom:14px;display:none;animation:slideIn .3s ease;}
@keyframes slideIn{from{opacity:0;transform:translateX(-8px);}to{opacity:1;transform:none;}}
.flash-ok{background:var(--green-pale);color:var(--green);border:1px solid rgba(34,211,160,.25);}
.flash-err{background:var(--rose-pale);color:var(--rose);border:1px solid rgba(248,113,113,.25);}
.bar-row{display:flex;align-items:center;gap:12px;margin-bottom:12px;}
.bar-label{font-size:12.5px;width:90px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:500;color:var(--text2);}
.bar-bg{flex:1;height:6px;background:var(--bg3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;transition:width .7s cubic-bezier(.16,1,.3,1);}
.bar-val{font-size:11.5px;font-weight:700;font-family:var(--mono);width:36px;text-align:right;flex-shrink:0;}
.item-row{display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid var(--border);}
.item-row:last-child{border-bottom:none;}
.item-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:5px;}
.item-body{flex:1;}
.item-title{font-size:13.5px;font-weight:600;color:var(--text);line-height:1.4;}
.item-meta{font-size:11.5px;color:var(--text3);margin-top:2px;}
.pending-pill{background:var(--amber);color:#0b0e1a;font-size:9.5px;font-weight:800;padding:2px 8px;border-radius:10px;margin-left:6px;font-family:var(--mono);}
.profile-hero{background:linear-gradient(135deg,var(--primary3),var(--primary));border-radius:var(--r-xl);padding:32px;margin-bottom:16px;position:relative;overflow:hidden;}
.profile-hero::before{content:'';position:absolute;top:-60px;right:-60px;width:200px;height:200px;background:rgba(255,255,255,.05);border-radius:50%;}
.profile-av-lg{width:70px;height:70px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800;background:rgba(255,255,255,.2);border:3px solid rgba(255,255,255,.3);color:white;margin-bottom:14px;}
.profile-name{font-size:20px;font-weight:800;color:white;}
.profile-sub{font-size:13px;color:rgba(255,255,255,.7);margin-top:3px;}
.class-section-header{background:linear-gradient(90deg,var(--primary-glow),transparent);border-left:3px solid var(--primary2);padding:10px 14px;border-radius:0 8px 8px 0;font-size:12px;font-weight:700;color:var(--primary2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:white;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px;}
@keyframes spin{to{transform:rotate(360deg);}}
@media(max-width:900px){.stat-grid{grid-template-columns:1fr 1fr;}.g2{grid-template-columns:1fr;}.f-row-3{grid-template-columns:1fr 1fr;}.f-row-4{grid-template-columns:1fr 1fr;}}
</style>
</head>
<body>

<!-- LOGIN -->
<div id="screen-login" class="screen active">
  <div class="auth-bg"><div class="auth-grid"></div><div class="auth-orb orb1"></div><div class="auth-orb orb2"></div><div class="auth-orb orb3"></div></div>
  <div class="auth-wrap">
    <div class="auth-box">
      <div class="auth-logo">
        <div class="auth-logo-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div>
        <div class="auth-logo-text">Scholar<span>Hub</span></div>
      </div>
      <div class="auth-tagline">School Management System · Class 6–12</div>
      <div class="auth-head">Welcome back</div>
      <div class="auth-sub">Sign in to your account</div>
      <div class="role-tabs">
        <button class="role-tab active" onclick="switchRole('student',this)">Student</button>
        <button class="role-tab" onclick="switchRole('admin',this)">Admin</button>
        <button class="role-tab" id="teacher-tab" onclick="switchRole('teacher',this)" style="color:var(--text3);">🎓 Teacher</button>
      </div>
      <div id="l-err" class="alert alert-err"></div>
      <div class="f-group"><label class="f-label">Username</label><input class="f-input" id="l-user" placeholder="Enter username" onkeydown="if(event.key==='Enter')doLogin()"/></div>
      <div class="f-group"><label class="f-label">Password</label><input class="f-input" id="l-pass" type="password" placeholder="Enter password" onkeydown="if(event.key==='Enter')doLogin()"/></div>
      <button class="btn-primary" id="login-btn" onclick="doLogin()">Sign In →</button>
      <div class="auth-footer">Student? <a onclick="showScreen('screen-register')">Register</a> &nbsp;·&nbsp; Teacher? <a onclick="showScreen('screen-teacher-register')" style="color:var(--teal);">Register</a></div>
    </div>
  </div>
</div>

<!-- REGISTER -->
<div id="screen-register" class="screen">
  <div class="auth-bg"><div class="auth-grid"></div><div class="auth-orb orb1"></div><div class="auth-orb orb2"></div></div>
  <div class="auth-wrap" style="max-width:520px;">
    <div class="auth-box">
      <div class="auth-logo">
        <div class="auth-logo-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div>
        <div class="auth-logo-text">Scholar<span>Hub</span></div>
      </div>
      <div class="auth-head" style="margin-top:8px;">Create account</div>
      <div class="auth-sub">Fill in your details to register</div>
      <div id="r-err" class="alert alert-err"></div>
      <div id="r-ok" class="alert alert-ok"></div>
      <div class="f-row-2" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
        <div class="f-group"><label class="f-label">Full Name</label><input class="f-input" id="r-name" placeholder="Your full name"/></div>
        <div class="f-group"><label class="f-label">Roll Number</label><input class="f-input" id="r-roll" placeholder="e.g. 2024001"/></div>
      </div>
      <div class="f-row-2" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
        <div class="f-group"><label class="f-label">Class</label>
          <select class="f-select" id="r-class"><option value="">Select Class</option><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select>
        </div>
        <div class="f-group"><label class="f-label">Section</label>
          <select class="f-select" id="r-sec"><option>A</option><option>B</option><option>C</option><option>D</option></select>
        </div>
      </div>
      <div class="f-row-2" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
        <div class="f-group"><label class="f-label">Username</label><input class="f-input" id="r-user" placeholder="Choose username"/></div>
        <div class="f-group"><label class="f-label">Password</label><input class="f-input" id="r-pass" type="password" placeholder="Min 6 characters"/></div>
      </div>
      <button class="btn-primary" id="reg-btn" onclick="doRegister()">Create Account →</button>
      <button class="btn-outline" onclick="showScreen('screen-login')">Back to login</button>
    </div>
  </div>
</div>


<!-- TEACHER REGISTER -->
<div id="screen-teacher-register" class="screen">
  <div class="auth-bg"><div class="auth-grid"></div><div class="auth-orb orb1"></div><div class="auth-orb orb2"></div></div>
  <div class="auth-wrap" style="max-width:480px;">
    <div class="auth-box">
      <div class="auth-logo">
        <div class="auth-logo-mark" style="background:linear-gradient(135deg,#0d9488,var(--sky));"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div>
        <div class="auth-logo-text">Scholar<span>Hub</span></div>
      </div>
      <div class="auth-head" style="margin-top:8px;">Teacher Registration</div>
      <div class="auth-sub">Create your teacher portal account</div>
      <div id="tr-err" class="alert alert-err"></div>
      <div id="tr-ok" class="alert alert-ok"></div>
      <div class="f-group"><label class="f-label">Full Name</label><input class="f-input" id="tr-name" placeholder="Your full name"/></div>
      <div class="f-group"><label class="f-label">Subject Specialty</label>
        <select class="f-select" id="tr-subject">
          <option value="">Select Subject</option>
          <option>Mathematics</option><option>English</option><option>Physics</option>
          <option>Chemistry</option><option>Biology</option><option>Social Studies</option>
          <option>Hindi</option><option>Computer Science</option><option>Economics</option>
          <option>Accounts</option><option>Science</option><option>All Subjects</option>
        </select>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
        <div class="f-group"><label class="f-label">Username</label><input class="f-input" id="tr-user" placeholder="Choose username"/></div>
        <div class="f-group"><label class="f-label">Password</label><input class="f-input" id="tr-pass" type="password" placeholder="Min 6 chars"/></div>
      </div>
      <button class="btn-primary" id="tr-btn" onclick="doTeacherRegister()" style="background:linear-gradient(135deg,#0d9488,var(--sky));">Register as Teacher →</button>
      <button class="btn-outline" onclick="showScreen('screen-login')">Back to login</button>
    </div>
  </div>
</div>

<!-- ADMIN -->
<div id="screen-admin" class="screen">
  <aside class="sidebar">
    <div class="sb-brand">
      <div class="sb-brand-inner"><div class="sb-brand-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="sb-brand-name">Scholar<span>Hub</span></div></div>
      <div class="sb-role-pill"><div class="sb-role-dot" style="background:var(--violet);"></div><span class="sb-role-text">Admin</span></div>
    </div>
    <nav class="nav">
      <div class="nav-section">Main</div>
      <div class="nav-item active" onclick="aPage('overview',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg><span>Overview</span></div>
      <div class="nav-item" onclick="aPage('students',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><span>Students</span><span class="nav-badge" id="nb-pend" style="display:none;">0</span></div>
      <div class="nav-item" onclick="aPage('teachers',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><span>Teachers</span><span class="nav-badge" id="nb-tpend" style="display:none;">0</span></div>
      <div class="nav-section">Records</div>
      <div class="nav-item" onclick="aPage('assignments',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg><span>Assignments</span></div>
      <div class="nav-item" onclick="aPage('grades',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><span>Marks & Grades</span></div>
      <div class="nav-item" onclick="aPage('attendance',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><polyline points="9 16 11 18 15 14"/></svg><span>Attendance</span></div>
      <div class="nav-item" onclick="aPage('assigns',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/></svg><span>Homework</span></div>
      <div class="nav-item" onclick="aPage('notices',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><span>Notice Board</span></div>
      <div class="nav-item" onclick="aPage('timetable',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><span>Timetable</span></div>
    </nav>
    <div class="sb-user">
      <div class="sb-user-info"><div class="sb-av av-p">AD</div><div><div class="sb-user-name">Administrator</div><div class="sb-user-sub">admin@scholarhub</div></div></div>
      <button class="btn-logout" onclick="doLogout()">Sign out</button>
    </div>
  </aside>
  <main class="main">
    <div id="ap-overview" class="page active">
      <div class="topbar"><div><div class="page-title">Dashboard</div><div class="page-sub">School overview at a glance</div></div><span class="badge b-violet">Administrator</span></div>
      <div class="stat-grid">
        <div class="stat-card sc-p"><div class="stat-icon si-p"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg></div><div class="stat-val" id="ov-st" style="color:var(--primary2);">0</div><div class="stat-label">Total Students</div></div>
        <div class="stat-card sc-a"><div class="stat-icon si-a"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div><div class="stat-val" id="ov-pend" style="color:var(--amber);">0</div><div class="stat-label">Pending Approval</div></div>
        <div class="stat-card sc-g"><div class="stat-icon si-g"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div><div class="stat-val" id="ov-as" style="color:var(--green);">0</div><div class="stat-label">Homework Posted</div></div>
        <div class="stat-card sc-r"><div class="stat-icon si-r"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg></div><div class="stat-val" id="ov-no" style="color:var(--rose);">0</div><div class="stat-label">Notices Posted</div></div>
      </div>
      <div class="g2">
        <div class="card"><div class="card-header"><div class="card-title">Students by Class</div></div><div id="ov-class-bars"></div></div>
        <div class="card"><div class="card-header"><div class="card-title">Recent Students</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Class</th><th>Roll No</th><th>Status</th></tr></thead><tbody id="ov-tbody"></tbody></table></div></div>
      </div>
    </div>
    <div id="ap-students" class="page">
      <div class="topbar"><div><div class="page-title">Students</div><div class="page-sub">Manage registrations and accounts</div></div></div>
      <div class="card"><div class="card-header"><div class="card-title">Pending Approval <span class="pending-pill" id="pend-pill">0</span></div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Roll No</th><th>Class</th><th>Section</th><th>Username</th><th>Action</th></tr></thead><tbody id="pend-tbody"></tbody></table></div></div>
      <div class="card"><div class="card-header"><div class="card-title">Approved Students</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Roll No</th><th>Class</th><th>Section</th><th>Username</th><th>Joined</th><th>Action</th></tr></thead><tbody id="appr-tbody"></tbody></table></div></div>
    </div>

    <div id="ap-teachers" class="page">
      <div class="topbar"><div><div class="page-title">Teachers</div><div class="page-sub">Manage teacher accounts</div></div></div>
      <div class="card"><div class="card-header"><div class="card-title">Pending Approval <span class="pending-pill" id="tpend-pill">0</span></div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Subject</th><th>Username</th><th>Registered</th><th>Action</th></tr></thead><tbody id="tpend-tbody"></tbody></table></div></div>
      <div class="card"><div class="card-header"><div class="card-title">Approved Teachers</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Subject</th><th>Username</th><th>Joined</th><th>Action</th></tr></thead><tbody id="tappr-tbody"></tbody></table></div></div>
    </div>
    <div id="ap-assignments" class="page">
      <div class="topbar"><div><div class="page-title">Assignments</div><div class="page-sub">Post assignments with multiple photos & files</div></div></div>
      <div class="form-section">
        <div class="form-section-title">Post New Assignment</div>
        <div id="asf-ok" class="flash flash-ok">✓ Assignment posted!</div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Title</label><input class="fi" id="asf-title" placeholder="Assignment title"/></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="asf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">For Class</label><select class="fs" id="asf-class"><option value="All">All Classes</option><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select></div>
        </div>
        <div class="f-row f-row-2">
          <div class="f-grp"><label class="f-lbl">Due Date</label><input class="fi" id="asf-due" type="date"/></div>
          <div class="f-grp"><label class="f-lbl">Priority</label><select class="fs" id="asf-pri"><option>High</option><option selected>Medium</option><option>Low</option></select></div>
        </div>
        <div class="f-grp" style="margin-bottom:14px;"><label class="f-lbl">Description</label><textarea class="ft" id="asf-desc" rows="2" placeholder="Describe the assignment..."></textarea></div>
        <div class="f-grp" style="margin-bottom:14px;">
          <label class="f-lbl">📎 Upload Photos / PDFs (unlimited files)</label>
          <label style="display:block;border:2px dashed rgba(255,255,255,.15);border-radius:14px;padding:24px;text-align:center;cursor:pointer;background:var(--bg3);transition:all .2s;" onmouseover="this.style.borderColor='var(--primary2)'" onmouseout="this.style.borderColor='rgba(255,255,255,.15)'">
            <input type="file" id="asf-files" multiple accept="image/*,.pdf" style="display:none;" onchange="handleFileSelect('asf-files','asf-preview-grid')"/>
            <div style="font-size:28px;margin-bottom:8px;">📁</div>
            <div style="color:var(--primary2);font-weight:700;font-size:13px;">Click to choose files</div>
            <div style="color:var(--text3);font-size:12px;margin-top:4px;">Photos & PDFs · Unlimited files</div>
          </label>
          <div id="asf-preview-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(90px,1fr));gap:8px;margin-top:12px;"></div>
        </div>
        <button class="btn-save" id="asf-btn" onclick="saveAssignment('asf')">Post Assignment</button>
      </div>
      <div id="assignments-list-admin"></div>
    </div>
    <div id="ap-grades" class="page">
      <div class="topbar"><div><div class="page-title">Marks & Grades</div><div class="page-sub">Enter marks per student</div></div></div>
      <div class="form-section">
        <div class="form-section-title">Add Mark Record</div>
        <div id="gf-ok" class="flash flash-ok">✓ Grade saved successfully!</div>
        <div id="gf-err" class="flash flash-err"></div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Student</label><select class="fs" id="gf-st" onchange="updateSubjects('gf-sub','gf-st')"><option value="">Select student</option></select></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="gf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">Exam Type</label><select class="fs" id="gf-exam"><option>Unit Test</option><option>Half Yearly</option><option>Annual</option><option>Practical</option></select></div>
        </div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Max Marks</label><input class="fi" id="gf-max" type="number" min="0" placeholder="100" oninput="calcGrade()"/></div>
          <div class="f-grp"><label class="f-lbl">Obtained</label><input class="fi" id="gf-obt" type="number" min="0" placeholder="75" oninput="calcGrade()"/></div>
          <div class="f-grp"><label class="f-lbl">Grade</label><input class="fi" id="gf-grd" readonly/></div>
        </div>
        <button class="btn-save" id="gf-btn" onclick="saveGrade()">Save Grade</button>
      </div>
      <div class="card"><div class="card-header"><div class="card-title">All Grade Records</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Class</th><th>Subject</th><th>Exam</th><th>Max</th><th>Obtained</th><th>%</th><th>Grade</th><th></th></tr></thead><tbody id="grd-tbody"></tbody></table></div></div>
    </div>
    <div id="ap-attendance" class="page">
      <div class="topbar"><div><div class="page-title">Attendance</div><div class="page-sub">Mark attendance per student</div></div></div>
      <div class="form-section">
        <div class="form-section-title">Mark Attendance</div>
        <div id="af-ok" class="flash flash-ok">✓ Attendance saved!</div>
        <div id="af-err" class="flash flash-err"></div>
        <div class="f-row f-row-4">
          <div class="f-grp"><label class="f-lbl">Student</label><select class="fs" id="af-st" onchange="updateSubjects('af-sub','af-st')"><option value="">Select</option></select></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="af-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">Total Classes</label><input class="fi" id="af-tot" type="number" min="0" placeholder="40"/></div>
          <div class="f-grp"><label class="f-lbl">Present</label><input class="fi" id="af-pre" type="number" min="0" placeholder="35"/></div>
        </div>
        <button class="btn-save" id="af-btn" onclick="saveAtt()">Save Attendance</button>
      </div>
      <div class="card"><div class="card-header"><div class="card-title">Attendance Records</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Class</th><th>Subject</th><th>Total</th><th>Present</th><th>Absent</th><th>%</th><th>Status</th><th></th></tr></thead><tbody id="att-tbody"></tbody></table></div></div>
    </div>
    <div id="ap-assigns" class="page">
      <div class="topbar"><div><div class="page-title">Homework</div><div class="page-sub">Post homework for students</div></div></div>
      <div class="form-section">
        <div class="form-section-title">Add Homework</div>
        <div id="hf-ok" class="flash flash-ok">✓ Homework posted!</div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Title</label><input class="fi" id="hf-title" placeholder="Homework title"/></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="hf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">For Class</label><select class="fs" id="hf-class"><option value="All">All Classes</option><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select></div>
        </div>
        <div class="f-row f-row-2">
          <div class="f-grp"><label class="f-lbl">Due Date</label><input class="fi" id="hf-due" type="date"/></div>
          <div class="f-grp"><label class="f-lbl">Priority</label><select class="fs" id="hf-pri"><option>High</option><option>Medium</option><option>Low</option></select></div>
        </div>
        <div class="f-grp" style="margin-bottom:14px;"><label class="f-lbl">Description</label><textarea class="ft" id="hf-desc" rows="2" placeholder="Describe the task..."></textarea></div>
        <button class="btn-save" id="hf-btn" onclick="saveHW()">Post Homework</button>
      </div>
      <div class="card"><div class="card-header"><div class="card-title">All Homework</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Title</th><th>Subject</th><th>Class</th><th>Due Date</th><th>Priority</th><th></th></tr></thead><tbody id="hw-tbody"></tbody></table></div></div>
    </div>
    <div id="ap-notices" class="page">
      <div class="topbar"><div><div class="page-title">Notice Board</div><div class="page-sub">Post announcements</div></div></div>
      <div class="form-section">
        <div class="form-section-title">Post Notice</div>
        <div id="nf-ok" class="flash flash-ok">✓ Notice posted!</div>
        <div class="f-row f-row-2">
          <div class="f-grp"><label class="f-lbl">Title</label><input class="fi" id="nf-title" placeholder="Notice title"/></div>
          <div class="f-grp"><label class="f-lbl">Category</label><select class="fs" id="nf-cat"><option>Exam</option><option>Event</option><option>Fee</option><option>Holiday</option><option>General</option></select></div>
        </div>
        <div class="f-grp" style="margin-bottom:14px;"><label class="f-lbl">Message</label><textarea class="ft" id="nf-msg" rows="3" placeholder="Type notice here..."></textarea></div>
        <button class="btn-save" id="nf-btn" onclick="saveNotice()">Post Notice</button>
      </div>
      <div id="nlist-admin"></div>
    </div>
    <div id="ap-timetable" class="page">
      <div class="topbar"><div><div class="page-title">Timetable</div><div class="page-sub">Manage class schedules</div></div></div>
      <div class="form-section">
        <div class="form-section-title">Add Entry</div>
        <div id="tf-ok" class="flash flash-ok">✓ Entry saved!</div>
        <div class="f-row f-row-4">
          <div class="f-grp"><label class="f-lbl">Class</label><select class="fs" id="tf-class"><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select></div>
          <div class="f-grp"><label class="f-lbl">Day</label><select class="fs" id="tf-day"><option>Monday</option><option>Tuesday</option><option>Wednesday</option><option>Thursday</option><option>Friday</option><option>Saturday</option></select></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="tf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">Period</label><select class="fs" id="tf-period"><option>1st (8:00–8:45)</option><option>2nd (8:45–9:30)</option><option>3rd (9:30–10:15)</option><option>4th (10:30–11:15)</option><option>5th (11:15–12:00)</option><option>6th (12:45–1:30)</option><option>7th (1:30–2:15)</option></select></div>
        </div>
        <button class="btn-save" id="tf-btn" onclick="saveTT()">Add Entry</button>
      </div>
      <div class="card"><div class="card-header"><div class="card-title">Timetable Entries</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Class</th><th>Day</th><th>Period</th><th>Subject</th><th></th></tr></thead><tbody id="tt-tbody"></tbody></table></div></div>
    </div>
  </main>
</div>


<!-- TEACHER SCREEN -->
<div id="screen-teacher" class="screen">
  <aside class="sidebar" style="border-right-color:rgba(45,212,191,.2);">
    <div class="sb-brand">
      <div class="sb-brand-inner"><div class="sb-brand-mark" style="background:linear-gradient(135deg,#0d9488,var(--sky));"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="sb-brand-name">Scholar<span>Hub</span></div></div>
      <div class="sb-role-pill"><div class="sb-role-dot" style="background:#2dd4bf;"></div><span class="sb-role-text">Teacher</span></div>
    </div>
    <nav class="nav">
      <div class="nav-section">Main</div>
      <div class="nav-item active" onclick="tPage('dash',this)" style=""><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg><span>Dashboard</span></div>
      <div class="nav-section">Manage</div>
      <div class="nav-item" onclick="tPage('assignments',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg><span>Assignments</span></div>
      <div class="nav-item" onclick="tPage('grades',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><span>Enter Marks</span></div>
      <div class="nav-item" onclick="tPage('attendance',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><polyline points="9 16 11 18 15 14"/></svg><span>Attendance</span></div>
      <div class="nav-item" onclick="tPage('profile',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><span>My Profile</span></div>
    </nav>
    <div class="sb-user">
      <div class="sb-user-info"><div class="sb-av" style="background:linear-gradient(135deg,#0d9488,var(--sky));color:white;" id="t-av-sidebar">TC</div><div><div class="sb-user-name" id="t-sname">Teacher</div><div class="sb-user-sub" id="t-ssub">Subject</div></div></div>
      <button class="btn-logout" onclick="doLogout()">Sign out</button>
    </div>
  </aside>
  <main class="main">
    <div id="tp-dash" class="page active">
      <div class="topbar"><div><div class="page-title" id="t-greet">Welcome!</div><div class="page-sub" id="t-sub2"></div></div><span class="badge" style="background:rgba(45,212,191,.12);color:#2dd4bf;border:1px solid rgba(45,212,191,.3);">🎓 Teacher</span></div>
      <div class="stat-grid">
        <div class="stat-card sc-p"><div class="stat-icon" style="background:rgba(45,212,191,.12);"><svg viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg></div><div class="stat-val" id="t-nst" style="color:#2dd4bf;">0</div><div class="stat-label">Total Students</div></div>
        <div class="stat-card sc-g"><div class="stat-icon si-g"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></div><div class="stat-val" id="t-nas" style="color:var(--green);">0</div><div class="stat-label">Assignments</div></div>
        <div class="stat-card sc-p"><div class="stat-icon si-p"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><div class="stat-val" id="t-ngr" style="color:var(--primary2);">0</div><div class="stat-label">Marks Entered</div></div>
        <div class="stat-card sc-a"><div class="stat-icon si-a"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/></svg></div><div class="stat-val" id="t-nat" style="color:var(--amber);">0</div><div class="stat-label">Attendance Records</div></div>
      </div>
      <div class="card"><div class="card-header"><div class="card-title">Recent Assignments</div></div><div id="t-recent-assigns"><div class="tbl-empty">No assignments yet</div></div></div>
    </div>
    <div id="tp-assignments" class="page">
      <div class="topbar"><div><div class="page-title">Assignments</div><div class="page-sub">Post with photos & PDFs</div></div></div>
      <div class="form-section" style="border-color:rgba(45,212,191,.2);">
        <div class="form-section-title" style="color:#2dd4bf;">Post New Assignment</div>
        <div id="tasf-ok" class="flash flash-ok">✓ Assignment posted!</div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Title</label><input class="fi" id="tasf-title" placeholder="Assignment title"/></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="tasf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">For Class</label><select class="fs" id="tasf-class"><option value="All">All Classes</option><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select></div>
        </div>
        <div class="f-row f-row-2">
          <div class="f-grp"><label class="f-lbl">Due Date</label><input class="fi" id="tasf-due" type="date"/></div>
          <div class="f-grp"><label class="f-lbl">Priority</label><select class="fs" id="tasf-pri"><option>High</option><option selected>Medium</option><option>Low</option></select></div>
        </div>
        <div class="f-grp" style="margin-bottom:14px;"><label class="f-lbl">Description</label><textarea class="ft" id="tasf-desc" rows="2"></textarea></div>
        <div class="f-grp" style="margin-bottom:14px;">
          <label class="f-lbl">📎 Upload Files (up to 10)</label>
          <label style="display:block;border:2px dashed rgba(45,212,191,.3);border-radius:14px;padding:24px;text-align:center;cursor:pointer;background:var(--bg3);transition:all .2s;">
            <input type="file" id="tasf-files" multiple accept="image/*,.pdf" style="display:none;" onchange="handleFileSelect('tasf-files','tasf-preview-grid')"/>
            <div style="font-size:28px;margin-bottom:8px;">📁</div>
            <div style="color:#2dd4bf;font-weight:700;font-size:13px;">Click to choose files</div>
            <div style="color:var(--text3);font-size:12px;margin-top:4px;">Photos & PDFs · Unlimited files</div>
          </label>
          <div id="tasf-preview-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(90px,1fr));gap:8px;margin-top:12px;"></div>
        </div>
        <button class="btn-save" id="tasf-btn" onclick="saveAssignment('tasf')" style="background:linear-gradient(135deg,#0d9488,var(--sky));">Post Assignment</button>
      </div>
      <div id="t-assignments-list"></div>
    </div>
    <div id="tp-grades" class="page">
      <div class="topbar"><div><div class="page-title">Enter Marks</div><div class="page-sub">Add grades and upload marksheets</div></div></div>
      <div class="form-section" style="border-color:rgba(45,212,191,.2);">
        <div class="form-section-title" style="color:#2dd4bf;">Add Mark Record</div>
        <div id="tgf-ok" class="flash flash-ok">✓ Grade saved!</div>
        <div id="tgf-err" class="flash flash-err"></div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Student</label><select class="fs" id="tgf-st" onchange="updateSubjects('tgf-sub','tgf-st')"><option value="">Select student</option></select></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="tgf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">Exam</label><select class="fs" id="tgf-exam"><option>Unit Test</option><option>Half Yearly</option><option>Annual</option><option>Practical</option></select></div>
        </div>
        <div class="f-row f-row-3">
          <div class="f-grp"><label class="f-lbl">Max Marks</label><input class="fi" id="tgf-max" type="number" min="0" placeholder="100" oninput="calcGradeT()"/></div>
          <div class="f-grp"><label class="f-lbl">Obtained</label><input class="fi" id="tgf-obt" type="number" min="0" placeholder="75" oninput="calcGradeT()"/></div>
          <div class="f-grp"><label class="f-lbl">Grade</label><input class="fi" id="tgf-grd" readonly/></div>
        </div>
        <div class="f-grp" style="margin-bottom:14px;">
          <label class="f-lbl">Upload Marksheet (optional)</label>
          <label style="display:block;border:2px dashed rgba(45,212,191,.2);border-radius:10px;padding:14px;text-align:center;cursor:pointer;background:var(--bg3);">
            <input type="file" id="tgf-file" accept="image/*,.pdf" style="display:none;" onchange="previewSingleFile('tgf-file','tgf-file-preview')"/>
            <span style="color:#2dd4bf;font-size:12.5px;font-weight:600;">📄 Click to upload marksheet</span>
          </label>
          <div id="tgf-file-preview" style="margin-top:6px;font-size:12px;color:var(--text3);"></div>
        </div>
        <button class="btn-save" id="tgf-btn" onclick="saveGradeTeacher()" style="background:linear-gradient(135deg,#0d9488,var(--sky));">Save Grade</button>
      </div>
      <div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Class</th><th>Subject</th><th>Exam</th><th>Max</th><th>Obtained</th><th>%</th><th>Grade</th><th>File</th></tr></thead><tbody id="tgrd-tbody"></tbody></table></div></div>
    </div>
    <div id="tp-attendance" class="page">
      <div class="topbar"><div><div class="page-title">Attendance</div></div></div>
      <div class="form-section" style="border-color:rgba(45,212,191,.2);">
        <div class="form-section-title" style="color:#2dd4bf;">Mark Attendance</div>
        <div id="taf-ok" class="flash flash-ok">✓ Saved!</div>
        <div class="f-row f-row-4">
          <div class="f-grp"><label class="f-lbl">Student</label><select class="fs" id="taf-st" onchange="updateSubjects('taf-sub','taf-st')"><option value="">Select</option></select></div>
          <div class="f-grp"><label class="f-lbl">Subject</label><select class="fs" id="taf-sub"></select></div>
          <div class="f-grp"><label class="f-lbl">Total Classes</label><input class="fi" id="taf-tot" type="number" min="0" placeholder="40"/></div>
          <div class="f-grp"><label class="f-lbl">Present</label><input class="fi" id="taf-pre" type="number" min="0" placeholder="35"/></div>
        </div>
        <button class="btn-save" id="taf-btn" onclick="saveAttTeacher()" style="background:linear-gradient(135deg,#0d9488,var(--sky));">Save Attendance</button>
      </div>
      <div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Class</th><th>Subject</th><th>Total</th><th>Present</th><th>%</th><th>Status</th></tr></thead><tbody id="tatt-tbody"></tbody></table></div></div>
    </div>
    <div id="tp-profile" class="page">
      <div class="topbar"><div><div class="page-title">My Profile</div></div></div>
      <div style="background:linear-gradient(135deg,#0d7377,#2dd4bf);border-radius:var(--r-xl);padding:32px;margin-bottom:16px;position:relative;overflow:hidden;">
        <div style="width:80px;height:80px;border-radius:50%;background:rgba(255,255,255,.2);border:3px solid rgba(255,255,255,.3);display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:800;color:white;margin-bottom:14px;" id="tp-av-text">TC</div>
        <div style="font-size:20px;font-weight:800;color:white;" id="tp-name">Teacher</div>
        <div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:3px;" id="tp-subject">Subject</div>
      </div>
      <div class="card"><table class="tbl"><tr><td style="color:var(--text3);width:40%;">Username</td><td id="tp-user" style="font-family:var(--mono);font-weight:600;"></td></tr><tr><td style="color:var(--text3);">Role</td><td><span style="background:rgba(45,212,191,.12);color:#2dd4bf;border:1px solid rgba(45,212,191,.3);border-radius:20px;padding:3px 10px;font-size:10.5px;font-weight:700;">🎓 Teacher</span></td></tr><tr><td style="color:var(--text3);">Status</td><td><span class="badge b-green">Active</span></td></tr></table></div>
    </div>
  </main>
</div>

<!-- STUDENT -->
<div id="screen-student" class="screen">
  <aside class="sidebar">
    <div class="sb-brand">
      <div class="sb-brand-inner"><div class="sb-brand-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="sb-brand-name">Scholar<span>Hub</span></div></div>
      <div class="sb-role-pill"><div class="sb-role-dot" style="background:var(--green);"></div><span class="sb-role-text">Student</span></div>
    </div>
    <nav class="nav">
      <div class="nav-section">Main</div>
      <div class="nav-item active" onclick="sPage('dash',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg><span>My Dashboard</span></div>
      <div class="nav-section">Academics</div>
      <div class="nav-item" onclick="sPage('assignments',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg><span>Assignments</span></div>
      <div class="nav-item" onclick="sPage('grades',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><span>My Marks</span></div>
      <div class="nav-item" onclick="sPage('att',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><polyline points="9 16 11 18 15 14"/></svg><span>Attendance</span></div>
      <div class="nav-item" onclick="sPage('hw',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span>Homework</span></div>
      <div class="nav-item" onclick="sPage('tt',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><span>Timetable</span></div>
      <div class="nav-item" onclick="sPage('notices',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><span>Notices</span></div>
      <div class="nav-item" onclick="sPage('profile',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><span>Profile</span></div>
    </nav>
    <div class="sb-user">
      <div class="sb-user-info"><div class="sb-av av-g" id="s-av">ST</div><div><div class="sb-user-name" id="s-sname">Student</div><div class="sb-user-sub" id="s-ssub">Class</div></div></div>
      <button class="btn-logout" onclick="doLogout()">Sign out</button>
    </div>
  </aside>
  <main class="main">
    <div id="sp-dash" class="page active">
      <div class="topbar"><div><div class="page-title" id="s-greet">Welcome!</div><div class="page-sub" id="s-sub2">Loading...</div></div><span class="badge b-green">Student</span></div>
      <div class="stat-grid">
        <div class="stat-card sc-p"><div class="stat-icon si-p"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><div class="stat-val" id="s-avgG" style="color:var(--primary2);">—</div><div class="stat-label">Avg. Score</div></div>
        <div class="stat-card sc-g"><div class="stat-icon si-g"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><polyline points="9 16 11 18 15 14"/></svg></div><div class="stat-val" id="s-avgA" style="color:var(--green);">—</div><div class="stat-label">Avg. Attendance</div></div>
        <div class="stat-card sc-a"><div class="stat-icon si-a"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg></div><div class="stat-val" id="s-nHW" style="color:var(--amber);">0</div><div class="stat-label">Homework Due</div></div>
        <div class="stat-card sc-r"><div class="stat-icon si-r"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg></div><div class="stat-val" id="s-nNot" style="color:var(--rose);">0</div><div class="stat-label">Notices</div></div>
      </div>
      <div class="g2">
        <div class="card"><div class="card-header"><div class="card-title">My Marks</div></div><div id="d-grades"><div class="tbl-empty">No marks yet</div></div></div>
        <div class="card"><div class="card-header"><div class="card-title">Attendance</div></div><div id="d-att"><div class="tbl-empty">No attendance yet</div></div></div>
      </div>
      <div class="g2">
        <div class="card"><div class="card-header"><div class="card-title">Upcoming Homework</div></div><div id="d-hw"><div class="tbl-empty">No homework yet</div></div></div>
        <div class="card"><div class="card-header"><div class="card-title">Latest Notices</div></div><div id="d-not"><div class="tbl-empty">No notices yet</div></div></div>
      </div>
    </div>

    <div id="sp-assignments" class="page">
      <div class="topbar"><div><div class="page-title">Assignments</div><div class="page-sub">View and submit your work</div></div></div>
      <div id="s-assignments-list"></div>
    </div>
    <div id="sp-grades" class="page"><div class="topbar"><div><div class="page-title">My Marks</div><div class="page-sub">Your academic performance</div></div></div><div class="card"><div class="card-header"><div class="card-title">All Marks</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Subject</th><th>Exam</th><th>Max</th><th>Obtained</th><th>%</th><th>Grade</th><th>Status</th></tr></thead><tbody id="sg-tbody"></tbody></table></div></div></div>
    <div id="sp-att" class="page"><div class="topbar"><div><div class="page-title">Attendance</div><div class="page-sub">Your class presence</div></div></div><div class="card"><div class="card-header"><div class="card-title">Attendance Summary</div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Subject</th><th>Total</th><th>Present</th><th>Absent</th><th>%</th><th>Status</th></tr></thead><tbody id="sa-tbody"></tbody></table></div></div></div>
    <div id="sp-hw" class="page"><div class="topbar"><div><div class="page-title">Homework</div><div class="page-sub">Your assignments</div></div></div><div id="s-hwlist"></div></div>
    <div id="sp-tt" class="page"><div class="topbar"><div><div class="page-title">My Timetable</div><div class="page-sub">Your class schedule</div></div></div><div id="s-ttlist"></div></div>
    <div id="sp-notices" class="page"><div class="topbar"><div><div class="page-title">Notice Board</div><div class="page-sub">School announcements</div></div></div><div id="s-notlist"></div></div>
    <div id="sp-profile" class="page">
      <div class="topbar"><div><div class="page-title">My Profile</div><div class="page-sub">Your account details</div></div></div>
      <div class="profile-hero"><div class="profile-av-lg" id="p-av">ST</div><div class="profile-name" id="p-name">Student Name</div><div class="profile-sub" id="p-class-sec">Class —</div></div>
      <div class="g2">
        <div class="card"><div class="card-header"><div class="card-title">Academic Info</div></div><table class="tbl"><tr><td style="color:var(--text3);width:40%;">Roll Number</td><td id="p-roll" style="font-family:var(--mono);font-weight:600;"></td></tr><tr><td style="color:var(--text3);">Class</td><td id="p-cls"></td></tr><tr><td style="color:var(--text3);">Section</td><td id="p-sec"></td></tr></table></div>
        <div class="card"><div class="card-header"><div class="card-title">Account Info</div></div><table class="tbl"><tr><td style="color:var(--text3);width:40%;">Username</td><td id="p-user" style="font-family:var(--mono);font-weight:600;"></td></tr><tr><td style="color:var(--text3);">Status</td><td><span class="badge b-green">Active</span></td></tr></table></div>
      </div>
    </div>
  </main>
</div>

<script>
// ── Constants ──────────────────────────────────────────────
const SUBJECTS = {
  'Class 6':  ['Mathematics','English','Science','Social Studies','Hindi','Computer'],
  'Class 7':  ['Mathematics','English','Science','Social Studies','Hindi','Computer'],
  'Class 8':  ['Mathematics','English','Science','Social Studies','Hindi','Computer'],
  'Class 9':  ['Mathematics','English','Physics','Chemistry','Biology','Social Studies','Hindi'],
  'Class 10': ['Mathematics','English','Physics','Chemistry','Biology','Social Studies','Hindi'],
  'Class 11': ['Mathematics','English','Physics','Chemistry','Biology','Computer Science','Economics','Accounts'],
  'Class 12': ['Mathematics','English','Physics','Chemistry','Biology','Computer Science','Economics','Accounts'],
};
const ALL_SUBS = [...new Set(Object.values(SUBJECTS).flat())];
const CLASSES  = ['Class 6','Class 7','Class 8','Class 9','Class 10','Class 11','Class 12'];

let curRole = 'student';
let curStudent = null;
let allStudents = [];

// ── API helpers ────────────────────────────────────────────
async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  return r.json();
}
const GET  = url       => api('GET',    url);
const POST = (url, b)  => api('POST',   url, b);
const DEL  = url       => api('DELETE', url);

// ── UI helpers ─────────────────────────────────────────────
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}
function setText(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }
function showAlert(id, msg, type='err') {
  const e = document.getElementById(id);
  if (!e) return;
  e.className = 'alert alert-' + type;
  e.textContent = msg;
  e.style.display = 'block';
}
function hideAlert(id) { const e = document.getElementById(id); if (e) e.style.display = 'none'; }
function flashMsg(id) { const e = document.getElementById(id); if (e) { e.style.display = 'block'; setTimeout(() => e.style.display = 'none', 3000); } }
function setLoading(btnId, loading) {
  const b = document.getElementById(btnId);
  if (!b) return;
  b.disabled = loading;
  b.innerHTML = loading ? '<span class="spinner"></span>Please wait...' : b.getAttribute('data-label') || b.textContent;
}
function saveLabel(btnId) {
  const b = document.getElementById(btnId);
  if (b && !b.getAttribute('data-label')) b.setAttribute('data-label', b.textContent);
}

// ── Role switch ────────────────────────────────────────────
function switchRole(r, el) {
  curRole = r;
  document.querySelectorAll('#screen-login .role-tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
}

// ── Login / Register / Logout ──────────────────────────────
async function doLogin() {
  saveLabel('login-btn');
  setLoading('login-btn', true);
  hideAlert('l-err');
  const username = document.getElementById('l-user').value.trim();
  const password = document.getElementById('l-pass').value;
  if (!username || !password) { showAlert('l-err', 'Please enter username and password.'); setLoading('login-btn', false); return; }
  const r = await POST('/api/login', { username, password, role: curRole });
  setLoading('login-btn', false);
  if (!r.ok) { showAlert('l-err', r.msg || 'Login failed.'); return; }
  if (r.role === 'admin') { showScreen('screen-admin'); loadAdminOverview(); }
  else { curStudent = r.student; showScreen('screen-student'); loadStudentDash(); }
}

async function doRegister() {
  saveLabel('reg-btn');
  setLoading('reg-btn', true);
  hideAlert('r-err'); hideAlert('r-ok');
  const name     = document.getElementById('r-name').value.trim();
  const roll     = document.getElementById('r-roll').value.trim();
  const cls      = document.getElementById('r-class').value;
  const section  = document.getElementById('r-sec').value;
  const username = document.getElementById('r-user').value.trim();
  const password = document.getElementById('r-pass').value;
  const r = await POST('/api/register', { name, roll, cls, section, username, password });
  setLoading('reg-btn', false);
  if (!r.ok) { showAlert('r-err', r.msg || 'Registration failed.'); return; }
  showAlert('r-ok', r.msg, 'ok');
  ['r-name','r-roll','r-user','r-pass'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('r-class').value = '';
}

async function doLogout() {
  await POST('/api/logout');
  curStudent = null; allStudents = [];
  showScreen('screen-login');
  document.getElementById('l-user').value = '';
  document.getElementById('l-pass').value = '';
}

// ── Check session on load ──────────────────────────────────
async function checkSession() {
  const r = await GET('/api/me');
  if (!r.ok) return;
  if (r.role === 'admin') { showScreen('screen-admin'); loadAdminOverview(); }
  else { curStudent = r.student; showScreen('screen-student'); loadStudentDash(); }
}

// ── Admin Navigation ───────────────────────────────────────
function aPage(name, el) {
  document.querySelectorAll('#screen-admin .page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('#screen-admin .nav-item').forEach(l => l.classList.remove('active'));
  document.getElementById('ap-' + name).classList.add('active');
  el.classList.add('active');
  ({ overview: loadAdminOverview, students: loadStudentsPage, grades: loadGradesPage,
     attendance: loadAttPage, assigns: loadHWPage, notices: loadNoticesPage, timetable: loadTTPage })[name]?.();
}

async function loadAdminOverview() {
  const [statsR, studentsR, teachersR] = await Promise.all([GET('/api/stats'), GET('/api/students'), GET('/api/teachers')]);
  allStudents = studentsR.students || [];
  if (statsR.ok) {
    setText('ov-st', statsR.totalStudents);
    setText('ov-pend', statsR.pending);
    setText('ov-as', statsR.homework);
    setText('ov-no', statsR.notices);
    updatePendBadge(statsR.pending);
    const max = Math.max(...Object.values(statsR.classCounts), 1);
    document.getElementById('ov-class-bars').innerHTML = CLASSES.map(c => {
      const n = statsR.classCounts[c] || 0;
      return \`<div class="bar-row"><span class="bar-label">\${c.replace('Class ','C-')}</span><div class="bar-bg"><div class="bar-fill" style="width:\${Math.round(n/max*100)}%;background:var(--primary2);"></div></div><span class="bar-val" style="color:var(--primary2);">\${n}</span></div>\`;
    }).join('');
  }
  document.getElementById('ov-tbody').innerHTML = allStudents.slice(-8).reverse().map(s =>
    \`<tr><td><strong>\${s.name}</strong></td><td><span class="badge b-primary">\${s.cls}</span></td><td style="font-family:var(--mono);font-size:12px;">\${s.roll}</td><td><span class="badge \${s.approved?'b-green':'b-amber'}">\${s.approved?'Active':'Pending'}</span></td></tr>\`
  ).join('') || '<tr><td colspan="4" class="tbl-empty">No students yet</td></tr>';
}

async function loadStudentsPage() {
  const r = await GET('/api/students');
  allStudents = r.students || [];
  const pend = allStudents.filter(s => !s.approved);
  const appr = allStudents.filter(s => s.approved);
  setText('pend-pill', pend.length);
  updatePendBadge(pend.length);
  document.getElementById('pend-tbody').innerHTML = pend.map(s =>
    \`<tr><td><strong>\${s.name}</strong></td><td style="font-family:var(--mono);font-size:12px;">\${s.roll}</td><td>\${s.cls}</td><td>\${s.section}</td><td style="font-family:var(--mono);font-size:12px;">\${s.username}</td><td><button class="btn-approve" onclick="approveStudent(\${s.id})">Approve</button></td></tr>\`
  ).join('') || '<tr><td colspan="6" class="tbl-empty">No pending requests</td></tr>';
  document.getElementById('appr-tbody').innerHTML = appr.map(s =>
    \`<tr><td><strong>\${s.name}</strong></td><td style="font-family:var(--mono);font-size:12px;">\${s.roll}</td><td>\${s.cls}</td><td>\${s.section}</td><td style="font-family:var(--mono);font-size:12px;">\${s.username}</td><td style="font-size:11px;color:var(--text3);">\${s.createdAt?new Date(s.createdAt).toLocaleDateString():''}</td><td><button class="btn-del" onclick="deleteStudent(\${s.id})">Remove</button></td></tr>\`
  ).join('') || '<tr><td colspan="7" class="tbl-empty">No approved students yet</td></tr>';
}

async function approveStudent(id) {
  await POST(\`/api/students/\${id}/approve\`);
  loadStudentsPage(); loadAdminOverview();
}
async function deleteStudent(id) {
  if (!confirm('Remove this student and all their records?')) return;
  await DEL(\`/api/students/\${id}\`);
  loadStudentsPage(); loadAdminOverview();
}
function updatePendBadge(n) {
  const b = document.getElementById('nb-pend');
  if (!b) return;
  b.style.display = n > 0 ? 'inline' : 'none';
  b.textContent = n;
}

// ── Grades (Admin) ─────────────────────────────────────────
async function loadGradesPage() {
  const r = await GET('/api/students');
  allStudents = (r.students || []).filter(s => s.approved);
  document.getElementById('gf-st').innerHTML = '<option value="">Select student</option>' +
    allStudents.map(s => \`<option value="\${s.id}">\${s.name} (\${s.cls}-\${s.section})</option>\`).join('');
  updateSubjects('gf-sub','gf-st');
  populateAllSubs('hf-sub'); populateAllSubs('tf-sub');
  await refreshGradeTable();
}
async function refreshGradeTable() {
  const r = await GET('/api/grades');
  const grades = r.grades || [];
  document.getElementById('grd-tbody').innerHTML = grades.map(g => {
    const st = allStudents.find(s => s.id === g.sid);
    const pct = Math.round(g.obt / g.max * 100);
    const col = gradeColor(pct);
    return \`<tr><td><strong>\${st?st.name:'Unknown'}</strong></td><td><span class="badge b-primary">\${st?st.cls:'—'}</span></td><td>\${g.sub}</td><td>\${g.exam}</td><td>\${g.max}</td><td style="font-family:var(--mono);font-weight:700;color:\${col};">\${g.obt}</td><td style="font-family:var(--mono);font-weight:700;color:\${col};">\${pct}%</td><td><span class="badge" style="background:\${col}1a;color:\${col};">\${gradeLabel(pct)}</span></td><td><button class="btn-del" onclick="delGrade(\${g.id})">Del</button></td></tr>\`;
  }).join('') || '<tr><td colspan="9" class="tbl-empty">No grade records yet</td></tr>';
}
async function saveGrade() {
  saveLabel('gf-btn'); setLoading('gf-btn', true);
  hideAlert('gf-err');
  const sid = document.getElementById('gf-st').value;
  const sub = document.getElementById('gf-sub').value;
  const exam = document.getElementById('gf-exam').value;
  const max  = document.getElementById('gf-max').value;
  const obt  = document.getElementById('gf-obt').value;
  const r = await POST('/api/grades', { sid: parseInt(sid), sub, exam, max: parseInt(max), obt: parseInt(obt) });
  setLoading('gf-btn', false);
  if (!r.ok) { showAlert('gf-err', r.msg || 'Error saving grade.'); return; }
  flashMsg('gf-ok');
  document.getElementById('gf-max').value = '';
  document.getElementById('gf-obt').value = '';
  document.getElementById('gf-grd').value = '';
  await refreshGradeTable();
}
async function delGrade(id) {
  await DEL('/api/grades/' + id);
  refreshGradeTable();
}
function calcGrade() {
  const max = parseInt(document.getElementById('gf-max').value) || 0;
  const obt = parseInt(document.getElementById('gf-obt').value) || 0;
  document.getElementById('gf-grd').value = max > 0 ? gradeLabel(Math.round(obt/max*100)) : '';
}

// ── Attendance (Admin) ─────────────────────────────────────
async function loadAttPage() {
  const r = await GET('/api/students');
  allStudents = (r.students || []).filter(s => s.approved);
  document.getElementById('af-st').innerHTML = '<option value="">Select student</option>' +
    allStudents.map(s => \`<option value="\${s.id}">\${s.name} (\${s.cls}-\${s.section})</option>\`).join('');
  updateSubjects('af-sub','af-st');
  await refreshAttTable();
}
async function refreshAttTable() {
  const r = await GET('/api/attendance');
  const att = r.attendance || [];
  document.getElementById('att-tbody').innerHTML = att.map(a => {
    const st = allStudents.find(s => s.id === a.sid);
    const pct = Math.round(a.pre / a.tot * 100);
    const col = pct>=75?'var(--green)':pct>=50?'var(--amber)':'var(--rose)';
    return \`<tr><td><strong>\${st?st.name:'Unknown'}</strong></td><td><span class="badge b-primary">\${st?st.cls:'—'}</span></td><td>\${a.sub}</td><td>\${a.tot}</td><td>\${a.pre}</td><td>\${a.tot-a.pre}</td><td style="font-family:var(--mono);font-weight:700;color:\${col};">\${pct}%</td><td><span class="badge \${pct>=75?'b-green':pct>=50?'b-amber':'b-rose'}">\${pct>=75?'Good':pct>=50?'Average':'Warning'}</span></td><td><button class="btn-del" onclick="delAtt(\${a.id})">Del</button></td></tr>\`;
  }).join('') || '<tr><td colspan="9" class="tbl-empty">No attendance records yet</td></tr>';
}
async function saveAtt() {
  saveLabel('af-btn'); setLoading('af-btn', true);
  const sid = document.getElementById('af-st').value;
  const sub = document.getElementById('af-sub').value;
  const tot = document.getElementById('af-tot').value;
  const pre = document.getElementById('af-pre').value;
  const r = await POST('/api/attendance', { sid: parseInt(sid), sub, tot: parseInt(tot), pre: parseInt(pre) });
  setLoading('af-btn', false);
  if (!r.ok) { showAlert('af-err', r.msg || 'Error.'); return; }
  flashMsg('af-ok');
  document.getElementById('af-tot').value = '';
  document.getElementById('af-pre').value = '';
  await refreshAttTable();
}
async function delAtt(id) { await DEL('/api/attendance/' + id); refreshAttTable(); }

// ── Homework (Admin) ───────────────────────────────────────
async function loadHWPage() {
  populateAllSubs('hf-sub');
  await refreshHWTable();
}
async function refreshHWTable() {
  const r = await GET('/api/homework');
  const hw = r.homework || [];
  document.getElementById('hw-tbody').innerHTML = hw.map(h => {
    const pb = h.pri==='High'?'b-rose':h.pri==='Medium'?'b-amber':'b-green';
    return \`<tr><td><strong>\${h.title}</strong></td><td>\${h.sub}</td><td><span class="badge b-primary">\${h.cls}</span></td><td style="font-family:var(--mono);font-size:12px;">\${h.due}</td><td><span class="badge \${pb}">\${h.pri}</span></td><td><button class="btn-del" onclick="delHW(\${h.id})">Del</button></td></tr>\`;
  }).join('') || '<tr><td colspan="6" class="tbl-empty">No homework posted yet</td></tr>';
}
async function saveHW() {
  saveLabel('hf-btn'); setLoading('hf-btn', true);
  const title = document.getElementById('hf-title').value.trim();
  const sub   = document.getElementById('hf-sub').value;
  const cls   = document.getElementById('hf-class').value;
  const due   = document.getElementById('hf-due').value;
  const pri   = document.getElementById('hf-pri').value;
  const desc  = document.getElementById('hf-desc').value.trim();
  const r = await POST('/api/homework', { title, sub, cls, due, pri, desc });
  setLoading('hf-btn', false);
  if (!r.ok) { alert(r.msg || 'Error'); return; }
  flashMsg('hf-ok');
  document.getElementById('hf-title').value = '';
  document.getElementById('hf-desc').value = '';
  document.getElementById('hf-due').value = '';
  await refreshHWTable();
}
async function delHW(id) { await DEL('/api/homework/' + id); refreshHWTable(); }

// ── Notices (Admin) ────────────────────────────────────────
async function loadNoticesPage() { await refreshNoticesAdmin(); }
async function refreshNoticesAdmin() {
  const r = await GET('/api/notices');
  const notices = r.notices || [];
  document.getElementById('nlist-admin').innerHTML = notices.map((n, i) => \`
    <div class="card" style="animation:pageIn .3s ease \${i*0.04}s both;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <span class="badge \${notCat(n.cat)}">\${n.cat}</span>
        <strong style="font-size:14px;color:var(--text);">\${n.title}</strong>
        <span style="margin-left:auto;font-size:11px;color:var(--text3);">\${n.date}</span>
        <button class="btn-del" onclick="delNotice(\${n.id})">Delete</button>
      </div>
      <div style="font-size:13px;color:var(--text2);line-height:1.6;">\${n.msg}</div>
    </div>\`).join('') || '<div class="card"><div class="tbl-empty">No notices yet</div></div>';
}
async function saveNotice() {
  saveLabel('nf-btn'); setLoading('nf-btn', true);
  const title = document.getElementById('nf-title').value.trim();
  const cat   = document.getElementById('nf-cat').value;
  const msg   = document.getElementById('nf-msg').value.trim();
  const r = await POST('/api/notices', { title, cat, msg });
  setLoading('nf-btn', false);
  if (!r.ok) { alert(r.msg || 'Error'); return; }
  flashMsg('nf-ok');
  document.getElementById('nf-title').value = '';
  document.getElementById('nf-msg').value = '';
  await refreshNoticesAdmin();
}
async function delNotice(id) { await DEL('/api/notices/' + id); refreshNoticesAdmin(); }

// ── Timetable (Admin) ──────────────────────────────────────
async function loadTTPage() {
  populateAllSubs('tf-sub');
  await refreshTTTable();
}
async function refreshTTTable() {
  const r = await GET('/api/timetable');
  const tt = r.timetable || [];
  document.getElementById('tt-tbody').innerHTML = tt.map(t =>
    \`<tr><td><span class="badge b-primary">\${t.cls}</span></td><td>\${t.day}</td><td style="font-size:12px;color:var(--text3);">\${t.period}</td><td><strong>\${t.sub}</strong></td><td><button class="btn-del" onclick="delTT(\${t.id})">Del</button></td></tr>\`
  ).join('') || '<tr><td colspan="5" class="tbl-empty">No entries yet</td></tr>';
}
async function saveTT() {
  saveLabel('tf-btn'); setLoading('tf-btn', true);
  const cls    = document.getElementById('tf-class').value;
  const day    = document.getElementById('tf-day').value;
  const sub    = document.getElementById('tf-sub').value;
  const period = document.getElementById('tf-period').value;
  const r = await POST('/api/timetable', { cls, day, sub, period });
  setLoading('tf-btn', false);
  if (!r.ok) { alert(r.msg || 'Error'); return; }
  flashMsg('tf-ok');
  await refreshTTTable();
}
async function delTT(id) { await DEL('/api/timetable/' + id); refreshTTTable(); }

// ── Student pages ──────────────────────────────────────────
function sPage(name, el) {
  document.querySelectorAll('#screen-student .page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('#screen-student .nav-item').forEach(l => l.classList.remove('active'));
  document.getElementById('sp-' + name).classList.add('active');
  el.classList.add('active');
  ({ dash: loadStudentDash, assignments: loadStudentAssignments, grades: loadStudentGrades, att: loadStudentAtt, hw: loadStudentHW, tt: loadStudentTT, notices: loadStudentNotices, profile: loadStudentProfile })[name]?.();
}
async function loadStudentDash() {
  const s = curStudent;
  const ini = s.name.split(' ').map(n => n[0]).join('').slice(0,2).toUpperCase();
  setText('s-av', ini); setText('s-sname', s.name); setText('s-ssub', s.cls + ' · Sec ' + s.section);
  setText('s-greet', 'Welcome back, ' + s.name.split(' ')[0] + '! 👋');
  setText('s-sub2', s.cls + ' · Section ' + s.section + ' · Roll: ' + s.roll);
  const [gR, aR, hR, nR] = await Promise.all([GET('/api/grades'), GET('/api/attendance'), GET('/api/homework'), GET('/api/notices')]);
  const gs = gR.grades || [], as = aR.attendance || [], hw = hR.homework || [], notices = nR.notices || [];
  const avgPct = gs.length ? Math.round(gs.reduce((x,g) => x+(g.obt/g.max*100),0)/gs.length) + '%' : '—';
  const avgA   = as.length ? Math.round(as.reduce((x,a) => x+(a.pre/a.tot*100),0)/as.length) + '%' : '—';
  setText('s-avgG', avgPct); setText('s-avgA', avgA); setText('s-nHW', hw.length); setText('s-nNot', notices.length);
  document.getElementById('d-grades').innerHTML = gs.length ? gs.map(g => { const pct=Math.round(g.obt/g.max*100); const c=gradeColor(pct); return \`<div class="bar-row"><span class="bar-label">\${g.sub.length>10?g.sub.slice(0,9)+'…':g.sub}</span><div class="bar-bg"><div class="bar-fill" style="width:\${pct}%;background:\${c};"></div></div><span class="bar-val" style="color:\${c};">\${pct}%</span></div>\`; }).join('') : '<div class="tbl-empty">No marks yet</div>';
  document.getElementById('d-att').innerHTML = as.length ? as.map(a => { const p=Math.round(a.pre/a.tot*100); const c=p>=75?'var(--green)':'var(--rose)'; return \`<div class="bar-row"><span class="bar-label">\${a.sub.length>10?a.sub.slice(0,9)+'…':a.sub}</span><div class="bar-bg"><div class="bar-fill" style="width:\${p}%;background:\${c};"></div></div><span class="bar-val" style="color:\${c};">\${p}%</span></div>\`; }).join('') : '<div class="tbl-empty">No attendance yet</div>';
  document.getElementById('d-hw').innerHTML = hw.length ? hw.slice(0,4).map(h => { const c=h.pri==='High'?'var(--rose)':h.pri==='Medium'?'var(--amber)':'var(--green)'; return \`<div class="item-row"><div class="item-dot" style="background:\${c};"></div><div class="item-body"><div class="item-title">\${h.title}</div><div class="item-meta">\${h.sub} · Due: \${h.due}</div></div></div>\`; }).join('') : '<div class="tbl-empty">No homework yet</div>';
  document.getElementById('d-not').innerHTML = notices.slice(0,3).map(n => \`<div class="item-row"><span class="badge \${notCat(n.cat)}">\${n.cat}</span><div class="item-body" style="margin-left:8px;"><div class="item-title">\${n.title}</div><div class="item-meta">\${n.date}</div></div></div>\`).join('') || '<div class="tbl-empty">No notices yet</div>';
}
async function loadStudentGrades() {
  const r = await GET('/api/grades');
  const gs = r.grades || [];
  document.getElementById('sg-tbody').innerHTML = gs.map(g => { const pct=Math.round(g.obt/g.max*100); const col=gradeColor(pct); return \`<tr><td><strong>\${g.sub}</strong></td><td>\${g.exam}</td><td>\${g.max}</td><td style="font-family:var(--mono);font-weight:700;color:\${col};">\${g.obt}</td><td style="font-family:var(--mono);font-weight:700;color:\${col};">\${pct}%</td><td><span class="badge" style="background:\${col}1a;color:\${col};">\${gradeLabel(pct)}</span></td><td><span class="badge \${pct>=33?'b-green':'b-rose'}">\${pct>=33?'Pass':'Fail'}</span></td></tr>\`; }).join('') || '<tr><td colspan="7" class="tbl-empty">No marks yet</td></tr>';
}
async function loadStudentAtt() {
  const r = await GET('/api/attendance');
  const as = r.attendance || [];
  document.getElementById('sa-tbody').innerHTML = as.map(a => { const p=Math.round(a.pre/a.tot*100); const col=p>=75?'var(--green)':p>=50?'var(--amber)':'var(--rose)'; return \`<tr><td><strong>\${a.sub}</strong></td><td>\${a.tot}</td><td>\${a.pre}</td><td>\${a.tot-a.pre}</td><td style="font-family:var(--mono);font-weight:700;color:\${col};">\${p}%</td><td><span class="badge \${p>=75?'b-green':p>=50?'b-amber':'b-rose'}">\${p>=75?'Good':p>=50?'Average':'Warning'}</span></td></tr>\`; }).join('') || '<tr><td colspan="6" class="tbl-empty">No attendance yet</td></tr>';
}
async function loadStudentHW() {
  const r = await GET('/api/homework');
  const hw = r.homework || [];
  document.getElementById('s-hwlist').innerHTML = hw.length ? hw.map((h,i) => { const pc=h.pri==='High'?'b-rose':h.pri==='Medium'?'b-amber':'b-green'; const dc=h.pri==='High'?'var(--rose)':h.pri==='Medium'?'var(--amber)':'var(--green)'; return \`<div class="card" style="animation:pageIn .3s ease \${i*0.05}s both;"><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;"><strong style="font-size:14px;color:var(--text);">\${h.title}</strong><span class="badge b-sky">\${h.sub}</span><span class="badge \${pc}">\${h.pri}</span><span style="margin-left:auto;font-size:11.5px;color:var(--text3);">Due: <strong style="color:\${dc};font-family:var(--mono);">\${h.due}</strong></span></div>\${h.desc?\`<div style="font-size:12.5px;color:var(--text2);margin-top:4px;">\${h.desc}</div>\`:''}</div>\`; }).join('') : '<div class="card"><div class="tbl-empty">No homework posted for your class yet</div></div>';
}
async function loadStudentTT() {
  const r = await GET('/api/timetable');
  const tt = r.timetable || [];
  const el = document.getElementById('s-ttlist');
  if (!tt.length) { el.innerHTML = '<div class="card"><div class="tbl-empty">No timetable posted yet</div></div>'; return; }
  const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  el.innerHTML = days.map(day => {
    const entries = tt.filter(t => t.day === day);
    if (!entries.length) return '';
    return \`<div class="card" style="margin-bottom:12px;"><div class="class-section-header">\${day}</div><div style="display:flex;gap:10px;flex-wrap:wrap;">\${entries.map(e => \`<div style="background:var(--bg3);border:1px solid var(--border);border-radius:9px;padding:10px 14px;min-width:120px;"><div style="font-weight:700;font-size:13px;">\${e.sub}</div><div style="font-size:11px;color:var(--text3);margin-top:2px;">\${e.period.split('(')[1]?.replace(')','') || e.period}</div></div>\`).join('')}</div></div>\`;
  }).join('');
}
async function loadStudentNotices() {
  const r = await GET('/api/notices');
  const notices = r.notices || [];
  document.getElementById('s-notlist').innerHTML = notices.map((n,i) => \`<div class="card" style="animation:pageIn .3s ease \${i*0.05}s both;"><div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;"><span class="badge \${notCat(n.cat)}">\${n.cat}</span><strong style="font-size:14px;color:var(--text);">\${n.title}</strong><span style="margin-left:auto;font-size:11px;color:var(--text3);">\${n.date}</span></div><div style="font-size:13px;color:var(--text2);line-height:1.6;">\${n.msg}</div></div>\`).join('') || '<div class="card"><div class="tbl-empty">No notices yet</div></div>';
}
function loadStudentProfile() {
  const s = curStudent;
  const ini = s.name.split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase();
  document.getElementById('p-av').textContent = ini;
  setText('p-name', s.name); setText('p-class-sec', s.cls + ' · Section ' + s.section);
  setText('p-roll', s.roll); setText('p-cls', s.cls); setText('p-sec', s.section); setText('p-user', s.username);
}

// ── Subject dropdowns ──────────────────────────────────────
function updateSubjects(subId, stId) {
  const sel = document.getElementById(stId);
  const sub = document.getElementById(subId);
  if (!sel || !sub) return;
  const refresh = () => {
    const id  = parseInt(sel.value);
    const st  = allStudents.find(s => s.id === id);
    const arr = st ? (SUBJECTS[st.cls] || []) : [];
    sub.innerHTML = arr.map(s => \`<option>\${s}</option>\`).join('');
  };
  sel.onchange = refresh; refresh();
}
function populateAllSubs(id) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = ALL_SUBS.map(s => \`<option>\${s}</option>\`).join('');
}

// ── Grade helpers ──────────────────────────────────────────
function gradeLabel(pct) { if(pct>=91)return'A1'; if(pct>=81)return'A2'; if(pct>=71)return'B1'; if(pct>=61)return'B2'; if(pct>=51)return'C1'; if(pct>=41)return'C2'; if(pct>=33)return'D'; return'F'; }
function gradeColor(pct) { if(pct>=75)return'var(--green)'; if(pct>=50)return'var(--sky)'; if(pct>=33)return'var(--amber)'; return'var(--rose)'; }
function notCat(c) { return c==='Exam'?'b-rose':c==='Event'?'b-green':c==='Fee'?'b-amber':c==='Holiday'?'b-sky':'b-primary'; }

// ── Boot ───────────────────────────────────────────────────

// ── Teacher & Assignment JS ─────────────────────────────────
let curTeacher = null;
let selectedFiles = {};

function switchRole(r, el) {
  curRole = r;
  document.querySelectorAll('#screen-login .role-tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
}

async function doTeacherRegister() {
  saveLabel('tr-btn'); setLoading('tr-btn', true); hideAlert('tr-err'); hideAlert('tr-ok');
  const r = await POST('/api/teacher/register', { name: document.getElementById('tr-name').value.trim(), subject: document.getElementById('tr-subject').value, username: document.getElementById('tr-user').value.trim(), password: document.getElementById('tr-pass').value });
  setLoading('tr-btn', false);
  if (!r.ok) { showAlert('tr-err', r.msg || 'Failed.'); return; }
  showAlert('tr-ok', r.msg, 'ok');
  ['tr-name','tr-user','tr-pass'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('tr-subject').value = '';
}

function handleFileSelect(inputId, previewGridId) {
  const input = document.getElementById(inputId);
  const grid = document.getElementById(previewGridId);
  if (!input || !grid) return;
  const files = Array.from(input.files);
  selectedFiles[inputId] = files;
  grid.innerHTML = '';
  files.forEach((f, i) => {
    const item = document.createElement('div');
    item.style.cssText = 'position:relative;border-radius:10px;overflow:hidden;aspect-ratio:1;animation:pageIn .3s ease ' + (i*0.05) + 's both;';
    if (f.type.includes('pdf')) {
      item.innerHTML = `<div style="width:100%;height:100%;background:var(--rose-pale);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;color:var(--rose);font-size:10px;font-weight:700;min-height:80px;">📄<span style="word-break:break-all;padding:0 4px;text-align:center;">${f.name.slice(0,14)}</span></div><button onclick="removeFile('${inputId}','${previewGridId}',${i})" style="position:absolute;top:4px;right:4px;width:18px;height:18px;border-radius:50%;background:rgba(0,0,0,.7);color:white;border:none;cursor:pointer;font-size:10px;">✕</button>`;
    } else {
      const url = URL.createObjectURL(f);
      item.innerHTML = `<img src="${url}" style="width:100%;height:100%;object-fit:cover;" alt=""/><button onclick="removeFile('${inputId}','${previewGridId}',${i})" style="position:absolute;top:4px;right:4px;width:18px;height:18px;border-radius:50%;background:rgba(0,0,0,.7);color:white;border:none;cursor:pointer;font-size:10px;">✕</button>`;
    }
    grid.appendChild(item);
  });
}
function removeFile(inputId, previewGridId, idx) {
  if (!selectedFiles[inputId]) return;
  selectedFiles[inputId].splice(idx, 1);
  const files = selectedFiles[inputId];
  const grid = document.getElementById(previewGridId);
  grid.innerHTML = '';
  files.forEach((f, i) => {
    const item = document.createElement('div');
    item.style.cssText = 'position:relative;border-radius:10px;overflow:hidden;aspect-ratio:1;';
    if (f.type.includes('pdf')) {
      item.innerHTML = `<div style="width:100%;height:100%;background:var(--rose-pale);display:flex;align-items:center;justify-content:center;color:var(--rose);font-size:10px;font-weight:700;min-height:80px;">📄 ${f.name.slice(0,12)}</div><button onclick="removeFile('${inputId}','${previewGridId}',${i})" style="position:absolute;top:4px;right:4px;width:18px;height:18px;border-radius:50%;background:rgba(0,0,0,.7);color:white;border:none;cursor:pointer;font-size:10px;">✕</button>`;
    } else {
      const url = URL.createObjectURL(f);
      item.innerHTML = `<img src="${url}" style="width:100%;height:100%;object-fit:cover;" alt=""/><button onclick="removeFile('${inputId}','${previewGridId}',${i})" style="position:absolute;top:4px;right:4px;width:18px;height:18px;border-radius:50%;background:rgba(0,0,0,.7);color:white;border:none;cursor:pointer;font-size:10px;">✕</button>`;
    }
    grid.appendChild(item);
  });
}
async function uploadMultipleFiles(inputId, folder) {
  const files = selectedFiles[inputId] || [];
  const results = [];
  for (const f of files) {
    const fd = new FormData(); fd.append('file', f); fd.append('folder', 'scholarhub/' + folder);
    const r = await (await fetch('/api/upload/file', { method: 'POST', body: fd })).json();
    if (r.ok) results.push({ url: r.url, name: r.name, type: f.type.includes('pdf') ? 'pdf' : 'image' });
  }
  return results;
}
async function uploadSingleFile(inputId, folder) {
  const input = document.getElementById(inputId);
  if (!input || !input.files[0]) return null;
  const fd = new FormData(); fd.append('file', input.files[0]); fd.append('folder', 'scholarhub/' + folder);
  const r = await (await fetch('/api/upload/file', { method: 'POST', body: fd })).json();
  return r.ok ? { url: r.url, name: r.name } : null;
}

function renderAssignCard(a, showSubmit) {
  const pb = a.priority==='High'?'b-rose':a.priority==='Medium'?'b-amber':'b-green';
  const dc = a.priority==='High'?'var(--rose)':a.priority==='Medium'?'var(--amber)':'var(--green)';
  const isTeacher = a.postedByRole === 'teacher';
  const byBadge = isTeacher ? `<span style="background:rgba(45,212,191,.12);color:#2dd4bf;border:1px solid rgba(45,212,191,.25);border-radius:20px;padding:3px 8px;font-size:10px;font-weight:700;">🎓 ${a.postedByName||'Teacher'}</span>` : `<span class="badge b-violet">👤 Admin</span>`;
  const gallery = a.files && a.files.length ? `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;margin-bottom:12px;">${a.files.map(f => f.type==='pdf' ? `<a href="${f.url}" target="_blank" style="border-radius:10px;overflow:hidden;aspect-ratio:1;background:var(--rose-pale);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;color:var(--rose);font-size:11px;font-weight:700;text-decoration:none;transition:transform .2s;" onmouseover="this.style.transform='scale(1.04)'" onmouseout="this.style.transform=''">📄<span style="word-break:break-all;padding:0 6px;text-align:center;">${(f.name||'PDF').slice(0,14)}</span></a>` : `<img src="${f.url}" style="border-radius:10px;aspect-ratio:1;object-fit:cover;width:100%;cursor:pointer;transition:transform .2s;" onmouseover="this.style.transform='scale(1.04)'" onmouseout="this.style.transform=''" onclick="openLightbox('${f.url}')" alt="" loading="lazy"/>`).join('')}</div>` : '';
  let submitHtml = '';
  if (showSubmit && curStudent) {
    const already = a.submissions && a.submissions.find(s => s.sid === curStudent.id);
    submitHtml = already ? `<div style="display:flex;align-items:center;gap:8px;padding-top:12px;border-top:1px solid var(--border);"><span class="badge b-green">✓ Submitted</span><a href="${already.fileUrl}" target="_blank" style="color:var(--primary2);font-size:12px;">View</a></div>` : `<div style="padding-top:12px;border-top:1px solid var(--border);display:flex;gap:10px;align-items:center;flex-wrap:wrap;"><label class="upload-btn" style="font-size:12px;padding:6px 12px;">📎 Attach File<input type="file" id="sub-${a.id}" accept="image/*,.pdf" style="display:none;" onchange="previewFile('sub-${a.id}','subprev-${a.id}')"/></label><span id="subprev-${a.id}" style="font-size:11px;color:var(--text3);"></span><button class="btn-save" style="padding:6px 14px;font-size:12px;" onclick="submitAssignment(${a.id})">Submit</button></div>`;
  }
  return `<div class="card" style="transition:transform .2s,box-shadow .2s;animation:pageIn .35s cubic-bezier(.16,1,.3,1);" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='var(--sh)'" onmouseout="this.style.transform='';this.style.boxShadow=''">
    <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:10px;flex-wrap:wrap;">
      <div style="font-size:15px;font-weight:700;color:var(--text);flex:1;">${a.title}</div>
      <span class="badge ${pb}">${a.priority}</span>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px;">
      <span class="badge b-sky">${a.subject||'General'}</span>
      <span class="badge b-primary">${a.cls||'All'}</span>
      <span style="font-size:12px;color:${dc};font-family:var(--mono);font-weight:700;">Due: ${a.due||'—'}</span>
    </div>
    ${a.description ? '<div style="font-size:13px;color:var(--text2);line-height:1.7;margin-bottom:12px;">'+a.description+'</div>' : ''}
    ${gallery}
    <div style="display:flex;align-items:center;gap:10px;padding-top:10px;border-top:1px solid var(--border);flex-wrap:wrap;">
      ${byBadge}
      <span style="margin-left:auto;font-size:11px;color:var(--text3);">${a.createdAt?new Date(a.createdAt).toLocaleDateString():''}</span>
    </div>
    ${submitHtml}
  </div>`;
}

async function saveAssignment(prefix) {
  const titleEl = document.getElementById(prefix + '-title');
  const title = titleEl?.value.trim();
  if (!title) { alert('Please enter a title!'); return; }
  saveLabel(prefix + '-btn'); setLoading(prefix + '-btn', true);
  const btn = document.getElementById(prefix + '-btn');
  btn.innerHTML = '<span class="spinner"></span>Uploading files...';
  const files = await uploadMultipleFiles(prefix + '-files', 'assignments');
  const data = { title, subject: document.getElementById(prefix + '-sub')?.value || '', cls: document.getElementById(prefix + '-class')?.value || 'All', due: document.getElementById(prefix + '-due')?.value || '', priority: document.getElementById(prefix + '-pri')?.value || 'Medium', description: document.getElementById(prefix + '-desc')?.value.trim() || '', files };
  const r = await POST('/api/assignments', data);
  setLoading(prefix + '-btn', false);
  if (!r.ok) { alert(r.msg || 'Error'); return; }
  flashMsg(prefix + '-ok');
  document.getElementById(prefix + '-title').value = '';
  document.getElementById(prefix + '-desc').value = '';
  document.getElementById(prefix + '-due').value = '';
  const grid = document.getElementById(prefix + '-preview-grid');
  if (grid) grid.innerHTML = '';
  selectedFiles[prefix + '-files'] = [];
  if (prefix === 'asf') loadAssignmentsAdmin(); else loadTeacherAssignments();
}

async function submitAssignment(assignId) {
  const input = document.getElementById('sub-' + assignId);
  if (!input || !input.files[0]) { alert('Please select a file!'); return; }
  const fd = new FormData(); fd.append('file', input.files[0]); fd.append('folder', 'scholarhub/submissions');
  const uploadRes = await (await fetch('/api/upload/file', { method: 'POST', body: fd })).json();
  if (!uploadRes.ok) { alert('Upload failed!'); return; }
  const r = await POST('/api/assignments/' + assignId + '/submit', { fileUrl: uploadRes.url, fileName: uploadRes.name });
  if (r.ok) loadStudentAssignments(); else alert(r.msg || 'Failed');
}

function openLightbox(url) { const lb = document.getElementById('lightbox'); if(!lb){const d=document.createElement('div');d.id='lightbox';d.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:9999;display:flex;align-items:center;justify-content:center;cursor:pointer;animation:fadeIn .2s;';d.onclick=()=>d.remove();d.innerHTML='<img src="'+url+'" style="max-width:90vw;max-height:90vh;border-radius:12px;box-shadow:0 24px 80px rgba(0,0,0,.8);" /><span style="position:absolute;top:20px;right:24px;font-size:28px;color:white;cursor:pointer;">✕</span>';document.body.appendChild(d);}else{document.getElementById('lightbox-img').src=url;lb.classList.add('open');}}
function closeLightbox() { const lb = document.getElementById('lightbox'); if(lb)lb.classList.remove('open'); }

// Teacher API calls
async function doLogin_teacher(username, password) {
  const r = await POST('/api/teacher/login', { username, password });
  return r;
}

// Patch doLogin to handle teacher
const _origDoLogin = doLogin;

// Teacher pages
function tPage(name, el) {
  document.querySelectorAll('#screen-teacher .page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('#screen-teacher .nav-item').forEach(l => l.classList.remove('active'));
  document.getElementById('tp-' + name).classList.add('active'); el.classList.add('active');
  ({ dash: loadTeacherDash, assignments: loadTeacherAssignments, grades: loadTeacherGrades, attendance: loadTeacherAtt, profile: loadTeacherProfile })[name]?.();
}
async function loadTeacherDash() {
  const t = curTeacher;
  setText('t-greet', 'Welcome, ' + t.name.split(' ')[0] + '! 👋');
  setText('t-sub2', t.subject + ' Teacher');
  setText('t-sname', t.name); setText('t-ssub', t.subject);
  const ini = t.name.split(' ').map(n => n[0]).join('').slice(0,2).toUpperCase();
  setText('t-av-sidebar', ini);
  const [stR, asR, grR, atR] = await Promise.all([GET('/api/students'), GET('/api/assignments'), GET('/api/grades'), GET('/api/attendance')]);
  setText('t-nst', (stR.students||[]).filter(s => s.approved).length);
  setText('t-nas', (asR.assignments||[]).length);
  setText('t-ngr', (grR.grades||[]).length);
  setText('t-nat', (atR.attendance||[]).length);
  const recent = (asR.assignments||[]).slice(-3).reverse();
  document.getElementById('t-recent-assigns').innerHTML = recent.length ? recent.map(a => renderAssignCard(a, false)).join('') : '<div class="tbl-empty">No assignments yet</div>';
}
async function loadTeacherAssignments() {
  populateAllSubs('tasf-sub');
  const r = await GET('/api/assignments');
  document.getElementById('t-assignments-list').innerHTML = (r.assignments||[]).map(a => renderAssignCard(a, false)).join('') || '<div class="card"><div class="tbl-empty">No assignments yet</div></div>';
}
async function loadTeacherGrades() {
  const r = await GET('/api/students'); allStudents = (r.students||[]).filter(s => s.approved);
  document.getElementById('tgf-st').innerHTML = '<option value="">Select student</option>' + allStudents.map(s => `<option value="${s.id}">${s.name} (${s.cls}-${s.section})</option>`).join('');
  updateSubjects('tgf-sub', 'tgf-st');
  const gr = await GET('/api/grades');
  document.getElementById('tgrd-tbody').innerHTML = (gr.grades||[]).map(g => { const st = allStudents.find(s => s.id === g.sid), pct = Math.round(g.obt/g.max*100), col = gradeColor(pct); return `<tr><td><strong>${st?st.name:'Unknown'}</strong></td><td><span class="badge b-primary">${st?st.cls:'—'}</span></td><td>${g.sub}</td><td>${g.exam}</td><td>${g.max}</td><td style="font-family:var(--mono);font-weight:700;color:${col};">${g.obt}</td><td style="font-family:var(--mono);font-weight:700;color:${col};">${pct}%</td><td><span class="badge" style="background:${col}1a;color:${col};">${gradeLabel(pct)}</span></td><td>${fileLink(g.fileUrl,g.fileName)}</td></tr>`; }).join('') || '<tr><td colspan="9" class="tbl-empty">No records</td></tr>';
}
async function saveGradeTeacher() {
  saveLabel('tgf-btn'); setLoading('tgf-btn', true);
  document.getElementById('tgf-btn').innerHTML = '<span class="spinner"></span>Uploading...';
  const uploaded = await uploadSingleFile('tgf-file', 'marksheets');
  const r = await POST('/api/grades', { sid: parseInt(document.getElementById('tgf-st').value), sub: document.getElementById('tgf-sub').value, exam: document.getElementById('tgf-exam').value, max: parseInt(document.getElementById('tgf-max').value), obt: parseInt(document.getElementById('tgf-obt').value), fileUrl: uploaded?.url||'', fileName: uploaded?.name||'' });
  setLoading('tgf-btn', false);
  if (!r.ok) { showAlert('tgf-err', r.msg||'Error'); return; }
  flashMsg('tgf-ok');
  ['tgf-max','tgf-obt','tgf-grd'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('tgf-file').value=''; document.getElementById('tgf-file-preview').textContent='';
  await loadTeacherGrades();
}
function calcGradeT(){const max=parseInt(document.getElementById('tgf-max').value)||0,obt=parseInt(document.getElementById('tgf-obt').value)||0;document.getElementById('tgf-grd').value=max>0?gradeLabel(Math.round(obt/max*100)):'';}

async function loadTeacherAtt() {
  const r = await GET('/api/students'); allStudents = (r.students||[]).filter(s => s.approved);
  document.getElementById('taf-st').innerHTML = '<option value="">Select</option>' + allStudents.map(s => `<option value="${s.id}">${s.name} (${s.cls}-${s.section})</option>`).join('');
  updateSubjects('taf-sub', 'taf-st');
  const at = await GET('/api/attendance');
  document.getElementById('tatt-tbody').innerHTML = (at.attendance||[]).map(a => { const st=allStudents.find(s=>s.id===a.sid),pct=Math.round(a.pre/a.tot*100),col=pct>=75?'var(--green)':pct>=50?'var(--amber)':'var(--rose)'; return `<tr><td><strong>${st?st.name:'Unknown'}</strong></td><td><span class="badge b-primary">${st?st.cls:'—'}</span></td><td>${a.sub}</td><td>${a.tot}</td><td>${a.pre}</td><td style="font-family:var(--mono);font-weight:700;color:${col};">${pct}%</td><td><span class="badge ${pct>=75?'b-green':pct>=50?'b-amber':'b-rose'}">${pct>=75?'Good':pct>=50?'Average':'Warning'}</span></td></tr>`; }).join('') || '<tr><td colspan="7" class="tbl-empty">No records</td></tr>';
}
async function saveAttTeacher() {
  saveLabel('taf-btn'); setLoading('taf-btn', true);
  const r = await POST('/api/attendance', { sid: parseInt(document.getElementById('taf-st').value), sub: document.getElementById('taf-sub').value, tot: parseInt(document.getElementById('taf-tot').value), pre: parseInt(document.getElementById('taf-pre').value) });
  setLoading('taf-btn', false); if (!r.ok) { alert(r.msg||'Error'); return; }
  flashMsg('taf-ok'); document.getElementById('taf-tot').value=''; document.getElementById('taf-pre').value='';
  await loadTeacherAtt();
}
function loadTeacherProfile() {
  const t = curTeacher, ini = t.name.split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase();
  setText('tp-av-text', ini); setText('tp-name', t.name); setText('tp-subject', t.subject + ' Teacher'); setText('tp-user', t.username);
}

// Admin teacher management
async function loadTeachersPage() {
  const r = await GET('/api/teachers');
  const teachers = r.teachers || [];
  const pend = teachers.filter(t => !t.approved), appr = teachers.filter(t => t.approved);
  setText('tpend-pill', pend.length); updateTPendBadge(pend.length);
  document.getElementById('tpend-tbody').innerHTML = pend.map(t => `<tr><td><strong>${t.name}</strong></td><td><span style="background:rgba(45,212,191,.12);color:#2dd4bf;border:1px solid rgba(45,212,191,.25);border-radius:20px;padding:2px 8px;font-size:10.5px;font-weight:700;">${t.subject}</span></td><td style="font-family:var(--mono);font-size:12px;">${t.username}</td><td style="font-size:11px;color:var(--text3);">${t.createdAt?new Date(t.createdAt).toLocaleDateString():''}</td><td><button class="btn-approve" onclick="approveTeacher(${t.id})">Approve</button></td></tr>`).join('') || '<tr><td colspan="5" class="tbl-empty">No pending teachers</td></tr>';
  document.getElementById('tappr-tbody').innerHTML = appr.map(t => `<tr><td><strong>${t.name}</strong></td><td><span style="background:rgba(45,212,191,.12);color:#2dd4bf;border:1px solid rgba(45,212,191,.25);border-radius:20px;padding:2px 8px;font-size:10.5px;font-weight:700;">${t.subject}</span></td><td style="font-family:var(--mono);font-size:12px;">${t.username}</td><td style="font-size:11px;color:var(--text3);">${t.createdAt?new Date(t.createdAt).toLocaleDateString():''}</td><td><button class="btn-del" onclick="deleteTeacher(${t.id})">Remove</button></td></tr>`).join('') || '<tr><td colspan="5" class="tbl-empty">No approved teachers</td></tr>';
}
async function approveTeacher(id){await POST('/api/teachers/'+id+'/approve');loadTeachersPage();loadAdminOverview();}
async function deleteTeacher(id){if(!confirm('Remove teacher?'))return;await DEL('/api/teachers/'+id);loadTeachersPage();}
function updateTPendBadge(n){const b=document.getElementById('nb-tpend');if(!b)return;b.style.display=n>0?'inline':'none';b.textContent=n;}

async function loadAssignmentsAdmin() {
  populateAllSubs('asf-sub');
  const r = await GET('/api/assignments');
  document.getElementById('assignments-list-admin').innerHTML = (r.assignments||[]).map(a => renderAssignCard(a, false)).join('') || '<div class="card"><div class="tbl-empty">No assignments yet</div></div>';
}

async function loadStudentAssignments() {
  const r = await GET('/api/assignments');
  document.getElementById('s-assignments-list').innerHTML = (r.assignments||[]).map(a => renderAssignCard(a, true)).join('') || '<div class="card"><div class="tbl-empty">No assignments yet</div></div>';
}

function previewSingleFile(inputId, previewId) { const f = document.getElementById(inputId)?.files[0]; if(f) document.getElementById(previewId).textContent = '📎 ' + f.name; }

checkSession();
</script>
</body>
</html>`;


// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.url.startsWith('/api/')) {
    await handleAPI(req, res);
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(HTML);
  }
});

loadData().then(data => {
  DB = data;
  server.listen(PORT, () => {
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║   ScholarHub School MIS — Server Running     ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log('║   Port: ' + PORT + '                                  ║');
    console.log('║   Admin login:     admin / admin123          ║');
    console.log('║   Data stored in:  MongoDB Atlas             ║');
    console.log('╚══════════════════════════════════════════════╝\n');
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});
