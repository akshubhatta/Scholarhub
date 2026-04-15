/**
 * ╔══════════════════════════════════════════════════════════╗
 *  ScholarHub — School MIS (Class 6–12) ENHANCED VERSION
 *  Full Stack: Node.js backend + HTML/CSS/JS frontend
 *  Features: Students, Grades, Attendance, Fees, Library, 
 *            Teachers, ID Cards, Exam Schedule, Timetable
 * ╚══════════════════════════════════════════════════════════╝
 */

const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const crypto = require('crypto');

// ── Config ──────────────────────────────────────────────────
const PORT           = 3000;
const DATA_FILE      = path.join(__dirname, 'school_data.json');
const SESSION_SECRET = 'scholarhub_super_secret_key_2024';
const ADMIN_PASSWORD = 'admin123'; 

// ── Helpers ──────────────────────────────────────────────────
function hashPass(p) { return crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('hex'); }
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
    req.on('end', () => { try { res(JSON.parse(b)); } catch { res({}); } });
  });
}
function json(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function authMiddleware(req) {
  const token = getCookie(req, 'sh_token');
  if (!token) return null;
  return verifyToken(token);
}

// ── Database ─────────────────────────────────────────────────
function loadData() {
  if (fs.existsSync(DATA_FILE)) {
    try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch {}
  }
  // Initial Data Structure with new features
  const init = {
    students:   [],
    teachers:   [], // NEW
    grades:     [],
    attendance: [],
    homework:   [],
    notices:    [{ id: 1, title: 'System Updated!', cat: 'General', msg: 'New features added: Library, Fees, Teachers, and ID Cards.', date: new Date().toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'}) }],
    timetable:  [],
    fees:       [], // NEW
    library:    [], // NEW
    exams:      [], // NEW
    ids:        { s: 100, t: 1, g: 1, a: 1, h: 1, n: 2, tt: 1, f: 1, l: 1, e: 1 }
  };
  saveData(init);
  return init;
}
function saveData(d) { fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2), 'utf8'); }
let DB = loadData();

// ── API Router ────────────────────────────────────────────────
async function handleAPI(req, res) {
  const url    = req.url.replace(/\?.*/, '');
  const method = req.method;
  const user   = authMiddleware(req);

  // POST /api/login
  if (url === '/api/login' && method === 'POST') {
    const { username, password, role } = await parseBody(req);
    if (role === 'admin') {
      if (username === 'admin' && password === ADMIN_PASSWORD) {
        const token = makeToken({ role: 'admin', username: 'admin' });
        res.writeHead(200, { 'Set-Cookie': `sh_token=${token}; Path=/; HttpOnly`, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, role: 'admin' }));
      } else { json(res, 401, { ok: false, msg: 'Invalid admin credentials.' }); }
      return;
    }
    const st = DB.students.find(s => s.username === username && s.password === hashPass(password));
    if (!st)      return json(res, 401, { ok: false, msg: 'Invalid credentials.' });
    if (!st.approved) return json(res, 403, { ok: false, msg: 'Account pending approval.' });
    const token = makeToken({ role: 'student', id: st.id });
    res.writeHead(200, { 'Set-Cookie': `sh_token=${token}; Path=/; HttpOnly`, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, role: 'student', student: sanitizeStudent(st) }));
    return;
  }

  if (url === '/api/logout' && method === 'POST') {
    res.writeHead(200, { 'Set-Cookie': 'sh_token=; Path=/; Max-Age=0', 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url === '/api/register' && method === 'POST') {
    const { name, roll, cls, section, username, password } = await parseBody(req);
    if (!name || !roll || !cls || !username || !password) return json(res, 400, { ok: false, msg: 'Fill all fields.' });
    if (password.length < 6) return json(res, 400, { ok: false, msg: 'Password too short.' });
    if (DB.students.find(s => s.username === username)) return json(res, 400, { ok: false, msg: 'Username taken.' });
    const st = { id: DB.ids.s++, name, roll, cls, section, username, password: hashPass(password), approved: false, createdAt: new Date().toISOString() };
    DB.students.push(st);
    saveData(DB);
    json(res, 200, { ok: true, msg: 'Registered! Await approval.' });
    return;
  }

  if (url === '/api/me' && method === 'GET') {
    if (!user) return json(res, 401, { ok: false });
    if (user.role === 'admin') return json(res, 200, { ok: true, role: 'admin' });
    const st = DB.students.find(s => s.id === user.id);
    if (!st) return json(res, 401, { ok: false });
    json(res, 200, { ok: true, role: 'student', student: sanitizeStudent(st) });
    return;
  }

  // ── AUTH REQUIRED ZONE ────────────────────────────────────
  if (!user) return json(res, 401, { ok: false, msg: 'Not authenticated.' });

  // --- Student Management (Admin) ---
  if (url === '/api/students' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    return json(res, 200, { ok: true, students: DB.students.map(sanitizeStudent) });
  }
  
  // Edit Student
  if (url === '/api/students/edit' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { id, name, roll, cls, section } = await parseBody(req);
    const st = DB.students.find(s => s.id === id);
    if (!st) return json(res, 404, { ok: false });
    st.name = name; st.roll = roll; st.cls = cls; st.section = section;
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  if (url.match(/^\/api\/students\/(\d+)\/approve$/) && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const id = parseInt(url.split('/')[3]);
    const st = DB.students.find(s => s.id === id);
    if (st) { st.approved = true; saveData(DB); }
    return json(res, 200, { ok: true });
  }
  
  if (url.match(/^\/api\/students\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    const id = parseInt(url.split('/')[3]);
    DB.students = DB.students.filter(s => s.id !== id);
    // Clean up related data
    DB.grades = DB.grades.filter(g => g.sid !== id);
    DB.attendance = DB.attendance.filter(a => a.sid !== id);
    DB.fees = DB.fees.filter(f => f.sid !== id);
    DB.library = DB.library.filter(l => l.sid !== id);
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Teachers (Admin) ---
  if (url === '/api/teachers' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    return json(res, 200, { ok: true, teachers: DB.teachers });
  }
  if (url === '/api/teachers' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { name, subject, cls, contact } = await parseBody(req);
    DB.teachers.push({ id: DB.ids.t++, name, subject, cls, contact });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/teachers\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.teachers = DB.teachers.filter(t => t.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Grades ---
  if (url === '/api/grades' && method === 'GET') {
    const sid = user.role === 'student' ? user.id : null;
    const grades = sid ? DB.grades.filter(g => g.sid === sid) : DB.grades;
    return json(res, 200, { ok: true, grades });
  }
  if (url === '/api/grades' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { sid, sub, exam, max, obt } = await parseBody(req);
    if(obt > max) return json(res, 400, { ok: false, msg: 'Obtained > Max' });
    DB.grades.push({ id: DB.ids.g++, sid: parseInt(sid), sub, exam, max: parseInt(max), obt: parseInt(obt) });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/grades\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.grades = DB.grades.filter(g => g.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Attendance ---
  if (url === '/api/attendance' && method === 'GET') {
    const sid = user.role === 'student' ? user.id : null;
    const att = sid ? DB.attendance.filter(a => a.sid === sid) : DB.attendance;
    return json(res, 200, { ok: true, attendance: att });
  }
  if (url === '/api/attendance' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { sid, sub, tot, pre } = await parseBody(req);
    DB.attendance.push({ id: DB.ids.a++, sid: parseInt(sid), sub, tot: parseInt(tot), pre: parseInt(pre) });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/attendance\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.attendance = DB.attendance.filter(a => a.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Homework ---
  if (url === '/api/homework' && method === 'GET') {
    let hw = DB.homework;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      hw = st ? hw.filter(h => h.cls === st.cls || h.cls === 'All') : [];
    }
    return json(res, 200, { ok: true, homework: hw });
  }
  if (url === '/api/homework' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { title, sub, cls, due, pri, desc } = await parseBody(req);
    DB.homework.push({ id: DB.ids.h++, title, sub, cls, due, pri, desc });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/homework\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.homework = DB.homework.filter(h => h.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Notices ---
  if (url === '/api/notices' && method === 'GET') {
    return json(res, 200, { ok: true, notices: DB.notices });
  }
  if (url === '/api/notices' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { title, cat, msg } = await parseBody(req);
    const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
    DB.notices.unshift({ id: DB.ids.n++, title, cat, msg, date });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/notices\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.notices = DB.notices.filter(n => n.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Timetable ---
  if (url === '/api/timetable' && method === 'GET') {
    let tt = DB.timetable;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      tt = st ? tt.filter(t => t.cls === st.cls) : [];
    }
    return json(res, 200, { ok: true, timetable: tt });
  }
  if (url === '/api/timetable' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { cls, day, sub, period } = await parseBody(req);
    DB.timetable.push({ id: DB.ids.tt++, cls, day, sub, period });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/timetable\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.timetable = DB.timetable.filter(t => t.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- NEW: Fees ---
  if (url === '/api/fees' && method === 'GET') {
    let fees = DB.fees;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      fees = st ? fees.filter(f => f.sid === st.id) : [];
    }
    return json(res, 200, { ok: true, fees });
  }
  if (url === '/api/fees' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { sid, amount, status, date, remark } = await parseBody(req);
    DB.fees.push({ id: DB.ids.f++, sid: parseInt(sid), amount, status, date, remark });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/fees\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.fees = DB.fees.filter(f => f.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- NEW: Library ---
  if (url === '/api/library' && method === 'GET') {
    let lib = DB.library;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      lib = st ? lib.filter(l => l.sid === st.id) : [];
    }
    return json(res, 200, { ok: true, library: lib });
  }
  if (url === '/api/library' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { sid, book, issueDate, returnDate, status } = await parseBody(req);
    DB.library.push({ id: DB.ids.l++, sid: parseInt(sid), book, issueDate, returnDate, status });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url === '/api/library/return' && method === 'POST') { // Quick return helper
    if (user.role !== 'admin') return json(res, 403, {});
    const { id } = await parseBody(req);
    const record = DB.library.find(l => l.id === id);
    if(record) { record.status = 'Returned'; saveData(DB); }
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/library\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.library = DB.library.filter(l => l.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- NEW: Exam Schedule ---
  if (url === '/api/exams' && method === 'GET') {
    let ex = DB.exams;
    if (user.role === 'student') {
      const st = DB.students.find(s => s.id === user.id);
      ex = st ? ex.filter(e => e.cls === st.cls) : [];
    }
    return json(res, 200, { ok: true, exams: ex });
  }
  if (url === '/api/exams' && method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, {});
    const { cls, title, sub, date, time } = await parseBody(req);
    DB.exams.push({ id: DB.ids.e++, cls, title, sub, date, time });
    saveData(DB);
    return json(res, 200, { ok: true });
  }
  if (url.match(/^\/api\/exams\/(\d+)$/) && method === 'DELETE') {
    if (user.role !== 'admin') return json(res, 403, {});
    DB.exams = DB.exams.filter(e => e.id !== parseInt(url.split('/')[3]));
    saveData(DB);
    return json(res, 200, { ok: true });
  }

  // --- Stats ---
  if (url === '/api/stats' && method === 'GET') {
    if (user.role !== 'admin') return json(res, 403, {});
    const approved = DB.students.filter(s => s.approved);
    const pending  = DB.students.filter(s => !s.approved);
    const classCounts = {};
    ['Class 6','Class 7','Class 8','Class 9','Class 10','Class 11','Class 12'].forEach(c => classCounts[c] = 0);
    approved.forEach(s => classCounts[s.cls] = (classCounts[s.cls] || 0) + 1);
    return json(res, 200, { ok: true, totalStudents: approved.length, pending: pending.length, homework: DB.homework.length, notices: DB.notices.length, classCounts });
  }

  json(res, 404, { ok: false, msg: 'API endpoint not found.' });
}

function sanitizeStudent(s) { const { password, ...safe } = s; return safe; }

// ── HTML Frontend ─────────────────────────────────────────────
// (Due to character limits, the HTML/JS is embedded directly. 
//  It contains the new UI for Fees, Library, Teachers, Exams, ID Cards)
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ScholarHub — Advanced MIS</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0b0e1a;--bg2:#111426;--bg3:#181c2e;--border:rgba(255,255,255,.07);--border2:rgba(255,255,255,.12);--text:#e8eaf6;--text2:#9ca3c9;--text3:#6b7299;--primary:#6c63ff;--primary2:#8b84ff;--primary3:#4a42dd;--primary-glow:rgba(108,99,255,.25);--green:#22d3a0;--green-pale:rgba(34,211,160,.12);--amber:#fbbf24;--amber-pale:rgba(251,191,36,.12);--rose:#f87171;--rose-pale:rgba(248,113,113,.12);--sky:#38bdf8;--sky-pale:rgba(56,189,248,.12);--violet:#a78bfa;--violet-pale:rgba(167,139,250,.12);--sidebar:240px;--r:10px;--r-lg:14px;--r-xl:20px;--font:'Plus Jakarta Sans',sans-serif;--mono:'DM Mono',monospace;--sh:0 4px 24px rgba(0,0,0,.4);}
html{scroll-behavior:smooth;}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;line-height:1.6;overflow-x:hidden;}
::-webkit-scrollbar{width:5px;height:5px;}::-webkit-scrollbar-track{background:var(--bg2);}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:99px;}
.screen{display:none;min-height:100vh;}.screen.active{display:flex;}
/* Auth Screens */
#screen-login,#screen-register{align-items:center;justify-content:center;background:var(--bg);position:relative;overflow:hidden;}
.auth-bg{position:absolute;inset:0;overflow:hidden;pointer-events:none;}
.auth-orb{position:absolute;border-radius:50%;filter:blur(80px);animation:orbFloat 8s ease-in-out infinite;}
.orb1{width:500px;height:500px;background:radial-gradient(circle,rgba(108,99,255,.18),transparent 70%);top:-150px;left:-100px;}
.orb2{width:400px;height:400px;background:radial-gradient(circle,rgba(34,211,160,.1),transparent 70%);bottom:-100px;right:-80px;animation-delay:-3s;}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1);}33%{transform:translate(30px,-20px) scale(1.05);}66%{transform:translate(-20px,15px) scale(.97);}}
.auth-wrap{position:relative;z-index:1;width:100%;max-width:480px;padding:20px;}
.auth-box{background:rgba(17,20,38,.92);backdrop-filter:blur(24px);border:1px solid var(--border2);border-radius:var(--r-xl);padding:44px 48px;box-shadow:var(--sh-lg);animation:authIn .5s cubic-bezier(.16,1,.3,1);}
@keyframes authIn{from{opacity:0;transform:translateY(24px) scale(.97);}to{opacity:1;transform:none;}}
.auth-logo{display:flex;align-items:center;gap:12px;margin-bottom:8px;}
.auth-logo-mark{width:44px;height:44px;background:linear-gradient(135deg,var(--primary),var(--primary2));border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 24px var(--primary-glow);}
.auth-logo-mark svg{width:24px;height:24px;fill:white;}
.auth-logo-text{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-.5px;}.auth-logo-text span{color:var(--primary2);}
.auth-head{font-size:19px;font-weight:700;color:var(--text);margin-bottom:4px;}.auth-sub{font-size:13px;color:var(--text3);margin-bottom:24px;}
.role-tabs{display:flex;background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:4px;gap:4px;margin-bottom:22px;}
.role-tab{flex:1;padding:8px 10px;font-size:12.5px;font-weight:600;font-family:var(--font);border:none;border-radius:7px;cursor:pointer;transition:all .2s;color:var(--text3);background:transparent;}
.role-tab.active{background:var(--primary);color:white;box-shadow:0 1px 6px rgba(0,0,0,.3);}
.f-group{margin-bottom:16px;}.f-label{font-size:11px;font-weight:700;color:var(--text2);margin-bottom:6px;display:block;text-transform:uppercase;}
.f-input,.f-select{width:100%;padding:11px 14px;font-size:13.5px;font-family:var(--font);background:var(--bg3);border:1.5px solid var(--border2);border-radius:9px;color:var(--text);outline:none;transition:all .2s;}
.f-input:focus,.f-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
.btn-primary{width:100%;padding:12px;font-size:14px;font-weight:700;font-family:var(--font);background:linear-gradient(135deg,var(--primary),var(--primary2));color:white;border:none;border-radius:10px;cursor:pointer;transition:all .2s;margin-top:4px;}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px var(--primary-glow);}
.alert{padding:10px 14px;border-radius:8px;font-size:12.5px;margin-bottom:14px;display:none;font-weight:500;}
.alert-err{background:var(--rose-pale);color:var(--rose);border:1px solid rgba(248,113,113,.25);}
.alert-ok{background:var(--green-pale);color:var(--green);border:1px solid rgba(34,211,160,.25);}
/* Admin/Student Layout */
.sidebar{width:var(--sidebar);background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:100;}
.sb-brand{padding:24px 18px 18px;border-bottom:1px solid var(--border);}.sb-brand-inner{display:flex;align-items:center;gap:10px;}
.sb-brand-mark{width:34px;height:34px;background:linear-gradient(135deg,var(--primary),var(--primary2));border-radius:9px;display:flex;align-items:center;justify-content:center;}
.sb-brand-mark svg{width:18px;height:18px;fill:white;}
.sb-brand-name{font-size:15px;font-weight:800;color:var(--text);}.sb-brand-name span{color:var(--primary2);}
.nav{padding:10px;flex:1;overflow-y:auto;}
.nav-section{font-size:9.5px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.1em;padding:10px 8px 4px;margin-top:6px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:9px;cursor:pointer;transition:all .15s;color:var(--text3);font-size:13px;font-weight:500;margin-bottom:2px;position:relative;}
.nav-item:hover{background:var(--bg3);color:var(--text2);}
.nav-item.active{background:rgba(108,99,255,.15);color:var(--primary2);}
.nav-item.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--primary2);border-radius:0 3px 3px 0;}
.nav-item-icon{width:17px;height:17px;flex-shrink:0;}
.main{margin-left:var(--sidebar);flex:1;padding:28px 30px;min-height:100vh;background:var(--bg);}
.page{display:none;}.page.active{display:block;animation:pageIn .3s cubic-bezier(.16,1,.3,1);}
@keyframes pageIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:none;}}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:28px;}
.page-title{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-.5px;}.page-sub{font-size:13px;color:var(--text3);margin-top:3px;}
.badge{font-size:10.5px;font-weight:700;padding:3px 10px;border-radius:20px;letter-spacing:.03em;display:inline-flex;align-items:center;}
.b-primary{background:var(--primary-glow);color:var(--primary2);}.b-green{background:var(--green-pale);color:var(--green);}.b-amber{background:var(--amber-pale);color:var(--amber);}.b-rose{background:var(--rose-pale);color:var(--rose);}.b-sky{background:var(--sky-pale);color:var(--sky);}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-lg);padding:18px 20px;position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s;}
.stat-card:hover{transform:translateY(-3px);box-shadow:var(--sh);}
.stat-val{font-size:30px;font-weight:800;font-family:var(--mono);letter-spacing:-1.5px;line-height:1;}.stat-label{font-size:11.5px;color:var(--text3);margin-top:4px;font-weight:500;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-lg);padding:20px 22px;margin-bottom:16px;}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.card-title{font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.07em;}
.tbl-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border);}
.tbl{width:100%;border-collapse:collapse;font-size:13px;}
.tbl thead tr{background:var(--bg3);}
.tbl th{padding:10px 14px;text-align:left;font-size:10.5px;font-weight:700;color:var(--text3);text-transform:uppercase;border-bottom:1px solid var(--border);}
.tbl td{padding:12px 14px;border-bottom:1px solid var(--border);transition:background .15s;}
.tbl tbody tr:last-child td{border-bottom:none;}
.tbl tbody tr:hover td{background:var(--bg3);}
.tbl-empty{text-align:center;color:var(--text3);padding:32px 0;font-size:13px;}
.form-section{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-lg);padding:22px;margin-bottom:16px;}
.form-section-title{font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.07em;margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--border);}
.f-row{display:grid;gap:14px;margin-bottom:14px;}.f-row-2{grid-template-columns:1fr 1fr;}.f-row-3{grid-template-columns:1fr 1fr 1fr;}.f-row-4{grid-template-columns:1fr 1fr 1fr 1fr;}
.f-grp{display:flex;flex-direction:column;gap:6px;}
.f-lbl{font-size:10.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;}
.fi,.fs,.ft{padding:10px 13px;font-size:13px;font-family:var(--font);background:var(--bg3);border:1.5px solid var(--border2);border-radius:9px;color:var(--text);outline:none;transition:all .2s;}
.fi:focus,.fs:focus,.ft:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
.btn-save{padding:10px 22px;font-size:13px;font-weight:700;font-family:var(--font);background:linear-gradient(135deg,var(--primary),var(--primary2));color:white;border:none;border-radius:9px;cursor:pointer;transition:all .2s;}
.btn-save:hover{transform:translateY(-1px);box-shadow:0 4px 16px var(--primary-glow);}
.btn-approve{padding:5px 11px;font-size:10.5px;font-weight:700;font-family:var(--font);background:var(--green-pale);color:var(--green);border:1px solid rgba(34,211,160,.25);border-radius:7px;cursor:pointer;margin-right:4px;}
.btn-edit{padding:5px 11px;font-size:10.5px;font-weight:700;font-family:var(--font);background:var(--sky-pale);color:var(--sky);border:1px solid rgba(56,189,248,.25);border-radius:7px;cursor:pointer;margin-right:4px;}
.btn-del{padding:5px 11px;font-size:10.5px;font-weight:700;font-family:var(--font);background:var(--rose-pale);color:var(--rose);border:1px solid rgba(248,113,113,.25);border-radius:7px;cursor:pointer;}
.flash{padding:10px 14px;border-radius:9px;font-size:12.5px;font-weight:600;margin-bottom:14px;display:none;}
.flash-ok{background:var(--green-pale);color:var(--green);border:1px solid rgba(34,211,160,.25);}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:white;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px;}
@keyframes spin{to{transform:rotate(360deg);}}
/* ID Card specific */
.id-card-wrap{background:white;color:#333;width:320px;border-radius:12px;padding:0;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.3);font-family:sans-serif;margin:10px auto;}
.id-card-header{background:linear-gradient(135deg,#4a42dd,#6c63ff);color:white;padding:15px;text-align:center;}
.id-card-body{padding:20px;text-align:center;}
.id-avatar{width:80px;height:80px;background:#eee;border-radius:50%;margin:0 auto 10px;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:bold;color:#555;border:3px solid white;margin-top:-50px;}
.id-row{text-align:left;display:flex;justify-content:space-between;margin-bottom:8px;font-size:13px;}
.id-label{font-weight:600;color:#777;}
.id-val{font-weight:600;color:#333;}
.btn-print{background:none;border:1px solid var(--border);color:var(--text);padding:8px 16px;border-radius:6px;cursor:pointer;font-size:12px;}

@media(max-width:900px){.stat-grid{grid-template-columns:1fr 1fr;}.f-row-3,.f-row-4{grid-template-columns:1fr 1fr;}}
</style>
</head>
<body>

<!-- LOGIN -->
<div id="screen-login" class="screen active">
  <div class="auth-bg"><div class="auth-orb orb1"></div><div class="auth-orb orb2"></div></div>
  <div class="auth-wrap">
    <div class="auth-box">
      <div class="auth-logo"><div class="auth-logo-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="auth-logo-text">Scholar<span>Hub</span></div></div>
      <div class="auth-head">Welcome back</div>
      <div class="auth-sub">Sign in to manage school data</div>
      <div class="role-tabs"><button class="role-tab active" onclick="switchRole('student',this)">Student</button><button class="role-tab" onclick="switchRole('admin',this)">Admin</button></div>
      <div id="l-err" class="alert alert-err"></div>
      <div class="f-group"><label class="f-label">Username</label><input class="f-input" id="l-user" placeholder="Enter username"/></div>
      <div class="f-group"><label class="f-label">Password</label><input class="f-input" id="l-pass" type="password" placeholder="Enter password"/></div>
      <button class="btn-primary" onclick="doLogin()">Sign In</button>
      <div style="margin-top:16px;text-align:center;font-size:13px;color:var(--text3);">New student? <a onclick="showScreen('screen-register')" style="color:var(--primary2);cursor:pointer;">Register here</a></div>
    </div>
  </div>
</div>

<!-- REGISTER -->
<div id="screen-register" class="screen">
  <div class="auth-bg"><div class="auth-orb orb1"></div><div class="auth-orb orb2"></div></div>
  <div class="auth-wrap" style="max-width:520px;">
    <div class="auth-box">
      <div class="auth-logo"><div class="auth-logo-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="auth-logo-text">Scholar<span>Hub</span></div></div>
      <div class="auth-head">Create account</div>
      <div id="r-err" class="alert alert-err"></div>
      <div id="r-ok" class="alert alert-ok"></div>
      <div class="f-row f-row-2">
        <div class="f-grp"><label class="f-lbl">Full Name</label><input class="fi" id="r-name"/></div>
        <div class="f-grp"><label class="f-lbl">Roll No</label><input class="fi" id="r-roll"/></div>
      </div>
      <div class="f-row f-row-2">
        <div class="f-grp"><label class="f-lbl">Class</label><select class="fs" id="r-class"><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select></div>
        <div class="f-grp"><label class="f-lbl">Section</label><select class="fs" id="r-sec"><option>A</option><option>B</option><option>C</option></select></div>
      </div>
      <div class="f-row f-row-2">
        <div class="f-grp"><label class="f-lbl">Username</label><input class="fi" id="r-user"/></div>
        <div class="f-grp"><label class="f-lbl">Password</label><input class="fi" id="r-pass" type="password"/></div>
      </div>
      <button class="btn-primary" onclick="doRegister()">Register</button>
      <button class="btn-primary" style="background:var(--bg3);color:var(--text);margin-top:10px;" onclick="showScreen('screen-login')">Back to Login</button>
    </div>
  </div>
</div>

<!-- ADMIN PANEL -->
<div id="screen-admin" class="screen">
  <aside class="sidebar">
    <div class="sb-brand"><div class="sb-brand-inner"><div class="sb-brand-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="sb-brand-name">Scholar<span>Hub</span></div></div></div>
    <nav class="nav">
      <div class="nav-section">Main</div>
      <div class="nav-item active" onclick="aPage('overview',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg><span>Dashboard</span></div>
      <div class="nav-item" onclick="aPage('students',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg><span>Students</span></div>
      <div class="nav-item" onclick="aPage('teachers',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><span>Teachers</span></div>
      
      <div class="nav-section">Academics</div>
      <div class="nav-item" onclick="aPage('grades',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><span>Grades</span></div>
      <div class="nav-item" onclick="aPage('attendance',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><polyline points="9 16 11 18 15 14"/></svg><span>Attendance</span></div>
      <div class="nav-item" onclick="aPage('exams',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span>Exam Schedule</span></div>
      <div class="nav-item" onclick="aPage('timetable',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><span>Timetable</span></div>
      
      <div class="nav-section">Management</div>
      <div class="nav-item" onclick="aPage('fees',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg><span>Fees</span></div>
      <div class="nav-item" onclick="aPage('library',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg><span>Library</span></div>
      <div class="nav-item" onclick="aPage('homework',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg><span>Homework</span></div>
      <div class="nav-item" onclick="aPage('notices',this)"><svg class="nav-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><span>Notices</span></div>
    </nav>
    <div style="padding:16px;border-top:1px solid var(--border);"><button class="btn-del" style="width:100%;" onclick="doLogout()">Logout</button></div>
  </aside>
  
  <main class="main">
    <!-- Admin Pages Container -->
    <div id="ap-overview" class="page active"><div class="topbar"><div><div class="page-title">Dashboard</div><div class="page-sub">Overview</div></div></div><div class="stat-grid"><div class="stat-card"><div class="stat-val" id="ov-st" style="color:var(--primary2);">0</div><div class="stat-label">Students</div></div><div class="stat-card"><div class="stat-val" id="ov-teach" style="color:var(--sky);">0</div><div class="stat-label">Teachers</div></div><div class="stat-card"><div class="stat-val" id="ov-fees" style="color:var(--green);">0</div><div class="stat-label">Fees Collected</div></div><div class="stat-card"><div class="stat-val" id="ov-pend" style="color:var(--amber);">0</div><div class="stat-label">Pending Approvals</div></div></div><div class="card"><div class="card-title">Recent Activity</div><div style="padding:10px;color:var(--text3);">System ready.</div></div></div>
    
    <!-- Students Page (With Edit) -->
    <div id="ap-students" class="page"><div class="topbar"><div><div class="page-title">Student Management</div></div></div><div class="card"><div class="card-title">Pending Approval</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Class</th><th>Action</th></tr></thead><tbody id="pend-tbody"></tbody></table></div></div><div class="card"><div class="card-title">All Students</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Roll</th><th>Class</th><th>Sec</th><th>ID Card</th><th>Action</th></tr></thead><tbody id="appr-tbody"></tbody></table></div></div></div>

    <!-- Teachers Page -->
    <div id="ap-teachers" class="page"><div class="topbar"><div><div class="page-title">Teacher Management</div></div></div><div class="form-section"><div class="form-section-title">Add Teacher</div><div class="f-row f-row-3"><input class="fi" id="t-name" placeholder="Name"><input class="fi" id="t-sub" placeholder="Subject"><input class="fi" id="t-cls" placeholder="Class (e.g. Class 10)"></div><button class="btn-save" onclick="saveTeacher()">Add</button></div><div class="card"><div class="card-title">Teachers List</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Subject</th><th>Class</th><th>Action</th></tr></thead><tbody id="t-tbody"></tbody></table></div></div></div>

    <!-- Fees Page -->
    <div id="ap-fees" class="page"><div class="topbar"><div><div class="page-title">Fee Management</div></div></div><div class="form-section"><div class="form-section-title">Record Fee</div><div class="f-row f-row-4"><select class="fs" id="f-st"><option>Select Student</option></select><input class="fi" id="f-amt" placeholder="Amount"><input class="fi" id="f-date" type="date"><select class="fs" id="f-status"><option>Paid</option><option>Due</option></select></div><button class="btn-save" onclick="saveFee()">Save</button></div><div class="card"><div class="card-title">Transactions</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Amount</th><th>Date</th><th>Status</th><th>Action</th></tr></thead><tbody id="f-tbody"></tbody></table></div></div></div>

    <!-- Library Page -->
    <div id="ap-library" class="page"><div class="topbar"><div><div class="page-title">Library</div></div></div><div class="form-section"><div class="form-section-title">Issue Book</div><div class="f-row f-row-4"><select class="fs" id="l-st"><option>Select Student</option></select><input class="fi" id="l-book" placeholder="Book Name"><input class="fi" id="l-issue" type="date"><input class="fi" id="l-ret" type="date"></div><button class="btn-save" onclick="saveLibrary()">Issue</button></div><div class="card"><div class="card-title">Issued Books</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Book</th><th>Issue Date</th><th>Status</th><th>Action</th></tr></thead><tbody id="l-tbody"></tbody></table></div></div></div>
    
    <!-- Exam Schedule Page -->
    <div id="ap-exams" class="page"><div class="topbar"><div><div class="page-title">Exam Schedule</div></div></div><div class="form-section"><div class="form-section-title">Add Exam</div><div class="f-row f-row-4"><select class="fs" id="e-cls"><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select><input class="fi" id="e-title" placeholder="Exam Title"><input class="fi" id="e-sub" placeholder="Subject"><input class="fi" id="e-date" type="date"></div><button class="btn-save" onclick="saveExam()">Add</button></div><div class="card"><div class="card-title">Schedule</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Class</th><th>Exam</th><th>Subject</th><th>Date</th><th>Action</th></tr></thead><tbody id="e-tbody"></tbody></table></div></div></div>

    <!-- Grades Page -->
    <div id="ap-grades" class="page"><div class="topbar"><div><div class="page-title">Grades</div></div></div><div class="form-section"><div class="form-section-title">Add Marks</div><div class="f-row f-row-3"><select class="fs" id="g-st"><option>Select Student</option></select><input class="fi" id="g-sub" placeholder="Subject"><select class="fs" id="g-exam"><option>Unit Test</option><option>Half Yearly</option><option>Annual</option></select></div><div class="f-row f-row-2"><input class="fi" id="g-max" type="number" placeholder="Max"><input class="fi" id="g-obt" type="number" placeholder="Obtained"></div><button class="btn-save" onclick="saveGrade()">Save</button></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Subject</th><th>Marks</th><th>Action</th></tr></thead><tbody id="g-tbody"></tbody></table></div></div></div>

    <!-- Attendance Page -->
    <div id="ap-attendance" class="page"><div class="topbar"><div><div class="page-title">Attendance</div></div></div><div class="form-section"><div class="form-section-title">Mark Attendance</div><div class="f-row f-row-4"><select class="fs" id="a-st"><option>Select Student</option></select><input class="fi" id="a-sub" placeholder="Subject"><input class="fi" id="a-tot" type="number" placeholder="Total"><input class="fi" id="a-pre" type="number" placeholder="Present"></div><button class="btn-save" onclick="saveAtt()">Save</button></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Student</th><th>Subject</th><th>Attendance</th><th>Action</th></tr></thead><tbody id="a-tbody"></tbody></table></div></div></div>
    
    <!-- Other Pages (Homework, Notices, Timetable) -->
    <div id="ap-homework" class="page"><div class="topbar"><div><div class="page-title">Homework</div></div></div><div class="form-section"><div class="form-section-title">Add Homework</div><div class="f-row f-row-3"><input class="fi" id="h-title" placeholder="Title"><input class="fi" id="h-sub" placeholder="Subject"><select class="fs" id="h-cls"><option>All</option><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select></div><input class="fi" id="h-due" type="date" style="margin-bottom:14px;"><button class="btn-save" onclick="saveHW()">Post</button></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Title</th><th>Class</th><th>Due</th><th>Action</th></tr></thead><tbody id="h-tbody"></tbody></table></div></div></div>

    <div id="ap-notices" class="page"><div class="topbar"><div><div class="page-title">Notices</div></div></div><div class="form-section"><div class="form-section-title">Post Notice</div><input class="fi" id="n-title" placeholder="Title" style="margin-bottom:14px;"><textarea class="fi" id="n-msg" rows="3" placeholder="Message"></textarea><button class="btn-save" onclick="saveNotice()" style="margin-top:14px;">Post</button></div><div id="n-list"></div></div>
    
    <div id="ap-timetable" class="page"><div class="topbar"><div><div class="page-title">Timetable</div></div></div><div class="form-section"><div class="form-section-title">Add Entry</div><div class="f-row f-row-4"><select class="fs" id="tt-cls"><option>Class 6</option><option>Class 7</option><option>Class 8</option><option>Class 9</option><option>Class 10</option><option>Class 11</option><option>Class 12</option></select><select class="fs" id="tt-day"><option>Monday</option><option>Tuesday</option><option>Wednesday</option><option>Thursday</option><option>Friday</option></select><input class="fi" id="tt-sub" placeholder="Subject"><input class="fi" id="tt-per" placeholder="Period"></div><button class="btn-save" onclick="saveTT()">Add</button></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Class</th><th>Day</th><th>Subject</th><th>Action</th></tr></thead><tbody id="tt-tbody"></tbody></table></div></div></div>

  </main>
</div>

<!-- STUDENT PANEL -->
<div id="screen-student" class="screen">
  <aside class="sidebar">
    <div class="sb-brand"><div class="sb-brand-inner"><div class="sb-brand-mark"><svg viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></svg></div><div class="sb-brand-name">Scholar<span>Hub</span></div></div></div>
    <nav class="nav">
      <div class="nav-item active" onclick="sPage('dash',this)">Dashboard</div>
      <div class="nav-item" onclick="sPage('grades',this)">My Grades</div>
      <div class="nav-item" onclick="sPage('attendance',this)">Attendance</div>
      <div class="nav-item" onclick="sPage('fees',this)">Fees</div>
      <div class="nav-item" onclick="sPage('library',this)">Library</div>
      <div class="nav-item" onclick="sPage('exams',this)">Exams</div>
      <div class="nav-item" onclick="sPage('idcard',this)">ID Card</div>
    </nav>
    <div style="padding:16px;border-top:1px solid var(--border);"><button class="btn-del" style="width:100%;" onclick="doLogout()">Logout</button></div>
  </aside>
  
  <main class="main">
    <div id="sp-dash" class="page active"><div class="topbar"><div class="page-title" id="s-greet">Welcome</div></div><div class="card"><div class="card-title">Quick Stats</div><div id="s-stats"></div></div></div>
    <div id="sp-grades" class="page"><div class="topbar"><div class="page-title">My Grades</div></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Subject</th><th>Exam</th><th>Score</th></tr></thead><tbody id="sg-tbody"></tbody></table></div></div></div>
    <div id="sp-attendance" class="page"><div class="topbar"><div class="page-title">My Attendance</div></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Subject</th><th>Present/Total</th><th>%</th></tr></thead><tbody id="sa-tbody"></tbody></table></div></div></div>
    <div id="sp-fees" class="page"><div class="topbar"><div class="page-title">Fee Status</div></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Amount</th><th>Date</th><th>Status</th></tr></thead><tbody id="sf-tbody"></tbody></table></div></div></div>
    <div id="sp-library" class="page"><div class="topbar"><div class="page-title">Library Books</div></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Book</th><th>Issue Date</th><th>Status</th></tr></thead><tbody id="sl-tbody"></tbody></table></div></div></div>
    <div id="sp-exams" class="page"><div class="topbar"><div class="page-title">Exam Schedule</div></div><div class="card"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Exam</th><th>Subject</th><th>Date</th></tr></thead><tbody id="se-tbody"></tbody></table></div></div></div>
    <div id="sp-idcard" class="page"><div class="topbar"><div class="page-title">My ID Card</div><button class="btn-print" onclick="window.print()">Print</button></div><div id="id-card-container" style="padding:20px;"></div></div>
  </main>
</div>

<script>
const GET = url => fetch(url).then(r => r.json());
const POST = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json());
const DEL = url => fetch(url, { method: 'DELETE' }).then(r => r.json());

let curRole = 'student';
let curStudent = null;
let allStudents = [];

function showScreen(id) { document.querySelectorAll('.screen').forEach(s => s.classList.remove('active')); document.getElementById(id).classList.add('active'); }
function aPage(name, el) { document.querySelectorAll('#screen-admin .page').forEach(p => p.classList.remove('active')); document.querySelectorAll('#screen-admin .nav-item').forEach(n => n.classList.remove('active')); document.getElementById('ap-'+name).classList.add('active'); if(el) el.classList.add('active'); loadAdminPage(name); }
function sPage(name, el) { document.querySelectorAll('#screen-student .page').forEach(p => p.classList.remove('active')); document.querySelectorAll('#screen-student .nav-item').forEach(n => n.classList.remove('active')); document.getElementById('sp-'+name).classList.add('active'); if(el) el.classList.add('active'); loadStudentPage(name); }
function switchRole(r, el) { curRole = r; document.querySelectorAll('.role-tab').forEach(t => t.classList.remove('active')); el.classList.add('active'); }

async function doLogin() {
  const username = document.getElementById('l-user').value;
  const password = document.getElementById('l-pass').value;
  const r = await POST('/api/login', { username, password, role: curRole });
  if (r.ok) {
    if (r.role === 'admin') { showScreen('screen-admin'); loadAdminPage('overview'); }
    else { curStudent = r.student; showScreen('screen-student'); loadStudentPage('dash'); }
  } else { alert(r.msg); }
}

async function doRegister() {
  const r = await POST('/api/register', { 
    name: document.getElementById('r-name').value, 
    roll: document.getElementById('r-roll').value,
    cls: document.getElementById('r-class').value,
    section: document.getElementById('r-sec').value,
    username: document.getElementById('r-user').value,
    password: document.getElementById('r-pass').value
  });
  alert(r.msg);
  if(r.ok) showScreen('screen-login');
}

function doLogout() { POST('/api/logout'); location.reload(); }

async function checkSession() {
  const r = await GET('/api/me');
  if (r.ok) {
    if (r.role === 'admin') { showScreen('screen-admin'); loadAdminPage('overview'); }
    else { curStudent = r.student; showScreen('screen-student'); loadStudentPage('dash'); }
  }
}

// --- Admin Logic ---
async function loadAdminPage(name) {
  if(name === 'overview') {
    const stats = await GET('/api/stats');
    document.getElementById('ov-st').innerText = stats.totalStudents;
    document.getElementById('ov-pend').innerText = stats.pending;
    const t = await GET('/api/teachers');
    document.getElementById('ov-teach').innerText = t.teachers.length;
    const f = await GET('/api/fees');
    const paid = f.fees.filter(x => x.status === 'Paid').reduce((a,b) => a + parseInt(b.amount), 0);
    document.getElementById('ov-fees').innerText = '₹' + paid;
  }
  else if(name === 'students') {
    const r = await GET('/api/students');
    allStudents = r.students || [];
    const pend = allStudents.filter(s => !s.approved);
    const appr = allStudents.filter(s => s.approved);
    document.getElementById('pend-tbody').innerHTML = pend.map(s => \`<tr><td>\${s.name}</td><td>\${s.cls}</td><td><button class="btn-approve" onclick="approveStudent(\${s.id})">Approve</button></td></tr>\`).join('');
    document.getElementById('appr-tbody').innerHTML = appr.map(s => \`<tr><td>\${s.name}</td><td>\${s.roll}</td><td>\${s.cls}</td><td>\${s.section}</td><td><button class="btn-edit" onclick="showIdCard(\${s.id})">View ID</button></td><td><button class="btn-edit" onclick="editStudent(\${s.id})">Edit</button> <button class="btn-del" onclick="delStudent(\${s.id})">Del</button></td></tr>\`).join('');
  }
  else if(name === 'teachers') {
    const r = await GET('/api/teachers');
    document.getElementById('t-tbody').innerHTML = (r.teachers || []).map(t => \`<tr><td>\${t.name}</td><td>\${t.subject}</td><td>\${t.cls}</td><td><button class="btn-del" onclick="delTeacher(\${t.id})">Del</button></td></tr>\`).join('');
  }
  else if(name === 'fees') {
    await populateStudentSelect('f-st');
    const r = await GET('/api/fees');
    document.getElementById('f-tbody').innerHTML = (r.fees || []).map(f => {
      const st = allStudents.find(s => s.id === f.sid);
      return \`<tr><td>\${st ? st.name : 'Unknown'}</td><td>₹\${f.amount}</td><td>\${f.date}</td><td><span class="badge \${f.status==='Paid'?'b-green':'b-amber'}">\${f.status}</span></td><td><button class="btn-del" onclick="delFee(\${f.id})">Del</button></td></tr>\`;
    }).join('');
  }
  else if(name === 'library') {
    await populateStudentSelect('l-st');
    const r = await GET('/api/library');
    document.getElementById('l-tbody').innerHTML = (r.library || []).map(l => {
      const st = allStudents.find(s => s.id === l.sid);
      return \`<tr><td>\${st ? st.name : 'Unknown'}</td><td>\${l.book}</td><td>\${l.issueDate}</td><td><span class="badge \${l.status==='Issued'?'b-sky':'b-green'}">\${l.status}</span></td><td><button class="btn-approve" onclick="returnBook(\${l.id})">Return</button> <button class="btn-del" onclick="delLib(\${l.id})">Del</button></td></tr>\`;
    }).join('');
  }
  else if(name === 'exams') {
    const r = await GET('/api/exams');
    document.getElementById('e-tbody').innerHTML = (r.exams || []).map(e => \`<tr><td>\${e.cls}</td><td>\${e.title}</td><td>\${e.sub}</td><td>\${e.date}</td><td><button class="btn-del" onclick="delExam(\${e.id})">Del</button></td></tr>\`).join('');
  }
  else if(name === 'grades') {
    await populateStudentSelect('g-st');
    const r = await GET('/api/grades');
    document.getElementById('g-tbody').innerHTML = (r.grades || []).map(g => {
      const st = allStudents.find(s => s.id === g.sid);
      return \`<tr><td>\${st ? st.name : 'Unknown'}</td><td>\${g.sub}</td><td>\${g.obt}/\${g.max}</td><td><button class="btn-del" onclick="delGrade(\${g.id})">Del</button></td></tr>\`;
    }).join('');
  }
  else if(name === 'attendance') {
    await populateStudentSelect('a-st');
    const r = await GET('/api/attendance');
    document.getElementById('a-tbody').innerHTML = (r.attendance || []).map(a => {
      const st = allStudents.find(s => s.id === a.sid);
      return \`<tr><td>\${st ? st.name : 'Unknown'}</td><td>\${a.sub}</td><td>\${a.pre}/\${a.tot}</td><td><button class="btn-del" onclick="delAtt(\${a.id})">Del</button></td></tr>\`;
    }).join('');
  }
  else if(name === 'homework') {
    const r = await GET('/api/homework');
    document.getElementById('h-tbody').innerHTML = (r.homework || []).map(h => \`<tr><td>\${h.title}</td><td>\${h.cls}</td><td>\${h.due}</td><td><button class="btn-del" onclick="delHW(\${h.id})">Del</button></td></tr>\`).join('');
  }
  else if(name === 'notices') {
    const r = await GET('/api/notices');
    document.getElementById('n-list').innerHTML = (r.notices || []).map(n => \`<div class="card"><div style="display:flex;justify-content:space-between"><strong>\${n.title}</strong><button class="btn-del" onclick="delNotice(\${n.id})">Del</button></div><p style="margin-top:8px;color:var(--text2)">\${n.msg}</p></div>\`).join('');
  }
  else if(name === 'timetable') {
    const r = await GET('/api/timetable');
    document.getElementById('tt-tbody').innerHTML = (r.timetable || []).map(t => \`<tr><td>\${t.cls}</td><td>\${t.day}</td><td>\${t.sub}</td><td><button class="btn-del" onclick="delTT(\${t.id})">Del</button></td></tr>\`).join('');
  }
}

async function populateStudentSelect(id) {
  if(allStudents.length === 0) { const r = await GET('/api/students'); allStudents = r.students || []; }
  document.getElementById(id).innerHTML = '<option>Select</option>' + allStudents.filter(s => s.approved).map(s => \`<option value="\${s.id}">\${s.name} (\${s.cls})</option>\`).join('');
}

// Admin Actions
const save = async (url, data, cb) => { await POST(url, data); if(cb) cb(); else loadAdminPage(curPage); };
const del = async (url, cb) => { await DEL(url); if(cb) cb(); else loadAdminPage(curPage); };

let curPage = 'overview';
const origAPage = aPage;
aPage = (n, e) => { curPage = n; origAPage(n, e); };

const approveStudent = id => POST('/api/students/' + id + '/approve').then(() => loadAdminPage('students'));
const delStudent = id => { if(confirm('Delete student?')) DEL('/api/students/' + id).then(() => loadAdminPage('students')); };
const editStudent = id => { const s = allStudents.find(x => x.id === id); if(!s) return; const n = prompt('New Name:', s.name); if(n) { POST('/api/students/edit', { id, name: n, roll: s.roll, cls: s.cls, section: s.section }).then(() => loadAdminPage('students')); } }

const saveTeacher = () => POST('/api/teachers', { name: document.getElementById('t-name').value, subject: document.getElementById('t-sub').value, cls: document.getElementById('t-cls').value }).then(() => loadAdminPage('teachers'));
const delTeacher = id => DEL('/api/teachers/' + id).then(() => loadAdminPage('teachers'));

const saveFee = () => POST('/api/fees', { sid: document.getElementById('f-st').value, amount: document.getElementById('f-amt').value, date: document.getElementById('f-date').value, status: document.getElementById('f-status').value }).then(() => loadAdminPage('fees'));
const delFee = id => DEL('/api/fees/' + id).then(() => loadAdminPage('fees'));

const saveLibrary = () => POST('/api/library', { sid: document.getElementById('l-st').value, book: document.getElementById('l-book').value, issueDate: document.getElementById('l-issue').value, returnDate: document.getElementById('l-ret').value, status: 'Issued' }).then(() => loadAdminPage('library'));
const returnBook = id => POST('/api/library/return', { id }).then(() => loadAdminPage('library'));
const delLib = id => DEL('/api/library/' + id).then(() => loadAdminPage('library'));

const saveExam = () => POST('/api/exams', { cls: document.getElementById('e-cls').value, title: document.getElementById('e-title').value, sub: document.getElementById('e-sub').value, date: document.getElementById('e-date').value }).then(() => loadAdminPage('exams'));
const delExam = id => DEL('/api/exams/' + id).then(() => loadAdminPage('exams'));

const saveGrade = () => POST('/api/grades', { sid: document.getElementById('g-st').value, sub: document.getElementById('g-sub').value, exam: document.getElementById('g-exam').value, max: document.getElementById('g-max').value, obt: document.getElementById('g-obt').value }).then(() => loadAdminPage('grades'));
const delGrade = id => DEL('/api/grades/' + id).then(() => loadAdminPage('grades'));

const saveAtt = () => POST('/api/attendance', { sid: document.getElementById('a-st').value, sub: document.getElementById('a-sub').value, tot: document.getElementById('a-tot').value, pre: document.getElementById('a-pre').value }).then(() => loadAdminPage('attendance'));
const delAtt = id => DEL('/api/attendance/' + id).then(() => loadAdminPage('attendance'));

const saveHW = () => POST('/api/homework', { title: document.getElementById('h-title').value, sub: document.getElementById('h-sub').value, cls: document.getElementById('h-cls').value, due: document.getElementById('h-due').value }).then(() => loadAdminPage('homework'));
const delHW = id => DEL('/api/homework/' + id).then(() => loadAdminPage('homework'));

const saveNotice = () => POST('/api/notices', { title: document.getElementById('n-title').value, msg: document.getElementById('n-msg').value, cat: 'General' }).then(() => loadAdminPage('notices'));
const delNotice = id => DEL('/api/notices/' + id).then(() => loadAdminPage('notices'));

const saveTT = () => POST('/api/timetable', { cls: document.getElementById('tt-cls').value, day: document.getElementById('tt-day').value, sub: document.getElementById('tt-sub').value, period: document.getElementById('tt-per').value }).then(() => loadAdminPage('timetable'));
const delTT = id => DEL('/api/timetable/' + id).then(() => loadAdminPage('timetable'));

function showIdCard(id) {
  const s = allStudents.find(x => x.id === id);
  if(!s) return;
  const html = \`
    <div class="id-card-wrap">
      <div class="id-card-header"><h2>ScholarHub Academy</h2></div>
      <div class="id-card-body">
        <div class="id-avatar">\${s.name.split(' ').map(n=>n[0]).join('').substring(0,2)}</div>
        <h3 style="margin:10px 0 5px">\${s.name}</h3>
        <div class="id-row"><span class="id-label">Roll No:</span><span class="id-val">\${s.roll}</span></div>
        <div class="id-row"><span class="id-label">Class:</span><span class="id-val">\${s.cls} - \${s.section}</span></div>
      </div>
    </div>\`;
  document.getElementById('appr-tbody').innerHTML += \`<tr><td colspan="6">\${html}</td></tr>\`;
}

// --- Student Logic ---
async function loadStudentPage(name) {
  if(name === 'dash') {
    document.getElementById('s-greet').innerText = 'Welcome, ' + curStudent.name;
    document.getElementById('s-stats').innerHTML = \`
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
        <div class="stat-card"><div class="stat-label">Class</div><div class="stat-val">\${curStudent.cls}</div></div>
        <div class="stat-card"><div class="stat-label">Roll</div><div class="stat-val">\${curStudent.roll}</div></div>
      </div>
    \`;
  }
  else if(name === 'grades') {
    const r = await GET('/api/grades');
    document.getElementById('sg-tbody').innerHTML = (r.grades || []).map(g => \`<tr><td>\${g.sub}</td><td>\${g.exam}</td><td>\${g.obt}/\${g.max}</td></tr>\`).join('') || '<tr><td colspan="3" class="tbl-empty">No data</td></tr>';
  }
  else if(name === 'attendance') {
    const r = await GET('/api/attendance');
    document.getElementById('sa-tbody').innerHTML = (r.attendance || []).map(a => \`<tr><td>\${a.sub}</td><td>\${a.pre}/\${a.tot}</td><td>\${Math.round(a.pre/a.tot*100)}%</td></tr>\`).join('') || '<tr><td colspan="3" class="tbl-empty">No data</td></tr>';
  }
  else if(name === 'fees') {
    const r = await GET('/api/fees');
    document.getElementById('sf-tbody').innerHTML = (r.fees || []).map(f => \`<tr><td>₹\${f.amount}</td><td>\${f.date}</td><td><span class="badge \${f.status==='Paid'?'b-green':'b-amber'}">\${f.status}</span></td></tr>\`).join('') || '<tr><td colspan="3" class="tbl-empty">No data</td></tr>';
  }
  else if(name === 'library') {
    const r = await GET('/api/library');
    document.getElementById('sl-tbody').innerHTML = (r.library || []).map(l => \`<tr><td>\${l.book}</td><td>\${l.issueDate}</td><td><span class="badge \${l.status==='Issued'?'b-sky':'b-green'}">\${l.status}</span></td></tr>\`).join('') || '<tr><td colspan="3" class="tbl-empty">No data</td></tr>';
  }
  else if(name === 'exams') {
    const r = await GET('/api/exams');
    document.getElementById('se-tbody').innerHTML = (r.exams || []).map(e => \`<tr><td>\${e.title}</td><td>\${e.sub}</td><td>\${e.date}</td></tr>\`).join('') || '<tr><td colspan="3" class="tbl-empty">No data</td></tr>';
  }
  else if(name === 'idcard') {
    const s = curStudent;
    document.getElementById('id-card-container').innerHTML = \`
      <div class="id-card-wrap">
        <div class="id-card-header"><h2>ScholarHub Academy</h2></div>
        <div class="id-card-body">
          <div class="id-avatar">\${s.name.split(' ').map(n=>n[0]).join('').substring(0,2)}</div>
          <h3 style="margin:10px 0 5px">\${s.name}</h3>
          <div class="id-row"><span class="id-label">Roll No:</span><span class="id-val">\${s.roll}</span></div>
          <div class="id-row"><span class="id-label">Class:</span><span class="id-val">\${s.cls} - \${s.section}</span></div>
        </div>
      </div>\`;
  }
}

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

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
