require("dotenv").config?.();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Defina JWT_SECRET com pelo menos 32 caracteres.");
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300 }));

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "lkgerenciamento.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('ADMIN','SUBADMIN')),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 cad TEXT NOT NULL COLLATE NOCASE UNIQUE,
 matricula TEXT NOT NULL COLLATE NOCASE UNIQUE,
 serie TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('EM_ANALISE','EFETIVADO','REJEITADO')),
 created_at TEXT NOT NULL,
 reviewed_at TEXT,
 reviewed_by TEXT,
 FOREIGN KEY(owner_id) REFERENCES users(id),
 FOREIGN KEY(reviewed_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor_id TEXT,
 action TEXT NOT NULL,
 target_id TEXT,
 details TEXT,
 created_at TEXT NOT NULL,
 FOREIGN KEY(actor_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_records_owner ON records(owner_id);
CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
`);

function now(){ return new Date().toISOString(); }
function id(){ return crypto.randomUUID(); }
function normalize(v){ return String(v ?? "").trim().replace(/\s+/g," "); }
function normalizeKey(v){ return normalize(v).toLowerCase(); }

const adminEmail = process.env.ADMIN_EMAIL || "admin@lkgerenciamento.com";
const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword || adminPassword.length < 8) {
  console.error("Defina ADMIN_PASSWORD com pelo menos 8 caracteres.");
  process.exit(1);
}
const adminExists = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!adminExists) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(id,name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)")
    .run(id(), "Administrador Geral", adminEmail, hash, "ADMIN", now());
}

function sign(user){
  return jwt.sign({ sub:user.id, role:user.role }, JWT_SECRET, { expiresIn:"8h" });
}
function auth(req,res,next){
  try {
    const token = req.cookies?.lk_token;
    if (!token) return res.status(401).json({error:"Não autenticado"});
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare("SELECT id,name,email,role,active FROM users WHERE id=?").get(payload.sub);
    if (!user || !user.active) return res.status(401).json({error:"Sessão inválida"});
    req.user = user; next();
  } catch { return res.status(401).json({error:"Não autenticado"}); }
}
function adminOnly(req,res,next){
  if(req.user.role!=="ADMIN") return res.status(403).json({error:"Acesso restrito ao administrador geral"});
  next();
}
function audit(actor,action,target,details){
  db.prepare("INSERT INTO audit_log(actor_id,action,target_id,details,created_at) VALUES(?,?,?,?,?)")
    .run(actor,action,target,details||null,now());
}

// cookie parser minimal
app.use((req,res,next)=>{
  const raw=req.headers.cookie||"";
  req.cookies={};
  raw.split(";").forEach(part=>{
    const i=part.indexOf("=");
    if(i>0) req.cookies[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());
  });
  next();
});

app.post("/api/login", (req,res)=>{
  const email=normalizeKey(req.body.email), password=String(req.body.password||"");
  const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!user || !user.active || !bcrypt.compareSync(password,user.password_hash))
    return res.status(401).json({error:"E-mail ou senha inválidos"});
  const token=sign(user);
  const secure = process.env.COOKIE_SECURE === "true";
  const cookie = `lk_token=${encodeURIComponent(token)}; Max-Age=${8*60*60}; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
  res.setHeader("Set-Cookie", cookie);
  res.json({user:{id:user.id,name:user.name,email:user.email,role:user.role}});
});
app.post("/api/logout",(req,res)=>{
  res.setHeader("Set-Cookie", "lk_token=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
  res.json({ok:true});
});
app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));

app.get("/api/dashboard",auth,(req,res)=>{
  const where=req.user.role==="ADMIN"?"":"WHERE owner_id=?";
  const args=req.user.role==="ADMIN"?[]:[req.user.id];
  const total=db.prepare(`SELECT COUNT(*) c FROM records ${where}`).get(...args).c;
  const pending=db.prepare(`SELECT COUNT(*) c FROM records ${where}${where?" AND":"WHERE"} status='EM_ANALISE'`).get(...args).c;
  const effective=db.prepare(`SELECT COUNT(*) c FROM records ${where}${where?" AND":"WHERE"} status='EFETIVADO'`).get(...args).c;
  const rejected=db.prepare(`SELECT COUNT(*) c FROM records ${where}${where?" AND":"WHERE"} status='REJEITADO'`).get(...args).c;
  const subs=req.user.role==="ADMIN"?db.prepare("SELECT COUNT(*) c FROM users WHERE role='SUBADMIN' AND active=1").get().c:0;
  res.json({total,pending,effective,rejected,subs});
});

app.get("/api/users",auth,adminOnly,(req,res)=>{
  const rows=db.prepare(`
    SELECT u.id,u.name,u.email,u.active,u.created_at,
      (SELECT COUNT(*) FROM records r WHERE r.owner_id=u.id) AS record_count
    FROM users u WHERE u.role='SUBADMIN' ORDER BY u.created_at DESC
  `).all();
  res.json(rows);
});

app.post("/api/users",auth,adminOnly,(req,res)=>{
  const name=normalize(req.body.name), email=normalizeKey(req.body.email), password=String(req.body.password||"");
  if(!name || !email || password.length<8) return res.status(400).json({error:"Nome, e-mail e senha (mínimo 8 caracteres) são obrigatórios"});
  try{
    const user={id:id(),name,email,password_hash:bcrypt.hashSync(password,12),role:"SUBADMIN",created_at:now()};
    db.prepare("INSERT INTO users(id,name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)")
      .run(user.id,user.name,user.email,user.password_hash,user.role,user.created_at);
    audit(req.user.id,"CRIAR_SUBADMIN",user.id,`Criou ${name}`);
    res.status(201).json({id:user.id,name,email,role:user.role,access_path:`/login?subadmin=${user.id}`});
  }catch(e){ if(String(e).includes("UNIQUE")) return res.status(409).json({error:"Este e-mail já está cadastrado"}); throw e; }
});

app.patch("/api/users/:id/active",auth,adminOnly,(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE id=? AND role='SUBADMIN'").get(req.params.id);
  if(!u) return res.status(404).json({error:"Subadministrador não encontrado"});
  const active=req.body.active?1:0;
  db.prepare("UPDATE users SET active=? WHERE id=?").run(active,u.id);
  audit(req.user.id,active?"ATIVAR_SUBADMIN":"DESATIVAR_SUBADMIN",u.id,u.name);
  res.json({ok:true});
});

app.get("/api/records",auth,(req,res)=>{
  const rows=req.user.role==="ADMIN"
    ? db.prepare(`SELECT r.*,u.name owner_name FROM records r JOIN users u ON u.id=r.owner_id ORDER BY r.created_at DESC`).all()
    : db.prepare(`SELECT r.*,u.name owner_name FROM records r JOIN users u ON u.id=r.owner_id WHERE r.owner_id=? ORDER BY r.created_at DESC`).all(req.user.id);
  res.json(rows);
});

app.post("/api/records",auth,(req,res)=>{
  const name=normalize(req.body.name), cad=normalize(req.body.cad), matricula=normalize(req.body.matricula), serie=normalize(req.body.serie);
  if(!name||!cad||!matricula||!serie) return res.status(400).json({error:"Nome, CAD, matrícula e série são obrigatórios"});
  const dc=db.prepare("SELECT id,name FROM records WHERE cad=?").get(cad);
  const dm=db.prepare("SELECT id,name FROM records WHERE matricula=?").get(matricula);
  if(dc||dm) return res.status(409).json({
    error:"DUPLICIDADE",
    message:"Cadastro bloqueado por duplicidade.",
    duplicate:{cad:!!dc,matricula:!!dm}
  });
  const record={id:id(),name,cad,matricula,serie,owner_id:req.user.id,status:"EM_ANALISE",created_at:now()};
  try{
    db.prepare(`INSERT INTO records(id,name,cad,matricula,serie,owner_id,status,created_at) VALUES(?,?,?,?,?,?,?,?)`)
      .run(record.id,record.name,record.cad,record.matricula,record.serie,record.owner_id,record.status,record.created_at);
    audit(req.user.id,"CRIAR_CADASTRO",record.id,name);
    res.status(201).json(record);
  }catch(e){
    if(String(e).includes("UNIQUE")) return res.status(409).json({error:"DUPLICIDADE",message:"CAD ou matrícula já cadastrado."});
    throw e;
  }
});

app.patch("/api/records/:id/status",auth,adminOnly,(req,res)=>{
  const status=req.body.status;
  if(!["EFETIVADO","REJEITADO"].includes(status)) return res.status(400).json({error:"Status inválido"});
  const r=db.prepare("SELECT * FROM records WHERE id=?").get(req.params.id);
  if(!r) return res.status(404).json({error:"Cadastro não encontrado"});
  db.prepare("UPDATE records SET status=?,reviewed_at=?,reviewed_by=? WHERE id=?").run(status,now(),req.user.id,r.id);
  audit(req.user.id,status==="EFETIVADO"?"EFETIVAR_CADASTRO":"REJEITAR_CADASTRO",r.id,r.name);
  res.json({ok:true});
});

app.get("/api/history",auth,adminOnly,(req,res)=>{
  res.json(db.prepare(`
    SELECT a.*,u.name actor_name FROM audit_log a
    LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 500
  `).all());
});

app.get("/api/export.csv",auth,adminOnly,(req,res)=>{
  const rows=db.prepare(`
    SELECT r.name,r.cad,r.matricula,r.serie,u.name owner_name,r.status,r.created_at
    FROM records r JOIN users u ON u.id=r.owner_id ORDER BY r.created_at DESC
  `).all();
  const esc=v=>`"${String(v??"").replace(/"/g,'""')}"`;
  let csv="\ufeffNome;CAD;Matrícula;Série;Subadministrador;Status;Data\n";
  for(const r of rows) csv += [r.name,r.cad,r.matricula,r.serie,r.owner_name,r.status,r.created_at].map(esc).join(";")+"\n";
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="LKGERENCIAMENTO_cadastros.csv"');
  res.send(csv);
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>console.log(`LKGERENCIAMENTO rodando em http://localhost:${PORT}`));
