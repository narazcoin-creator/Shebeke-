import express from "express";
import http from "http";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import nodemailer from "nodemailer";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import pg from "pg";
import { Server } from "socket.io";

const __filename=fileURLToPath(import.meta.url), __dirname=path.dirname(__filename);
const app=express(), server=http.createServer(app);
const PORT=process.env.PORT||4000;
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL});
const allowed=process.env.WEB_ORIGIN||"http://localhost:3000";
const io=new Server(server,{cors:{origin:allowed,credentials:true}});
app.use(cors({origin:allowed,credentials:true}));
app.use(express.json({limit:"2mb"})); app.use(cookieParser());
const uploadDir=path.join(__dirname,"../uploads"); fs.mkdirSync(uploadDir,{recursive:true});
app.use("/uploads",express.static(uploadDir));

const q=(text,params=[])=>pool.query(text,params);
const hash=s=>crypto.createHash("sha256").update(s).digest("hex");
function token(u){return jwt.sign({sub:u.id,role:u.role,email:u.email},process.env.JWT_SECRET,{expiresIn:"30d"});}
function setAuth(res,u){res.cookie("shebeke_token",token(u),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:30*864e5});}
async function auth(req,res,next){
 try{const raw=req.cookies.shebeke_token;if(!raw)return res.status(401).json({error:"AUTH_REQUIRED"});
 const p=jwt.verify(raw,process.env.JWT_SECRET); const {rows}=await q("SELECT id,email,username,display_name,bio,avatar_url,city,role,email_verified FROM users WHERE id=$1",[p.sub]);
 if(!rows[0])return res.status(401).json({error:"AUTH_REQUIRED"}); req.user=rows[0]; await q("UPDATE users SET last_seen_at=now() WHERE id=$1",[req.user.id]); next();
 }catch(e){res.status(401).json({error:"AUTH_REQUIRED"});}
}
const admin=(req,res,next)=>req.user?.role==="admin"?next():res.status(403).json({error:"ADMIN_REQUIRED"});
const smtp=()=>process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS?nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE)==="true",auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}}):null;
function code(){return String(Math.floor(100000+Math.random()*900000));}
async function sendCode(email,c){
 const t=smtp(); if(!t) throw new Error("SMTP_NOT_CONFIGURED");
 await t.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:email,subject:"ŞƏBƏКƏ — təsdiq kodu",text:`ŞƏBƏКƏ hesabınızı təsdiqləmək üçün kodunuz: ${c}\nKod 10 dəqiqə etibarlıdır.`});
}
function publicUser(u){return {id:u.id,email:u.email,username:u.username,display_name:u.display_name,bio:u.bio,avatar_url:u.avatar_url,city:u.city,role:u.role,email_verified:u.email_verified};}

app.get("/health",async(_,res)=>{try{await q("SELECT 1");res.json({ok:true,service:"shebeke-api",time:new Date().toISOString()})}catch{res.status(503).json({ok:false})}});
app.get("/me",auth,(req,res)=>res.json({user:publicUser(req.user)}));
app.post("/auth/register",async(req,res)=>{
 const {email,password,username,display_name,city=""}=req.body||{};
 if(!email||!password||!username||!display_name)return res.status(400).json({error:"MISSING_FIELDS"});
 if(password.length<8)return res.status(400).json({error:"PASSWORD_TOO_SHORT"});
 if(!/^[a-zA-Z0-9_.]{3,24}$/.test(username))return res.status(400).json({error:"BAD_USERNAME"});
 try{
  const exists=await q("SELECT id FROM users WHERE lower(email)=lower($1) OR lower(username)=lower($2)",[email,username]);
  if(exists.rows[0])return res.status(409).json({error:"ACCOUNT_EXISTS"});
  const ph=await bcrypt.hash(password,12);
  const {rows}=await q("INSERT INTO users(email,password_hash,username,display_name,city) VALUES(lower($1),$2,lower($3),$4,$5) RETURNING id,email,username,display_name,bio,avatar_url,city,role,email_verified",[email,ph,username,display_name,city]);
  const c=code(); await q("INSERT INTO verification_codes(user_id,code_hash,expires_at) VALUES($1,$2,now()+interval '10 minutes')",[rows[0].id,hash(c)]);
  try{await sendCode(email,c)}catch(e){await q("DELETE FROM users WHERE id=$1",[rows[0].id]);return res.status(503).json({error:"SMTP_NOT_CONFIGURED"});}
  res.status(201).json({ok:true,needsVerification:true,email});
 }catch(e){console.error(e);res.status(500).json({error:"REGISTER_FAILED"});}
});
app.post("/auth/verify",async(req,res)=>{
 const {email,code:input}=req.body||{}; if(!email||!/^\d{6}$/.test(input||""))return res.status(400).json({error:"BAD_CODE"});
 const u=(await q("SELECT id,email,username,display_name,bio,avatar_url,city,role,email_verified FROM users WHERE email=lower($1)",[email])).rows[0];
 if(!u)return res.status(404).json({error:"NOT_FOUND"});
 const v=(await q("SELECT id FROM verification_codes WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL AND expires_at>now() ORDER BY id DESC LIMIT 1",[u.id,hash(input)])).rows[0];
 if(!v)return res.status(400).json({error:"INVALID_OR_EXPIRED_CODE"});
 await q("UPDATE verification_codes SET used_at=now() WHERE id=$1",[v.id]); await q("UPDATE users SET email_verified=true WHERE id=$1",[u.id]); u.email_verified=true; setAuth(res,u); res.json({user:publicUser(u)});
});
app.post("/auth/resend",async(req,res)=>{
 const {email}=req.body||{}; const u=(await q("SELECT id FROM users WHERE email=lower($1)",[email])).rows[0]; if(!u)return res.status(404).json({error:"NOT_FOUND"});
 const c=code(); await q("INSERT INTO verification_codes(user_id,code_hash,expires_at) VALUES($1,$2,now()+interval '10 minutes')",[u.id,hash(c)]); try{await sendCode(email,c);res.json({ok:true})}catch{res.status(503).json({error:"SMTP_NOT_CONFIGURED"});}
});
app.post("/auth/login",async(req,res)=>{
 const {email,password}=req.body||{}; const u=(await q("SELECT * FROM users WHERE email=lower($1)",[email])).rows[0];
 if(!u||!(await bcrypt.compare(password||"",u.password_hash)))return res.status(401).json({error:"INVALID_CREDENTIALS"});
 if(!u.email_verified)return res.status(403).json({error:"EMAIL_NOT_VERIFIED"});
 setAuth(res,u);res.json({user:publicUser(u)});
});
app.post("/auth/logout",(req,res)=>{res.clearCookie("shebeke_token");res.json({ok:true})});

const storage=multer.diskStorage({destination:uploadDir,filename:(_,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())});
const mediaUpload=multer({storage,limits:{fileSize:Number(process.env.UPLOAD_MAX_MB||25)*1024*1024},fileFilter:(_,f,cb)=>cb(null,/^(image|video)\//.test(f.mimetype))});
app.post("/media",auth,mediaUpload.single("file"),(req,res)=>{if(!req.file)return res.status(400).json({error:"FILE_REQUIRED"});res.json({url:`${process.env.API_PUBLIC_URL||`http://localhost:${PORT}`}/uploads/${req.file.filename}`,type:req.file.mimetype});});

app.get("/feed",auth,async(req,res)=>{
 const limit=Math.min(Number(req.query.limit||30),50), offset=Math.max(Number(req.query.offset||0),0);
 const {rows}=await q(`SELECT p.id,p.body,p.media_url,p.media_type,p.created_at,u.id user_id,u.username,u.display_name,u.avatar_url,
 (SELECT count(*) FROM likes l WHERE l.post_id=p.id)::int likes,(SELECT count(*) FROM comments c WHERE c.post_id=p.id)::int comments,
 EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=$1) liked
 FROM posts p JOIN users u ON u.id=p.user_id WHERE u.email_verified=true ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`,[req.user.id,limit,offset]);
 res.json({posts:rows});
});
app.post("/posts",auth,async(req,res)=>{
 const {body="",media_url="",media_type=""}=req.body||{}; if(!body.trim()&&!media_url)return res.status(400).json({error:"EMPTY_POST"});
 const {rows}=await q("INSERT INTO posts(user_id,body,media_url,media_type) VALUES($1,$2,$3,$4) RETURNING *",[req.user.id,body.trim(),media_url,media_type]);
 res.status(201).json({post:{...rows[0],user_id:req.user.id,username:req.user.username,display_name:req.user.display_name,avatar_url:req.user.avatar_url,likes:0,comments:0,liked:false}});
});
app.post("/posts/:id/like",auth,async(req,res)=>{
 const exists=await q("SELECT 1 FROM likes WHERE user_id=$1 AND post_id=$2",[req.user.id,req.params.id]);
 if(exists.rows[0]){await q("DELETE FROM likes WHERE user_id=$1 AND post_id=$2",[req.user.id,req.params.id]);res.json({liked:false})}
 else {await q("INSERT INTO likes(user_id,post_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.user.id,req.params.id]);res.json({liked:true})}
});
app.get("/posts/:id/comments",auth,async(req,res)=>res.json({comments:(await q("SELECT c.id,c.body,c.created_at,u.username,u.display_name,u.avatar_url FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=$1 ORDER BY c.created_at ASC",[req.params.id])).rows}));
app.post("/posts/:id/comments",auth,async(req,res)=>{const b=(req.body?.body||"").trim();if(!b)return res.status(400).json({error:"EMPTY_COMMENT"});const {rows}=await q("INSERT INTO comments(post_id,user_id,body) VALUES($1,$2,$3) RETURNING id,body,created_at",[req.params.id,req.user.id,b]);res.status(201).json({comment:{...rows[0],username:req.user.username,display_name:req.user.display_name,avatar_url:req.user.avatar_url}})});

app.get("/users/search",auth,async(req,res)=>{const s=`%${String(req.query.q||"").slice(0,50)}%`;res.json({users:(await q("SELECT id,username,display_name,avatar_url,city,bio FROM users WHERE email_verified=true AND (username ILIKE $1 OR display_name ILIKE $1) ORDER BY display_name LIMIT 30",[s])).rows})});
app.get("/users/:username",auth,async(req,res)=>{const u=(await q("SELECT id,username,display_name,bio,avatar_url,city,created_at FROM users WHERE username=lower($1) AND email_verified=true",[req.params.username])).rows[0];if(!u)return res.status(404).json({error:"NOT_FOUND"});const f=await q("SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2",[req.user.id,u.id]);const counts=await q("SELECT (SELECT count(*) FROM follows WHERE following_id=$1)::int followers,(SELECT count(*) FROM follows WHERE follower_id=$1)::int following",( [u.id]));res.json({user:u,following:!!f.rows[0],...counts.rows[0]})});
app.post("/users/:id/follow",auth,async(req,res)=>{if(req.params.id===req.user.id)return res.status(400).json({error:"SELF_FOLLOW"});const x=await q("SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2",[req.user.id,req.params.id]);if(x.rows[0]){await q("DELETE FROM follows WHERE follower_id=$1 AND following_id=$2",[req.user.id,req.params.id]);res.json({following:false})}else{await q("INSERT INTO follows(follower_id,following_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.user.id,req.params.id]);res.json({following:true})}});
app.patch("/me",auth,async(req,res)=>{const {display_name,bio,city,avatar_url}=req.body||{};const {rows}=await q("UPDATE users SET display_name=COALESCE($1,display_name),bio=COALESCE($2,bio),city=COALESCE($3,city),avatar_url=COALESCE($4,avatar_url) WHERE id=$5 RETURNING id,email,username,display_name,bio,avatar_url,city,role,email_verified",[display_name,bio,city,avatar_url,req.user.id]);res.json({user:publicUser(rows[0])})});

app.get("/communities",auth,async(_,res)=>res.json({items:(await q("SELECT c.*,count(cm.user_id)::int members FROM communities c LEFT JOIN community_members cm ON cm.community_id=c.id GROUP BY c.id ORDER BY members DESC, c.name LIMIT 100")).rows}));
app.post("/communities",auth,async(req,res)=>{const {name,description="",city=""}=req.body||{};if(!name)return res.status(400).json({error:"NAME_REQUIRED"});const {rows}=await q("INSERT INTO communities(name,description,city,created_by) VALUES($1,$2,$3,$4) RETURNING *",[name,description,city,req.user.id]);res.status(201).json({item:rows[0]})});
app.post("/communities/:id/join",auth,async(req,res)=>{const x=await q("SELECT 1 FROM community_members WHERE community_id=$1 AND user_id=$2",[req.params.id,req.user.id]);if(x.rows[0]){await q("DELETE FROM community_members WHERE community_id=$1 AND user_id=$2",[req.params.id,req.user.id]);res.json({joined:false})}else{await q("INSERT INTO community_members(community_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.params.id,req.user.id]);res.json({joined:true})}});

app.get("/events",auth,async(_,res)=>res.json({items:(await q("SELECT * FROM events WHERE starts_at>=now() ORDER BY starts_at ASC LIMIT 100")).rows}));
app.post("/events",auth,async(req,res)=>{const {title,description="",city="",venue="",starts_at}=req.body||{};if(!title||!starts_at)return res.status(400).json({error:"MISSING_FIELDS"});const {rows}=await q("INSERT INTO events(title,description,city,venue,starts_at,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",[title,description,city,venue,starts_at,req.user.id]);res.status(201).json({item:rows[0]})});

app.get("/businesses",auth,async(req,res)=>{const {lat,lng,radius=25}=req.query;let sql="SELECT * FROM businesses",params=[];if(lat&&lng){sql+=` WHERE lat IS NOT NULL AND lng IS NOT NULL AND (6371*acos(least(1,cos(radians($1))*cos(radians(lat))*cos(radians(lng)-radians($2))+sin(radians($1))*sin(radians(lat))))) <= $3`;params=[Number(lat),Number(lng),Number(radius)];}sql+=" ORDER BY created_at DESC LIMIT 100";res.json({items:(await q(sql,params)).rows})});
app.post("/businesses",auth,async(req,res)=>{const {name,description="",city="",category="",address="",lat=null,lng=null}=req.body||{};if(!name)return res.status(400).json({error:"NAME_REQUIRED"});const {rows}=await q("INSERT INTO businesses(name,description,city,category,address,lat,lng,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",[name,description,city,category,address,lat,lng,req.user.id]);res.status(201).json({item:rows[0]})});

app.get("/nearby",auth,async(req,res)=>{const {lat,lng,radius=10}=req.query;if(!lat||!lng)return res.status(400).json({error:"LOCATION_REQUIRED"});const sql=`SELECT *,6371*acos(least(1,cos(radians($1))*cos(radians(lat))*cos(radians(lng)-radians($2))+sin(radians($1))*sin(radians(lat)))) distance_km FROM businesses WHERE lat IS NOT NULL AND lng IS NOT NULL AND 6371*acos(least(1,cos(radians($1))*cos(radians(lat))*cos(radians(lng)-radians($2))+sin(radians($1))*sin(radians(lat)))) <= $3 ORDER BY distance_km LIMIT 100`;res.json({items:(await q(sql,[Number(lat),Number(lng),Number(radius)])).rows})});

app.post("/conversations",auth,async(req,res)=>{const other=req.body?.user_id;if(!other||other===req.user.id)return res.status(400).json({error:"BAD_USER"});const existing=await q(`SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id JOIN conversation_members b ON b.conversation_id=c.id WHERE a.user_id=$1 AND b.user_id=$2 GROUP BY c.id HAVING count(*)=2 LIMIT 1`,[req.user.id,other]);if(existing.rows[0])return res.json({id:existing.rows[0].id});const c=(await q("INSERT INTO conversations DEFAULT VALUES RETURNING id")).rows[0];await q("INSERT INTO conversation_members VALUES($1,$2),($1,$3)",[c.id,req.user.id,other]);res.status(201).json(c)});
app.get("/conversations",auth,async(req,res)=>{res.json({items:(await q(`SELECT c.id,c.created_at,(SELECT m.body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_message,(SELECT m.created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_at,(SELECT json_build_object('id',u.id,'username',u.username,'display_name',u.display_name,'avatar_url',u.avatar_url) FROM conversation_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conversation_id=c.id AND u.id<>$1 LIMIT 1) other FROM conversations c JOIN conversation_members me ON me.conversation_id=c.id AND me.user_id=$1 ORDER BY last_at DESC NULLS LAST`,[req.user.id])).rows})});
app.get("/conversations/:id/messages",auth,async(req,res)=>{const member=await q("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[req.params.id,req.user.id]);if(!member.rows[0])return res.status(403).json({error:"FORBIDDEN"});res.json({items:(await q("SELECT m.*,u.username,u.display_name,u.avatar_url FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=$1 ORDER BY m.created_at ASC LIMIT 500",[req.params.id])).rows})});
app.post("/conversations/:id/messages",auth,async(req,res)=>{const b=(req.body?.body||"").trim();const member=await q("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[req.params.id,req.user.id]);if(!member.rows[0])return res.status(403).json({error:"FORBIDDEN"});if(!b)return res.status(400).json({error:"EMPTY_MESSAGE"});const {rows}=await q("INSERT INTO messages(conversation_id,sender_id,body) VALUES($1,$2,$3) RETURNING *",[req.params.id,req.user.id,b]);const msg={...rows[0],username:req.user.username,display_name:req.user.display_name,avatar_url:req.user.avatar_url};io.to(`conversation:${req.params.id}`).emit("message",msg);res.status(201).json({message:msg})});

app.get("/notifications",auth,async(req,res)=>res.json({items:(await q("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",[req.user.id])).rows}));
app.post("/ai/chat",auth,async(req,res)=>{
 const {message}=req.body||{}; if(!message?.trim())return res.status(400).json({error:"MESSAGE_REQUIRED"});
 if(!process.env.AI_BASE_URL||!process.env.AI_API_KEY||!process.env.AI_MODEL)return res.status(503).json({error:"AI_NOT_CONFIGURED"});
 try{const r=await fetch(`${process.env.AI_BASE_URL.replace(/\/$/,"")}/chat/completions`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${process.env.AI_API_KEY}`},body:JSON.stringify({model:process.env.AI_MODEL,messages:[{role:"system",content:"You are the ŞƏBƏКƏ assistant. Help users navigate the app and Azerbaijan-related everyday tasks. Never create fake users, fake posts, fake engagement, or pretend to be a real person."},{role:"user",content:message}]})});const data=await r.json();if(!r.ok)throw new Error("AI_PROVIDER_ERROR");res.json({answer:data.choices?.[0]?.message?.content||"Cavab alınmadı."})}catch(e){res.status(502).json({error:"AI_PROVIDER_ERROR"})}
});
app.get("/admin/stats",auth,admin,async(_,res)=>{
 const vals=await Promise.all([
  q("SELECT count(*)::int n FROM users"),q("SELECT count(*)::int n FROM users WHERE email_verified=true"),
  q("SELECT count(*)::int n FROM users WHERE last_seen_at>now()-interval '15 minutes'"),
  q("SELECT count(*)::int n FROM posts"),q("SELECT count(*)::int n FROM messages"),
  q("SELECT count(*)::int n FROM communities"),q("SELECT count(*)::int n FROM businesses"),q("SELECT count(*)::int n FROM events")
 ]);res.json({users:vals[0].rows[0].n,verified_users:vals[1].rows[0].n,active_15m:vals[2].rows[0].n,posts:vals[3].rows[0].n,messages:vals[4].rows[0].n,communities:vals[5].rows[0].n,businesses:vals[6].rows[0].n,events:vals[7].rows[0].n});
});

io.use((socket,next)=>{try{const raw=socket.handshake.headers.cookie||"";const m=raw.match(/shebeke_token=([^;]+)/);if(!m)return next(new Error("unauthorized"));socket.user=jwt.verify(decodeURIComponent(m[1]),process.env.JWT_SECRET);next()}catch{next(new Error("unauthorized"))}});
io.on("connection",socket=>{socket.on("join_conversation",async id=>{try{const ok=await q("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[id,socket.user.sub]);if(ok.rows[0])socket.join(`conversation:${id}`)}catch{}})});

server.listen(PORT,()=>console.log(`ŞƏBƏКƏ API listening on ${PORT}`));
