const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8787);
const DATABASE_URL = process.env.DATABASE_URL || "";
const ADMIN_KEY = process.env.ADMIN_KEY || "CHANGE_ME";
const ADMIN_ACCOUNTS = [
  { username:(process.env.ADMIN_USER_1 || process.env.ADMIN_USER || "commissioner").toLowerCase(), password:process.env.ADMIN_PASSWORD_1 || process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW", name:"Admin 1" },
  { username:(process.env.ADMIN_USER_2 || "").toLowerCase(), password:process.env.ADMIN_PASSWORD_2 || "", name:"Admin 2" },
  { username:(process.env.ADMIN_USER_3 || "").toLowerCase(), password:process.env.ADMIN_PASSWORD_3 || "", name:"Admin 3" }
].filter(a=>a.username && a.password);
const usePostgres = Boolean(DATABASE_URL);

app.use(express.json({limit:"1mb"}));
app.use(express.static(ROOT));

const cleanState = {
  teams:[], players:[], playerRequests:[], dtRequests:[],
  picks:[], skips:[], paused:false, scouting:{}, combine:{},
  settings:{seconds:45,draftType:"Snake"}, log:[]
};

let pool=null;
const DATA_DIR=path.join(ROOT,"data"), LOCAL_DB=path.join(DATA_DIR,"state.json");
const LOCAL_USERS=path.join(DATA_DIR,"users.json");
fs.mkdirSync(DATA_DIR,{recursive:true});
let localStore={revision:1,state:cleanState};
let localUsers=[];
if(!usePostgres && fs.existsSync(LOCAL_DB)){try{localStore=JSON.parse(fs.readFileSync(LOCAL_DB,"utf8"))}catch{}}
if(!usePostgres && fs.existsSync(LOCAL_USERS)){try{localUsers=JSON.parse(fs.readFileSync(LOCAL_USERS,"utf8"))}catch{}}
function saveLocal(){fs.writeFileSync(LOCAL_DB,JSON.stringify(localStore,null,2));fs.writeFileSync(LOCAL_USERS,JSON.stringify(localUsers,null,2))}
function hashPassword(p,salt=crypto.randomBytes(16).toString("hex")){return {salt,hash:crypto.scryptSync(p,salt,64).toString("hex")}}
function verifyPassword(p,salt,hash){const a=Buffer.from(hash,"hex"),b=crypto.scryptSync(p,salt,64);return a.length===b.length&&crypto.timingSafeEqual(a,b)}
function b64(o){return Buffer.from(JSON.stringify(o)).toString("base64url")}
function signToken(user){
 const payload=b64({id:user.id,username:user.username,role:user.role,status:user.status,teamId:user.team_id||null,exp:Date.now()+1000*60*60*24*7});
 const sig=crypto.createHmac("sha256",ADMIN_KEY).update(payload).digest("base64url");
 return payload+"."+sig;
}
function auth(req,res,next){
 try{
  const t=(req.headers.authorization||"").replace(/^Bearer\s+/,""),[p,s]=t.split(".");
  const sig=crypto.createHmac("sha256",ADMIN_KEY).update(p).digest("base64url");
  if(!p||!s||s!==sig)throw 0;
  const u=JSON.parse(Buffer.from(p,"base64url").toString());
  if(u.exp<Date.now())throw 0;req.user=u;next();
 }catch{res.status(401).json({error:"unauthorized"})}
}
function adminOnly(req,res,next){if(req.user?.role!=="admin")return res.status(403).json({error:"admin_only"});next()}

async function initDb(){
 if(!usePostgres){
   for(const adm of ADMIN_ACCOUNTS){
     const hp=hashPassword(adm.password);
     let a=localUsers.find(x=>x.username===adm.username);
     if(a)Object.assign(a,{password_hash:hp.hash,salt:hp.salt,role:"admin",status:"approved",display_name:adm.name});
     else localUsers.push({id:Date.now()+Math.random(),username:adm.username,password_hash:hp.hash,salt:hp.salt,role:"admin",status:"approved",display_name:adm.name,team_id:null});
   }
   saveLocal(); return;
 }
 pool=new Pool({connectionString:DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:undefined});
 await pool.query(`CREATE TABLE IF NOT EXISTS pinto_state(id INTEGER PRIMARY KEY,revision BIGINT NOT NULL,state JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 await pool.query(`CREATE TABLE IF NOT EXISTS pinto_users(
   id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
   role TEXT NOT NULL CHECK(role IN ('player','dt','viewer','admin')),
   status TEXT NOT NULL DEFAULT 'pending', display_name TEXT NOT NULL, ea_id TEXT, country TEXT, platform TEXT,
   position TEXT, secondary_position TEXT, discord TEXT, availability TEXT, club TEXT, abbr TEXT, region TEXT,
   team_id BIGINT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`);
 const s=await pool.query("SELECT id FROM pinto_state WHERE id=1");
 if(!s.rowCount)await pool.query("INSERT INTO pinto_state(id,revision,state) VALUES(1,1,$1::jsonb)",[JSON.stringify(cleanState)]);
 for (const adm of ADMIN_ACCOUNTS){
   const hp=hashPassword(adm.password);
   const existing=await pool.query("SELECT id FROM pinto_users WHERE username=$1",[adm.username]);
   if(!existing.rowCount){
     await pool.query(`INSERT INTO pinto_users(username,password_hash,salt,role,status,display_name)
                       VALUES($1,$2,$3,'admin','approved',$4)`,[adm.username,hp.hash,hp.salt,adm.name]);
   }else{
     await pool.query(`UPDATE pinto_users SET password_hash=$1,salt=$2,role='admin',status='approved',display_name=$3 WHERE id=$4`,
                      [hp.hash,hp.salt,adm.name,existing.rows[0].id]);
   }
 }
}
async function getStore(){if(!usePostgres)return localStore;const r=await pool.query("SELECT revision,state FROM pinto_state WHERE id=1");return {revision:Number(r.rows[0].revision),state:r.rows[0].state}}
async function replaceStore(state,rev){
 if(!usePostgres){if(Number(rev)!==Number(localStore.revision))return {conflict:true,store:localStore};localStore={state,revision:localStore.revision+1};saveLocal();return {revision:localStore.revision}}
 const r=await pool.query("UPDATE pinto_state SET state=$1::jsonb,revision=revision+1,updated_at=NOW() WHERE id=1 AND revision=$2 RETURNING revision",[JSON.stringify(state),rev]);
 if(!r.rowCount)return {conflict:true,store:await getStore()};return {revision:Number(r.rows[0].revision)}
}
async function mutate(fn){for(let i=0;i<6;i++){const s=await getStore(),n=structuredClone(s.state);fn(n);const r=await replaceStore(n,s.revision);if(!r.conflict)return r}throw new Error("conflict")}
async function getUser(username){
 username=username.toLowerCase();
 if(!usePostgres)return localUsers.find(x=>x.username===username)||null;
 const r=await pool.query("SELECT * FROM pinto_users WHERE username=$1",[username]);return r.rows[0]||null;
}
async function createUser(u){
 const hp=hashPassword(u.password), username=u.username.toLowerCase();
 if(!usePostgres){if(localUsers.some(x=>x.username===username))throw Object.assign(new Error("duplicate"),{code:"23505"});const x={id:Date.now(),username,password_hash:hp.hash,salt:hp.salt,status:"pending",team_id:null,...u,password:undefined};localUsers.push(x);saveLocal();return x}
 const r=await pool.query(`INSERT INTO pinto_users(username,password_hash,salt,role,status,display_name,ea_id,country,platform,position,secondary_position,discord,availability,club,abbr,region)
 VALUES($1,$2,$3,$4,'pending',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
 [username,hp.hash,hp.salt,u.role,u.display_name,u.ea_id||null,u.country||null,u.platform||null,u.position||null,u.secondary_position||null,u.discord||null,u.availability||null,u.club||null,u.abbr||null,u.region||null]);
 return r.rows[0];
}
async function updateUser(id,fields){
 if(!usePostgres){const u=localUsers.find(x=>String(x.id)===String(id));Object.assign(u,fields);saveLocal();return u}
 const keys=Object.keys(fields), vals=Object.values(fields); if(!keys.length)return null;
 const sets=keys.map((k,i)=>`${k}=$${i+1}`).join(",");
 const r=await pool.query(`UPDATE pinto_users SET ${sets} WHERE id=$${keys.length+1} RETURNING *`,[...vals,id]);return r.rows[0];
}
async function pendingUsers(){
 if(!usePostgres)return localUsers.filter(x=>x.status==="pending"&&x.role!=="admin").map(({password_hash,salt,...x})=>x);
 const r=await pool.query("SELECT id,username,role,status,display_name,ea_id,country,platform,position,secondary_position,discord,availability,club,abbr,region,created_at FROM pinto_users WHERE status='pending' AND role<>'admin' ORDER BY created_at");
 return r.rows;
}


function makeRoundRobin(teams){
  const ids=teams.map(t=>Number(t.id));
  if(ids.length<2)return [];
  if(ids.length%2===1)ids.push(null);
  let arr=[...ids],out=[],matchNo=1;
  const n=arr.length,half=n/2;
  for(let round=1;round<n;round++){
    for(let i=0;i<half;i++){
      let home=arr[i],away=arr[n-1-i];
      if(home==null||away==null)continue;
      if((round+i)%2===0)[home,away]=[away,home];
      out.push({
        id:`M${matchNo++}`,round,homeTeamId:home,awayTeamId:away,
        homeScore:null,awayScore:null,status:"scheduled",
        submittedByTeamId:null,submittedByUserId:null,submittedAt:null,
        confirmedByTeamId:null,confirmedAt:null,disputeNote:null
      });
    }
    arr=[arr[0],arr[n-1],...arr.slice(1,n-1)];
  }
  return out;
}
function fixturesLocked(st){
  return (st.fixtures||[]).some(m=>m.status!=="scheduled");
}
function refreshFixturesIfSafe(st){
  const teams=(st.teams||[]).filter(t=>t.approved);
  if(teams.length<2){st.fixtures=[];return}
  if(!fixturesLocked(st))st.fixtures=makeRoundRobin(teams);
}
function accountTeamId(user,st){
  if(!user)return null;
  if(user.role==="dt")return Number(user.teamId)||null;
  if(user.role==="player"){
    const p=(st.players||[]).find(x=>String(x.accountId)===String(user.id));
    if(!p)return null;
    const pick=(st.picks||[]).find(x=>String(x.playerId)===String(p.id));
    return pick?Number(pick.teamId):null;
  }
  return null;
}
function scoreValue(v){
  const n=Number(v);
  return Number.isInteger(n)&&n>=0&&n<=99?n:null;
}
function fixtureById(st,id){return (st.fixtures||[]).find(m=>String(m.id)===String(id))}

app.get("/api/info",(req,res)=>res.json({online:true,registrationUrl:`${req.protocol}://${req.get("host")}/register.html`,appUrl:`${req.protocol}://${req.get("host")}/`}));
app.get("/api/health",(req,res)=>res.json({ok:true,db:usePostgres?"postgres":"local"}));

app.post("/api/auth/register",async(req,res)=>{
 try{
  const u=req.body||{};
  if(!["player","dt","viewer"].includes(u.role))return res.status(400).json({error:"invalid_role"});
  if(!/^[a-zA-Z0-9_.-]{3,24}$/.test(u.username||""))return res.status(400).json({error:"invalid_username"});
  if(String(u.password||"").length<8)return res.status(400).json({error:"password_short"});
  if(!String(u.display_name||"").trim())return res.status(400).json({error:"name_required"});
  if(u.role==="dt"&&!String(u.club||"").trim())return res.status(400).json({error:"club_required"});
  if(u.role==="player"&&!String(u.position||"").trim())return res.status(400).json({error:"position_required"});
  await createUser(u);
  res.json({ok:true,message:"pending"});
 }catch(e){if(e.code==="23505"||String(e.message).includes("duplicate"))return res.status(409).json({error:"username_exists"});res.status(500).json({error:"server_error"})}
});
app.post("/api/auth/login",async(req,res)=>{
 try{
  const u=await getUser(String(req.body?.username||""));
  if(!u||!verifyPassword(String(req.body?.password||""),u.salt,u.password_hash))return res.status(401).json({error:"invalid_credentials"});
  if(u.status!=="approved")return res.status(403).json({error:u.status==="rejected"?"rejected":"pending"});
  res.json({token:signToken(u),user:{id:u.id,username:u.username,role:u.role,status:u.status,display_name:u.display_name,teamId:u.team_id||null}});
 }catch{res.status(500).json({error:"server_error"})}
});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:req.user}));
app.get("/api/admin/pending",auth,adminOnly,async(req,res)=>{try{res.json({users:await pendingUsers()})}catch{res.status(500).json({error:"server_error"})}});
app.post("/api/admin/users/:id/:action",auth,adminOnly,async(req,res)=>{
 try{
  const id=req.params.id, action=req.params.action;
  if(!["approve","reject"].includes(action))return res.status(400).json({error:"bad_action"});
  let u;
  if(!usePostgres)u=localUsers.find(x=>String(x.id)===String(id));
  else {const r=await pool.query("SELECT * FROM pinto_users WHERE id=$1",[id]);u=r.rows[0]}
  if(!u)return res.status(404).json({error:"not_found"});
  if(action==="reject"){await updateUser(id,{status:"rejected"});return res.json({ok:true})}
  let teamId=u.team_id||null;
  await mutate(st=>{
    if(u.role==="player"){
      if(!st.players.some(p=>p.accountId==u.id))st.players.push({id:Date.now()+Math.random(),accountId:u.id,name:u.display_name,ea:u.ea_id||u.username,pos:u.position,sec:u.secondary_position||"-",country:u.country||"—",platform:u.platform||"—",discord:u.discord||"",availability:u.availability||"",notes:"",ovr:80,status:"Disponible"});
    }else if(u.role==="dt"){
      teamId=Math.max(0,...st.teams.map(t=>Number(t.id)||0))+1;
      if(!st.teams.some(t=>t.accountId==u.id))st.teams.push({id:teamId,accountId:u.id,name:String(u.club).toUpperCase(),abbr:(u.abbr||"FC").toUpperCase(),dt:u.display_name,approved:true});
    }
    refreshFixturesIfSafe(st);
    st.log.unshift(`${u.role.toUpperCase()} aprobado: ${u.display_name}`);
  });
  await updateUser(id,{status:"approved",team_id:teamId});
  res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});



async function deleteUserAccount(id){
 if(!id)return;
 if(!usePostgres){
   localUsers=localUsers.filter(u=>String(u.id)!==String(id)||u.role==="admin");
   saveLocal(); return;
 }
 await pool.query("DELETE FROM pinto_users WHERE id=$1 AND role<>'admin'",[id]);
}

app.delete("/api/admin/players/:id",auth,adminOnly,async(req,res)=>{
 try{
   const id=req.params.id;
   const st=(await getStore()).state;
   const player=(st.players||[]).find(p=>String(p.id)===String(id));
   if(!player)return res.status(404).json({error:"not_found"});
   await mutate(x=>{
     x.players=(x.players||[]).filter(p=>String(p.id)!==String(id));
     x.picks=(x.picks||[]).filter(pk=>String(pk.playerId)!==String(id));
     if(x.scouting)Object.values(x.scouting).forEach(v=>{
       if(v?.favorites)v.favorites=v.favorites.filter(pid=>String(pid)!==String(id));
       if(v?.notes)delete v.notes[id];
     });
     if(x.combine)delete x.combine[id];
     x.log.unshift(`Jugador eliminado: ${player.name}`);
   });
   if(player.accountId)await deleteUserAccount(player.accountId);
   res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.delete("/api/admin/clubs/:id",auth,adminOnly,async(req,res)=>{
 try{
   const id=req.params.id;
   const st=(await getStore()).state;
   const team=(st.teams||[]).find(t=>String(t.id)===String(id));
   if(!team)return res.status(404).json({error:"not_found"});
   await mutate(x=>{
     x.teams=(x.teams||[]).filter(t=>String(t.id)!==String(id));
     const removedPicks=(x.picks||[]).filter(pk=>String(pk.teamId)===String(id));
     const returned=new Set(removedPicks.map(pk=>String(pk.playerId)));
     x.picks=(x.picks||[]).filter(pk=>String(pk.teamId)!==String(id));
     (x.players||[]).forEach(p=>{if(returned.has(String(p.id)))p.status="Disponible"});
     x.skips=(x.skips||[]).filter(sk=>String(sk.teamId)!==String(id));
     x.log.unshift(`Club eliminado: ${team.name}`);
   });
   if(team.accountId)await deleteUserAccount(team.accountId);
   res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/admin/clean-league",auth,adminOnly,async(req,res)=>{
 try{
   await mutate(x=>{
     x.teams=[];x.players=[];x.playerRequests=[];x.dtRequests=[];x.picks=[];x.skips=[];x.fixtures=[];
     x.paused=false;x.scouting={};x.combine={};x.log=["Liga limpiada por administrador"];
   });
   if(!usePostgres){
     localUsers=localUsers.filter(u=>u.role==="admin"); saveLocal();
   }else{
     await pool.query("DELETE FROM pinto_users WHERE role<>'admin'");
   }
   res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.get("/api/admin/users",auth,adminOnly,async(req,res)=>{
 try{
   let users;
   if(!usePostgres){
     users=localUsers.map(({password_hash,salt,...u})=>u);
   }else{
     const r=await pool.query(`SELECT id,username,role,status,display_name,ea_id,country,platform,position,secondary_position,discord,availability,club,abbr,region,team_id,created_at
                               FROM pinto_users ORDER BY created_at DESC`);
     users=r.rows;
   }
   res.json({users});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.get("/api/admin/summary",auth,adminOnly,async(req,res)=>{
 try{
   const st=(await getStore()).state;
   let users;
   if(!usePostgres) users=localUsers;
   else { const r=await pool.query("SELECT role,status FROM pinto_users"); users=r.rows; }
   res.json({
     pending:users.filter(u=>u.status==="pending").length,
     players:users.filter(u=>u.role==="player"&&u.status==="approved").length,
     dts:users.filter(u=>u.role==="dt"&&u.status==="approved").length,
     viewers:users.filter(u=>u.role==="viewer"&&u.status==="approved").length,
     admins:users.filter(u=>u.role==="admin"&&u.status==="approved").length,
     teams:(st.teams||[]).length,
     picks:(st.picks||[]).length
   });
 }catch(e){res.status(500).json({error:"server_error"})}
});


app.post("/api/matches/:id/submit",auth,async(req,res)=>{
 try{
   if(!["admin","dt","player"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
   const hs=scoreValue(req.body?.homeScore),as=scoreValue(req.body?.awayScore);
   if(hs===null||as===null)return res.status(400).json({error:"invalid_score"});
   const st=(await getStore()).state,m=fixtureById(st,req.params.id);
   if(!m)return res.status(404).json({error:"not_found"});
   const teamId=req.user.role==="admin"
     ? Number(req.body?.teamId||m.homeTeamId)
     : accountTeamId(req.user,st);
   if(req.user.role!=="admin" && teamId!==Number(m.homeTeamId) && teamId!==Number(m.awayTeamId))
     return res.status(403).json({error:"not_your_match"});
   await mutate(x=>{
     const mm=fixtureById(x,req.params.id);
     mm.homeScore=hs;mm.awayScore=as;mm.status="pending_confirmation";
     mm.submittedByTeamId=teamId;mm.submittedByUserId=req.user.id;mm.submittedAt=new Date().toISOString();
     mm.confirmedByTeamId=null;mm.confirmedAt=null;mm.disputeNote=null;
     const ht=x.teams.find(t=>Number(t.id)===Number(mm.homeTeamId))?.name||"Local";
     const at=x.teams.find(t=>Number(t.id)===Number(mm.awayTeamId))?.name||"Visitante";
     x.log.unshift(`Resultado enviado: ${ht} ${hs}-${as} ${at}`);
   });
   res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/matches/:id/confirm",auth,async(req,res)=>{
 try{
   if(!["admin","dt","player"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
   const st=(await getStore()).state,m=fixtureById(st,req.params.id);
   if(!m)return res.status(404).json({error:"not_found"});
   if(m.status!=="pending_confirmation")return res.status(400).json({error:"not_pending"});
   const teamId=req.user.role==="admin"?null:accountTeamId(req.user,st);
   if(req.user.role!=="admin"){
     if(teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))
       return res.status(403).json({error:"not_your_match"});
     if(Number(teamId)===Number(m.submittedByTeamId))
       return res.status(403).json({error:"opponent_must_confirm"});
   }
   await mutate(x=>{
     const mm=fixtureById(x,req.params.id);
     mm.status="confirmed";mm.confirmedByTeamId=teamId;mm.confirmedAt=new Date().toISOString();
     const ht=x.teams.find(t=>Number(t.id)===Number(mm.homeTeamId))?.name||"Local";
     const at=x.teams.find(t=>Number(t.id)===Number(mm.awayTeamId))?.name||"Visitante";
     x.log.unshift(`Resultado confirmado: ${ht} ${mm.homeScore}-${mm.awayScore} ${at}`);
   });
   res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/matches/:id/dispute",auth,async(req,res)=>{
 try{
   if(!["admin","dt","player"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
   const st=(await getStore()).state,m=fixtureById(st,req.params.id);
   if(!m)return res.status(404).json({error:"not_found"});
   const teamId=req.user.role==="admin"?null:accountTeamId(req.user,st);
   if(req.user.role!=="admin" && teamId!==Number(m.homeTeamId) && teamId!==Number(m.awayTeamId))
     return res.status(403).json({error:"not_your_match"});
   await mutate(x=>{
     const mm=fixtureById(x,req.params.id);
     mm.status="disputed";mm.disputeNote=String(req.body?.note||"Resultado no coincide").slice(0,250);
     x.log.unshift(`Resultado en disputa: ${mm.id}`);
   });
   res.json({ok:true});
 }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/admin/matches/:id/resolve",auth,adminOnly,async(req,res)=>{
 try{
   const hs=scoreValue(req.body?.homeScore),as=scoreValue(req.body?.awayScore);
   if(hs===null||as===null)return res.status(400).json({error:"invalid_score"});
   await mutate(x=>{
     const mm=fixtureById(x,req.params.id);
     if(!mm)throw new Error("not_found");
     mm.homeScore=hs;mm.awayScore=as;mm.status="confirmed";
     mm.confirmedByTeamId=null;mm.confirmedAt=new Date().toISOString();mm.disputeNote=null;
     x.log.unshift(`Admin resolvió ${mm.id}: ${hs}-${as}`);
   });
   res.json({ok:true});
 }catch(e){res.status(e.message==="not_found"?404:500).json({error:e.message==="not_found"?"not_found":"server_error"})}
});


app.get("/api/state",async(req,res)=>{try{res.json(await getStore())}catch{res.status(500).json({error:"database_error"})}});
app.put("/api/state",auth,async(req,res)=>{
 try{
  if(!["admin","dt"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
  const {state,revision}=req.body||{};if(!state)return res.status(400).json({error:"bad_state"});
  const r=await replaceStore(state,revision);if(r.conflict)return res.status(409).json(r.store);res.json({revision:r.revision});
 }catch{res.status(500).json({error:"database_error"})}
});

app.get("/app.html",(req,res)=>res.sendFile(path.join(ROOT,"app.html")));
app.get("*",(req,res)=>res.sendFile(path.join(ROOT,"index.html")));

initDb().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log(`PINTO FC26 RELEASE 1.1.0 on ${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
