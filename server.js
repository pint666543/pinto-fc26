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
  settings:{seconds:45,draftType:"Snake"},
  clubProfiles:{},
  organizerTournaments:[],
  playerStats:{},
  relampago:{
    name:"RELÁMPAGO FC26-27",
    status:"not_started",
    phase:"registration",
    teamIds:[],
    leagueRounds:5,
    qualifiers:8,
    matches:[],
    championTeamId:null,
    startedAt:null,
    completedAt:null
  },
  rulebook:{
    title:"REGLAMENTO FC26-27",
    updatedAt:null,
    updatedBy:null,
    sections:[
      {id:"general",title:"1. REGLAS GENERALES",body:"Respeto obligatorio entre jugadores, DTs y administradores. El uso de exploits, trampas o conductas antideportivas puede resultar en sanción."},
      {id:"rosters",title:"2. PLANTILLAS",body:"Cada club deberá utilizar únicamente jugadores registrados y aprobados dentro de la plataforma."},
      {id:"matches",title:"3. PARTIDOS",body:"Los partidos deben jugarse en la fecha acordada. El resultado será cargado por uno de los clubes y confirmado por el rival."},
      {id:"disconnects",title:"4. DESCONEXIONES",body:"En caso de desconexión, los clubes deberán seguir el procedimiento establecido por la administración antes de reiniciar o abandonar el partido."},
      {id:"discipline",title:"5. DISCIPLINA",body:"Insultos, amenazas, discriminación, manipulación de resultados o suplantación de identidad pueden resultar en suspensión o expulsión."}
    ]
  },
  log:[]
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
   role TEXT NOT NULL CHECK(role IN ('player','dt','viewer','organizer','admin')),
   status TEXT NOT NULL DEFAULT 'pending', display_name TEXT NOT NULL, ea_id TEXT, country TEXT, platform TEXT,
   position TEXT, secondary_position TEXT, discord TEXT, availability TEXT, club TEXT, abbr TEXT, region TEXT,
   team_id BIGINT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`);
 try{
   await pool.query(`ALTER TABLE pinto_users DROP CONSTRAINT IF EXISTS pinto_users_role_check`);
   await pool.query(`ALTER TABLE pinto_users ADD CONSTRAINT pinto_users_role_check CHECK(role IN ('player','dt','viewer','organizer','admin'))`);
 }catch(e){console.warn("Role constraint migration:",e.message)}
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


function defaultRelampago(){
  return {
    name:"RELÁMPAGO FC26-27",status:"not_started",phase:"registration",
    teamIds:[],registrations:[],leagueRounds:5,qualifiers:8,matches:[],
    championTeamId:null,startedAt:null,completedAt:null,
    drawOrder:[],drawCompletedAt:null,twoLegged:true,history:[]
  };
}
function ensureRelampago(st){
  if(!st.relampago || typeof st.relampago!=="object")st.relampago=defaultRelampago();
  const r=st.relampago;
  if(!Array.isArray(r.teamIds))r.teamIds=[];
  if(!Array.isArray(r.registrations))r.registrations=[];
  if(!Array.isArray(r.matches))r.matches=[];
  if(!Array.isArray(r.drawOrder))r.drawOrder=[];
  if(!Array.isArray(r.history))r.history=[];
  if(typeof r.twoLegged!=="boolean")r.twoLegged=true;
  return r;
}
function isPowerOfTwo(n){return n>=2 && (n&(n-1))===0}
function shuffleIds(ids){
  const a=[...ids];
  for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]]}
  return a;
}
function relampagoLeagueSchedule(teamIds,maxRounds){
  let ids=teamIds.map(Number);
  if(ids.length%2===1)ids.push(null);
  const n=ids.length,half=n/2;
  let arr=[...ids],out=[],matchNo=1;
  const rounds=Math.max(1,Math.min(Number(maxRounds)||5,n-1));
  for(let round=1;round<=rounds;round++){
    for(let i=0;i<half;i++){
      let home=arr[i],away=arr[n-1-i];
      if(home==null||away==null)continue;
      if((round+i)%2===0)[home,away]=[away,home];
      out.push({
        id:`RLG-${matchNo++}`,competition:"relampago",phase:"league",stage:"FASE LIGA",round,
        homeTeamId:home,awayTeamId:away,homeScore:null,awayScore:null,status:"scheduled",
        submittedByTeamId:null,submittedByUserId:null,submittedAt:null,
        confirmedByTeamId:null,confirmedAt:null,disputeNote:null,winnerTeamId:null
      });
    }
    arr=[arr[0],arr[n-1],...arr.slice(1,n-1)];
  }
  return out;
}
function relampagoStandings(st){
  const r=ensureRelampago(st);
  const rows=r.teamIds.map(id=>{
    const t=(st.teams||[]).find(x=>Number(x.id)===Number(id));
    return {id:Number(id),name:t?.name||"Club",pj:0,pg:0,pe:0,pp:0,gf:0,gc:0,pts:0};
  });
  const by=Object.fromEntries(rows.map(x=>[x.id,x]));
  r.matches.filter(m=>m.phase==="league"&&m.status==="confirmed").forEach(m=>{
    const a=by[Number(m.homeTeamId)],b=by[Number(m.awayTeamId)];
    if(!a||!b)return;
    const x=Number(m.homeScore),y=Number(m.awayScore);
    a.pj++;b.pj++;a.gf+=x;a.gc+=y;b.gf+=y;b.gc+=x;
    if(x>y){a.pg++;b.pp++;a.pts+=3}
    else if(y>x){b.pg++;a.pp++;b.pts+=3}
    else{a.pe++;b.pe++;a.pts++;b.pts++}
  });
  return rows.sort((a,b)=>b.pts-a.pts||((b.gf-b.gc)-(a.gf-a.gc))||b.gf-a.gf||a.name.localeCompare(b.name));
}
function knockoutStageName(teamCount){
  if(teamCount===16)return "OCTAVOS";
  if(teamCount===8)return "CUARTOS";
  if(teamCount===4)return "SEMIFINAL";
  if(teamCount===2)return "FINAL";
  return `TOP ${teamCount}`;
}
function makeKoMatch({id,tieId,stage,stageNo,leg,home,away}){
  return {
    id,tieId,competition:"relampago",phase:"knockout",stage,round:stageNo,leg,
    homeTeamId:Number(home),awayTeamId:Number(away),
    homeScore:null,awayScore:null,penaltyHome:null,penaltyAway:null,status:"scheduled",
    submittedByTeamId:null,submittedByUserId:null,submittedAt:null,
    confirmedByTeamId:null,confirmedAt:null,disputeNote:null,winnerTeamId:null
  };
}
function createKnockoutStage(teamIds,stageNo,twoLegged=true){
  const n=teamIds.length,stage=knockoutStageName(n),out=[];
  for(let i=0;i<n/2;i++){
    const a=Number(teamIds[i]),b=Number(teamIds[n-1-i]),tieId=`RTIE-${stageNo}-${i+1}`;
    const useTwoLegs=twoLegged && n>2;
    out.push(makeKoMatch({id:`RKO-${stageNo}-${i+1}-L1`,tieId,stage,stageNo,leg:1,home:a,away:b}));
    if(useTwoLegs)out.push(makeKoMatch({id:`RKO-${stageNo}-${i+1}-L2`,tieId,stage,stageNo,leg:2,home:b,away:a}));
  }
  return out;
}
function knockoutTieResult(st,tieId){
  const r=ensureRelampago(st);
  const games=r.matches.filter(m=>m.phase==="knockout"&&String(m.tieId||m.id)===String(tieId));
  if(!games.length||!games.every(m=>m.status==="confirmed"))return {ready:false};
  const teams=[...new Set(games.flatMap(m=>[Number(m.homeTeamId),Number(m.awayTeamId)]))];
  if(teams.length!==2)return {ready:false};
  const agg=Object.fromEntries(teams.map(id=>[id,0]));
  games.forEach(m=>{agg[Number(m.homeTeamId)]+=Number(m.homeScore)||0;agg[Number(m.awayTeamId)]+=Number(m.awayScore)||0});
  if(agg[teams[0]]>agg[teams[1]])return {ready:true,winner:teams[0],aggregate:agg};
  if(agg[teams[1]]>agg[teams[0]])return {ready:true,winner:teams[1],aggregate:agg};
  const decider=[...games].sort((a,b)=>(Number(b.leg)||1)-(Number(a.leg)||1))[0];
  const ph=Number(decider.penaltyHome),pa=Number(decider.penaltyAway);
  if(!Number.isInteger(ph)||!Number.isInteger(pa)||ph<0||pa<0||ph===pa)return {ready:true,needsPenalties:true,aggregate:agg,deciderId:decider.id};
  return {ready:true,winner:ph>pa?Number(decider.homeTeamId):Number(decider.awayTeamId),aggregate:agg,penalties:[ph,pa]};
}
function maybeAdvanceRelampago(st){
  const r=ensureRelampago(st);
  if(r.status!=="active")return;
  const league=r.matches.filter(m=>m.phase==="league");
  const kos=r.matches.filter(m=>m.phase==="knockout");
  if(!kos.length){
    if(league.length && league.every(m=>m.status==="confirmed")){
      const standings=relampagoStandings(st);
      const q=Math.min(Number(r.qualifiers)||8,standings.length);
      let seeded=standings.slice(0,q).map(x=>x.id);
      if(r.drawOrder?.length){
        const qset=new Set(seeded.map(Number));
        const drawn=r.drawOrder.map(Number).filter(id=>qset.has(id));
        seeded=[...drawn,...seeded.filter(id=>!drawn.includes(Number(id)))];
      }
      if(seeded.length>=2 && isPowerOfTwo(seeded.length)){
        r.matches.push(...createKnockoutStage(seeded,1,r.twoLegged));
        r.phase="knockout";
        st.log.unshift(`⚡ Relámpago: ${knockoutStageName(seeded.length)} generados automáticamente`);
      }
    }
    return;
  }
  const maxRound=Math.max(...kos.map(m=>Number(m.round)||1));
  const current=kos.filter(m=>Number(m.round)===maxRound);
  const ties=[...new Set(current.map(m=>String(m.tieId||m.id)))];
  const results=ties.map(id=>knockoutTieResult(st,id));
  if(results.some(x=>!x.ready||x.needsPenalties||!x.winner))return;
  if(ties.length===1){
    r.championTeamId=Number(results[0].winner);
    r.status="completed";r.phase="champion";r.completedAt=new Date().toISOString();
    const club=(st.teams||[]).find(t=>Number(t.id)===Number(r.championTeamId));
    const already=r.history.some(x=>String(x.completedAt)===String(r.completedAt));
    if(!already)r.history.unshift({
      id:`RH-${Date.now()}`,name:r.name,championTeamId:r.championTeamId,
      championName:club?.name||"Club",completedAt:r.completedAt,teamCount:r.teamIds.length
    });
    st.log.unshift(`🏆 ${club?.name||"Club"} campeón de ${r.name}`);
    return;
  }
  if(kos.some(m=>Number(m.round)===maxRound+1))return;
  const winners=results.map(x=>Number(x.winner));
  r.matches.push(...createKnockoutStage(winners,maxRound+1,r.twoLegged));
  st.log.unshift(`⚡ Relámpago: ${knockoutStageName(winners.length)} generado automáticamente`);
}
function relampagoMatch(st,id){
  const r=ensureRelampago(st);
  return r.matches.find(m=>String(m.id)===String(id));
}

app.get("/api/info",(req,res)=>res.json({online:true,registrationUrl:`${req.protocol}://${req.get("host")}/register.html`,appUrl:`${req.protocol}://${req.get("host")}/`}));
app.get("/api/health",(req,res)=>res.json({ok:true,db:usePostgres?"postgres":"local"}));

app.post("/api/auth/register",async(req,res)=>{
 try{
  const u=req.body||{};
  if(!["player","dt","viewer","organizer"].includes(u.role))return res.status(400).json({error:"invalid_role"});
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
     x.paused=false;x.scouting={};x.combine={};
     if(!x.rulebook)x.rulebook={title:"REGLAMENTO FC26-27",updatedAt:null,updatedBy:null,sections:[]};
     x.log=["Liga limpiada por administrador"];
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




app.put("/api/clubs/:id/profile",auth,async(req,res)=>{
  try{
    const st=(await getStore()).state;
    const club=(st.teams||[]).find(t=>Number(t.id)===Number(req.params.id));
    if(!club)return res.status(404).json({error:"club_not_found"});
    const myTeam=req.user.role==="admin"?Number(req.params.id):accountTeamId(req.user,st);
    if(req.user.role!=="admin"&&(req.user.role!=="dt"||Number(myTeam)!==Number(req.params.id)))
      return res.status(403).json({error:"forbidden"});
    const p=req.body||{};
    await mutate(x=>{
      x.clubProfiles=x.clubProfiles||{};
      x.clubProfiles[String(req.params.id)]={
        bio:String(p.bio||"").slice(0,500),
        region:String(p.region||"").slice(0,60),
        captain:String(p.captain||"").slice(0,60),
        social:String(p.social||"").slice(0,100),
        updatedAt:new Date().toISOString()
      };
      x.log.unshift(`Perfil de club actualizado: ${club.name}`);
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.put("/api/admin/player-stats/:id",auth,adminOnly,async(req,res)=>{
  try{
    const st=(await getStore()).state;
    const pl=(st.players||[]).find(p=>Number(p.id)===Number(req.params.id));
    if(!pl)return res.status(404).json({error:"player_not_found"});
    const n=v=>Math.max(0,Math.min(999,parseInt(v)||0));
    await mutate(x=>{
      x.playerStats=x.playerStats||{};
      x.playerStats[String(req.params.id)]={
        matches:n(req.body?.matches),
        goals:n(req.body?.goals),
        assists:n(req.body?.assists),
        cleanSheets:n(req.body?.cleanSheets),
        mvp:n(req.body?.mvp)
      };
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.get("/api/rulebook",async(req,res)=>{
  try{
    const st=(await getStore()).state;
    res.json({rulebook:st.rulebook||{title:"REGLAMENTO FC26-27",sections:[]}});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.put("/api/admin/rulebook",auth,adminOnly,async(req,res)=>{
  try{
    const rb=req.body?.rulebook;
    if(!rb||typeof rb!=="object"||!Array.isArray(rb.sections))
      return res.status(400).json({error:"invalid_rulebook"});
    const safe={
      title:String(rb.title||"REGLAMENTO FC26-27").slice(0,80),
      updatedAt:new Date().toISOString(),
      updatedBy:req.user.username||"admin",
      sections:rb.sections.slice(0,30).map((sec,i)=>({
        id:String(sec.id||`section-${i+1}`).slice(0,60),
        title:String(sec.title||`Sección ${i+1}`).slice(0,120),
        body:String(sec.body||"").slice(0,10000)
      }))
    };
    await mutate(x=>{
      x.rulebook=safe;
      x.log.unshift(`Reglamento actualizado por ${safe.updatedBy}`);
    });
    res.json({ok:true,rulebook:safe});
  }catch(e){res.status(500).json({error:"server_error"})}
});



app.post("/api/relampago/register",auth,async(req,res)=>{
  try{
    if(req.user.role!=="dt")return res.status(403).json({error:"dt_only"});
    const st=(await getStore()).state;
    const teamId=accountTeamId(req.user,st);
    if(!teamId)return res.status(400).json({error:"no_club"});
    const club=(st.teams||[]).find(t=>Number(t.id)===Number(teamId)&&t.approved);
    if(!club)return res.status(400).json({error:"club_not_approved"});
    const rr=ensureRelampago(st);
    if(rr.status!=="not_started"&&rr.phase!=="registration")return res.status(400).json({error:"registration_closed"});
    if((rr.registrations||[]).some(x=>Number(x.teamId)===Number(teamId)&&x.status!=="rejected"))
      return res.status(409).json({error:"already_registered"});
    await mutate(x=>{
      const r=ensureRelampago(x);
      r.registrations=r.registrations||[];
      r.registrations.push({
        id:`RREG-${Date.now()}-${teamId}`,teamId:Number(teamId),dtUserId:req.user.id,
        dtUsername:req.user.username,status:"pending",createdAt:new Date().toISOString()
      });
      x.log.unshift(`⚡ ${club.name} solicitó inscripción al Relámpago`);
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/admin/relampago/registrations/:id/:action",auth,adminOnly,async(req,res)=>{
  try{
    const action=req.params.action;
    if(!["approve","reject"].includes(action))return res.status(400).json({error:"invalid_action"});
    await mutate(x=>{
      const r=ensureRelampago(x);
      const reg=(r.registrations||[]).find(v=>String(v.id)===String(req.params.id));
      if(!reg)throw new Error("not_found");
      reg.status=action==="approve"?"approved":"rejected";
      reg.reviewedAt=new Date().toISOString();reg.reviewedBy=req.user.username;
      if(action==="approve"&&!r.teamIds.some(id=>Number(id)===Number(reg.teamId)))r.teamIds.push(Number(reg.teamId));
      if(action==="reject")r.teamIds=r.teamIds.filter(id=>Number(id)!==Number(reg.teamId));
      const club=(x.teams||[]).find(t=>Number(t.id)===Number(reg.teamId));
      x.log.unshift(`⚡ Inscripción ${action==="approve"?"aprobada":"rechazada"}: ${club?.name||"Club"}`);
    });
    res.json({ok:true});
  }catch(e){
    if(e.message==="not_found")return res.status(404).json({error:"not_found"});
    res.status(500).json({error:"server_error"})
  }
});


app.post("/api/relampago/checkin",auth,async(req,res)=>{
  try{
    if(req.user.role!=="dt")return res.status(403).json({error:"dt_only"});
    const st=(await getStore()).state,teamId=accountTeamId(req.user,st),r=ensureRelampago(st);
    if(!teamId)return res.status(400).json({error:"no_club"});
    if(r.status!=="not_started")return res.status(400).json({error:"checkin_closed"});
    const reg=(r.registrations||[]).find(x=>Number(x.teamId)===Number(teamId)&&x.status==="approved");
    if(!reg)return res.status(400).json({error:"registration_not_approved"});
    await mutate(x=>{
      const rr=ensureRelampago(x);
      const rg=rr.registrations.find(v=>String(v.id)===String(reg.id));
      rg.checkedIn=true;rg.checkedInAt=new Date().toISOString();
      const club=(x.teams||[]).find(t=>Number(t.id)===Number(teamId));
      x.log.unshift(`✅ Check-in Relámpago: ${club?.name||"Club"}`);
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/admin/relampago/draw",auth,adminOnly,async(req,res)=>{
  try{
    await mutate(x=>{
      const r=ensureRelampago(x);
      if(r.status!=="not_started")throw new Error("already_started");
      const checked=(r.registrations||[]).filter(v=>v.status==="approved"&&v.checkedIn).map(v=>Number(v.teamId));
      const source=checked.length>=4?checked:r.teamIds.map(Number);
      if(source.length<4)throw new Error("minimum_4_teams");
      r.drawOrder=shuffleIds([...new Set(source)]);
      r.drawCompletedAt=new Date().toISOString();
      x.log.unshift(`🎲 Sorteo Relámpago realizado con ${r.drawOrder.length} clubes`);
    });
    res.json({ok:true});
  }catch(e){
    if(e.message==="minimum_4_teams")return res.status(400).json({error:e.message});
    if(e.message==="already_started")return res.status(400).json({error:e.message});
    res.status(500).json({error:"server_error"})
  }
});

app.post("/api/admin/relampago/start",auth,adminOnly,async(req,res)=>{
  try{
    const st=(await getStore()).state;
    const rr=ensureRelampago(st);
    const approved=new Set((st.teams||[]).filter(t=>t.approved).map(t=>Number(t.id)));
    let teamIds=[...new Set((req.body?.teamIds||[]).map(Number))].filter(id=>approved.has(id));
    const checked=new Set((rr.registrations||[]).filter(v=>v.status==="approved"&&v.checkedIn).map(v=>Number(v.teamId)));
    const registeredSelected=teamIds.filter(id=>(rr.registrations||[]).some(v=>Number(v.teamId)===id&&v.status==="approved"));
    if(registeredSelected.some(id=>!checked.has(id)))return res.status(400).json({error:"checkin_required"});
    if(rr.drawOrder?.length){
      const set=new Set(teamIds);
      const ordered=rr.drawOrder.map(Number).filter(id=>set.has(id));
      teamIds=[...ordered,...teamIds.filter(id=>!ordered.includes(id))];
    }
    const leagueRounds=Math.max(1,Math.min(Number(req.body?.leagueRounds)||5,Math.max(1,teamIds.length-1)));
    const qualifiers=Number(req.body?.qualifiers)||8;
    const twoLegged=req.body?.twoLegged!==false;
    if(teamIds.length<4)return res.status(400).json({error:"minimum_4_teams"});
    if(!isPowerOfTwo(qualifiers)||qualifiers>teamIds.length||qualifiers<2)
      return res.status(400).json({error:"invalid_qualifiers"});
    await mutate(x=>{
      const r=ensureRelampago(x);
      r.name=String(req.body?.name||"RELÁMPAGO FC26-27").slice(0,80);
      r.status="active";r.phase="league";r.teamIds=teamIds;
      r.leagueRounds=leagueRounds;r.qualifiers=qualifiers;r.twoLegged=twoLegged;
      r.matches=relampagoLeagueSchedule(teamIds,leagueRounds);
      r.championTeamId=null;r.startedAt=new Date().toISOString();r.completedAt=null;
      x.log.unshift(`⚡ ${r.name} iniciado con ${teamIds.length} clubes`);
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/admin/relampago/reset",auth,adminOnly,async(req,res)=>{
  try{
    await mutate(x=>{
      const old=ensureRelampago(x);
      const name=old.name||"RELÁMPAGO FC26-27",history=Array.isArray(old.history)?old.history:[];
      x.relampago=defaultRelampago();
      x.relampago.name=name;x.relampago.history=history;
      x.log.unshift("⚡ Relámpago reiniciado por administrador");
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/relampago/matches/:id/submit",auth,async(req,res)=>{
  try{
    if(!["admin","dt","player"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
    const hs=scoreValue(req.body?.homeScore),as=scoreValue(req.body?.awayScore);
    if(hs===null||as===null)return res.status(400).json({error:"invalid_score"});
    const ph=req.body?.penaltyHome===""||req.body?.penaltyHome==null?null:scoreValue(req.body?.penaltyHome);
    const pa=req.body?.penaltyAway===""||req.body?.penaltyAway==null?null:scoreValue(req.body?.penaltyAway);
    if((ph===null)!==(pa===null))return res.status(400).json({error:"invalid_penalties"});
    const st=(await getStore()).state,m=relampagoMatch(st,req.params.id);
    if(!m)return res.status(404).json({error:"not_found"});
    const teamId=req.user.role==="admin"?Number(req.body?.teamId||m.homeTeamId):accountTeamId(req.user,st);
    if(req.user.role!=="admin"&&teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))
      return res.status(403).json({error:"not_your_match"});
    await mutate(x=>{
      const mm=relampagoMatch(x,req.params.id);
      mm.homeScore=hs;mm.awayScore=as;mm.penaltyHome=ph;mm.penaltyAway=pa;mm.status="pending_confirmation";
      mm.submittedByTeamId=teamId;mm.submittedByUserId=req.user.id;mm.submittedAt=new Date().toISOString();
      mm.confirmedByTeamId=null;mm.confirmedAt=null;mm.disputeNote=null;mm.winnerTeamId=null;
      const ht=x.teams.find(t=>Number(t.id)===Number(mm.homeTeamId))?.name||"Local";
      const at=x.teams.find(t=>Number(t.id)===Number(mm.awayTeamId))?.name||"Visitante";
      x.log.unshift(`⚡ Resultado enviado: ${ht} ${hs}-${as} ${at}`);
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/relampago/matches/:id/confirm",auth,async(req,res)=>{
  try{
    if(!["admin","dt","player"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
    const st=(await getStore()).state,m=relampagoMatch(st,req.params.id);
    if(!m)return res.status(404).json({error:"not_found"});
    if(m.status!=="pending_confirmation")return res.status(400).json({error:"not_pending"});
    const teamId=req.user.role==="admin"?null:accountTeamId(req.user,st);
    if(req.user.role!=="admin"){
      if(teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))return res.status(403).json({error:"not_your_match"});
      if(Number(teamId)===Number(m.submittedByTeamId))return res.status(403).json({error:"opponent_must_confirm"});
    }
    await mutate(x=>{
      const mm=relampagoMatch(x,req.params.id);
      mm.status="confirmed";mm.confirmedByTeamId=teamId;mm.confirmedAt=new Date().toISOString();
      if(mm.phase==="knockout"){
        const tie=knockoutTieResult(x,String(mm.tieId||mm.id));
        if(tie.ready&&tie.needsPenalties)throw new Error("penalties_required");
        if(tie.ready&&tie.winner){
          x.relampago.matches.filter(g=>String(g.tieId||g.id)===String(mm.tieId||mm.id)).forEach(g=>g.winnerTeamId=Number(tie.winner));
        }
      }
      const ht=x.teams.find(t=>Number(t.id)===Number(mm.homeTeamId))?.name||"Local";
      const at=x.teams.find(t=>Number(t.id)===Number(mm.awayTeamId))?.name||"Visitante";
      x.log.unshift(`⚡ Resultado confirmado: ${ht} ${mm.homeScore}-${mm.awayScore} ${at}`);
      maybeAdvanceRelampago(x);
    });
    res.json({ok:true});
  }catch(e){
    if(e.message==="penalties_required")return res.status(400).json({error:e.message});
    res.status(500).json({error:"server_error"})
  }
});

app.post("/api/relampago/matches/:id/dispute",auth,async(req,res)=>{
  try{
    if(!["admin","dt","player"].includes(req.user.role))return res.status(403).json({error:"forbidden"});
    const st=(await getStore()).state,m=relampagoMatch(st,req.params.id);
    if(!m)return res.status(404).json({error:"not_found"});
    const teamId=req.user.role==="admin"?null:accountTeamId(req.user,st);
    if(req.user.role!=="admin"&&teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))
      return res.status(403).json({error:"not_your_match"});
    await mutate(x=>{
      const mm=relampagoMatch(x,req.params.id);
      mm.status="disputed";mm.disputeNote=String(req.body?.note||"El marcador no coincide").slice(0,250);
      mm.confirmedByTeamId=null;mm.confirmedAt=null;mm.winnerTeamId=null;
      x.log.unshift(`⚡ Resultado en disputa: ${mm.id}`);
    });
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"server_error"})}
});

app.post("/api/admin/relampago/matches/:id/resolve",auth,adminOnly,async(req,res)=>{
  try{
    const hs=scoreValue(req.body?.homeScore),as=scoreValue(req.body?.awayScore);
    if(hs===null||as===null)return res.status(400).json({error:"invalid_score"});
    const ph=req.body?.penaltyHome===""||req.body?.penaltyHome==null?null:scoreValue(req.body?.penaltyHome);
    const pa=req.body?.penaltyAway===""||req.body?.penaltyAway==null?null:scoreValue(req.body?.penaltyAway);
    await mutate(x=>{
      const mm=relampagoMatch(x,req.params.id);
      if(!mm)throw new Error("not_found");
      mm.homeScore=hs;mm.awayScore=as;mm.penaltyHome=ph;mm.penaltyAway=pa;mm.status="confirmed";
      mm.confirmedByTeamId=null;mm.confirmedAt=new Date().toISOString();mm.disputeNote=null;
      if(mm.phase==="knockout"){
        const tie=knockoutTieResult(x,String(mm.tieId||mm.id));
        if(tie.ready&&tie.needsPenalties)throw new Error("penalties_required");
        if(tie.ready&&tie.winner)x.relampago.matches.filter(g=>String(g.tieId||g.id)===String(mm.tieId||mm.id)).forEach(g=>g.winnerTeamId=Number(tie.winner));
      }
      x.log.unshift(`⚡ Admin resolvió ${mm.id}: ${hs}-${as}`);
      maybeAdvanceRelampago(x);
    });
    res.json({ok:true});
  }catch(e){
    if(e.message==="not_found")return res.status(404).json({error:"not_found"});
    if(e.message==="penalties_required")return res.status(400).json({error:e.message});
    res.status(500).json({error:"server_error"})
  }
});



function ensureOrganizerTournaments(st){if(!Array.isArray(st.organizerTournaments))st.organizerTournaments=[];return st.organizerTournaments}
function organizerOnly(req,res,next){if(!["admin","organizer"].includes(req.user?.role))return res.status(403).json({error:"organizer_only"});next()}
function organizerAllowed(user,t){return user?.role==="admin"||(user?.role==="organizer"&&String(t.ownerUserId)===String(user.id))}
function organizerBracket(teamIds,tournamentId){
 const ids=[...teamIds].map(Number),out=[];let matchNo=1,size=ids.length;
 for(let i=0;i<ids.length;i+=2)out.push({id:`ORG-${tournamentId}-R1-M${matchNo++}`,round:1,stage:size===2?"FINAL":size===4?"SEMIFINAL":size===8?"CUARTOS":size===16?"OCTAVOS":`TOP ${size}`,homeTeamId:ids[i],awayTeamId:ids[i+1],homeScore:null,awayScore:null,winnerTeamId:null,status:"scheduled"});
 return out
}
function organizerMaybeAdvance(t){
 const currentRound=Math.max(1,...(t.matches||[]).map(m=>Number(m.round)||1)),current=(t.matches||[]).filter(m=>Number(m.round)===currentRound);
 if(!current.length||!current.every(m=>m.status==="confirmed"&&m.winnerTeamId))return;
 if(current.length===1){t.status="completed";t.championTeamId=Number(current[0].winnerTeamId);t.completedAt=new Date().toISOString();return}
 if((t.matches||[]).some(m=>Number(m.round)===currentRound+1))return;
 const winners=current.map(m=>Number(m.winnerTeamId)),size=winners.length;
 for(let i=0;i<winners.length;i+=2)t.matches.push({id:`ORG-${t.id}-R${currentRound+1}-M${Math.floor(i/2)+1}`,round:currentRound+1,stage:size===2?"FINAL":size===4?"SEMIFINAL":size===8?"CUARTOS":`TOP ${size}`,homeTeamId:winners[i],awayTeamId:winners[i+1],homeScore:null,awayScore:null,winnerTeamId:null,status:"scheduled"})
}
app.get("/api/organizer/tournaments",auth,async(req,res)=>{try{
 const st=(await getStore()).state,all=ensureOrganizerTournaments(st);
 if(req.user.role==="admin")return res.json({tournaments:all});
 if(req.user.role==="organizer")return res.json({tournaments:all.filter(t=>String(t.ownerUserId)===String(req.user.id))});
 if(req.user.role==="dt"){const teamId=accountTeamId(req.user,st);return res.json({tournaments:all.filter(t=>(t.teamIds||[]).some(id=>Number(id)===Number(teamId)))})}
 return res.status(403).json({error:"forbidden"});
}catch{res.status(500).json({error:"server_error"})}});
app.post("/api/organizer/tournaments",auth,organizerOnly,async(req,res)=>{try{
 const name=String(req.body?.name||"").trim().slice(0,80),size=Number(req.body?.size)||8;
 const format=["knockout","groups_playoffs"].includes(req.body?.format)?req.body.format:"knockout";
 const visibility=["public","private"].includes(req.body?.visibility)?req.body.visibility:"public";
 const twoLegged=!!req.body?.twoLegged,penalties=req.body?.penalties!==false;
 const registrationMode=["open","invite"].includes(req.body?.registrationMode)?req.body.registrationMode:"open";
 const deadline=String(req.body?.deadline||"").slice(0,32);
 if(!name)return res.status(400).json({error:"name_required"});if(![4,8,16].includes(size))return res.status(400).json({error:"invalid_size"});
 const id=`T${Date.now()}`,inviteCode=visibility==="private"?Math.random().toString(36).slice(2,8).toUpperCase():null;
 await mutate(st=>{ensureOrganizerTournaments(st).unshift({id,name,size,format,visibility,twoLegged,penalties,registrationMode,deadline,inviteCode,status:"draft",ownerUserId:req.user.id,ownerUsername:req.user.username,createdAt:new Date().toISOString(),teamIds:[],applications:[],matches:[],championTeamId:null,completedAt:null});st.log.unshift(`🏆 Torneo creado: ${name}`)});res.json({ok:true,id})
}catch{res.status(500).json({error:"server_error"})}});app.put("/api/organizer/tournaments/:id/config",auth,organizerOnly,async(req,res)=>{try{
 const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id));if(!t)return res.status(404).json({error:"not_found"});if(!organizerAllowed(req.user,t))return res.status(403).json({error:"forbidden"});if(t.status!=="draft")return res.status(400).json({error:"already_started"});
 await mutate(x=>{const tt=ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id));if(req.body?.name)tt.name=String(req.body.name).trim().slice(0,80);if(["knockout","groups_playoffs"].includes(req.body?.format))tt.format=req.body.format;if(["public","private"].includes(req.body?.visibility))tt.visibility=req.body.visibility;tt.twoLegged=!!req.body?.twoLegged;tt.penalties=req.body?.penalties!==false;if(["open","invite"].includes(req.body?.registrationMode))tt.registrationMode=req.body.registrationMode;tt.deadline=String(req.body?.deadline||"").slice(0,32);if(tt.visibility==="private"&&!tt.inviteCode)tt.inviteCode=Math.random().toString(36).slice(2,8).toUpperCase()});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});
app.put("/api/organizer/tournaments/:id/teams",auth,organizerOnly,async(req,res)=>{try{
 const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id));if(!t)return res.status(404).json({error:"not_found"});if(!organizerAllowed(req.user,t))return res.status(403).json({error:"forbidden"});if(t.status!=="draft")return res.status(400).json({error:"already_started"});
 const approved=new Set((st.teams||[]).filter(x=>x.approved).map(x=>Number(x.id))),valid=[...new Set((req.body?.teamIds||[]).map(Number))].filter(id=>approved.has(id)).slice(0,t.size);
 await mutate(x=>{ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id)).teamIds=valid});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});
app.post("/api/organizer/tournaments/:id/start",auth,organizerOnly,async(req,res)=>{try{
 const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id));if(!t)return res.status(404).json({error:"not_found"});if(!organizerAllowed(req.user,t))return res.status(403).json({error:"forbidden"});if((t.teamIds||[]).length!==Number(t.size))return res.status(400).json({error:"fill_all_slots"});
 await mutate(x=>{const tt=ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id)),shuffled=shuffleIds(tt.teamIds);tt.teamIds=shuffled;tt.matches=organizerBracket(shuffled,tt.id);tt.status="active";tt.startedAt=new Date().toISOString()});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});
app.post("/api/organizer/tournaments/:id/matches/:matchId/result",auth,organizerOnly,async(req,res)=>{try{
 const hs=scoreValue(req.body?.homeScore),as=scoreValue(req.body?.awayScore);if(hs===null||as===null||hs===as)return res.status(400).json({error:"decisive_score_required"});
 const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id));if(!t)return res.status(404).json({error:"not_found"});if(!organizerAllowed(req.user,t))return res.status(403).json({error:"forbidden"});
 await mutate(x=>{const tt=ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id)),m=tt.matches.find(v=>String(v.id)===String(req.params.matchId));if(!m)throw new Error("match_not_found");m.homeScore=hs;m.awayScore=as;m.status="confirmed";m.winnerTeamId=hs>as?Number(m.homeTeamId):Number(m.awayTeamId);m.resolvedByUserId=req.user.id;m.resolvedAt=new Date().toISOString();organizerMaybeAdvance(tt)});res.json({ok:true})
}catch(e){if(e.message==="match_not_found")return res.status(404).json({error:"match_not_found"});res.status(500).json({error:"server_error"})}});

app.post("/api/organizer/tournaments/:id/matches/:matchId/submit",auth,async(req,res)=>{try{
 if(!["dt","admin"].includes(req.user.role))return res.status(403).json({error:"dt_only"});
 const hs=scoreValue(req.body?.homeScore),as=scoreValue(req.body?.awayScore);if(hs===null||as===null||hs===as)return res.status(400).json({error:"decisive_score_required"});
 const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id)),teamId=req.user.role==="admin"?Number(req.body?.teamId):accountTeamId(req.user,st);
 if(!t)return res.status(404).json({error:"not_found"});const m=(t.matches||[]).find(v=>String(v.id)===String(req.params.matchId));if(!m)return res.status(404).json({error:"match_not_found"});
 if(teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))return res.status(403).json({error:"not_your_match"});
 if(m.status==="confirmed")return res.status(400).json({error:"already_confirmed"});
 await mutate(x=>{const tt=ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id)),mm=tt.matches.find(v=>String(v.id)===String(req.params.matchId));mm.homeScore=hs;mm.awayScore=as;mm.status="pending_confirmation";mm.submittedByTeamId=Number(teamId);mm.submittedByUserId=req.user.id;mm.submittedAt=new Date().toISOString();mm.disputeNote=null});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});

app.post("/api/organizer/tournaments/:id/matches/:matchId/confirm",auth,async(req,res)=>{try{
 if(req.user.role!=="dt")return res.status(403).json({error:"dt_only"});const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id)),teamId=accountTeamId(req.user,st);
 if(!t)return res.status(404).json({error:"not_found"});const m=(t.matches||[]).find(v=>String(v.id)===String(req.params.matchId));if(!m)return res.status(404).json({error:"match_not_found"});
 if(m.status!=="pending_confirmation")return res.status(400).json({error:"not_pending"});if(teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))return res.status(403).json({error:"not_your_match"});if(Number(teamId)===Number(m.submittedByTeamId))return res.status(403).json({error:"opponent_must_confirm"});
 await mutate(x=>{const tt=ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id)),mm=tt.matches.find(v=>String(v.id)===String(req.params.matchId));mm.status="confirmed";mm.confirmedByTeamId=Number(teamId);mm.confirmedAt=new Date().toISOString();mm.winnerTeamId=Number(mm.homeScore)>Number(mm.awayScore)?Number(mm.homeTeamId):Number(mm.awayTeamId);organizerMaybeAdvance(tt)});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});

app.post("/api/organizer/tournaments/:id/matches/:matchId/dispute",auth,async(req,res)=>{try{
 if(req.user.role!=="dt")return res.status(403).json({error:"dt_only"});const note=String(req.body?.note||"Resultado disputado").trim().slice(0,300),st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id)),teamId=accountTeamId(req.user,st);
 if(!t)return res.status(404).json({error:"not_found"});const m=(t.matches||[]).find(v=>String(v.id)===String(req.params.matchId));if(!m)return res.status(404).json({error:"match_not_found"});if(m.status!=="pending_confirmation")return res.status(400).json({error:"not_pending"});if(teamId!==Number(m.homeTeamId)&&teamId!==Number(m.awayTeamId))return res.status(403).json({error:"not_your_match"});if(Number(teamId)===Number(m.submittedByTeamId))return res.status(403).json({error:"opponent_only"});
 await mutate(x=>{const tt=ensureOrganizerTournaments(x).find(v=>String(v.id)===String(req.params.id)),mm=tt.matches.find(v=>String(v.id)===String(req.params.matchId));mm.status="disputed";mm.disputeNote=note;mm.disputedByTeamId=Number(teamId);mm.disputedAt=new Date().toISOString()});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});
app.delete("/api/organizer/tournaments/:id",auth,organizerOnly,async(req,res)=>{try{
 const st=(await getStore()).state,t=ensureOrganizerTournaments(st).find(x=>String(x.id)===String(req.params.id));if(!t)return res.status(404).json({error:"not_found"});if(!organizerAllowed(req.user,t))return res.status(403).json({error:"forbidden"});
 await mutate(x=>{x.organizerTournaments=ensureOrganizerTournaments(x).filter(v=>String(v.id)!==String(req.params.id))});res.json({ok:true})
}catch{res.status(500).json({error:"server_error"})}});

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

initDb().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log(`PINTO FC26 RELEASE 1.6.5 on ${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
