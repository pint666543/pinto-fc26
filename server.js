const express = require("express");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8787);
const ADMIN_KEY = process.env.ADMIN_KEY || "pinto-admin-demo";
const DATABASE_URL = process.env.DATABASE_URL || "";
const usePostgres = Boolean(DATABASE_URL);

app.use(express.json({ limit: "1mb" }));
app.use(express.static(ROOT));

const initialState = {
  teams:[
    {id:1,name:"REAL BAKARDI FC",abbr:"RB",dt:"DT Bakardi",approved:true},
    {id:2,name:"TITANS X",abbr:"TX",dt:"DT Titans",approved:true},
    {id:3,name:"RELÁMPAGOS FC",abbr:"RF",dt:"DT Rayo",approved:true},
    {id:4,name:"INVICTUS X VKGY",abbr:"IX",dt:"DT Invictus",approved:true}
  ],
  players:[
    {id:1,name:"LV_Pint0",ea:"LV_Pint0",pos:"POR",sec:"-",country:"Cuba",platform:"PC",discord:"",availability:"",notes:"",ovr:88,status:"Disponible"},
    {id:2,name:"Player02",ea:"Player02",pos:"DFC",sec:"MCD",country:"Brasil",platform:"PC",discord:"",availability:"",notes:"",ovr:87,status:"Disponible"}
  ],
  playerRequests:[],dtRequests:[],picks:[],skips:[],paused:false,
  scouting:{},combine:{},settings:{seconds:45,draftType:"Snake"},log:[]
};

let pool = null;
const DATA_DIR = path.join(ROOT, "data");
const LOCAL_DB = path.join(DATA_DIR, "state.json");
fs.mkdirSync(DATA_DIR, { recursive:true });
let localStore = { revision:1, state:initialState };

if (!usePostgres && fs.existsSync(LOCAL_DB)) {
  try { localStore = JSON.parse(fs.readFileSync(LOCAL_DB, "utf8")); } catch {}
}
function saveLocal(){ fs.writeFileSync(LOCAL_DB, JSON.stringify(localStore,null,2)); }

async function initDb(){
  if(!usePostgres) return;
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized:false } : undefined
  });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pinto_state(
      id INTEGER PRIMARY KEY,
      revision BIGINT NOT NULL,
      state JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  const r = await pool.query("SELECT id FROM pinto_state WHERE id=1");
  if(r.rowCount===0){
    await pool.query("INSERT INTO pinto_state(id,revision,state) VALUES(1,1,$1::jsonb)", [JSON.stringify(initialState)]);
  }
}

async function getStore(){
  if(!usePostgres) return localStore;
  const r=await pool.query("SELECT revision,state FROM pinto_state WHERE id=1");
  return { revision:Number(r.rows[0].revision), state:r.rows[0].state };
}
async function replaceStore(state, expectedRevision){
  if(!usePostgres){
    if(Number(expectedRevision)!==Number(localStore.revision)) return { conflict:true, store:localStore };
    localStore={state,revision:localStore.revision+1};saveLocal();
    return { conflict:false, revision:localStore.revision };
  }
  const r=await pool.query(
    `UPDATE pinto_state SET state=$1::jsonb, revision=revision+1, updated_at=NOW()
     WHERE id=1 AND revision=$2 RETURNING revision`,
    [JSON.stringify(state), expectedRevision]
  );
  if(r.rowCount===0) return { conflict:true, store:await getStore() };
  return { conflict:false, revision:Number(r.rows[0].revision) };
}
async function mutateState(mutator){
  for(let tries=0; tries<5; tries++){
    const s=await getStore();
    const next=structuredClone(s.state);
    mutator(next);
    const r=await replaceStore(next,s.revision);
    if(!r.conflict) return {state:next,revision:r.revision};
  }
  throw new Error("Concurrent update conflict");
}

function adminAuthorized(req){
  const supplied = req.header("x-admin-key") || req.query.admin_key || "";
  return supplied === ADMIN_KEY;
}

app.get("/api/info",(req,res)=>{
  res.json({
    online:true,
    registrationUrl:`${req.protocol}://${req.get("host")}/register.html`,
    appUrl:`${req.protocol}://${req.get("host")}/`,
    database:usePostgres?"postgres":"local-json"
  });
});

app.get("/api/state", async (req,res)=>{
  try{ res.json(await getStore()); }
  catch(e){ res.status(500).json({error:"database_error"}); }
});

app.put("/api/state", async (req,res)=>{
  try{
    const {state,revision}=req.body||{};
    if(!state || typeof state!=="object") return res.status(400).json({error:"bad_state"});
    const r=await replaceStore(state,revision);
    if(r.conflict) return res.status(409).json(r.store);
    res.json({revision:r.revision});
  }catch(e){ res.status(500).json({error:"database_error"}); }
});

app.post("/api/register/player", async (req,res)=>{
  try{
    const r=req.body||{};
    if(!String(r.name||"").trim()) return res.status(400).json({error:"name_required"});
    r.id = r.id || Date.now();
    r.status="Pendiente";
    r.created = r.created || new Date().toISOString();
    const result=await mutateState(st=>{
      st.playerRequests=st.playerRequests||[];
      st.log=st.log||[];
      st.playerRequests.push(r);
      st.log.unshift(`Nueva inscripción online: ${r.name}`);
    });
    res.json({ok:true,revision:result.revision});
  }catch(e){ res.status(500).json({error:"database_error"}); }
});

app.post("/api/register/dt", async (req,res)=>{
  try{
    const r=req.body||{};
    if(!String(r.name||"").trim() || !String(r.club||"").trim()) return res.status(400).json({error:"fields_required"});
    r.id = r.id || Date.now();
    r.status="Pendiente";
    r.created = r.created || new Date().toISOString();
    const result=await mutateState(st=>{
      st.dtRequests=st.dtRequests||[];
      st.log=st.log||[];
      st.dtRequests.push(r);
      st.log.unshift(`Nueva solicitud online de DT: ${r.name} / ${r.club}`);
    });
    res.json({ok:true,revision:result.revision});
  }catch(e){ res.status(500).json({error:"database_error"}); }
});

app.get("/api/health",(req,res)=>res.json({ok:true,db:usePostgres?"postgres":"local"}));

initDb().then(()=>{
  app.listen(PORT,"0.0.0.0",()=>{
    console.log(`PINTO FC26 V10 ONLINE running on port ${PORT}`);
    console.log(usePostgres ? "PostgreSQL: connected" : "Local JSON fallback active");
  });
}).catch(err=>{
  console.error("Startup failed:",err);
  process.exit(1);
});
