import crypto from 'node:crypto';
export default async function handler(req,res){
res.setHeader('Cache-Control','no-store');
if(req.method!=='POST')return res.status(405).json({ok:false});
const {ADMIN_PASSWORD:p,GAS_SHARED_SECRET:s,GAS_ENDPOINT:e}=process.env;
if(!p||!s||!e)return res.status(503).json({ok:false,error:'Configuration missing'});
const equal=(a,b)=>crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(),crypto.createHash('sha256').update(String(b)).digest());
const sign=t=>crypto.createHmac('sha256',s).update('admin:'+p+':'+t).digest('hex');
try{
if(req.headers.origin!== 'https://gloryland-connect.vercel.app')return res.status(403).json({ok:false});
const b=typeof req.body==='string'?JSON.parse(req.body):req.body||{};
if(b.action==='login'){
if(!equal(b.password,p))return res.status(401).json({ok:false,error:'Incorrect password'});
const t=String(Date.now()+3600000);
res.setHeader('Set-Cookie','gl_session='+t+'.'+sign(t)+'; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=3600');
return res.json({ok:true});
}
if(b.action==='logout'){res.setHeader('Set-Cookie','gl_session=; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0');return res.json({ok:true});}
const token=(req.headers.cookie||'').match(/(?:^|; )gl_session=([^;]+)/)?.[1]||'';
const [t,h]=token.split('.');
if(!t||!h||!/^\d+$/.test(t)||Number(t)<Date.now()||!equal(h,sign(t)))return res.status(401).json({ok:false,error:'Please sign in'});
if(!['list','update','archive','restore','visits','addVisit','bulkAssign','commGet','commSave','commTest'].includes(b.action))return res.status(400).json({ok:false});
const upstream=await fetch(e,{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:JSON.stringify({secret:s,action:'admin',payload:{action:b.action,id:b.id,updates:b.updates,ids:b.ids,assignedTo:b.assignedTo,date:b.date,service:b.service,notes:b.notes}}),signal:AbortSignal.timeout(25000)});
const raw=await upstream.text();
let data;try{data=JSON.parse(raw)}catch{console.error('Admin upstream non-JSON',b.action,upstream.status);return res.status(502).json({ok:false,error:'Apps Script returned an invalid response. Check deployment access and execution logs.'})}
if(!upstream.ok||!data.ok)return res.status(502).json({ok:false,error:'Apps Script rejected this operation. Check Apps Script execution logs.'});
return res.json(data);
}catch(err){console.error('Admin request failed',err.name,err.cause?.code||'');return res.status(502).json({ok:false,error:err.name==='TimeoutError'||err.name==='AbortError'?'Google Sheets request timed out. Refresh records before retrying.':'Unable to reach Apps Script. Refresh records before retrying.'});}
}