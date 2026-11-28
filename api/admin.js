export default async function handler(req,res){
res.setHeader('Cache-Control','no-store');
if(req.method!=='POST')return res.status(405).json({ok:false});
const {GAS_SHARED_SECRET:s,GAS_ENDPOINT:e}=process.env;
const base='https://odbyijwovivsqdbsgyfd.supabase.co';
const key='sb_publishable_MYuw17oSrSCJt5Sq3lYeOg_nP1LvDpb';
try{
const allowed=new Set(['https://gloryland-connect.vercel.app',...([process.env.VERCEL_URL,process.env.VERCEL_BRANCH_URL].filter(Boolean).map(h=>'https://'+h))]);
if(!allowed.has(req.headers.origin))return res.status(403).json({ok:false,error:'Untrusted origin'});
const b=typeof req.body==='string'?JSON.parse(req.body):req.body||{};
const authorization=req.headers.authorization||'';
if(!/^Bearer [^\s]+$/.test(authorization))return res.status(401).json({ok:false,error:'Please sign in'});
const headers={apikey:key,Authorization:authorization};
const userRes=await fetch(base+'/auth/v1/user',{headers,signal:AbortSignal.timeout(10000)});
if(!userRes.ok)return res.status(401).json({ok:false,error:'Session expired. Please sign in.'});
const user=await userRes.json();
if(!user.id||!user.email_confirmed_at)return res.status(403).json({ok:false,error:'Account not verified'});
const roleRes=await fetch(base+'/rest/v1/gl_team?select=user_id,display_name,role,active&user_id=eq.'+encodeURIComponent(user.id),{headers,signal:AbortSignal.timeout(10000)});
if(!roleRes.ok)return res.status(502).json({ok:false,error:'Unable to verify permissions'});
const roles=await roleRes.json();
const member=roles[0];
if(!member||!member.active)return res.status(403).json({ok:false,error:'Account is not authorised'});
if(b.action==='identity')return res.json({ok:true,member});
if(!['super_admin','admin'].includes(member.role))return res.status(403).json({ok:false,error:'This workspace is currently restricted to Super Admins and Admins'});
if(member.role!=='super_admin'&&['teamList','teamUpdate','commGet','commSave','commTest'].includes(b.action))return res.status(403).json({ok:false,error:'This operation requires Super Admin access'});
if(b.action==='teamList'){
const response=await fetch(base+'/rest/v1/gl_team?select=user_id,display_name,role,active,created_at&order=created_at.asc',{headers,signal:AbortSignal.timeout(10000)});
if(!response.ok)return res.status(502).json({ok:false,error:'Unable to load team'});
return res.json({ok:true,team:await response.json()});
}
if(b.action==='teamUpdate'){
if(typeof b.user_id!=='string'||typeof b.display_name!=='string'||typeof b.active!=='boolean'||!['super_admin','admin','media','welfare','pastor','viewer'].includes(b.role))return res.status(400).json({ok:false,error:'Invalid team member'});
const response=await fetch(base+'/rest/v1/rpc/gl_set_team_member',{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({p_user:b.user_id,p_name:b.display_name,p_role:b.role,p_active:b.active}),signal:AbortSignal.timeout(10000)});
if(!response.ok)return res.status(400).json({ok:false,error:'Unable to update member. Check account ID, name and the last active Super Admin rule.'});
return res.json({ok:true});
}
if(!s||!e)return res.status(503).json({ok:false,error:'Registration backend configuration missing'});
if(!['list','update','archive','restore','visits','addVisit','bulkAssign','commGet','commSave','commTest'].includes(b.action))return res.status(400).json({ok:false});
const upstream=await fetch(e,{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:JSON.stringify({secret:s,action:'admin',payload:{action:b.action,id:b.id,updates:b.updates,ids:b.ids,assignedTo:b.assignedTo,date:b.date,service:b.service,notes:b.notes}}),signal:AbortSignal.timeout(25000)});
const raw=await upstream.text();
let data;try{data=JSON.parse(raw)}catch{console.error('Admin upstream non-JSON',b.action,upstream.status);return res.status(502).json({ok:false,error:'Apps Script returned an invalid response. Check deployment access and execution logs.'})}
if(!upstream.ok||!data.ok)return res.status(502).json({ok:false,error:'Apps Script rejected this operation. Check Apps Script execution logs.'});
return res.json(data);
}catch(err){console.error('Admin request failed',err.name,err.cause?.code||'');return res.status(502).json({ok:false,error:err.name==='TimeoutError'||err.name==='AbortError'?'Google Sheets request timed out. Refresh records before retrying.':'Unable to reach Apps Script. Refresh records before retrying.'});}
}