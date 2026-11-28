const base=Deno.env.get('SUPABASE_URL')!;
const service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const pub='sb_publishable_MYuw17oSrSCJt5Sq3lYeOg_nP1LvDpb';
const origins=new Set(['https://gloryland-connect.vercel.app','https://gloryland-connect-git-v35-acce-0a385e-yungdave01-8115s-projects.vercel.app']);
const hash=async (s:string)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),b=>b.toString(16).padStart(2,'0')).join('');
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
const q=encodeURIComponent;
async function call(path:string,method='GET',body?:unknown,token=service,key=service,prefer='return=representation'){
 const headers:Record<string,string>={apikey:key,Authorization:'Bearer '+token,'Content-Type':'application/json',Prefer:prefer};
 const r=await fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
 const data=await r.json().catch(()=>null);if(!r.ok)throw new Error('Upstream request failed');return data;
}
const table='/rest/v1/gl_enrollment';
Deno.serve(async req=>{
 const origin=req.headers.get('origin')||'';
 const headers={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Headers':'authorization, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Vary':'Origin','Content-Type':'application/json','Cache-Control':'no-store'};
 const out=(data:unknown,status=200)=>new Response(JSON.stringify(data),{headers,status});
 if(!origins.has(origin))return new Response(null,{status:403});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return out({error:'Method not allowed'},405);
 try{
 if(Number(req.headers.get('content-length')||0)>8192)return out({error:'Invalid request'},400);
 const raw=await req.text();if(raw.length>8192)return out({error:'Invalid request'},400);
 const b=JSON.parse(raw),email=String(b.email||'').trim().toLowerCase(),username=String(b.username||'').trim().toLowerCase(),password=String(b.password||'');
 if(b.action==='activate'){
  const code=String(b.code||'').trim().toLowerCase();
  if(!/^[a-f0-9]{64}$/.test(code)||password.length<12||new TextEncoder().encode(password).length>72)return out({error:'Invalid activation details. Use a password of 12–72 bytes.'},400);
  const digest=await hash(code);
  const found=await call(table+'?email=eq.'+q(email)+'&activation_hash=eq.'+digest+'&expires_at=gt.'+q(new Date().toISOString())+'&activated_at=is.null&select=email,user_id');
  if(!Array.isArray(found)||found.length!==1||!found[0].user_id)return out({error:'Invalid or expired activation code'},400);
  const member=await call('/rest/v1/gl_team?user_id=eq.'+q(found[0].user_id)+'&active=eq.true&select=user_id');
  if(!member.length)return out({error:'Account not approved or suspended'},403);
  const claimed=await call(table+'?email=eq.'+q(email)+'&activation_hash=eq.'+digest+'&expires_at=gt.'+q(new Date().toISOString())+'&activated_at=is.null','PATCH',{activation_hash:null,expires_at:null});
  if(claimed.length!==1)return out({error:'Invalid or expired activation code'},400);
  // The code is consumed before changing the password. A failed request requires owner reissue.
  await call('/auth/v1/admin/users/'+q(found[0].user_id),'PUT',{password});
  await call(table+'?email=eq.'+q(email),'PATCH',{activated_at:new Date().toISOString()});
  await call('/rest/v1/gl_activity','POST',{actor:found[0].user_id,action:'account_activated',target:found[0].user_id});
  return out({ok:true});
 }
 if(b.action==='login'){
  const ident=String(b.identifier||'').trim().toLowerCase();
  if(!ident||ident.length>254||!password||new TextEncoder().encode(password).length>72)return out({error:'Invalid credentials'},401);
  const field=ident.includes('@')?'email':'username';
  const matches=await call(table+'?'+field+'=eq.'+q(ident)+'&activated_at=not.is.null&select=email,user_id');
  if(matches.length!==1)return out({error:'Invalid credentials or account not activated'},401);
  const member=await call('/rest/v1/gl_team?user_id=eq.'+q(matches[0].user_id)+'&active=eq.true&select=user_id');
  if(!member.length)return out({error:'Invalid credentials or account not activated'},401);
  const r=await fetch(base+'/auth/v1/token?grant_type=password',{method:'POST',headers:{apikey:pub,'Content-Type':'application/json'},body:JSON.stringify({email:matches[0].email,password}),signal:AbortSignal.timeout(10000)});
  if(!r.ok)return out({error:r.status===429?'Too many login attempts. Try again later.':'Invalid credentials'},r.status===429?429:401);
  const data=await r.json();return out({access_token:data.access_token});
 }
 // Only a verified current Super Admin can provision other accounts.
 const token=(req.headers.get('authorization')||'').replace(/^Bearer /,'');
 if(!token)return out({error:'Access denied'},403);
 const user=await call('/auth/v1/user','GET',undefined,token,pub);
 const owner=await call('/rest/v1/gl_team?user_id=eq.'+q(user.id)+'&active=eq.true&role=eq.super_admin&select=user_id');
 if(owner.length!==1)return out({error:'Access denied'},403);
 if(b.action==='list')return out({ok:true,accounts:await call(table+'?select=email,username,display_name,role,user_id,activated_at,expires_at&order=created_at.desc')});
 if(b.action==='approve'){
  const name=String(b.display_name||'').trim(),role=String(b.role||'');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||!/^[a-z0-9_]{3,32}$/.test(username)||!name||name.length>120||!['admin','media','welfare','pastor','viewer','super_admin'].includes(role)||b.verified!==true)return out({error:'Check details and confirm identity verification'},400);
  const existing=await call(table+'?or=(email.eq.'+q(email)+',username.eq.'+q(username)+')&select=email');
  if(existing.length)return out({error:'Email or username already enrolled. Use reissue for an unfinished account.'},409);
  // Reserve the email/username before creating an Auth account.
  const reserved=await call(table,'POST',{email,username,display_name:name,role});
  if(!reserved?.length)throw Error('Reservation failed');
  let createdId='';
  try{
   const created=await call('/auth/v1/admin/users','POST',{email,password:random(),email_confirm:true});
   createdId=created.id;if(!createdId)throw Error('Creation failed');
   await call('/rest/v1/gl_team','POST',{user_id:createdId,display_name:name,role,active:true});
   const code=random();
   await call(table+'?email=eq.'+q(email),'PATCH',{user_id:createdId,activation_hash:await hash(code),expires_at:new Date(Date.now()+3600000).toISOString()});
   await call('/rest/v1/gl_activity','POST',{actor:user.id,action:'account_approved',target:createdId});
   return out({ok:true,code});
  }catch{
   // No password was disclosed. Do not delete an Auth account automatically.
   if(!createdId)await call(table+'?email=eq.'+q(email),'DELETE').catch(()=>{});
   return out({error:'Approval could not finish. Ask the project owner to inspect the pending record.'},409);
  }
 }
 if(b.action==='reissue'){
  const found=await call(table+'?email=eq.'+q(email)+'&activated_at=is.null&select=user_id');
  if(found.length!==1||!found[0].user_id)return out({error:'No pending account found'},400);
  const active=await call('/rest/v1/gl_team?user_id=eq.'+q(found[0].user_id)+'&active=eq.true&select=user_id');
  if(!active.length)return out({error:'Account suspended'},403);
  const code=random();
  const updated=await call(table+'?email=eq.'+q(email)+'&activated_at=is.null','PATCH',{activation_hash:await hash(code),expires_at:new Date(Date.now()+3600000).toISOString()});
  if(updated.length!==1)return out({error:'Account already activated'},409);
  return out({ok:true,code});
 }
 return out({error:'Unknown operation'},400);
 }catch{return out({error:'Unable to complete this request'},400)}
});