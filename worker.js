// Higher Place Church Volunteer Tool: shared events, RSVPs, reminders, cloud backup. Cloudflare Workers + D1.
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json'}});
let ready;
const init=db=>ready||(ready=db.batch([
 'CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,owner TEXT NOT NULL,data TEXT NOT NULL,img TEXT,status TEXT,updated INTEGER)',
 'CREATE TABLE IF NOT EXISTS rsvps(id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,name TEXT NOT NULL COLLATE NOCASE,resp TEXT NOT NULL,comment TEXT,act TEXT,t INTEGER,UNIQUE(event_id,name))',
 'CREATE TABLE IF NOT EXISTS notify(event_id TEXT PRIMARY KEY,emails TEXT)',
 'CREATE TABLE IF NOT EXISTS reminders(id TEXT PRIMARY KEY,owner TEXT NOT NULL,send_at INTEGER,subject TEXT,body TEXT,rcpt TEXT,ev TEXT,mode TEXT,sent INTEGER DEFAULT 0)',
 'CREATE TABLE IF NOT EXISTS vault(owner TEXT PRIMARY KEY,blob TEXT,updated INTEGER)',
 'CREATE TABLE IF NOT EXISTS hits(k TEXT PRIMARY KEY,n INTEGER)',
 'CREATE TABLE IF NOT EXISTS staff(id TEXT PRIMARY KEY COLLATE NOCASE,name TEXT,role TEXT,salt TEXT,hash TEXT,created INTEGER)',
 'CREATE TABLE IF NOT EXISTS sessions(t TEXT PRIMARY KEY,sid TEXT,role TEXT,exp INTEGER)',
 'CREATE TABLE IF NOT EXISTS members(id TEXT PRIMARY KEY,name TEXT,email TEXT,phone TEXT,role TEXT,grp TEXT,created INTEGER)',
 'CREATE TABLE IF NOT EXISTS groups(id TEXT PRIMARY KEY,name TEXT)',
 'CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT)',
 'CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT,note TEXT,t INTEGER,done INTEGER DEFAULT 0)',
 'CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,code TEXT,payload TEXT,exp INTEGER,tries INTEGER)',
 'CREATE TABLE IF NOT EXISTS avail_msgs(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,msg TEXT,t INTEGER,to_id TEXT,ev TEXT)',
 'CREATE TABLE IF NOT EXISTS avail_log(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,msg TEXT,t INTEGER)'].map(q=>db.prepare(q))));
const sha=async s=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))].map(b=>b.toString(16).padStart(2,'0')).join('');
const clip=(v,n)=>String(v==null?'':v).slice(0,n);
const b2h=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>b2h(crypto.getRandomValues(new Uint8Array(n)));
async function hashPw(pw,salt){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);return b2h(await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:10000,hash:'SHA-256'},k,256))}
const ALPH='abcdefghjkmnpqrstuvwxyz23456789',genPw=()=>Array.from(crypto.getRandomValues(new Uint8Array(12)),b=>ALPH[b%ALPH.length]).join('');
async function auth(req,db){const h=req.headers.get('authorization')||'';if(!h.startsWith('Bearer '))return null;const r=await db.prepare('SELECT sid,role,exp FROM sessions WHERE t=?').bind(await sha(h.slice(7))).first();return r&&r.exp>Date.now()?{id:r.sid,role:r.role}:null}
async function session(db,id,role,name){const t=rnd(24);await db.prepare('INSERT INTO sessions(t,sid,role,exp) VALUES(?,?,?,?)').bind(await sha(t),id,role,Date.now()+2592000000).run();db.prepare('DELETE FROM sessions WHERE exp<?').bind(Date.now()).run();return{token:t,id,role,name}}
async function limit(db,req,tag,max){const k=await sha(tag+(req.headers.get('cf-connecting-ip')||'')+Math.floor(Date.now()/3600000)),h=await db.prepare('INSERT INTO hits(k,n) VALUES(?,1) ON CONFLICT(k) DO UPDATE SET n=n+1 RETURNING n').bind(k).first();return !!h&&h.n>max}
const ADMIN_MAIL=env=>env.ADMIN_EMAIL||'digitalforchrist.team@gmail.com';
const maskMail=e=>e.replace(/^(.{2}).*(@.*)$/,'$1•••••$2');
async function startChallenge(env,db,req,payload,subject){if(!mailOn(env))return{err:'mail'};if(await limit(db,req,'C',6))return{err:'slow'};const code=String(100000+crypto.getRandomValues(new Uint32Array(1))[0]%900000),id=rnd(6);await db.prepare('INSERT INTO challenges(id,code,payload,exp,tries) VALUES(?,?,?,?,0)').bind(id,await sha('c:'+id+code),JSON.stringify(payload),Date.now()+600000,).run();const ok=await mail(env,ADMIN_MAIL(env),subject,'Your Higher Place verification code is '+code+'. It expires in 10 minutes. If you did not ask for this, please ignore this email.');return ok?{id}:{err:'mail'}}
async function checkChallenge(db,id,code){const r=await db.prepare('SELECT * FROM challenges WHERE id=?').bind(clip(id,12)).first();if(!r||r.exp<Date.now()||r.tries>=5)return null;if(r.code!==await sha('c:'+r.id+String(code||'').trim())){await db.prepare('UPDATE challenges SET tries=tries+1 WHERE id=?').bind(r.id).run();return null}await db.prepare('DELETE FROM challenges WHERE id=?').bind(r.id).run();return JSON.parse(r.payload)}
const setting=async(db,k)=>{const r=await db.prepare('SELECT v FROM settings WHERE k=?').bind(k).first();return r?r.v:''};
const setSet=(db,k,v)=>db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind(k,v).run();
const isMail=e=>/^\S+@\S+\.\S+$/.test(String(e||''));
const mailOn=e=>!!(e.BREVO_KEY&&e.MAIL_FROM);
async function mail(env,to,subject,text){if(!mailOn(env)||!to)return false;try{const r=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':env.BREVO_KEY,'content-type':'application/json'},body:JSON.stringify({sender:{email:env.MAIL_FROM,name:'Higher Place Church Volunteer Tool'},to:[{email:to}],subject:clip(subject,150),textContent:clip(text,4000)})});return r.ok}catch(e){return false}}
const pub=d=>({n:clip(d.n,120),d:clip(d.d,20),v:clip(d.v,160),ds:clip(d.ds,2000),rc:clip(d.rc,30),c:['event','project','activity'].includes(d.c)?d.c:'event',w:clip(d.w,25),st:['draft','published','cancelled','completed'].includes(d.st)?d.st:'draft',
 a:(Array.isArray(d.a)?d.a:[]).slice(0,60).map(a=>[clip(a[0],40),clip(a[1],120),clip(a[2],5),clip(a[3],5),clip(a[4],400),Math.max(0,Math.min(500,+a[5]||0)),clip(a[6],80),(Array.isArray(a[7])?a[7]:[]).slice(0,12).map(r=>[clip(r[0],20),clip(r[1],80),Math.max(1,Math.min(500,+r[2]||1))])])});
async function counts(db,ids){const o={};if(!ids.length)return o;const q=await db.prepare(`SELECT event_id e,act a,COUNT(*) c FROM rsvps WHERE resp='yes' AND event_id IN (${ids.map(()=>'?').join(',')}) GROUP BY event_id,act`).bind(...ids).all();q.results.forEach(r=>{(o[r.e]=o[r.e]||{})[r.a]=r.c});return o}
async function owner(me,db,id){if(!me)return false;if(me.role==='admin')return true;const o=await db.prepare('SELECT owner FROM events WHERE id=?').bind(id).first();return !!o&&o.owner===me.id}
async function runReminders(env){await init(env.DB);const db=env.DB,due=await db.prepare('SELECT * FROM reminders WHERE sent=0 AND send_at<=? LIMIT 10').bind(Date.now()).all();
 for(const r of due.results){let to=JSON.parse(r.rcpt||'[]');if(r.mode==='pending'&&r.ev){const d=await db.prepare('SELECT name FROM rsvps WHERE event_id=?').bind(r.ev).all(),s=new Set(d.results.map(x=>x.name.toLowerCase()));to=to.filter(p=>!s.has(String(p.n).toLowerCase()))}
  let ok=0;for(const p of to.slice(0,60)){if(await mail(env,p.e,r.subject,'Hi '+clip(p.n,40).split(' ')[0]+',\n\n'+r.body))ok++}
  if(ok||!to.length)await db.prepare('UPDATE reminders SET sent=1 WHERE id=?').bind(r.id).run()}}
export default{
 async scheduled(ev,env,ctx){ctx.waitUntil(runReminders(env))},
 async fetch(req,env,ctx){
 const u=new URL(req.url),p=u.pathname;
 if(!p.startsWith('/api/'))return env.ASSETS.fetch(req);
 if(!env.DB)return J({error:'no-db'},503);
 try{await init(env.DB);const db=env.DB,m=req.method,key=req.headers.get('x-key')||'';let x;
  if(p==='/api/status')return J({db:true,mail:mailOn(env)});
  const me=await auth(req,db),body=async()=>{try{return await req.json()}catch(e){return{}}};
  if(p==='/api/state'){const c=await db.prepare('SELECT COUNT(*) c FROM staff').first();return J({setup:c.c>0,wa:await setting(db,'wa'),mail:mailOn(env),noph:!!await setting(db,'noph')})}
  if(p==='/api/setup'&&m==='POST'){const b=await body();
   if(!b.challenge){const c=await startChallenge(env,db,req,{op:'setup',name:clip(b.name,60).trim()||'Admin'},'Verify admin sign-in setup');if(c.err)return J({error:c.err},c.err==='slow'?429:503);return J({challenge:c.id,to:maskMail(ADMIN_MAIL(env))})}
   const pw=String(b.pw||'');if(pw.length<10)return J({error:'short'},400);const pl=await checkChallenge(db,b.challenge,b.code);if(!pl||pl.op!=='setup')return J({error:'code'},403);const salt=rnd(8);
   await db.prepare("INSERT INTO staff(id,name,role,salt,hash,created) VALUES('admin',?,'admin',?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,salt=excluded.salt,hash=excluded.hash").bind(pl.name,salt,await hashPw(pw,salt),Date.now()).run();await db.prepare("DELETE FROM sessions WHERE sid='admin'").run();return J(await session(db,'admin','admin',pl.name))}
  if(p==='/api/login'&&m==='POST'){if(await limit(db,req,'L',12))return J({error:'slow'},429);const b=await body(),s=await db.prepare('SELECT * FROM staff WHERE id=?').bind(clip(b.id,30).trim()).first();if(!s||s.hash!==await hashPw(String(b.pw||''),s.salt))return J({error:'bad'},401);return J(await session(db,s.id,s.role,s.name))}
  if(p==='/api/logout'&&m==='POST'){const h=req.headers.get('authorization')||'';if(h.startsWith('Bearer '))await db.prepare('DELETE FROM sessions WHERE t=?').bind(await sha(h.slice(7))).run();return J({ok:true})}
  if(p==='/api/me')return me?J(me):J({error:'auth'},401);
  if(p==='/api/staff'){if(!me||me.role!=='admin')return J({error:'forbidden'},403);if(m==='GET'){const r=await db.prepare("SELECT id,name,created FROM staff WHERE role='leader' ORDER BY created DESC").all();return J(r.results)}
   const b=await body();
   if(!b.challenge){if(!['new','reset','del'].includes(b.op)||(b.op==='new'&&!clip(b.name,60).trim()))return J({error:'bad'},400);const c=await startChallenge(env,db,req,{op:b.op,name:clip(b.name,60).trim(),id:clip(b.id,30)},'Verify: '+({new:'appoint a leader',reset:'reset a leader password',del:'remove a leader'})[b.op]);if(c.err)return J({error:c.err},c.err==='slow'?429:503);return J({challenge:c.id,to:maskMail(ADMIN_MAIL(env))})}
   const pl=await checkChallenge(db,b.challenge,b.code);if(!pl)return J({error:'code'},403);
   if(pl.op==='del'){await db.prepare("DELETE FROM staff WHERE id=? AND role='leader'").bind(pl.id).run();await db.prepare('DELETE FROM sessions WHERE sid=?').bind(pl.id).run();return J({ok:true})}
   const pw=genPw(),salt=rnd(8);if(pl.op==='reset'){await db.prepare("UPDATE staff SET salt=?,hash=? WHERE id=? AND role='leader'").bind(salt,await hashPw(pw,salt),pl.id).run();await db.prepare('DELETE FROM sessions WHERE sid=?').bind(pl.id).run();return J({id:pl.id,pw})}
   let id='';for(let i=0;i<6;i++){id='HP-'+(1000+Math.floor(Math.random()*9000));if(!await db.prepare('SELECT 1 x FROM staff WHERE id=?').bind(id).first())break}
   await db.prepare("INSERT INTO staff(id,name,role,salt,hash,created) VALUES(?,?,'leader',?,?,?)").bind(id,pl.name,salt,await hashPw(pw,salt),Date.now()).run();return J({id,pw,name:pl.name})}
  if(p==='/api/leaders'){const r=await db.prepare("SELECT id,name FROM staff WHERE role='leader' ORDER BY name").all();return J(await Promise.all(r.results.map(async x=>({pid:(await sha(x.id+':p')).slice(0,10),name:x.name}))))}
  if(p==='/api/settings'){if(!me||me.role!=='admin')return J({error:'forbidden'},403);if(m==='GET')return J({admin_email:await setting(db,'admin_email'),wa:await setting(db,'wa'),tpw:!!await setting(db,'tpw')});const b=await body();if('admin_email' in b)await setSet(db,'admin_email',isMail(b.admin_email)?b.admin_email:'');if('wa' in b)await setSet(db,'wa',clip(b.wa,25));if('noph' in b)await setSet(db,'noph',b.noph?'1':'');if(b.teampass!==undefined){const t=String(b.teampass);if(t&&t.length<6)return J({error:'short'},400);await setSet(db,'tpw',t?await sha('tp:'+t):'')}return J({ok:true})}
  if(p==='/api/members'||p==='/api/groups'){const gm=p==='/api/members';
   if(m==='GET'){let ok=!!me;if(!ok){const tp=req.headers.get('x-team-pass')||'',s=await setting(db,'tpw');ok=!!s&&!!tp&&s===await sha('tp:'+tp)}if(!ok)return J({error:'locked'},401);
    if(!gm){const r=await db.prepare('SELECT id,name FROM groups ORDER BY name COLLATE NOCASE').all();return J(r.results)}
    const r=await db.prepare('SELECT id,name,email,phone,role,grp FROM members ORDER BY name COLLATE NOCASE').all();return J(r.results.map(o=>me?o:{id:o.id,name:o.name,role:o.role,grp:o.grp}))}
   if(!me)return J({error:'forbidden'},403);const b=await body();
   if(b.del){await db.prepare(gm?'DELETE FROM members WHERE id=?':'DELETE FROM groups WHERE id=?').bind(clip(b.id,20)).run();if(!gm)await db.prepare("UPDATE members SET grp='' WHERE grp=?").bind(clip(b.id,20)).run();return J({ok:true})}
   if(!gm){const nm=clip(b.name,60).trim();if(!nm)return J({error:'bad'},400);const id=rnd(4);await db.prepare('INSERT INTO groups(id,name) VALUES(?,?)').bind(id,nm).run();return J({id})}
   const nm=clip(b.name,80).trim();if(!nm||!isMail(b.email))return J({error:'bad'},400);const id=/^\w{4,20}$/.test(b.id||'')?b.id:rnd(5);
   await db.prepare('INSERT INTO members(id,name,email,phone,role,grp,created) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,email=excluded.email,phone=excluded.phone,role=excluded.role,grp=excluded.grp').bind(id,nm,clip(b.email,120),clip(b.phone,25),b.role==='group leader'&&me.role==='admin'?'group leader':'volunteer',clip(b.grp,20),Date.now()).run();return J({id})}
  if(p==='/api/access-request'&&m==='POST'){if(await limit(db,req,'A',5))return J({error:'slow'},429);const b=await body(),nm=clip(b.name,80).trim();if(!nm||!isMail(b.email))return J({error:'bad'},400);await db.prepare('INSERT INTO requests(name,email,note,t) VALUES(?,?,?,?)').bind(nm,clip(b.email,120),clip(b.note,300),Date.now()).run();const a=await setting(db,'admin_email');if(a)ctx.waitUntil(mail(env,a,'Team directory access request: '+nm,nm+' ('+b.email+') asked for the team password.\n'+clip(b.note,300)));return J({ok:true})}
  if(p==='/api/requests'){if(!me||me.role!=='admin')return J({error:'forbidden'},403);if(m==='POST'){const b=await body();await db.prepare('UPDATE requests SET done=1 WHERE id=?').bind(+b.id||0).run();return J({ok:true})}const r=await db.prepare('SELECT id,name,email,note,t FROM requests WHERE done=0 ORDER BY id DESC LIMIT 30').all();return J(r.results)}
  if(p==='/api/avail'){if(m==='POST'){if(await limit(db,req,'V',20))return J({error:'slow'},429);const b=await body(),nm=clip(b.n,80).trim(),t=clip(b.msg,300);if(!nm)return J({error:'bad'},400);let to='admin',evn='';
    if(b.ev&&/^\w+$/.test(b.ev)){const e=await db.prepare('SELECT owner,data FROM events WHERE id=?').bind(b.ev).first();if(e){to=e.owner;evn=JSON.parse(e.data).n}}
    else if(b.to&&b.to!=='admin'){const r=await db.prepare("SELECT id FROM staff WHERE role='leader'").all();for(const x of r.results)if((await sha(x.id+':p')).slice(0,10)===b.to)to=x.id}
    await db.prepare('INSERT INTO avail_msgs(name,msg,t,to_id,ev) VALUES(?,?,?,?,?)').bind(nm,t,Date.now(),to,evn).run();ctx.waitUntil(mail(env,ADMIN_MAIL(env),'Availability from '+nm+(evn?' for '+evn:''),t));return J({ok:true,wa:await setting(db,'wa')})}
   if(!me)return J({error:'forbidden'},403);const r=me.role==='admin'?await db.prepare('SELECT name,msg,t,ev FROM avail_msgs ORDER BY id DESC LIMIT 30').all():await db.prepare('SELECT name,msg,t,ev FROM avail_msgs WHERE to_id=? ORDER BY id DESC LIMIT 30').bind(me.id).all();return J(r.results)}
  if(p==='/api/events'&&m==='GET'){const r=await db.prepare("SELECT id,data,(img IS NOT NULL AND img!='') hi FROM events WHERE status IN ('published','completed') ORDER BY updated DESC LIMIT 100").all();const y=await counts(db,r.results.map(e=>e.id));return J(r.results.map(e=>({id:e.id,data:JSON.parse(e.data),hi:e.hi,y:y[e.id]||{}})))}
  if(p==='/api/events'&&m==='POST'){const b=await req.json();if(!me)return J({error:'auth'},401);if(!b.data)return J({error:'bad'},400);const d=pub(b.data),k=me.id,now=Date.now(),hasImg=typeof b.img==='string'&&b.img.startsWith('data:image/jpeg;base64,')&&b.img.length<400000,em=(Array.isArray(b.notify)?b.notify:[]).filter(e=>/^\S+@\S+\.\S+$/.test(e)).slice(0,5);
   let id=b.id&&/^\w+$/.test(b.id)?b.id:'';if(id){const o=await db.prepare('SELECT owner FROM events WHERE id=?').bind(id).first();if(o&&o.owner!==k&&me.role!=='admin')return J({error:'forbidden'},403);if(o){await db.prepare('UPDATE events SET data=?,status=?,updated=? WHERE id=?').bind(JSON.stringify(d),d.st,now,id).run();if(hasImg||b.img==='')await db.prepare('UPDATE events SET img=? WHERE id=?').bind(hasImg?b.img:'',id).run()}else id=''}
   if(!id){id=crypto.randomUUID().replace(/-/g,'').slice(0,10);await db.prepare('INSERT INTO events(id,owner,data,img,status,updated) VALUES(?,?,?,?,?,?)').bind(id,k,JSON.stringify(d),hasImg?b.img:'',d.st,now).run()}
   await db.prepare('INSERT INTO notify(event_id,emails) VALUES(?,?) ON CONFLICT(event_id) DO UPDATE SET emails=excluded.emails').bind(id,JSON.stringify(em)).run();return J({id})}
  if(p==='/api/mine'&&m==='GET'){if(!me)return J({error:'auth'},401);const r=me.role==='admin'?await db.prepare("SELECT id,(img IS NOT NULL AND img!='') hi FROM events").all():await db.prepare("SELECT id,(img IS NOT NULL AND img!='') hi FROM events WHERE owner=?").bind(me.id).all();return J(r.results)}
  if(p==='/api/vault'&&key.length>=16){const k=await sha(key);if(m==='GET'){const r=await db.prepare('SELECT blob FROM vault WHERE owner=?').bind(k).first();return r?new Response(r.blob,{headers:{'content-type':'application/json'}}):J({error:'notfound'},404)}
   if(m==='PUT'){const t=await req.text();if(t.length>1500000)return J({error:'toobig'},413);await db.prepare('INSERT INTO vault(owner,blob,updated) VALUES(?,?,?) ON CONFLICT(owner) DO UPDATE SET blob=excluded.blob,updated=excluded.updated').bind(k,t,Date.now()).run();return J({ok:true})}}
  if(p==='/api/reminders'){if(!me)return J({error:'auth'},401);const k=me.id;
   if(m==='GET'){const r=await db.prepare('SELECT id,sent FROM reminders WHERE owner=?').bind(k).all();return J(r.results)}
   if(m==='POST'){const b=await req.json(),id=clip(b.id,40);if(!/^\w+$/.test(id))return J({error:'bad'},400);const o=await db.prepare('SELECT owner FROM reminders WHERE id=?').bind(id).first();if(o&&o.owner!==k)return J({error:'forbidden'},403);
    if(b.del){await db.prepare('DELETE FROM reminders WHERE id=?').bind(id).run();return J({ok:true})}
    const at=Date.parse(b.at);if(!at)return J({error:'bad'},400);const rc=(Array.isArray(b.rcpt)?b.rcpt:[]).filter(e=>/^\S+@\S+\.\S+$/.test(e.e)).slice(0,100).map(e=>({n:clip(e.n,60),e:clip(e.e,120)}));
    await db.prepare('INSERT INTO reminders(id,owner,send_at,subject,body,rcpt,ev,mode,sent) VALUES(?,?,?,?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET send_at=excluded.send_at,subject=excluded.subject,body=excluded.body,rcpt=excluded.rcpt,ev=excluded.ev,mode=excluded.mode').bind(id,k,at,clip(b.subject,150),clip(b.body,1500),JSON.stringify(rc),clip(b.ev,20),b.mode==='pending'?'pending':'all').run();return J({ok:true})}}
  if(x=p.match(/^\/api\/img\/(\w+)$/)){const r=await db.prepare('SELECT img FROM events WHERE id=?').bind(x[1]).first();if(!r||!r.img)return new Response('',{status:404});return new Response(Uint8Array.from(atob(r.img.split(',')[1]),c=>c.charCodeAt(0)),{headers:{'content-type':'image/jpeg','cache-control':'public,max-age=300'}})}
  if(x=p.match(/^\/api\/events\/(\w+)$/)){if(m!=='GET')return J({error:'method'},405);const r=await db.prepare("SELECT id,data,(img IS NOT NULL AND img!='') hi FROM events WHERE id=? AND status!='draft'").bind(x[1]).first();if(!r)return J({error:'notfound'},404);const y=await counts(db,[r.id]);return J({id:r.id,data:JSON.parse(r.data),hi:r.hi,y:y[r.id]||{}})}
  if(x=p.match(/^\/api\/events\/(\w+)\/rsvp$/)&&m==='POST'){const id=x[1],b=await req.json(),e=await db.prepare('SELECT data,status FROM events WHERE id=?').bind(id).first();
   if(!e||e.status!=='published')return J({error:'closed'},403);const d=JSON.parse(e.data);if(d.rc&&Date.now()>Date.parse(d.rc))return J({error:'deadline'},403);
   const n=clip(b.n,80).trim(),r=b.r==='yes'?'yes':b.r==='no'?'no':'';if(!n||!r)return J({error:'bad'},400);
   const hk=await sha((req.headers.get('cf-connecting-ip')||'')+Math.floor(Date.now()/3600000)),h=await db.prepare('INSERT INTO hits(k,n) VALUES(?,1) ON CONFLICT(k) DO UPDATE SET n=n+1 RETURNING n').bind(hk).first();if(h&&h.n>40)return J({error:'slow-down'},429);
   const c=await db.prepare('SELECT COUNT(*) c FROM rsvps WHERE event_id=?').bind(id).first();if(c.c>=1500)return J({error:'full'},429);const cm=clip(b.c,500);
   await db.prepare('INSERT INTO rsvps(event_id,name,resp,comment,act,t) VALUES(?,?,?,?,?,?) ON CONFLICT(event_id,name) DO UPDATE SET resp=excluded.resp,comment=excluded.comment,act=excluded.act,t=excluded.t').bind(id,n,r,cm,clip(b.a,40),Date.now()).run();
   if(isMail(b.e))ctx.waitUntil(mail(env,b.e,'You are signed up: '+d.n,'Thank you, '+n+'! We have recorded your answer ('+r.toUpperCase()+') for '+d.n+'. Higher Place Church'));const nt=await db.prepare('SELECT emails FROM notify WHERE event_id=?').bind(id).first();if(nt)ctx.waitUntil(Promise.all(JSON.parse(nt.emails).map(a=>mail(env,a,'RSVP: '+n+' says '+r.toUpperCase()+' for '+d.n,n+' says '+r.toUpperCase()+' for '+d.n+(cm?'\nComment: '+cm:'')))));return J({ok:true})}
  if(x=p.match(/^\/api\/events\/(\w+)\/rsvps$/)&&m==='GET'){if(!await owner(me,db,x[1]))return J({error:'forbidden'},403);const r=await db.prepare('SELECT id,name n,resp r,comment c,act a,t FROM rsvps WHERE event_id=? ORDER BY id').bind(x[1]).all();return J(r.results)}
  return J({error:'notfound'},404)
 }catch(e){return J({error:'server'},500)}}};
