import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
process.env.DATABASE_URL=execFileSync('npx',['--yes','neonctl','connection-string','main','--project-id','calm-rain-40269954','--pooled'],{encoding:'utf8',env:{...process.env,npm_config_cache:'/private/tmp/pixel-pulse-npm-cache'},stdio:['ignore','pipe','pipe']}).trim();
process.env.BETTER_AUTH_SECRET=randomBytes(48).toString('base64url');
const {ensureAuthReady,ORIGIN}=await import('../lib/auth.js');
const {default:link}=await import('../api/link.js');
const {auth,pool}=await ensureAuthReady();
const prefix=`test_${randomBytes(8).toString('hex')}`,ids=[randomUUID(),randomUUID()],legacyIds=[randomUUID(),randomUUID()];
const nativeFetch=globalThis.fetch, originalGetSession=auth.api.getSession;
let activeId=ids[0],proof='valid',checks=0;
async function invoke({method='POST',origin=ORIGIN,body={legacyAccessToken:'owned-test-proof'}}={}){
  let result='';const res={headers:{},setHeader(n,v){this.headers[n]=v},end(s=''){result=s}};
  await link({method,headers:{origin,'content-type':'application/json'},body},res);
  return {status:res.statusCode,body:result?JSON.parse(result):null};
}
try{
  for(let i=0;i<ids.length;i++)await pool.query('INSERT INTO "user"(id,name,email,"emailVerified","createdAt","updatedAt",username) VALUES($1,$2,$3,false,NOW(),NOW(),$2)',[ids[i],`${prefix}_${i}`,`${prefix}_${i}@example.invalid`]);
  auth.api.getSession=async()=>activeId?{user:{id:activeId,name:prefix,username:prefix}}:null;
  globalThis.fetch=async(url,options)=>{
    assert.equal(String(url),'https://sfvnmmcmobnoslkmmknb.supabase.co/auth/v1/user');
    assert.equal(options.headers.Authorization,'Bearer owned-test-proof');
    if(proof==='down')throw new Error('Legacy service unavailable');
    if(proof==='invalid')return new Response('{}',{status:401});
    return Response.json({id:proof==='second'?legacyIds[1]:legacyIds[0],email:`${prefix}@example.invalid`});
  };
  assert.equal((await invoke({origin:'https://evil.example'})).status,403);checks++;
  assert.equal((await invoke({method:'DELETE'})).status,405);checks++;
  activeId=null;assert.equal((await invoke()).status,401);checks++;activeId=ids[0];
  assert.equal((await invoke({body:{email:`${prefix}@example.invalid`}})).status,400);checks++;
  proof='invalid';assert.equal((await invoke()).status,401);checks++;
  assert.equal((await pool.query('SELECT * FROM triad_legacy_links WHERE user_id=ANY($1)',[ids])).rowCount,0);checks++;
  proof='down';assert.equal((await invoke()).status,503);checks++;
  proof='valid';assert.equal((await invoke()).status,200);assert.equal((await invoke()).status,200);checks+=2;
  assert.equal((await invoke({method:'GET'})).body.linked,true);checks++;
  activeId=ids[1];assert.equal((await invoke()).status,409);checks++;
  activeId=ids[0];proof='second';assert.equal((await invoke()).status,409);checks++;
  const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
  for(const [,script]of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))if(script.trim())new vm.Script(script);
  assert.ok(html.includes("localStorage.getItem('triadCustomMap')"));
  assert.ok(html.includes('CONTINUE WITH PIXEL PULSE'));checks+=2;
  console.log(JSON.stringify({passed:true,checks,coverage:'strict origins, independent proof, no email-only links, unavailable legacy service, unique bidirectional bindings, idempotency, retained game syntax/maps'}));
}finally{
  globalThis.fetch=nativeFetch;auth.api.getSession=originalGetSession;
  await pool.query('DELETE FROM "user" WHERE id=ANY($1) AND email LIKE $2',[ids,`${prefix}%@example.invalid`]);
  await pool.end();console.log('Exact synthetic Triad test identities removed.');
}
