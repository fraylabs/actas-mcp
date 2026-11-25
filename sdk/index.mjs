// ActAs SDK: identity, inbox codes and vault logins for agents.
// Every call goes to the ActAs API; the server enforces scopes and grants.
import {readFile} from 'node:fs/promises';

export class ActAsError extends Error {
 constructor(message,{status=0,code='actas_error',state='failed'}={}){super(message);this.name=new.target.name;this.status=status;this.code=code;this.state=state;}
}
// state 'pending': not finished yet (code not arrived, mailbox or domain still pending). Safe to wait and retry.
export class ActAsPendingError extends ActAsError {constructor(message,opts={}){super(message,{...opts,state:'pending'});}}
// state 'failed': the request was refused or broke. Do not retry blindly.
export class ActAsFailedError extends ActAsError {constructor(message,opts={}){super(message,{...opts,state:'failed'});}}
export class AuthError extends ActAsFailedError {}
export class PermissionError extends ActAsFailedError {}
export class NotFoundError extends ActAsFailedError {}
export class CodePendingError extends ActAsPendingError {}
export class InboxNotVerifiedError extends ActAsPendingError {}

const PENDING_CODES=new Set(['mail_not_ready','domain_not_ready','email_not_live']);
function errorFor(status,code,message){
 if(PENDING_CODES.has(code))return code==='email_not_live'?new InboxNotVerifiedError(message,{status,code}):new ActAsPendingError(message,{status,code});
 if(status===401)return new AuthError(message,{status,code});
 if(status===403)return new PermissionError(message,{status,code});
 if(status===404)return new NotFoundError(message,{status,code});
 return new ActAsFailedError(message,{status,code});
}
function connectionFrom(value){
 if(!value||typeof value!=='object'||typeof value.token!=='string'||!value.token)throw new ActAsFailedError('An ActAs connection needs apiUrl and token.',{code:'invalid_connection'});
 const url=new URL(value.apiUrl);
 if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))))throw new ActAsFailedError('ActAs connections need HTTPS (or localhost for the sandbox).',{code:'invalid_connection'});
 return {...value,apiUrl:url.origin};
}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

export class ActAs {
 #connections;#scopes=new Map();#fetch;
 /** One connection, or several (e.g. an inbox-codes connection plus a vault connection). */
 constructor(connections,{fetch:fetchImpl=globalThis.fetch}={}){
  this.#connections=(Array.isArray(connections)?connections:[connections]).map(connectionFrom);
  if(!this.#connections.length)throw new ActAsFailedError('Pass at least one connection.',{code:'invalid_connection'});
  this.#fetch=fetchImpl;
  this.identity={create:o=>this.#createIdentity(o),get:id=>this.#request(this.#pick(),'/identities/'+encodeURIComponent(id)),connect:(id,o)=>this.#connectIdentity(id,o)};
  this.inbox={waitForCode:o=>this.#waitForCode(o)};
  this.messages={search:({inboxId,...query})=>{const params=new URLSearchParams();for(const [k,v]of Object.entries(query))if(v!==undefined)params.set(k,String(v));return this.#request(this.#pick('emails:read',inboxId),'/emails/'+encodeURIComponent(inboxId)+'/messages/search?'+params);},
   getLabels:({inboxId,messageId})=>this.#request(this.#pick('emails:read',inboxId),'/emails/'+encodeURIComponent(inboxId)+'/messages/'+encodeURIComponent(messageId)+'/labels'),
   setLabels:({inboxId,messageId,userLabels})=>this.#request(this.#pick('resources:write',inboxId),'/emails/'+encodeURIComponent(inboxId)+'/messages/'+encodeURIComponent(messageId)+'/labels','PUT',{userLabels})};
  this.attachments={list:({inboxId,messageId})=>this.#request(this.#pick('emails:read',inboxId),'/emails/'+encodeURIComponent(inboxId)+'/messages/'+encodeURIComponent(messageId)+'/attachments'),
   download:({inboxId,messageId,attachmentId,maxBytes=5242880})=>this.#request(this.#pick('emails:read',inboxId),'/emails/'+encodeURIComponent(inboxId)+'/messages/'+encodeURIComponent(messageId)+'/attachments/'+encodeURIComponent(attachmentId)+'/download?encoding=base64&maxBytes='+encodeURIComponent(maxBytes))};
  this.delivery={waitFor:({resourceId,cursor,timeoutMs=30000,kind='email'})=>this.#request(this.#deliveryConnection(resourceId,kind),'/resources/'+encodeURIComponent(resourceId)+'/events/wait','POST',{...(cursor===undefined?{}:{cursor}),timeoutMs},{timeoutMs:timeoutMs+15000}),
   subscribe:({resourceId,endpoint,kind='email'})=>this.#request(this.#deliveryConnection(resourceId,kind),'/resources/'+encodeURIComponent(resourceId)+'/webhooks','POST',{endpoint}),
   list:({resourceId,kind='email'})=>this.#request(this.#deliveryConnection(resourceId,kind),'/resources/'+encodeURIComponent(resourceId)+'/webhooks'),
   revoke:({resourceId,webhookId,kind='email'})=>this.#request(this.#deliveryConnection(resourceId,kind),'/resources/'+encodeURIComponent(resourceId)+'/webhooks/'+encodeURIComponent(webhookId),'DELETE'),
   deliveries:({resourceId,webhookId,kind='email'})=>this.#request(this.#deliveryConnection(resourceId,kind),'/resources/'+encodeURIComponent(resourceId)+'/webhooks/'+encodeURIComponent(webhookId)+'/deliveries')};
  this.passkeys={register:(path,options)=>this.#passkey('register',path,options),sign:(path,options)=>this.#passkey('sign',path,options)};
  this.vault={login:p=>this.#login(p),saveLogin:(p,item,o)=>this.#saveLogin(p,item,o),grant:o=>this.#grant(o)};
 }
 /** Read connection file(s) such as the ones the dashboard or sandbox writes. */
 static async fromFile(...files){
  const list=files.length?files:[process.env.ACTAS_CONNECTION_FILE];
  if(list.some(f=>!f))throw new ActAsFailedError('Set ACTAS_CONNECTION_FILE or pass a connection file path.',{code:'invalid_connection'});
  return new ActAs(await Promise.all(list.map(async f=>JSON.parse(await readFile(f,'utf8')))));
 }
 // Prefer the connection issued for this scope/resource; otherwise the first.
 #pick(scope,resourceId){
  return this.#connections.find(c=>scope&&c.scopes?.includes(scope)&&(!resourceId||c.resourceIds?.includes(resourceId)||c.resourceIds?.includes('*')))??this.#connections.find(c=>!c.scopes||!scope)??this.#connections[0];
 }
 async #request(connection,route,method='GET',body,{timeoutMs=15000}={}){
  let response;
  try{response=await this.#fetch(connection.apiUrl+'/api/v1'+route,{method,redirect:'error',headers:{Origin:connection.apiUrl,Authorization:'Bearer '+connection.token,'Content-Type':'application/json'},signal:AbortSignal.timeout(timeoutMs),...(body===undefined?{}:{body:JSON.stringify(body)})});}
  catch{throw new ActAsFailedError('ActAs could not be reached. No automatic retry was made.',{code:'network_error'});}
  let json;try{json=await response.json();}catch{json=null;}
  if(!response.ok)throw errorFor(response.status,json?.error?.code??'http_'+response.status,json?.error?.message??`ActAs request failed (${response.status}).`);
  if(!json||!('data' in json))throw new ActAsFailedError('Invalid ActAs response.',{status:response.status,code:'invalid_response'});
  return json.data;
 }
 async #scope(connection){
  if(this.#scopes.has(connection))return this.#scopes.get(connection);
  let scope;
  if(connection.kind==='management')scope={ownerId:connection.ownerId,productId:null};
  else if(connection.identityId){const id=await this.#request(connection,'/identities/'+encodeURIComponent(connection.identityId));scope={ownerId:id.ownerId,productId:id.productId};}
  else{const me=await this.#request(connection,'/me');scope={ownerId:me.owners?.[0]?.id,productId:null};}
  this.#scopes.set(connection,scope);return scope;
 }
 async #createIdentity({name,localPart,domain,inbox=true}={}){
  const c=this.#pick('identities:manage'),scope=await this.#scope(c);
  const identity=await this.#request(c,'/identities','POST',{name,...scope,...(localPart?{localPart}:{}),...(domain?{domain}:{})});
  if(!inbox)return {...identity,inbox:null};
  const mailbox=await this.#request(c,'/identities/'+encodeURIComponent(identity.id)+'/email','POST',{});
  const result={...identity,inbox:{id:mailbox.id,address:mailbox.metadata?.address,status:mailbox.status}};
  if(mailbox.status!=='verified')throw new InboxNotVerifiedError(`Inbox ${mailbox.id} is ${mailbox.status}, not verified.`,{code:'inbox_'+mailbox.status});
  return result;
 }
 // Issues the least-privilege connections an agent needs: codes for one inbox, and vault reads for listed paths.
 async #connectIdentity(identityId,{inbox,logins=[],name='Agent'}={}){
  const c=this.#pick('connections:manage'),scope=await this.#scope(c),out=[];
  if(inbox){
   const issued=await this.#request(c,'/clients','POST',{...scope,identityId,name:name+' codes',scopes:['emails:codes'],resourceIds:[inbox],identityFields:[]});
   out.push({version:1,apiUrl:c.apiUrl,identityId,token:issued.token,scopes:['emails:codes'],resourceIds:[inbox]});
  }
  if(logins.length){
   for(const path of logins)await this.#grant({path,principalKind:'identity',principalId:identityId,actions:['read','reveal','totp:code']},c);
   const issued=await this.#request(c,'/clients','POST',{...scope,identityId,name:name+' vault',scopes:['resources:read','secrets:reveal'],resourceIds:['*'],identityFields:[]});
   out.push({version:1,apiUrl:c.apiUrl,identityId,token:issued.token,scopes:['resources:read','secrets:reveal'],resourceIds:['*']});
  }
  return out;
 }
 #deliveryConnection(resource,kind){
  const scopes=kind==='sms'?['phones:read','phones:codes']:['emails:read','emails:codes','emails:links'];
  return this.#connections.find(c=>c.scopes?.some(s=>scopes.includes(s))&&(!c.resourceIds||c.resourceIds.includes('*')||c.resourceIds.includes(resource)))??this.#pick();
 }
 async #waitForCode({inboxId,sender,subject,after,pattern='\\d{6}',timeoutMs=60000}={}){
  if(!inboxId||!sender||!subject||!after)throw new ActAsFailedError('waitForCode needs inboxId, sender, subject and after.',{code:'invalid_request'});
  const c=this.#pick('emails:codes',inboxId),afterIso=after instanceof Date?after.toISOString():after,deadline=Date.now()+timeoutMs;
  for(;;){
   const wait=Math.max(0,Math.min(60000,deadline-Date.now()));
   const result=await this.#request(c,'/emails/'+encodeURIComponent(inboxId)+'/code','POST',{sender,subject,after:afterIso,codePattern:pattern,timeoutMs:wait},{timeoutMs:wait+15000});
   if(result.status==='matched')return {code:result.code,receivedAt:result.receivedAt};
   if(Date.now()>=deadline)throw new CodePendingError(`No code from ${sender} yet.`,{code:'code_pending'});

  }
 }
 async #passkey(operation,path,options){
  const c=this.#pick('secrets:reveal'),scope=await this.#scope(c);
  return this.#request(c,'/vault/passkeys/'+operation,'POST',{...options,...scope,path});
 }
 async #saveLogin(path,item,{replace=false}={}){
  const c=this.#pick('resources:write'),scope=await this.#scope(c);
  return this.#request(c,'/vault/set','POST',{...scope,path,kind:'login',value:item,replace});
 }
 async #grant({path,principalKind,principalId,actions,folder=false},connection=this.#pick('vault:manage')){
  const scope=await this.#scope(connection);
  return this.#request(connection,'/vault/grants','POST',{...scope,path,principalKind,principalId,actions,folder});
 }
 // Returns username/email, password and a fresh TOTP code. The TOTP seed never leaves ActAs.
 async #login(path){
  const c=this.#pick('secrets:reveal'),scope=await this.#scope(c);
  const read=body=>this.#request(c,'/vault/read','POST',{...scope,path,...body});
  const entry=await read({action:'read'});
  if(entry.kind!=='login')throw new ActAsFailedError(`${path} is not a login item.`,{code:'not_a_login'});
  const signInMethod=entry.login?.signInMethod??'password',ssoAccountId=entry.login?.ssoAccountId??null;
  if(!['password','google','github','apple'].includes(signInMethod))throw new ActAsFailedError('Invalid login sign-in metadata.',{code:'invalid_login_metadata'});
  const field=async name=>(await read({action:'reveal',field:name})).value||null;
  const [username,email,password]=await Promise.all([field('username'),field('email'),signInMethod==='password'&&entry.login?.hasPassword?field('password'):null]);
  const totp=entry.login?.hasTotp?await read({action:'totp:code'}):null;
  return {path,signInMethod,ssoAccountId,username,email,password,totp:totp?{code:totp.code,secondsRemaining:totp.secondsRemaining}:null};
 }
}
export default ActAs;

/** Verify before parsing. Deduplicate event IDs separately after acceptance. */
export async function verifyWebhook(secret,headers,rawBody,{now=Date.now(),toleranceMs=300000}={}){
 const get=name=>headers instanceof Headers?headers.get(name):headers[name]??headers[name.toLowerCase()];
 const ts=get('X-ActAs-Timestamp'),sig=get('X-ActAs-Signature');
 if(typeof ts!=='string'||!/^\d{1,12}$/.test(ts)||Math.abs(now-Number(ts)*1000)>toleranceMs||typeof sig!=='string'||!/^v1=[0-9a-f]{64}$/.test(sig)||typeof rawBody!=='string'||typeof secret!=='string')return false;
 const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
 return crypto.subtle.verify('HMAC',key,Uint8Array.from(sig.slice(3).match(/../g),x=>parseInt(x,16)),new TextEncoder().encode(ts+'.'+rawBody));
}
