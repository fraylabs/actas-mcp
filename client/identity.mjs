import {readFile,mkdir,open,rename} from 'node:fs/promises';
import {homedir} from 'node:os';
import {join,dirname} from 'node:path';
import {randomUUID} from 'node:crypto';

const path=()=>process.env.ACTAS_CONNECTION_FILE||join(homedir(),'.config','actas','identity.json');
function validate(value){
 if(value?.kind==='management'){
  if(value.version!==1||typeof value.ownerId!=='string'||!value.ownerId||typeof value.managementId!=='string'||!/^actas_m_[0-9a-f-]{36}\.[A-Za-z0-9_-]{32,}$/.test(value.token)||value.token.split('.')[0]!=='actas_m_'+value.managementId)throw Error('Invalid management connection.');
  const url=new URL(value.apiUrl);if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))))throw Error('Connection requires HTTPS or local development.');
  return {version:1,kind:'management',apiUrl:url.origin,ownerId:value.ownerId,managementId:value.managementId,token:value.token};
 }
 if(value?.version!==1||typeof value.identityId!=='string'||!/^agt_[0-9a-f-]{36}$/.test(value.identityId)||typeof value.token!=='string'||!/^actas_[0-9a-f-]{36}\.[A-Za-z0-9_-]{32,}$/.test(value.token))throw Error('Invalid identity connection.');
 const url=new URL(value.apiUrl);
 if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))))throw Error('Identity connection requires HTTPS or local development.');
 return {version:1,apiUrl:url.origin,identityId:value.identityId,token:value.token};
}
async function readConnection(file){
 try{const raw=await readFile(file,'utf8');if(raw.length>16384)throw Error();return validate(JSON.parse(raw));}catch{throw Error('Could not read a valid identity connection. Run actas connect <connection.json>.');}
}
export async function readIdentityConnection(file=path()){return readConnection(file);}
export async function identityRequest(connection,route,method='GET',body,extraHeaders={}){
 let response;
 try{response=await fetch(connection.apiUrl+'/api/v1'+route,{method,redirect:'error',headers:{Origin:connection.apiUrl,Authorization:'Bearer '+connection.token,'Content-Type':'application/json',...extraHeaders},signal:AbortSignal.timeout(Math.max(15000,Math.min(75000,(body?.timeoutMs??0)+15000))),...(body===undefined?{}:{body:JSON.stringify(body)})});}catch{throw Error('ActAs could not be reached. No automatic retry was made.');}
 if(!response.ok){
  const error=Error(response.status===401?'Access expired or was revoked. Reconnect through your workspace.':response.status===403?'This connection does not permit that action.':`ActAs request failed (${response.status}).`);
  if(response.status===403){const message=(await response.json().catch(()=>null))?.error?.message;if(typeof message==='string'){error.message=message;error.actasRefusal=message;}}
  throw error;
 }
 try{return (await response.json()).data;}catch{throw Error('Invalid ActAs response.');}
}
export async function connectIdentity(file){
 const connection=await readConnection(file);
 const identity=await identityRequest(connection,connection.kind==='management'?'/me':'/identities/'+encodeURIComponent(connection.identityId));
 if(connection.kind==='management'?(identity.id!==connection.managementId||identity.owners?.[0]?.id!==connection.ownerId):identity.id!==connection.identityId)throw Error('Identity connection mismatch.');
 const destination=path();await mkdir(dirname(destination),{recursive:true,mode:0o700});
 const temp=destination+'.'+randomUUID();const handle=await open(temp,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(connection)+'\n');}finally{await handle.close();}
 await rename(temp,destination);
 return {status:'connected',...(connection.kind==='management'?{managementId:identity.id,ownerId:connection.ownerId}:{identityId:identity.id}),name:identity.name};
}
export const identityHelp=`ActAs — identity, email and accounts for agents

  actas connect <connection.json>  Import scoped identity access
  actas identity                   Show your connected identity
  actas resources                  List permitted identity resources
  actas resources save             Save a resource from JSON on stdin
  actas mail <inbox-id>             List inbox messages
  actas mail <inbox-id> <message-id> Read one message
  actas mail send <inbox-id> --key <stable-key>   Send JSON on stdin
  actas mail reply <inbox-id> <message-id> --key <stable-key>  Reply with JSON on stdin
  actas secret <resource-id>        Retrieve a permitted secret

Make a connection in the agent's Connection tab in your workspace (Connect CLI, Create connection,
then Download connection). Revoke it there with Revoke access.
Secret retrieval and message reads can return sensitive values; use only in the
intended authorized runtime. Never pass secret values as command arguments.
Sending from your own domain starts once ActAs has approved that domain for sending. Email support@actas.dev to ask.
Sending needs emails:send plus the owner’s Can send email switch. Reply also needs
emails:read. Send: {"to":"person@example.com","subject":"Hello","text":"Hello"}.
Reply: {"text":"Thanks"}. Optional simple HTML; no attachments, CC or BCC.
Reuse the SAME key and SAME body to inspect uncertain sends; never use a fresh key
while a pending/unknown result needs operator reconciliation. Exit 2 means unconfirmed.
Legacy configure/signup/login commands remain available for existing clients.
`;
export async function runIdentityCommand(args){
 const [command,...rest]=args;
 if(!['connect','identity','resources','mail','secret'].includes(command))return false;
 try{
  let result;
  if(command==='connect'){
   if(rest.length!==1)throw Error('Use actas connect <connection.json>.');
   result=await connectIdentity(rest[0]);
  }else{
   const connection=await readConnection(path());
   if(connection.kind==='management')throw Error('Use management commands: actas identity list/create, email create, connection issue/revoke, or activity.');
   if(command==='identity'&&!rest.length)result=await identityRequest(connection,'/identities/'+connection.identityId);
   else if(command==='resources'&&!rest.length)result=await identityRequest(connection,'/identities/'+connection.identityId+'/resources');
   else if(command==='resources'&&rest.length===1&&rest[0]==='save'){
    let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>100000)throw Error('Resource input is too large.');}
    let body;try{body=JSON.parse(input);}catch{throw Error('Expected a resource JSON object on stdin.');}
    if(!body||typeof body!=='object'||Array.isArray(body))throw Error('Expected a resource JSON object on stdin.');
    const identity=await identityRequest(connection,'/identities/'+connection.identityId);
    result=await identityRequest(connection,'/resources','POST',{...body,ownerId:identity.ownerId,productId:identity.productId,identityId:identity.id});
   }else if(command==='mail'&&['send','reply'].includes(rest[0])){
    const reply=rest[0]==='reply',keyIndex=reply?3:2;
    if(rest.length!==keyIndex+2||rest[keyIndex]!=='--key'||! /^[A-Za-z0-9_-]{16,128}$/.test(rest[keyIndex+1]))throw Error('Use actas mail send <inbox-id> --key <stable-key> or mail reply <inbox-id> <message-id> --key <stable-key>.');
    let input='';for await(const chunk of process.stdin){input+=chunk;if(Buffer.byteLength(input)>256*1024)throw Error('Message input is too large.');}
    let body;try{body=JSON.parse(input);}catch{throw Error('Expected message JSON on stdin.');}
    if(!body||typeof body!=='object'||Array.isArray(body))throw Error('Expected message JSON on stdin.');
    result=await identityRequest(connection,'/emails/'+encodeURIComponent(rest[1])+(reply?'/messages/'+encodeURIComponent(rest[2])+'/reply':'/send'),'POST',body,{'Idempotency-Key':rest[keyIndex+1]});
    if(!['sent','delivered'].includes(result.status))process.exitCode=2;
   }else if(command==='mail'&&rest.length>=1&&rest.length<=2){
    result=await identityRequest(connection,'/emails/'+encodeURIComponent(rest[0])+'/messages'+(rest[1]?'/'+encodeURIComponent(rest[1]):''));
   }else if(command==='secret'&&rest.length===1)result=await identityRequest(connection,'/resources/'+encodeURIComponent(rest[0])+'/reveal','POST',{});
   else throw Error('Invalid command arguments. Run actas help.');
  }
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
 }catch(error){process.stderr.write(JSON.stringify({status:'failed',message:error.message})+'\n');process.exitCode=1;}
 return true;
}
