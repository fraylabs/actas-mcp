import {readFile,open} from 'node:fs/promises';
import {identityRequest,readIdentityConnection} from './identity.mjs';
export const managementHelp=`Workspace management
  actas connect ./mgmt.json
  actas identity list
  actas identity create <name> [--product ID] [--local-part NAME] [--domain DOMAIN]
  actas identity rename <id> <name>
  actas identity revoke <id>
  actas domains list
  actas domains add <domain>
  actas domains verify <domain>
  actas domains remove <domain>
  actas sending <identity> on|off
  actas email create <identity>
  actas connection list
  actas connection issue <identity> --scopes emails:read --inbox ID --out ./agent.json
  actas connection revoke <id>
  actas activity
  actas management list --owner ID
  actas management issue --owner ID --name NAME --scopes LIST --confirm WORKSPACE --out ./mgmt.json
  actas management rotate ID --owner ID --name NAME --scopes LIST --confirm WORKSPACE --out ./mgmt.json
  actas management revoke ID
Management issuance uses ACTAS_HUMAN_CONNECTION_FILE (a private human bearer file).
An explicit --confirm workspace name reconfirms delegation. --days defaults to 90,
maximum 365. Secret connection output requires --out (exclusive mode 0600 file)
or explicit --stdout. Never place a token in command arguments.
`;
function flags(args,allowed){const values={};for(let i=0;i<args.length;i++){const k=args[i];if(!allowed.includes(k)||Object.hasOwn(values,k))throw Error('Unknown or repeated management option.');values[k]=k==='--stdout'?true:args[++i];if(values[k]===undefined)throw Error('Missing management option.');}return values;}
async function secretOutput(options,action){
 if(Boolean(options['--out'])===Boolean(options['--stdout']))throw Error('Choose --out FILE or explicit --stdout for connection output.');
 let handle;if(options['--out'])handle=await open(options['--out'],'wx',0o600);
 try{const result=await action();if(handle){await handle.writeFile(JSON.stringify(result,null,2)+'\n');return {status:'issued',file:options['--out']};}process.stdout.write(JSON.stringify(result,null,2)+'\n');return null;}finally{await handle?.close();}
}
async function human(){
 try{const c=JSON.parse(await readFile(process.env.ACTAS_HUMAN_CONNECTION_FILE,'utf8'));const u=new URL(c.apiUrl);if(u.username||u.password||u.search||u.hash||u.pathname!=='/'||(u.protocol!=='https:'&&!(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname)))||typeof c.token!=='string'||!c.token||c.token.startsWith('actas_'))throw Error();return {...c,apiUrl:u.origin};}catch{throw Error('Use a private ACTAS_HUMAN_CONNECTION_FILE with a current human bearer.');}
}
export async function runManagementCommand(args){
 const [command,action,...rest]=args;
 if(!(['sending','domains','email','connection','management','activity'].includes(command)||command==='identity'&&['list','create','rename','revoke'].includes(action)))return false;
 try{
  let result;
  if(command==='management'){
   const c=await human();
   if(action==='list'){const f=flags(rest,['--owner']);if(!f['--owner'])throw Error('Select --owner.');result=await identityRequest(c,'/management?ownerId='+encodeURIComponent(f['--owner']));}
   else if(action==='revoke'&&rest.length===1)result=await identityRequest(c,'/management/'+encodeURIComponent(rest[0]),'DELETE');
   else if(['issue','rotate'].includes(action)){
    const id=action==='rotate'?rest.shift():null;const f=flags(rest,['--owner','--name','--scopes','--confirm','--days','--out','--stdout']);
    const days=Number(f['--days']??90);if(!Number.isInteger(days)||days<1||days>365||!f['--owner']||!f['--name']||!f['--scopes']||!f['--confirm']||action==='rotate'&&!id)throw Error('Supply owner, name, scopes, confirmation and 1–365 days.');
    result=await secretOutput(f,async()=> (await identityRequest(c,'/management'+(id?'/'+encodeURIComponent(id)+'/rotate':''),'POST',{ownerId:f['--owner'],name:f['--name'],scopes:f['--scopes'].split(','),confirmWorkspace:f['--confirm'],expiresAt:Date.now()+days*86400000})).connection);
   }else throw Error('Invalid management command.');
  }else{
   const c=await readIdentityConnection();if(c.kind!=='management')throw Error('Connect a management connection first.');
   if(command==='sending'&&action&&rest.length===1&&['on','off'].includes(rest[0]))result=await identityRequest(c,'/identities/'+encodeURIComponent(action)+'/sending','PATCH',{canSend:rest[0]==='on'});
   else if(command==='domains'&&action==='list'&&!rest.length)result=await identityRequest(c,'/domains?ownerId='+encodeURIComponent(c.ownerId));
   else if(command==='domains'&&action==='add'&&rest.length===1)result=await identityRequest(c,'/domains','POST',{ownerId:c.ownerId,domain:rest[0]});
   else if(command==='domains'&&action==='verify'&&rest.length===1)result=await identityRequest(c,'/domains/'+encodeURIComponent(rest[0])+'/verify','POST',{});
   else if(command==='domains'&&action==='remove'&&rest.length===1)result=await identityRequest(c,'/domains/'+encodeURIComponent(rest[0]),'DELETE');
   else if(command==='identity'&&action==='list'&&!rest.length)result=await identityRequest(c,'/identities');
   else if(command==='identity'&&action==='create'){const name=rest.shift(),f=flags(rest,['--product','--local-part','--domain']);if(!name)throw Error('Supply an agent name.');result=await identityRequest(c,'/identities','POST',{ownerId:c.ownerId,name,productId:f['--product']||null,...(f['--local-part']?{localPart:f['--local-part']}:{}),...(f['--domain']?{domain:f['--domain']}:{})});}
   else if(command==='identity'&&action==='rename'&&rest.length===2)result=await identityRequest(c,'/identities/'+encodeURIComponent(rest[0]),'PATCH',{name:rest[1]});
   else if(command==='identity'&&action==='revoke'&&rest.length===1)result=await identityRequest(c,'/identities/'+encodeURIComponent(rest[0])+'/revoke','POST',{});
   else if(command==='email'&&action==='create'&&rest.length===1)result=await identityRequest(c,'/identities/'+encodeURIComponent(rest[0])+'/email','POST',{});
   else if(command==='connection'&&action==='list'&&!rest.length)result=await identityRequest(c,'/clients');
   else if(command==='connection'&&action==='revoke'&&rest.length===1)result=await identityRequest(c,'/clients/'+encodeURIComponent(rest[0]),'DELETE');
   else if(command==='connection'&&action==='issue'){
    const id=rest.shift(),f=flags(rest,['--scopes','--inbox','--resources','--name','--out','--stdout']);if(!id||!f['--scopes']||!f['--inbox']&&!f['--resources'])throw Error('Supply identity, scopes and --inbox or --resources.');
    result=await secretOutput(f,async()=>{const identity=await identityRequest(c,'/identities/'+encodeURIComponent(id));const issued=await identityRequest(c,'/clients','POST',{ownerId:c.ownerId,productId:identity.productId,identityId:id,name:f['--name']||identity.name+' runtime',scopes:[...new Set(['resources:read',...f['--scopes'].split(',')])],resourceIds:f['--inbox']?[f['--inbox']] : f['--resources'].split(','),identityFields:[]});return {version:1,apiUrl:c.apiUrl,identityId:id,token:issued.token};});
   }else if(command==='activity'&&action===undefined)result=await identityRequest(c,'/activity');
   else throw Error('Invalid management command. Run actas help.');
  }
  if(result!==null)process.stdout.write(JSON.stringify(result,null,2)+'\n');
 }catch{process.stderr.write(JSON.stringify({status:'failed',message:'Management command failed. Check arguments, access and private output file; reconcile uncertain issuance in Access before retrying.'})+'\n');process.exitCode=1;}
 return true;
}
