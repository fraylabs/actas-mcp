import {readFile,open,rename,unlink,lstat,chmod,readdir} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import {homedir} from 'node:os';
import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {StringDecoder} from 'node:string_decoder';
import {parseEnv} from 'node:util';
import {identityRequest,readIdentityConnection} from './identity.mjs';
const fail=()=>{throw Error('Invalid vault command. Run actas help. Values belong only at private prompts.');};
export const vaultHelp=`Workspace vault (exact and folder grants; no values in command arguments)
  actas totp add /path [--replace]    Read seed or otpauth URI from stdin
  actas totp code /path
  actas totp status /path
  actas secret set /path/KEY [--replace]
  actas secret list [--path /folder]
  actas secret versions /path/KEY
  actas secret restore /path/KEY VERSION
  actas run --keys A,B [--path /folder] -- cmd [args]
  actas env sync <dir> --path /folder --keys A,B [--force] [--dry-run]
  actas env inventory <dir>       List local .env.local key names only
  actas script add /path/script
  actas script check /path/script
  actas grant list
  actas grant add <client|identity>:ID /path <read|write|reveal|run|totp:code> [--folder]
  actas grant revoke ID
Connected agents and management automation use ACTAS_CONNECTION_FILE. Paths default to ACTAS_VAULT_PATH
or /shared for run and env sync. For owner grant management use a
private ACTAS_HUMAN_CONNECTION_FILE containing apiUrl and a current human bearer
token, plus ACTAS_WORKSPACE_ID and optional ACTAS_PRODUCT_ID. Human tokens expire;
reconnect through the normal workspace session. Membership suffices; no admin powers.
Children are trusted consumers, not a sandbox. They may intentionally print values.
`;
export function validPath(path){if(typeof path!=='string'||path.length>512||!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(path))fail();return path;}
export function keyNames(raw){const keys=raw?.split(',');if(!keys?.length||keys.some(x=>! /^[A-Za-z_][A-Za-z0-9_]*$/.test(x))||new Set(keys).size!==keys.length)fail();return keys;}
export function childEnvironment(parent=process.env){return Object.fromEntries(['PATH','HOME','TMPDIR','LANG','LC_ALL','SYSTEMROOT'].filter(k=>parent[k]!==undefined).map(k=>[k,parent[k]]));}
export function privatePrompt(labels,input=process.stdin,output=process.stdout){
 if(!input.isTTY||!output.isTTY||typeof input.setRawMode!=='function')throw Error('Use a private Terminal with TTY input and output. Nothing saved.');
 return new Promise((resolve,reject)=>{
  let fields=[],current='',done=false,swallowLF=false;const decoder=new StringDecoder('utf8'),wasRaw=input.isRaw;
  function finish(error){if(done)return;done=true;input.removeListener('data',data);input.removeListener('end',cancel);input.removeListener('error',cancel);for(const s of ['SIGINT','SIGTERM','SIGHUP'])process.removeListener(s,cancel);input.setRawMode(Boolean(wasRaw));input.pause();output.write('\n');const result=fields;fields=[];current='';error?reject(error):resolve(result);}
  function cancel(){finish(Error('Private entry cancelled. Nothing saved.'));}
  function data(chunk){for(const c of typeof chunk==='string'?chunk:decoder.write(chunk)){
   if(done)return;if(c==='\x03'||c==='\x04')return cancel();if(c==='\x7f'||c==='\b'){current=[...current].slice(0,-1).join('');continue;}if(c==='\x15'){current='';continue;}
   if(c==='\n'&&swallowLF){swallowLF=false;continue;}swallowLF=c==='\r';
   if(c==='\n'||c==='\r'){fields.push(current);current='';output.write('\n');if(fields.length===labels.length)return finish();output.write(labels[fields.length]+': ');}
   else if(c.charCodeAt(0)<32||c.charCodeAt(0)===127)return finish(Error('Unsupported control input. Nothing saved.'));
   else{current+=c;if(current.length>65536)return finish(Error('Entry too long. Nothing saved.'));}
  }}
  input.setRawMode(true);input.on('data',data);input.once('end',cancel);input.once('error',cancel);for(const s of ['SIGINT','SIGTERM','SIGHUP'])process.once(s,cancel);output.write(labels[0]+': ');input.resume();
 });
}
async function context(){
 if(process.env.ACTAS_HUMAN_CONNECTION_FILE){
  let connection;try{connection=JSON.parse(await readFile(process.env.ACTAS_HUMAN_CONNECTION_FILE,'utf8'));const url=new URL(connection.apiUrl);if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname)))||typeof connection.token!=='string'||!connection.token||connection.token.startsWith('actas_'))throw Error();connection.apiUrl=url.origin;}catch{throw Error('Could not read a valid human connection.');}
  if(!process.env.ACTAS_WORKSPACE_ID)throw Error('Select ACTAS_WORKSPACE_ID for human vault commands.');
  return {connection,scope:{ownerId:process.env.ACTAS_WORKSPACE_ID,productId:process.env.ACTAS_PRODUCT_ID||null}};
 }
 const connection=await readIdentityConnection();if(connection.kind==='management')return {connection,scope:{ownerId:connection.ownerId,productId:process.env.ACTAS_PRODUCT_ID||null}};const identity=await identityRequest(connection,'/identities/'+connection.identityId);return {connection,scope:{ownerId:identity.ownerId,productId:identity.productId}};
}
export function requestVault(ctx,route,body,method='POST'){return identityRequest(ctx.connection,'/vault'+route,method,body===undefined?undefined:{...body,...ctx.scope});}
function options(args,allowed){const out={};for(let i=0;i<args.length;i++){const name=args[i];if(!allowed.includes(name)||Object.hasOwn(out,name))fail();out[name]=['--replace','--force','--dry-run'].includes(name)?true:args[++i];if(out[name]===undefined)fail();}return out;}
async function selected(ctx,path,keys){validPath(path);const values={};for(const key of keys){const item=await requestVault(ctx,'/read',{path:path+'/'+key,action:'reveal'});if(typeof item?.value!=='string'||item.value.includes('\0'))throw Error('Invalid vault response. Command was not started.');values[key]=item.value;}return values;}
export function runChild(command,env,card,spawnChild=spawn){
 if(!command.length)fail();return new Promise((resolve,reject)=>{
  let child;try{child=spawnChild(command[0],command.slice(1),{env,shell:false,stdio:card?['pipe','inherit','inherit']:'inherit'});}catch{reject(Error('Unable to start requested command.'));return;}
  const forward=signal=>child.kill(signal);const sigint=()=>forward('SIGINT'),sigterm=()=>forward('SIGTERM');process.on('SIGINT',sigint);process.on('SIGTERM',sigterm);
  function cleanup(){process.removeListener('SIGINT',sigint);process.removeListener('SIGTERM',sigterm);}
  child.once('error',()=>{cleanup();reject(Error('Unable to start requested command.'));});child.once('exit',(code,signal)=>{cleanup();resolve(code??(signal?1:0));});
  if(card){child.stdin.on('error',()=>{});child.stdin.end(JSON.stringify(card)+'\n');}
 });
}
// Node dotenv has no escaped-newline syntax. Quote literal multiline values and
// reject the rare value containing all three quote delimiters rather than corrupt it.
export function encodeEnv(value){for(const quote of ['"',"'",'`'])if(!value.includes(quote))return quote+value+quote;throw Error('Value cannot be represented losslessly in a dotenv file. Use actas run.');}
export async function syncEnv(directory,values,{force=false,dryRun=false}={}){
 const file=join(resolve(directory),'.env.local');let raw='';try{const info=await lstat(file);if(!info.isFile()||info.isSymbolicLink())throw Error();raw=await readFile(file,'utf8');}catch(e){if(e.code!=='ENOENT')throw Error('Unable to read a regular target env file.');}
 let existing;try{existing=parseEnv(raw);}catch{throw Error('Target env file could not be parsed.');}
 const updates=new Map(),actions=[];for(const [key,value] of Object.entries(values)){keyNames(key);if(existing[key]&&!force){actions.push({key,action:'kept-existing'});continue;}updates.set(key,encodeEnv(value));actions.push({key,action:Object.hasOwn(existing,key)?'updated':'added'});}
 if(!dryRun&&updates.size){
  // Remove complete multiline assignments, preserve unrelated lines/comments.
  const lines=raw.split(/\r?\n/),out=[];const consumed=new Set();
  for(let i=0;i<lines.length;i++){const match=/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(lines[i]);if(!match||!updates.has(match[1])){out.push(lines[i]);continue;}
   const v=match[2],q=v[0];if(['"',"'",'`'].includes(q)&&!v.slice(1).includes(q)){while(++i<lines.length&&!lines[i].includes(q)){} }
   if(!consumed.has(match[1]))out.push(match[1]+'='+updates.get(match[1]));consumed.add(match[1]);
  }
  for(const [k,v] of updates)if(!consumed.has(k))out.push(k+'='+v);
  const next=out.join('\n').replace(/\n*$/,'')+'\n';const parsed=parseEnv(next);for(const [key] of updates)if(parsed[key]!==values[key])throw Error('Env serialization could not preserve the value. Nothing written.');
  const temp=join(dirname(file),'.actas-env-'+randomUUID());let handle;try{handle=await open(temp,'wx',0o600);await handle.writeFile(next);await handle.close();handle=null;await rename(temp,file);await chmod(file,0o600);}finally{await handle?.close();await unlink(temp).catch(()=>{});}
 }
 return {target:file,dryRun,actions};
}
export async function inventoryEnv(directory){
 const raw=await readFile(join(resolve(directory),'.env.local'),'utf8');return {keys:[...new Set([...raw.matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/gm)].map(m=>m[1]))].sort()};
}
export async function runVaultCommand(args){
 const [cmd,sub,...rest]=args;if(!['run','env','card','script','grant','totp'].includes(cmd)&&!(cmd==='secret'&&['set','list','versions','restore'].includes(sub)))return false;
 try{
  let result;
  if(cmd==='env'&&sub==='inventory'){if(rest.length!==1)fail();result=await inventoryEnv(rest[0]);}
  else{
   const ctx=await context();
   if(cmd==='run'||cmd==='card'&&sub==='run'){
    const split=args.indexOf('--');if(split<0||split===args.length-1)fail();let values,card;
    if(cmd==='run'){const flags=options(args.slice(1,split),['--path','--keys']);values=await selected(ctx,flags['--path']||process.env.ACTAS_VAULT_PATH||'/shared',keyNames(flags['--keys']));}
    else{if(split!==3)fail();card=(await requestVault(ctx,'/read',{path:validPath(args[2]),action:'run'})).card;if(!card)throw Error('Invalid card response. Command was not started.');}
    process.exitCode=await runChild(args.slice(split+1),{...childEnvironment(),...values},card);return true;
   }
   else if(cmd==='env'&&sub==='sync'){const [dir,...extra]=rest;if(!dir)fail();const flags=options(extra,['--path','--keys','--force','--dry-run']);const values=await selected(ctx,flags['--path']||process.env.ACTAS_VAULT_PATH||'/shared',keyNames(flags['--keys']));result=await syncEnv(dir,values,{force:flags['--force'],dryRun:flags['--dry-run']});}
   else if(cmd==='secret'&&sub==='list'){const flags=options(rest,['--path']);const query=new URLSearchParams({ownerId:ctx.scope.ownerId,...(ctx.scope.productId?{productId:ctx.scope.productId}:{}),...(flags['--path']?{path:validPath(flags['--path'])}:{})});result=(await requestVault(ctx,'/entries?'+query,undefined,'GET')).filter(x=>x.kind==='secret'&&(!flags['--path']||x.path.startsWith(validPath(flags['--path'])+'/')));}
   else if(cmd==='totp'&&sub==='add'){const path=validPath(rest[0]),flags=options(rest.slice(1),['--replace']);let value='';for await(const chunk of process.stdin){value+=chunk;if(value.length>8192)fail();}result=await requestVault(ctx,'/set',{path,kind:'totp',value:value.trim(),replace:flags['--replace']===true});}
   else if(cmd==='totp'&&['code','status'].includes(sub)){if(rest.length!==1)fail();result=await requestVault(ctx,'/read',{path:validPath(rest[0]),action:sub==='code'?'totp:code':'read'});}
   else if(cmd==='secret'&&sub==='set'||cmd==='card'&&sub==='add'){
    const path=validPath(rest[0]),flags=options(rest.slice(1),['--replace']);let value;
    if(cmd==='secret'){const entered=await privatePrompt(['Secret value','Repeat value']);if(!entered[0]||entered[0]!==entered[1])throw Error('Values are empty or do not match. Nothing saved.');value=entered[0];}
    else{const [cardholder,number,expiryMonth,expiryYear,cvc,label]=await privatePrompt(['Cardholder','Number','Expiry month (MM)','Expiry year (YYYY)','CVC (internal workspace only; blank to omit)','Label']);value={cardholder,number,expiryMonth,expiryYear,...(cvc?{cvc}:{}),label};}
    result=await requestVault(ctx,'/set',{path,kind:cmd==='secret'?'secret':'card',value,replace:flags['--replace']===true});
   }
   else if(cmd==='secret'&&sub==='versions'){if(rest.length!==1)fail();result=await requestVault(ctx,'/versions',{path:validPath(rest[0])});}
   else if(cmd==='secret'&&sub==='restore'){if(rest.length!==2||!/^\d+$/.test(rest[1]))fail();result=await requestVault(ctx,'/restore',{path:validPath(rest[0]),version:Number(rest[1])});}
   else if(cmd==='card'&&sub==='status'||cmd==='script'&&sub==='check'){if(rest.length!==1)fail();result=await requestVault(ctx,'/read',{path:validPath(rest[0]),action:cmd==='script'?'run':'read'});}
   else if(cmd==='script'&&sub==='add'){if(rest.length!==1)fail();result=await requestVault(ctx,'/set',{path:validPath(rest[0]),kind:'script'});}
   else if(cmd==='grant'&&sub==='list'){if(rest.length)fail();const query=new URLSearchParams({ownerId:ctx.scope.ownerId,...(ctx.scope.productId?{productId:ctx.scope.productId}:{})});result=await requestVault(ctx,'/grants?'+query,undefined,'GET');}
   else if(cmd==='grant'&&sub==='add'){if(rest.length!==3&&!(rest.length===4&&rest[3]==='--folder'))fail();const m=/^(client|identity):(.+)$/.exec(rest[0]);if(!m||!['read','write','reveal','run','totp:code'].includes(rest[2]))fail();result=await requestVault(ctx,'/grants',{principalKind:m[1],principalId:m[2],path:validPath(rest[1]),action:rest[2],folder:rest[3]==='--folder'});}
   else if(cmd==='grant'&&sub==='revoke'){if(rest.length!==1)fail();result=await requestVault(ctx,'/grants/'+encodeURIComponent(rest[0]),undefined,'DELETE');}
   else fail();
  }
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
 }catch{process.stderr.write('ActAs vault operation failed. No sensitive diagnostics displayed; verify metadata before retrying a write.\n');process.exitCode=1;}
 return true;
}
