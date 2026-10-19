import {readFile,mkdir,open,rename,unlink} from 'node:fs/promises';
import {homedir} from 'node:os';
import {join,dirname,resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {targetUrl} from './accounts.mjs';
import {loadMappings} from './caller.mjs';
function verificationRule(rule) {
 if(rule===undefined)return undefined;
 if(!rule||!Array.isArray(rule.senders)||!rule.senders.length||rule.senders.length>20||rule.senders.some(s=>typeof s!=='string'||!/^[-a-zA-Z0-9_.+]+@[-a-zA-Z0-9.]+$/.test(s)))throw Error();
 const senders=[...new Set(rule.senders)];
 if(rule.kind==='code'){
  if(typeof rule.label!=='string'||!rule.label||rule.label.length>200||/[\r\n]/.test(rule.label)||!Number.isInteger(rule.digits)||rule.digits<4||rule.digits>10)throw Error();
  return {kind:'code',senders,label:rule.label,digits:rule.digits};
 }
 if(rule.kind!=='link'||!Array.isArray(rule.links)||!rule.links.length||rule.links.length>20)throw Error();
 const links=rule.links.map(r=>{
  if(!r||targetUrl(r.origin).origin!==r.origin||typeof r.path!=='string'||!r.path.startsWith('/')||r.path.startsWith('//')||/[?#]/.test(r.path)||new URL(r.path,r.origin).pathname!==r.path)throw Error();
  return {origin:r.origin,path:r.path};
 });
 return {kind:'link',senders,links};
}
export async function configureAccount(bundlePath,{accountsPath=process.env.ACTAS_ACCOUNTS_FILE||join(homedir(),'.config','actas','accounts.json')}={}){
 let bundle;try{const raw=await readFile(bundlePath,'utf8');if(raw.length>65536)throw Error();bundle=JSON.parse(raw);}catch{throw new Error('Could not read account connection file.');}
 const m=bundle?.mapping;let verification;
 try{
 if(bundle.version!==1||typeof bundle.token!=='string'||!/^actas_[\w-]+\.[\w-]+$/.test(bundle.token)||!m||targetUrl(m.origin).origin!==m.origin||typeof m.accountRef!=='string'||!m.accountRef||typeof m.principal!=='string'||!m.principal||!Array.isArray(m.actions)||!m.actions.length||m.actions.some(a=>!['signup','login'].includes(a))||typeof m.authenticatedPath!=='string'||!m.authenticatedPath.startsWith('/')||m.authenticatedPath.startsWith('//')||/[?#]/.test(m.authenticatedPath)||m.credentials?.kind!=='actas-external'||targetUrl(m.credentials.url).origin!==m.credentials.url||typeof m.credentials.secretId!=='string'||!m.credentials.secretId||typeof m.mailbox?.emailId!=='string'||!m.mailbox.emailId)throw Error();
 verification=verificationRule(m.mailbox.verification);
 }catch{throw new Error('Invalid account connection. No configuration was changed.');}
 const file=resolve(accountsPath),dir=dirname(file);await mkdir(dir,{recursive:true,mode:0o700});
 let lock;try{lock=await open(file+'.lock','wx',0o600);}catch{throw new Error('Account configuration is busy. Retry after the other operation finishes.');}
 try{
 let mappings;try{mappings=await loadMappings(file);}catch(error){try{await readFile(file);throw error;}catch(e){if(e.code!=='ENOENT')throw error;mappings=[];}}
 const id=createHash('sha256').update(JSON.stringify([m.origin,m.accountRef])).digest('hex');
 const tokenPath=join(dir,'tokens',id+'.token');
 // Construct an allowlisted mapping; imported paths, drivers and brokers are ignored.
 const mapping={origin:m.origin,accountRef:m.accountRef,principal:m.principal,custodian:'ActAs',actions:m.actions,authenticatedPath:m.authenticatedPath,credentials:{kind:'actas-external',url:m.credentials.url,secretId:m.credentials.secretId,tokenPath},mailbox:{emailId:m.mailbox.emailId,...(verification?{verification}:{})}};
 const prior=mappings.find(x=>x.origin===m.origin&&x.accountRef===m.accountRef);
 if(prior&&JSON.stringify(prior)!==JSON.stringify(mapping))throw new Error('An existing account mapping differs. It was preserved.');
 await mkdir(dirname(tokenPath),{recursive:true,mode:0o700});
 async function save(path,value){const tmp=path+'.'+randomUUID();const out=await open(tmp,'wx',0o600);try{await out.writeFile(value);}finally{await out.close();}await rename(tmp,path);}
 await save(tokenPath,bundle.token);
 if(!prior)await save(file,JSON.stringify([...mappings,mapping],null,2)+'\n');
 return {status:'configured',origin:m.origin,accountRef:m.accountRef};
 }finally{await lock.close();await unlink(file+'.lock');}
}
