import {readFile} from 'node:fs/promises';
import {ActAs} from '../scripts/proof-client.mjs';
import {loadMappings,selectMapping,callerExecutor} from './caller.mjs';
import {helper} from './helper.mjs';

// Provider messages are untrusted. Only exact owner-assigned senders, recipients,
// verification paths and recent received messages can supply a challenge.
export function emailChallenge(message,config,principal,since,now=Date.now()) {
 const timestamp=Date.parse(message.timestamp);
 if(!Number.isFinite(since)||since>now||!Number.isFinite(timestamp)||timestamp<since||timestamp>now||now-timestamp>900000||!message.labels?.includes('received'))return;
 const address=value=>typeof value==='string'?value.match(/<([^<>]+)>$/)?.[1]||value:undefined;
 if(!config.senders?.includes(address(message.from))||!Array.isArray(message.to)||!message.to.some(v=>address(v)===principal)||typeof message.text!=='string')return;
 if(config.kind==='code'){
  // A fixed label avoids arbitrary regex execution and ambiguous numbers in mail.
  if(typeof config.label!=='string'||!config.label||!Number.isInteger(config.digits)||config.digits<4||config.digits>10)return;
  const candidates=message.text.split(/\r?\n/).filter(line=>line.startsWith(config.label)).map(line=>line.slice(config.label.length).trim()).filter(v=>/^\d+$/.test(v)&&v.length===config.digits);
  return candidates.length===1?{code:candidates[0]}:undefined;
 }
 if(config.kind==='link'){
  const candidates=[...new Set(message.text.match(/https:\/\/[^\s<>"']+/g)||[])].filter(value=>{
   try{const url=new URL(value);return !url.username&&!url.password&&config.links?.some(rule=>rule.origin===url.origin&&rule.path===url.pathname);}catch{return false;}
  });
  return candidates.length===1?{verificationUrl:candidates[0]}:undefined;
 }
}

export async function externalExecutor({accountsPath,reportPath,clientFactory=options=>new ActAs(options),deliver=helper}={}) {
 const mappings=await loadMappings(accountsPath);
 const caller=await callerExecutor({accountsPath,reportPath});
 let report;if(reportPath)report=JSON.parse(await readFile(reportPath,'utf8'));
 return async state=>{
  const mapping=selectMapping(mappings,state.origin,state.accountRef);
  if(mapping?.credentials?.kind!=='actas-external')return null;
  if(!mapping.actions.includes(state.action))return {status:'blocked',reason:'authorization_required'};
  const continuation=await caller(state);
  if(continuation.status==='failed'||continuation.status==='needs_browser'&&continuation.browser.step==='inspect_form')return continuation;
  try{
   const token=(await readFile(mapping.credentials.tokenPath,'utf8')).trim();
   const client=clientFactory({url:mapping.credentials.url,token});
   await client.request('/accounts/'+encodeURIComponent(mapping.accountRef)+'/registry-observe',{method:'POST',body:{action:state.action,completed:continuation.status==='succeeded'}});
  }catch{return {status:'blocked',reason:'registry_unavailable'};}
  if(continuation.status!=='needs_browser')return continuation;
  const step=continuation.browser.step;
  if(!['enter_credentials','verify_email'].includes(step))return continuation;
  // The continuation report is account-bound before any secret or mail access.
  if(report&&(report.accountRef!==mapping.accountRef||report.principal!==mapping.principal))return {status:'failed',reason:'unverified'};
  try{
   const token=(await readFile(mapping.credentials.tokenPath,'utf8')).trim();
   const client=clientFactory({url:mapping.credentials.url,token});
   const [account,email]=await Promise.all([client.get(mapping.accountRef),client.get(mapping.mailbox.emailId)]);
   if(account.metadata.emailId!==email.id||!account.metadata.secretIds?.includes(mapping.credentials.secretId)||email.metadata.address!==mapping.principal)throw new Error('scope');
   let values;
   if(step==='enter_credentials'){
    const credential=JSON.parse((await client.reveal(mapping.credentials.secretId)).value);
    if(credential.origin!==state.origin||credential.email!==mapping.principal||typeof credential.password!=='string'||!credential.password)throw new Error('scope');
    values={email:credential.email,password:credential.password,...(typeof credential.username==='string'?{username:credential.username}:{})};
   }else{
    if(!mapping.mailbox.verification)return {...continuation,browser:{...continuation.browser,step:'verify_email',mailboxUrl:mapping.credentials.url+'/app/inboxes/'+encodeURIComponent(email.id),nextStep:'Open the assigned inbox, use the matching verification message in the website, then report verify_session. No automatic extraction rule is configured.'}};
    const since=Date.parse(state.progress?.verificationRequestedAt||report?.verificationRequestedAt);
    if(!Number.isFinite(since)||since<Date.parse(state.createdAt)||since>Date.now())return {status:'failed',reason:'unverified'};
    const progress={step:'verify_email',verificationRequestedAt:new Date(since).toISOString()};
    const listing=await client.request('/emails/'+encodeURIComponent(email.id)+'/messages?limit=20');
    const matches=[];
    for(const item of listing.messages||listing){
     if(!item.labels?.includes('received'))continue;
     const detail=await client.message(email.id,item.message_id||item.id);
     const candidate=emailChallenge({...detail,labels:item.labels,timestamp:item.timestamp},mapping.mailbox.verification,mapping.principal,since);
     if(candidate)matches.push(candidate);
    }
    // Never guess between concurrent challenges on a shared mailbox.
    if(matches.length!==1)return {status:'blocked',reason:'verification_pending',progress};
    values=matches[0];
    continuation.progress=progress;
   }
   continuation.browser={...continuation.browser,credentialCustody:'actas',credentialHelperUrl:await deliver(values)};
   return continuation;
  }catch{return {status:'blocked',reason:'vault_unavailable'};}
 };
}
