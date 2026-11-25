import {PrivateValues,waitForInbox} from './accounts-inbox.mjs';

// Routing metadata stays outside the strict browser report/vault boundary.
// The step ID survives token rotation so callers can keep one request for a person across retries.
function humanResult(result,name,args,account,action){
 if(result.status!=='needs_human')return result;
 account=result.account??account;
 const platform={x:'X',instagram:'Instagram',github:'GitHub',bluesky:'Bluesky',reddit:'Reddit',discord:'Discord'}[account?.platform]??account?.platform??'the provider';
 const ref=account?.accountRef??args.accountRef;
 const reason=result.handoff??result.reason??(account?.method==='browser'?'human_credential_entry':'api_credentials');
 const actions={captcha:'Complete the CAPTCHA',mfa:'Complete the authentication challenge',phone:'Complete the phone verification',provider_policy:'Review the provider approval',human_credential_entry:`Sign in as ${account?.handle??ref}`,api_credentials:`Create and save official ${platform} API credentials for ${ref} in its ActAs vault`};
 const where=reason==='api_credentials'?`${platform} account ${account?.handle??ref}: developer settings, then a private Terminal running actas secret set`: `ActAs ${platform} ${action==='signup'?'signup':'sign-in'} window for ${ref} at ${result.origin??result.humanRequest?.openedUrl}`;
 const question=reason==='api_credentials'?`${actions[reason]}.`:`${actions[reason]??actions.provider_policy} in the ActAs ${action==='signup'?'signup':'sign-in'} window.`;
 const resumeHandle=result.resumeToken?{tool:name,arguments:{accountRef:ref,resumeToken:result.resumeToken}}:name==='actas_account_connect'?{tool:account?.method==='browser'?'actas_account_signup':name,arguments:account?.method==='browser'?{accountRef:ref}:{...args}}:undefined;
 return {...result,kind:'action',question,where,
  why:`${action==='signup'?'Signup':action==='login'?'Sign-in':'Account connection'} for ${platform} account ${ref}${account?.product?` (product ${account.product})`:''} is paused until a person completes this step.`,
  brianOnly:true,humanStepId:JSON.stringify([account?.workspace,account?.product,ref,result.flowId??'connect',reason,result.flowId?result.humanRequest?.createdAt:null]),
  ...(resumeHandle?{resumeHandle}:{})};
}

// The caller cannot supply argv. Only owner-registered exact arguments execute.
export async function runAccountCommand(consumer,env,spawnChild){
 const {childEnvironment}=await import('./vault.mjs');
 spawnChild??=(await import('node:child_process')).spawn;
 if(!consumer||typeof consumer.executable!=='string'||!consumer.executable.startsWith('/')||!/^[a-f0-9]{64}$/.test(consumer.contentHash)||!Array.isArray(consumer.args)||consumer.args.some(x=>typeof x!=='string'||x.includes('\0')))throw Error('Invalid registered consumer.');
 if(!env||typeof env!=='object'||Object.values(env).some(x=>typeof x!=='string'||x.includes('\0'))||'ACTAS_BROWSER_STATE' in env)throw Error('Invalid private session.');
 const {open,mkdtemp,writeFile,rm}=await import('node:fs/promises'),{createHash}=await import('node:crypto'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const binary=await open(consumer.executable,'r');let directory;
 try{
  const stat=await binary.stat();if(!stat.isFile()||stat.size>100*1024*1024||stat.mode&0o022)throw Error('Consumer binary must not be writable by its group or others.');
  const bytes=await binary.readFile();if(createHash('sha256').update(bytes).digest('hex')!==consumer.contentHash)throw Error('Registered consumer changed.');
  // Execute a private verified snapshot: replacing the registered path cannot
  // substitute code between validation and exec (portable to macOS).
  directory=await mkdtemp(join(tmpdir(),'actas-consumer-'));
  const executable=join(directory,'consumer');await writeFile(executable,bytes,{mode:0o500,flag:'wx'});
  return await new Promise((resolve,reject)=>{
   let child;try{child=spawnChild(executable,consumer.args,{env:{...childEnvironment(),...env},shell:false,stdio:'ignore'});}catch{reject(Error('Account consumer could not start.'));return;}
   const timer=setTimeout(()=>child.kill('SIGKILL'),30000);
   child.once('error',()=>{clearTimeout(timer);reject(Error('Account consumer could not start.'));});
   child.once('exit',code=>{clearTimeout(timer);resolve({status:code===0?'succeeded':'failed'});});
  });
 }finally{await binary.close();if(directory)await rm(directory,{recursive:true,force:true});}
}
// Same contract as the SDK's vault.login: username/email, password and a current TOTP code, never the seed.
export async function vaultLogin(request,scope,path){
 const read=body=>request('/vault/read','POST',{...scope,path,...body});
 const entry=await read({action:'read'});if(entry.kind!=='login')throw Error('Not a login item.');
 const signInMethod=entry.login?.signInMethod??'password',ssoAccountId=entry.login?.ssoAccountId??null;
 if(!['password','google','github','apple'].includes(signInMethod))throw Error('Invalid login sign-in metadata.');
 const field=async name=>(await read({action:'reveal',field:name})).value||null;
 const [username,email,password]=await Promise.all([field('username'),field('email'),signInMethod==='password'&&entry.login?.hasPassword?field('password'):null]);
 const totp=entry.login?.hasTotp?await read({action:'totp:code'}):null;
 return {path,signInMethod,ssoAccountId,username,email,password,totp:totp?{code:totp.code,secondsRemaining:totp.secondsRemaining}:null};
}
export function createAccountsRuntime({request,codesRequest=request,scope,identityId,browserAdapter,spawnChild,runConsumer,values=new PrivateValues()}){
 const call=(route,body={})=>request('/account-tools'+route,'POST',{...body,...scope});
 const inbox=args=>waitForInbox(args,args.codePattern?codesRequest:request,values);
 const flows=new Map();
 async function saveReport(report){
  const state=flows.get(report.flowId);if(!state||state.accountRef!==report.accountRef||state.uncertain)throw Error('Flow must be reconciled before reporting.');
  const key=JSON.stringify(report);if(state.lastReport===key)return state.latest;
  if(state.saving)throw Error('Flow report already in flight.');state.saving=true;
  try{
   state.latest=await call('/flow/report',{accountRef:state.accountRef,flowId:report.flowId,report,...(state.resumeToken?{resumeToken:state.resumeToken}:{})});
   state.resumeToken=state.latest.resumeToken;state.lastReport=key;return state.latest;
  }catch(error){state.uncertain=true;throw error;}finally{state.saving=false;}
 }
 const adapterOptions={request:(route,method,body)=>request(route,method,body===undefined?undefined:{...body,...scope}),scope,saveReport,waitForInbox:inbox,consumePrivateValue:handle=>values.consume(handle)};
 async function flow(action,args){
  // Without an installed browser adapter do not create a dispatched operation.
  const account=await call('/status',{accountRef:args.accountRef});
  if(account.status==='active'&&action==='signup')return {status:'complete',account,source:'saved_account'};
  if(account.status==='active'&&account.method!=='browser')return call('/flow/start',{accountRef:args.accountRef,action});
  if(!browserAdapter)return {status:'step',step:'inspect_form',reason:'browser_adapter_required',account};
  const started=args.resumeToken?await call('/flow/resume',args):await call('/flow/start',{accountRef:args.accountRef,action});
  if(!started.dispatch)return humanResult(flows.get(started.flowId)?.latest??started,`actas_account_${action}`,args,account,action);
  const state={accountRef:args.accountRef};flows.set(started.flowId,state);
  await browserAdapter.run({version:1,action:started.action??action,flowId:started.flowId,account:started.account,origin:started.origin,...(started.report?{report:started.report}:{})});
  if(!state.latest)throw Error('Browser adapter did not persist its report.');
  return humanResult(state.latest,`actas_account_${action}`,args,account,action);
 }
 return {adapterOptions,setBrowserAdapter(adapter){browserAdapter=adapter;},async invoke(name,args){
  switch(name){
   case 'actas_domains_list':return request('/domains?ownerId='+encodeURIComponent(scope.ownerId));
   case 'actas_domains_add':return request('/domains','POST',{ownerId:scope.ownerId,domain:args.domain});
   case 'actas_domains_verify':return request('/domains/'+encodeURIComponent(args.domain)+'/verify','POST',{});
   case 'actas_domains_remove':return request('/domains/'+encodeURIComponent(args.domain),'DELETE');
   case 'actas_identity_create':{
    const {inbox,...fields}=args,identity=await request('/identities','POST',{...fields,...scope});if(!inbox)return identity;
    const mailbox=await request('/identities/'+encodeURIComponent(identity.id)+'/email','POST',{});
    return {...identity,inbox:{id:mailbox.id,address:mailbox.metadata?.address,status:mailbox.status}};
   }
   case 'actas_inbox_wait_for_code':{
    const result=await codesRequest('/emails/'+encodeURIComponent(args.inboxId)+'/code','POST',{sender:args.sender,subject:args.subject,after:args.after,codePattern:args.pattern??'\\d{6}',timeoutMs:args.timeoutMs??30000});
    return result.status==='matched'?{status:'matched',code:result.code,receivedAt:result.receivedAt}:{status:'pending'};
   }
   case 'actas_messages_search':{const {inboxId,...query}=args;const params=new URLSearchParams();for(const[k,v]of Object.entries(query))if(v!==undefined)params.set(k,String(v));return request('/emails/'+encodeURIComponent(inboxId)+'/messages/search?'+params);}
   case 'actas_message_labels_get':return request('/emails/'+encodeURIComponent(args.inboxId)+'/messages/'+encodeURIComponent(args.messageId)+'/labels');
   case 'actas_message_labels_set':return request('/emails/'+encodeURIComponent(args.inboxId)+'/messages/'+encodeURIComponent(args.messageId)+'/labels','PUT',{userLabels:args.userLabels});
   case 'actas_attachment_list':return request('/emails/'+encodeURIComponent(args.inboxId)+'/messages/'+encodeURIComponent(args.messageId)+'/attachments');
   case 'actas_attachment_download':return request('/emails/'+encodeURIComponent(args.inboxId)+'/messages/'+encodeURIComponent(args.messageId)+'/attachments/'+encodeURIComponent(args.attachmentId)+'/download?encoding=base64&maxBytes=262144');
   case 'actas_events_wait_for':return request('/resources/'+encodeURIComponent(args.resourceId)+'/events/wait','POST',{...(args.cursor===undefined?{}:{cursor:args.cursor}),timeoutMs:args.timeoutMs??30000});
   case 'actas_webhook_create':return request('/resources/'+encodeURIComponent(args.resourceId)+'/webhooks','POST',{endpoint:args.endpoint});
   case 'actas_webhook_list':return request('/resources/'+encodeURIComponent(args.resourceId)+'/webhooks','GET');
   case 'actas_webhook_revoke':return request('/resources/'+encodeURIComponent(args.resourceId)+'/webhooks/'+encodeURIComponent(args.webhookId),'DELETE');
   case 'actas_webhook_deliveries':return request('/resources/'+encodeURIComponent(args.resourceId)+'/webhooks/'+encodeURIComponent(args.webhookId)+'/deliveries','GET');
   case 'actas_passkey_register':return request('/vault/passkeys/register','POST',{...args,...scope});
   case 'actas_passkey_sign':return request('/vault/passkeys/sign','POST',{...args,...scope});
   case 'actas_vault_login':return vaultLogin(request,scope,args.path);
   case 'actas_totp_code':return request('/vault/read','POST',{...scope,path:args.path,action:'totp:code'});
   case 'actas_identity_accounts':{const id=args.identityId??identityId;if(!id)throw Error('Choose an identity for this registry.');return request('/identities/'+encodeURIComponent(id)+'/accounts','GET');}
   case 'actas_identity_account_close':{const result=await request('/identities/'+encodeURIComponent(args.identityId)+'/accounts/'+encodeURIComponent(args.registryId)+'/close','POST',args.revokeProvider===undefined?{}:{revokeProvider:args.revokeProvider});return {...result,accountStatus:result.status,...result.closure};}
   case 'actas_account_list':return call('/list');
   case 'actas_account_status':return call('/status',args);
   case 'actas_account_connect':return humanResult(await call('/connect',args),name,args,undefined,'connect');
   case 'actas_account_revoke':{const account=await call('/status',args),result=await call('/revoke',args);await browserAdapter?.revoke?.(account);return result;}
   case 'actas_account_post':return call('/post',args);
   case 'actas_account_signup':return flow('signup',args);
   case 'actas_account_login':return flow('login',args);
   case 'actas_account_use':{
    if(Object.keys(args).some(k=>!['accountRef','consumerId'].includes(k))||!args.consumerId||!runConsumer)throw Error('An owner-registered consumer and isolated runtime are required.');
    const handle=await call('/use',args);
    const result=await runConsumer({...scope,accountRef:args.accountRef,sessionHandle:handle.sessionHandle});
    return {status:result?.status==='succeeded'?'succeeded':'failed'};
   }
   case 'actas_inbox_wait_for':return inbox(args);
   default:throw Error('Unknown account tool.');
  }
 }};
}
