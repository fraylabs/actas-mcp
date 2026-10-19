import {readFile} from 'node:fs/promises';
import {targetUrl} from './accounts.mjs';

export async function loadMappings(accountsPath) {
 let mappings=[];try{if(accountsPath)mappings=JSON.parse(await readFile(accountsPath,'utf8'));}catch{throw new Error('Account mappings could not be read.');}
 if(!Array.isArray(mappings)||mappings.some(m=>targetUrl(m.origin).origin!==m.origin||!Array.isArray(m.actions)||m.actions.some(a=>!['signup','login'].includes(a))||typeof m.accountRef!=='string'||typeof m.principal!=='string'||!m.principal||typeof m.custodian!=='string'||typeof m.authenticatedPath!=='string'||!m.authenticatedPath.startsWith('/')))throw new Error('Invalid authorised account mappings.');
 if(new Set(mappings.map(m=>JSON.stringify([m.origin,m.accountRef]))).size!==mappings.length)throw new Error('Duplicate origin/account mapping.');
 return mappings;
}
export function selectMapping(mappings,origin,accountRef) {
 const candidates=mappings.filter(m=>m.origin===origin);
 if(accountRef!==undefined){const selected=candidates.find(m=>m.accountRef===accountRef);if(!selected)throw new Error('The requested account is not assigned to this origin.');return selected;}
 if(candidates.length>1)throw new Error('Multiple accounts are assigned to this origin. Choose --account: '+candidates.map(m=>m.accountRef).join(', '));
 return candidates[0];
}
// Authority comes from owner configuration, never browser content or reports.
export async function callerExecutor({accountsPath,reportPath,brokerHandler}={}) {
 const mappings=await loadMappings(accountsPath);
 let report;try{if(reportPath)report=JSON.parse(await readFile(reportPath,'utf8'));}catch{throw new Error('Browser continuation could not be read.');}
 return async state=>{
  const selected=selectMapping(mappings,state.origin,state.accountRef);
  if(selected?.broker){if(!brokerHandler||selected.broker.kind!=='chief-infisical-caller')return {status:'blocked',reason:'broker_scope_denied'};return brokerHandler(state,selected,report);}
  const mapping=selected?.actions.includes(state.action)?selected:undefined;
  const browser={url:state.url,flowId:state.flowId,step:state.browser?.step||(state.progress?.step==='authorize_account'?undefined:state.progress?.step)||(mapping?'inspect_form':'assess_site'),credentialCustody:'external',...(mapping?{accountRef:mapping.accountRef,custodian:mapping.custodian,principal:mapping.principal,...(mapping.organization?{organization:mapping.organization}:{})}:{})};
  if(!report&&state.progress?.step&&['mfa','captcha','provider_policy','human_credential_entry'].includes(state.progress.step))return {status:'needs_human',reason:state.progress.step,progress:state.progress};
  if(!report)return {status:'needs_browser',reason:'browser_action_required',browser};
  if(report.flowId!==state.flowId||report.origin!==state.origin)return {status:'failed',reason:'unverified'};
  if(!mapping)return {status:'needs_human',reason:'authorization_required',progress:{step:'authorize_account'}};
  if(['mfa','captcha','provider_policy','human_credential_entry'].includes(report.handoff))return {status:'needs_human',reason:report.handoff,progress:{step:report.handoff}};
  const steps=['inspect_form','enter_credentials','submit','verify_email','verify_session'];
  if(steps.includes(report.step))return {status:'needs_browser',reason:'browser_action_required',browser:{...browser,step:report.step}};
  if(report.authenticated===true&&report.step==='complete'&&typeof report.observedUrl==='string'){
   let observed;try{observed=targetUrl(report.observedUrl)}catch{return {status:'failed',reason:'unverified'}}
   if(observed.origin!==mapping.origin||typeof mapping.authenticatedPath!=='string'||observed.pathname!==mapping.authenticatedPath||report.accountRef!==mapping.accountRef||report.principal!==mapping.principal||(mapping.organization&&report.organization!==mapping.organization)||!Number.isFinite(Date.parse(report.observedAt))||Date.parse(report.observedAt)>Date.now()||Date.now()-Date.parse(report.observedAt)>300000)return {status:'failed',reason:'unverified'};
   return {status:'succeeded',verification:{origin:state.origin,authenticated:true,method:'authenticated_page',source:'authorised_caller_observation'}};
  }
  return {status:'failed',reason:'unverified'};
 };
}
