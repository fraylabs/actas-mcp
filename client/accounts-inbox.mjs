import {randomBytes} from 'node:crypto';
import {mailContent} from './mail-content.mjs';

// Values never leave this trusted runtime through MCP. Handles expire and consume once.
export class PrivateValues {
 #values=new Map();
 constructor(now=Date.now){this.now=now;}
 put(value){for(const [key,item] of this.#values)if(item.expiresAt<=this.now())this.#values.delete(key);if(this.#values.size>=1000)throw Error('Private value capacity reached.');const handle=randomBytes(32).toString('base64url'),expiresAt=this.now()+60000;this.#values.set(handle,{value,expiresAt});return {valueHandle:handle,expiresAt};}
 consume(handle){const item=this.#values.get(handle);this.#values.delete(handle);if(!item||item.expiresAt<=this.now())throw Error('Private value is unavailable.');return item.value;}
}
function senderAddress(value){if(typeof value!=='string')return '';const match=/^(?:[^<>]*<)?([^<>\s]+@[^<>\s]+)>?$/.exec(value.trim());return match?.[1].toLowerCase()??'';}
export function validateInboxArgs(args){
 const keys=['emailId','sender','subject','after','linkOrigin','linkPath','codePattern','timeoutMs'];if(!args||Object.keys(args).some(k=>!keys.includes(k)))throw Error('Invalid inbox request.');
 if(typeof args.emailId!=='string'||!args.emailId||args.emailId.length>160||typeof args.sender!=='string'||!/^\S+@\S+\.\S+$/.test(args.sender)||args.sender.length>254||typeof args.subject!=='string'||!args.subject||args.subject.length>200||typeof args.after!=='string'||!Number.isFinite(Date.parse(args.after))||Date.parse(args.after)>Date.now())throw Error('Invalid inbox request.');
 if(args.codePattern){if(args.linkOrigin||args.linkPath||! /^(?:\\d|\[A-Z0-9\])\{(?:[4-9]|1[0-2])\}$/.test(args.codePattern))throw Error('Use a bounded digit or uppercase code pattern.');}
 else{const url=new URL(args.linkOrigin);if(url.protocol!=='https:'||url.origin!==args.linkOrigin||typeof args.linkPath!=='string'||!args.linkPath.startsWith('/')||/[?#\\]/.test(args.linkPath))throw Error('Use an exact HTTPS link origin and path.');}
 if(args.timeoutMs!==undefined&&(!Number.isInteger(args.timeoutMs)||args.timeoutMs<0||args.timeoutMs>30000))throw Error('Invalid timeout.');return args;
}
export function verificationValue(message,args,now=Date.now()){
 const data=mailContent(message);if(!data)return;
 const timestamp=Date.parse(message.timestamp),after=Date.parse(args.after);
 if(!message.labels?.includes('received')||!Number.isFinite(timestamp)||timestamp<after||timestamp>now||senderAddress(data.from)!==args.sender.toLowerCase()||data.subject!==args.subject||typeof data.text!=='string')return;
 // ActAs wraps received mail as untrusted; match only the body, and only
 // when ActAs authenticated the sender's domain.
 if(message.sender_check?.domain_verified!==true)return;
 const body=data.text.slice(0,200*1024);
 if(args.codePattern){const re=new RegExp(`(?:^|[^A-Za-z0-9])(${args.codePattern})(?=$|[^A-Za-z0-9])`),match=re.exec(body);return match?.[1];}
 for(const candidate of body.match(/https:\/\/[^\s<>"']+/g)??[]){try{const url=new URL(candidate);if(url.origin===args.linkOrigin&&url.pathname===args.linkPath&&!url.username&&!url.password&&!url.hash)return url.href;}catch{}}
}
export async function waitForInbox(args,request,values){
 validateInboxArgs(args);
 const query={sender:args.sender,subject:args.subject,after:args.after,timeoutMs:args.timeoutMs??0};
 const route='/emails/'+encodeURIComponent(args.emailId)+(args.codePattern?'/code':'/link');
 if(args.codePattern)query.codePattern=args.codePattern;
 else{query.urlHost=new URL(args.linkOrigin).hostname;query.urlPathPrefix=args.linkPath;}
 // Server waits on push and checks authenticated sender/exact subject/scope. No
 // message list/detail or body retrieval occurs in the local runtime.
 const result=await request(route,'POST',query);
 if(result.status!=='matched')return {status:'pending',...(result.reason?{reason:result.reason}:{})};
 const value=args.codePattern?result.code:result.url;
 if(typeof value!=='string')throw Error('Invalid verification result.');
 if(!args.codePattern){const u=new URL(value);if(u.origin!==args.linkOrigin||u.pathname!==args.linkPath||u.username||u.password||u.hash)throw Error('Verification link outside scope.');}
 return {status:'matched',...values.put(value)};
}
