/** Compatibility client for the retained controlled-service proof only. */
export class ActAsError extends Error {
 constructor(status,code,message){super(message);this.name='ActAsError';this.status=status;this.code=code;}
}
export class ActAs {
 constructor({url,token}) {
  this.url=(url||'https://actas.dev').replace(/\/$/,'');
  const parsed=new URL(this.url);
  if(parsed.protocol!=='https:' && !(parsed.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(parsed.hostname))) throw new Error('ActAs requires HTTPS, except on loopback for local development.');
  if(!token)throw new Error('An explicitly scoped ActAs API token is required.');
  this.token=token;
 }
 async request(path,{method='GET',body,idempotencyKey}={}) {
  const response=await fetch(this.url+'/api/v1'+path,{method,redirect:'error',headers:{Authorization:`Bearer ${this.token}`,...(body!==undefined?{'Content-Type':'application/json'}:{}),...(idempotencyKey?{'Idempotency-Key':idempotencyKey}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
  const payload=await response.json().catch(()=>null);
  if(!response.ok){const error=new ActAsError(response.status,payload?.error?.code||'request_failed',payload?.error?.message||'ActAs could not complete the request.');error.operation=method+' '+path;throw error;}
  return payload?.data;
 }
 me(){return this.request('/me');}
 list(type,filters={}){return this.request('/resources?'+new URLSearchParams({type,...Object.fromEntries(Object.entries(filters).filter(([,v])=>v!==null&&v!==undefined))}));}
 get(id){return this.request('/resources/'+encodeURIComponent(id));}
 create(resource){return this.request('/resources',{method:'POST',body:resource});}
 update(id,patch){return this.request('/resources/'+encodeURIComponent(id),{method:'PATCH',body:patch});}
 reveal(id){return this.request('/resources/'+encodeURIComponent(id)+'/reveal',{method:'POST'});}
 provisionEmail(resource,idempotencyKey){if(!idempotencyKey)throw new Error('An idempotency key is required.');return this.request('/emails',{method:'POST',body:resource,idempotencyKey});}
 messages(id){return this.request('/emails/'+encodeURIComponent(id)+'/messages');}
 message(id,messageId){return this.request('/emails/'+encodeURIComponent(id)+'/messages/'+encodeURIComponent(messageId));}
 activity(){return this.request('/activity');}
}
