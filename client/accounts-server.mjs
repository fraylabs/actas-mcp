import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {z} from 'zod';

const ref=z.string().regex(/^[A-Za-z0-9_-]{1,80}$/),path=z.string().regex(/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/).max(512);
const select={accountRef:ref};
export function createAccountsMcp(runtime){
 const server=new McpServer({name:'actas-accounts',version:'0.1.0'},{maxToolInputElements:300});
 const definitions=[
  ['actas_identity_create','Create an identity with a permanently reserved chosen email name (management). inbox:true also allocates its inbox.',{name:z.string().min(1).max(80),localPart:z.string().min(3).max(40).optional(),domain:z.string().min(3).max(253).optional(),inbox:z.boolean().optional()}],
  ['actas_inbox_wait_for_code','Wait up to 60s for one sign-in code from an authenticated sender (emails:codes). Returns only the code.',{inboxId:z.string().min(1).max(160),sender:z.string().email().max(254),subject:z.string().min(1).max(200),after:z.string().datetime(),pattern:z.string().regex(/^(?:\\d|\[A-Z0-9\])\{(?:[4-9]|1[0-2])\}$/).optional(),timeoutMs:z.number().int().min(0).max(60000).optional()}],
  ['actas_vault_login','Return a granted login item: username/email, password and a current TOTP code. Never the TOTP seed (secrets:reveal plus read, reveal and totp:code grants).',{path}],
  ['actas_domains_list','List workspace domains and exact DNS records (domain management).',{}],
  ['actas_domains_add','Claim a workspace mail domain (domain management); reconcile by checking the same domain.',{domain:z.string().min(3).max(253)}],
  ['actas_domains_verify','Check ownership, DKIM and MX and reconcile SES setup (domain management).',{domain:z.string().min(3).max(253)}],
  ['actas_domains_remove','Permanently retire a domain and stop delivery (domain management).',{domain:z.string().min(3).max(253)}],
  ['actas_totp_code','Return only a granted current six-digit TOTP code and seconds remaining.',{path}],
  ['actas_account_list','List accounts granted to this product agent.',{}],
  ['actas_identity_accounts','List this identity’s registry. Agents see only granted accounts.',{identityId:z.string().min(1).max(160).optional()}],
  ['actas_identity_account_close','Remove all ActAs grants and saved login; return external-deletion checklist (owner/management).',{identityId:z.string().min(1).max(160),registryId:z.string().min(1).max(512),revokeProvider:z.boolean().optional()}],
  ['actas_account_status','Read account status without exposing credentials.',select],
  ['actas_account_connect','Connect and verify official API credentials saved in the product vault (owner/management).',{...select,platform:z.enum(['bluesky','github','reddit','x','instagram','discord']),handle:z.string().regex(/^[A-Za-z0-9_.-]+$/).max(120),email:z.string().email().max(254),identityId:z.string().min(1).max(160).optional(),secretRefs:z.record(z.enum(['token','appPassword','clientId','clientSecret','password','appId','installationId','privateKey']),path).optional()}],
  ['actas_account_signup','Start or resume a saved account signup; pause for platform human checks.',{...select,resumeToken:z.string().max(160).optional()}],
  ['actas_account_login','Start or resume login for a saved account.',{...select,resumeToken:z.string().max(160).optional()}],
  ['actas_account_use','Run an owner-registered fixed consumer in the isolated ActAs runtime.',{...select,consumerId:z.string().uuid()}],
  ['actas_account_post','Post through a fixed official API action without exposing credentials.',{...select,action:z.enum(['post','issue','submit','comment']),target:z.string().max(180).optional(),title:z.string().max(300).optional(),text:z.string().min(1).max(10000)}],
  ['actas_account_revoke','Revoke future ActAs account use and pending handles (owner/management).',select],
  ['actas_inbox_wait_for','Wait for a received verification message. Returns a private value handle; never the code/link.',{emailId:z.string().min(1).max(160),sender:z.string().email().max(254),subject:z.string().min(1).max(200),after:z.string().datetime(),linkOrigin:z.string().url().optional(),linkPath:z.string().max(1024).optional(),codePattern:z.string().max(30).optional(),timeoutMs:z.number().int().min(0).max(30000).optional()}]
 ];
 for(const [name,description,shape] of definitions)server.registerTool(name,{description,inputSchema:z.object(shape).strict()},async args=>{
  try{const result=await runtime.invoke(name,args);return {content:[{type:'text',text:JSON.stringify(result)}]};}
  catch{return {isError:true,content:[{type:'text',text:'ActAs account operation failed. Check account status and permissions before retrying; no automatic retry was made.'}]};}
 });
 return server;
}
