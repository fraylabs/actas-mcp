#!/usr/bin/env node
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {z} from 'zod';
import {pathToFileURL} from 'node:url';
import {readIdentityConnection,identityRequest} from './identity.mjs';
import {createAccountsRuntime} from './accounts-mcp-core.mjs';
import {PrivateValues,validateInboxArgs} from './accounts-inbox.mjs';
import {createBrowserAdapter} from './browser-adapter.mjs';
import {request as socketRequest} from 'node:http';
import {readFile} from 'node:fs/promises';

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
export async function main(){
 if(process.argv.includes('--help')||process.argv.includes('-h')){
  process.stdout.write('ActAs MCP — identity, email and scoped accounts for AI agents.\nRequires Node.js 22+ and ActAs Pro (US$12/month or US$120/year).\nSet ACTAS_CONNECTION_FILE to your private identity connection JSON file.\nStart actas-accounts-mcp from a stdio MCP client.\nDocumentation: https://actas.dev/docs\n');return;
 }
 const connection=await readIdentityConnection(),request=(route,method='GET',body)=>identityRequest(connection,route,method,body);
 const identity=connection.kind==='management'?null:await request('/identities/'+connection.identityId);
 const scope={ownerId:identity?.ownerId??connection.ownerId,productId:identity?identity.productId:process.env.ACTAS_PRODUCT_ID??null};
 // Trusted operator configuration contains selectors/inbox filters, never credentials or executable code.
 let browserOptions={};
 if(process.env.ACTAS_BROWSER_CONFIG_FILE){
  const raw=await readFile(process.env.ACTAS_BROWSER_CONFIG_FILE,'utf8');if(raw.length>65536)throw Error('Browser configuration too large.');
  browserOptions=JSON.parse(raw);
  if(!browserOptions||Array.isArray(browserOptions)||Object.keys(browserOptions).some(k=>!['stateDir','emailRules'].includes(k))||browserOptions.stateDir!==undefined&&(typeof browserOptions.stateDir!=='string'||!browserOptions.stateDir))throw Error('Invalid browser configuration.');
  const rules=browserOptions.emailRules??{};
  if(!rules||typeof rules!=='object'||Array.isArray(rules))throw Error('Invalid email rules.');
  for(const [accountRef,rule] of Object.entries(rules)){
   ref.parse(accountRef);
   if(!rule||typeof rule!=='object'||Array.isArray(rule)||Object.keys(rule).some(k=>!['selector','submitSelector','match'].includes(k))||typeof rule.selector!=='string'||!rule.selector||rule.selector.length>1024||typeof rule.submitSelector!=='string'||!rule.submitSelector||rule.submitSelector.length>1024)throw Error('Invalid email rule.');
   validateInboxArgs(rule.match);
  }
 }
 // Codes connections hold only emails:codes, so they ride alongside the main connection.
 const codes=process.env.ACTAS_CODES_CONNECTION_FILE?await readIdentityConnection(process.env.ACTAS_CODES_CONNECTION_FILE):null;
 const codesRequest=codes?(route,method='GET',body)=>identityRequest(codes,route,method,body):request;
 const values=new PrivateValues(),runtime=createAccountsRuntime({request,codesRequest,scope,identityId:connection.identityId,values,runConsumer:process.env.ACTAS_RUNTIME_SOCKET?body=>new Promise((resolve,reject)=>{const req=socketRequest({socketPath:process.env.ACTAS_RUNTIME_SOCKET,path:'/use',method:'POST',timeout:35000},res=>{let raw='';res.on('data',b=>{raw+=b;if(raw.length>1024)req.destroy();});res.on('end',()=>{try{resolve(JSON.parse(raw));}catch{reject(Error('Runtime unavailable'));}});});req.on('error',()=>reject(Error('Runtime unavailable')));req.on('timeout',()=>req.destroy());req.end(JSON.stringify(body));}):undefined});
 const adapter=createBrowserAdapter({...browserOptions,...runtime.adapterOptions});runtime.setBrowserAdapter(adapter);
 const server=createAccountsMcp(runtime);
 let closing;
 const close=()=>closing??=Promise.resolve().then(async()=>{await adapter.close();await server.close();}).catch(()=>{});
 server.server.onclose=()=>{void close();};
 for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{void close();});
 await server.connect(new StdioServerTransport());
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.stderr.write('ActAs accounts MCP could not start. Verify the private connection file and account permissions.\n');process.exitCode=1;});
