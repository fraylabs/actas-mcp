#!/usr/bin/env node
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {z} from 'zod';
import {fileURLToPath} from 'node:url';
import {realpathSync} from 'node:fs';
import {readIdentityConnection,identityRequest} from './identity.mjs';
import {createAccountsRuntime} from './accounts-mcp-core.mjs';
import {PrivateValues,validateInboxArgs} from './accounts-inbox.mjs';
import {createBrowserAdapter} from './browser-adapter.mjs';
import {request as socketRequest} from 'node:http';
import {readFile} from 'node:fs/promises';

export {createAccountsMcp} from './accounts-server.mjs';
import {createAccountsMcp} from './accounts-server.mjs';
const ref=z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
export async function main(){
 if(process.argv.includes('--help')||process.argv.includes('-h')){
  process.stdout.write('ActAs MCP — identity, email and scoped accounts for AI agents.\nRequires Node.js 22+ and ActAs Pro.\nActAs Pro: US$12/month or US$120/year plus applicable tax, as of this release. Current price and any free trial: https://actas.dev/pricing\nSet ACTAS_CONNECTION_FILE to your private identity connection JSON file.\nMake the connection in the agent\'s Connection tab in your workspace, and revoke it there.\nStart actas mcp (or actas-accounts-mcp) from a stdio MCP client.\nDocumentation: https://actas.dev/docs\n');return;
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
// npm installs the command as a link, so compare real paths.
const startedDirectly=()=>{try{return realpathSync(process.argv[1])===realpathSync(fileURLToPath(import.meta.url));}catch{return false;}};
if(process.argv[1]&&startedDirectly())main().catch(()=>{process.stderr.write('ActAs accounts MCP could not start. Verify the private connection file and account permissions.\n');process.exitCode=1;});
