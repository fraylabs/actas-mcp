/** Owner-operated service. Run under a dedicated OS account; its config and
 * credentials must be inaccessible to the agent user. Socket grants operation only. */
import {createServer} from 'node:http';
import {readFile,lstat,chmod,unlink} from 'node:fs/promises';
import {runAccountCommand} from './accounts-mcp-core.mjs';
export function createConsumerService({connection,runtimeCredential,scope,consumers=[],fetcher=fetch,execute=runAccountCommand}){
 let busy=false;
 return createServer(async(req,res)=>{
  const reply=status=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({status}));};
  if(req.method!=='POST'||req.url!=='/use'||busy){reply('failed');return;}
  busy=true;
  try{
   let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>2048)throw Error();}
   const body=JSON.parse(raw);
   if(Object.keys(body).some(k=>!['ownerId','productId','accountRef','sessionHandle'].includes(k))||body.ownerId!==scope.ownerId||body.productId!==scope.productId||typeof body.accountRef!=='string'||typeof body.sessionHandle!=='string')throw Error();
   const response=await fetcher(connection.apiUrl+'/api/v1/account-tools/session/consume',{method:'POST',redirect:'error',headers:{Authorization:'Bearer '+connection.token,'X-ActAs-Runtime':runtimeCredential,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
   if(!response.ok)throw Error();const {data}=await response.json();
   const consumer=consumers.find(pin=>pin.id===data.consumer?.id&&pin.accountRef===body.accountRef);
   if(!consumer||consumer.executable!==data.consumer.executable||consumer.contentHash!==data.consumer.contentHash||JSON.stringify(consumer.args)!==JSON.stringify(data.consumer.args))throw Error();
   const allowed=new Set(['GH_TOKEN','BLUESKY_ACCESS_JWT','BLUESKY_HANDLE','BLUESKY_DID','BLUESKY_SERVICE','REDDIT_ACCESS_TOKEN','REDDIT_USERNAME']);
   if(!data.env||typeof data.env!=='object'||Array.isArray(data.env)||Object.keys(data.env).some(k=>!allowed.has(k)))throw Error();
   const result=await execute(consumer,data.env);reply(result.status==='succeeded'?'succeeded':'failed');
  }catch{reply('failed');}finally{busy=false;}
 });
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 const configPath=process.argv[2];
 try{
  const info=await lstat(configPath);if(!info.isFile()||info.isSymbolicLink()||info.uid!==process.getuid()||info.mode&0o077)throw Error();
  const config=JSON.parse(await readFile(configPath,'utf8'));
  if(!config.socket||!config.runtimeCredential||!config.scope||!config.connection||!Array.isArray(config.consumers)||!config.consumers.length)throw Error();
  try{const socket=await lstat(config.socket);if(!socket.isSocket()||socket.uid!==process.getuid())throw Error();await unlink(config.socket);}catch(error){if(error.code!=='ENOENT')throw error;}
  const server=createConsumerService(config);server.listen(config.socket,async()=>{await chmod(config.socket,0o660);});
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close(async()=>{await unlink(config.socket);process.exit(0);}));
 }catch{process.stderr.write('Private ActAs runtime configuration unavailable.\n');process.exitCode=1;}
}
