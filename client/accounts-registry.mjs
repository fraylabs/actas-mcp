import {readIdentityConnection,identityRequest} from './identity.mjs';
export const registryHelp=`ActAs — identity accounts registry
  actas accounts list [identity-id]
  actas accounts close <registry-id> [identity-id] [--revoke-provider]
  actas accounts retire <identity-id> --confirm-retire
Owners and management may close. Agents list only granted records.
Close erases ActAs credentials; follow the returned external-deletion checklist.
`;
export async function runRegistryCommand(args){
 if(args[0]!=='accounts')return false;
 try{
  const [,action,...raw]=args;
  const revokeProvider=raw.includes('--revoke-provider');
  if(revokeProvider&&(action!=='close'||raw.filter(v=>v==='--revoke-provider').length!==1))throw Error(registryHelp);
  const rest=raw.filter(v=>v!=='--revoke-provider');
  if(!['list','close','retire'].includes(action)||action==='list'&&rest.length>1||action==='close'&&(rest.length<1||rest.length>2)||action==='retire'&&(rest.length!==2||rest[1]!=='--confirm-retire'))throw Error(registryHelp);
  const connection=await readIdentityConnection();
  const identity=action==='list'?rest[0]??connection.identityId:action==='close'?rest[1]??connection.identityId:rest[0];
  if(!identity)throw Error('Management connections must select an identity ID.');
  const base='/identities/'+encodeURIComponent(identity)+'/accounts';
  const result=await identityRequest(connection,action==='list'?base:action==='close'?base+'/'+encodeURIComponent(rest[0])+'/close':base+'/retire',action==='list'?'GET':'POST',action==='list'?undefined:action==='close'?(revokeProvider?{revokeProvider:true}:{}):{confirm:'RETIRE ACCOUNTS'});
  process.stdout.write(JSON.stringify(action==='close'?{...result,accountStatus:result.status,...result.closure}:result,null,2)+'\n');
 }catch{process.stderr.write('Accounts registry request failed. Check identity, permissions and command arguments; refresh the list before retrying an uncertain close.\n');process.exitCode=1;}
 return true;
}
