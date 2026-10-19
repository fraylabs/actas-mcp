#!/usr/bin/env node
import {runRegistryCommand,registryHelp} from './accounts-registry.mjs';
if(await runRegistryCommand(process.argv.slice(2)))process.exit(process.exitCode||0);
import {runManagementCommand,managementHelp} from './management.mjs';
if(await runManagementCommand(process.argv.slice(2)))process.exit(process.exitCode||0);
import {runVaultCommand,vaultHelp} from './vault.mjs';
if(await runVaultCommand(process.argv.slice(2)))process.exit(process.exitCode||0);
import {runIdentityCommand,identityHelp} from './identity.mjs';
if(await runIdentityCommand(process.argv.slice(2)))process.exit(process.exitCode||0);
import {configureAccount} from './configure.mjs';
import {existsSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {accountFlow,targetUrl} from './accounts.mjs';
import {callerExecutor,loadMappings,selectMapping} from './caller.mjs';
import {externalExecutor} from './external-caller.mjs';
const [action,url,...args]=process.argv.slice(2);
if(action==='configure'){try{if(!url||args.length)throw new Error('Use actas configure <connection.json>.');console.log(JSON.stringify(await configureAccount(url)));}catch(e){console.error(JSON.stringify({status:'failed',message:e.message}));process.exitCode=1;}process.exit(process.exitCode||0);}
if(!action||['help','--help','-h'].includes(action)){
 console.log(registryHelp+"\n"+managementHelp+"\n"+identityHelp+"\n"+vaultHelp);
}else try{
 if(!['signup','login'].includes(action)||!url||args.length%2)throw new Error('Use actas signup <url> or actas login <url>.');
 const flags={};for(let i=0;i<args.length;i+=2){if(!['--account','--continue'].includes(args[i])||flags[args[i]]||!args[i+1])throw new Error('Unknown or repeated option.');flags[args[i]]=args[i+1];}
 const fallback=join(homedir(),'.config','actas','accounts.json');
 const accountsPath=process.env.ACTAS_ACCOUNTS_FILE||(existsSync(fallback)?fallback:undefined);
 const selected=selectMapping(await loadMappings(accountsPath),targetUrl(url).origin,flags['--account']);
 if(selected&&!selected.actions.includes(action))throw new Error('Account action is not authorised.');
 const options={accountsPath,reportPath:flags['--continue']};
 const external=await externalExecutor(options),caller=await callerExecutor(options);
 const {exitCode,...result}=await accountFlow(action,url,{accountRef:selected?.accountRef,execute:async state=>(await external(state))||caller(state)});
 console.log(JSON.stringify(result,null,2));process.exitCode=exitCode;
}catch(error){console.error(JSON.stringify({status:'failed',message:error.message}));process.exitCode=1;}
