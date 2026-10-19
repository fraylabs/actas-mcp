import {createHash, randomUUID} from 'node:crypto';
import {mkdir, open, readFile, rename, unlink} from 'node:fs/promises';
import {homedir} from 'node:os';
import {isAbsolute, join} from 'node:path';
import {spawn} from 'node:child_process';

const reasons = {
  custodian_action_required: 'Chief must validate the broker request, perform the authorised fresh login in the operations browser, and return a nonsecret observation.',
  broker_scope_denied: 'This broker only permits the assigned Infisical operations account login.',
  authorization_required: 'The site can be inspected, but the account owner must assign this exact origin and account before credential entry or signup submission.',
  verification_pending: 'Signup is saved. Resume after email verification; no duplicate account was requested.',
  account_lookup_failed: 'The mapped existing account could not be retrieved. No signup or login was performed.',
  registry_unavailable: 'The saved account registry could not be updated. Check the registry and connection before continuing; no browser credentials were delivered.',
  vault_unavailable: 'The assigned development vault key could not be read. No browser credentials were delivered.',
  helper_failed: 'The local credential-delivery helper could not start.',
  browser_action_required: 'Continue the returned browser step, preserving required human handoffs and the operation ID.',
  account_exists: 'This development profile maps an existing account. Use login; creating a new account is not enabled for this profile.',
  integration_not_configured: 'No browser account driver is configured. Signup/login has not been performed.',
  human_credential_entry: 'The browser requires a person to enter and submit credentials. Resume after that step.',
  mfa: 'The service requires a human authentication step.',
  captcha: 'The service requires a human verification step.',
  provider_policy: 'The service requires a human approval or onboarding step.',
  unsupported_site: 'The configured driver does not support this website.',
  unverified: 'The driver did not verify a successful signup/login at the requested origin.',
  driver_failed: 'The account driver failed. Its raw output was withheld because it may contain credentials.',
  driver_timeout: 'The account driver timed out. Progress is retained; completion is unknown.',
};

export function targetUrl(input) {
  let url;
  try {url = new URL(input);} catch {throw new Error('Provide a full website URL, such as https://example.com.');}
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname))) {
    throw new Error('Use HTTPS, or loopback HTTP for a local test service.');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Use a public website URL without credentials, query parameters or fragments.');
  }
  return url;
}

async function save(path, state) {
  const temp = `${path}.${randomUUID()}.tmp`;
  const file = await open(temp, 'wx', 0o600);
  try {await file.writeFile(JSON.stringify(state, null, 2)+'\n');} finally {await file.close();}
  await rename(temp, path);
}

function runDriver(executable, request, timeoutMs) {
  return new Promise(resolve => {
    // A trusted, explicitly configured driver. No shell or inherited provider keys.
    const env = Object.fromEntries(['PATH','HOME','TMPDIR','TEMP','SYSTEMROOT'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
    const child = spawn(executable, [], {shell:false, env, stdio:['pipe','pipe','pipe']});
    let stdout = ''; let oversized = false; let timedOut = false;
    const timer = setTimeout(()=>{timedOut=true;child.kill('SIGKILL');}, timeoutMs);
    child.stdout.on('data', chunk => {stdout += chunk.toString();if(Buffer.byteLength(stdout)>65536){oversized=true;child.kill('SIGKILL');}});
    child.stderr.resume(); // Never forward driver output: it can contain secrets.
    child.stdin.on('error',()=>{});
    child.on('error',()=>{clearTimeout(timer);resolve({status:'failed',reason:'driver_failed'});});
    child.on('close',code=>{
      clearTimeout(timer);
      if(timedOut)return resolve({status:'blocked',reason:'driver_timeout'});
      if(code!==0||oversized)return resolve({status:'failed',reason:'driver_failed'});
      try {resolve(JSON.parse(stdout));} catch {resolve({status:'failed',reason:'driver_failed'});}
    });
    child.stdin.end(JSON.stringify(request)+'\n');
  });
}

export async function accountFlow(action, input, options={}) {
  if(!['signup','login'].includes(action))throw new Error('Choose signup or login.');
  const url = targetUrl(input);
  const stateDir = options.stateDir || process.env.ACTAS_STATE_DIR || join(homedir(),'.local','state','actas','accounts');
  const driver = options.driver ?? process.env.ACTAS_ACCOUNT_DRIVER;
  if(driver && !isAbsolute(driver))throw new Error('ACTAS_ACCOUNT_DRIVER must be an absolute path to a trusted executable.');
  await mkdir(stateDir,{recursive:true,mode:0o700});
  // Paths share an operation only within the selected origin/account pair.
  const accountRef=options.accountRef;
  if(accountRef!==undefined&&(typeof accountRef!=='string'||!accountRef))throw new Error('A nonempty account reference is required.');
  const key = createHash('sha256').update(accountRef===undefined?url.origin:JSON.stringify([url.origin,accountRef])).digest('hex');
  const path = join(stateDir,`${action}-${key}.json`);
  const lockPath = join(stateDir,`${key}.lock`);
  let lock;
  try {lock = await open(lockPath,'wx',0o600);} catch(error) {
    if(error.code==='EEXIST')return {status:'blocked',action,origin:url.origin,reason:'operation_in_progress',message:'An account operation is already running for this website. No second operation was started.',exitCode:2};
    throw error;
  }
  try {
    await lock.writeFile(JSON.stringify({pid:process.pid,startedAt:new Date().toISOString()}));
    let previous;
    try {previous=JSON.parse(await readFile(path,'utf8'));} catch(error) {if(error.code!=='ENOENT')throw new Error('Saved operation state could not be read. It was not replaced.');}
    if(previous && (previous.version!==1 || previous.action!==action || previous.origin!==url.origin || previous.accountRef!==accountRef || typeof previous.flowId!=='string'))throw new Error('Saved operation state does not match this request. It was not replaced.');
    if(action==='signup' && previous?.status==='succeeded'&&!options.revalidateSignup)return {...receipt(previous),reused:true,exitCode:0};
    const state = previous && (previous.status!=='succeeded'||action==='signup'&&options.revalidateSignup) ? previous : {version:1,flowId:randomUUID(),action,origin:url.origin,...(accountRef?{accountRef}:{}),url:url.href,createdAt:new Date().toISOString()};
    state.updatedAt=new Date().toISOString();
    state.status='pending';
    delete state.verification;
    delete state.reason;
    await save(path,state); // Preserve the request before any external work.
    let result;
    if(options.execute)result=await options.execute(state);
    else if(!driver)result={status:'blocked',reason:'integration_not_configured'};
    else result=await runDriver(driver,{version:1,flowId:state.flowId,action,url:state.url,origin:state.origin,...(accountRef?{accountRef}:{}),requirements:{respectBrowserHumanTakeover:true,credentialsOutsideOutput:true,verifyAtRequestedOrigin:true}},options.timeoutMs||60000);
    if(result?.status==='succeeded' && result.verification?.origin===url.origin && result.verification?.authenticated===true && ['authenticated_page','provider_api'].includes(result.verification?.method)) {
      state.status='succeeded';
      state.verification={origin:url.origin,authenticated:true,method:result.verification.method,...(result.verification.source==='authorised_caller_observation'?{source:result.verification.source}:{}),...(options.execute&&result.verification.custody==='chief-caller'?{custody:'chief-caller'}:{})};
    } else {
      state.status=result?.status==='needs_custodian'?'needs_custodian':result?.status==='needs_browser'?'needs_browser':result?.status==='needs_human'?'needs_human':result?.status==='blocked'?'blocked':'failed';
      state.reason=Object.hasOwn(reasons,result?.reason)?result.reason:result?.status==='succeeded'?'unverified':'driver_failed';
    }
    if(result?.status==='needs_browser'&&options.execute)state.browser=result.browser;else delete state.browser;
    if(options.execute && result?.brokerRequest)state.brokerRequest=result.brokerRequest;else delete state.brokerRequest;
    if(options.execute && result?.progress)state.progress=result.progress;else delete state.progress;
    state.updatedAt=new Date().toISOString();
    await save(path,state);
    return {...receipt(state),exitCode:state.status==='succeeded'?0:state.status==='failed'?1:2};
  } finally {
    await lock.close();
    await unlink(lockPath);
  }
}

function receipt(state) {
  return {action:state.action,origin:state.origin,...(state.accountRef?{accountRef:state.accountRef}:{}),flowId:state.flowId,status:state.status,
    ...(state.reason?{reason:state.reason,message:reasons[state.reason]}:{}),
    ...(state.verification?{verification:state.verification}:{}),
    ...(state.browser?{browser:state.browser}:{}),
    ...(state.progress?{progress:state.progress}:{}),
    ...(state.brokerRequest?{brokerRequest:state.brokerRequest}:{}),
  };
}
