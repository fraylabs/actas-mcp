import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {mkdir, open, readFile, rename, unlink, chmod, rm, mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {targetUrl} from '../accounts.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const reasons = new Set(['captcha', 'mfa', 'phone', 'provider_policy', 'human_credential_entry']);
const instructions = {
  captcha: ['complete the human check', 'requires a human check'],
  mfa: ['complete the authentication challenge', 'requires multi-factor authentication'],
  phone: ['complete the phone verification', 'requires phone verification'],
  provider_policy: ['review and complete the approval shown', 'requires your approval'],
  human_credential_entry: ['enter your account credentials and submit', 'requires your credentials'],
};
async function writePrivate(path, value) {
  const tmp = `${path}.${randomUUID()}.tmp`;
  const file = await open(tmp, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(value)); } finally { await file.close(); }
  await rename(tmp, path);
}
function scope(account) {
  for (const key of ['workspace', 'product', 'platform', 'accountRef']) {
    if (key === 'product' && account?.product === null) continue;
    if (typeof account?.[key] !== 'string' || !account[key] || account[key].length > 256) throw Error('Invalid browser account scope.');
  }
  return Object.fromEntries(['workspace', 'product', 'platform', 'accountRef'].map(k => [k, account[k]]));
}

/** Local long-lived service; adapters are trusted code, never supplied by model input.
 * authorize must check current grants AND revocation on every call. Vault adapters
 * enforce the same scope server-side. Raw state is passed only to vault adapters.
 */
export class BrowserHandoffRunner {
  constructor({stateDir, authorize, vault, providers, launch, notifier = async () => {}, inbox,
    now = Date.now, pollMs = 1000, humanTimeoutMs = 86400000}) {
    if (!stateDir || !authorize || !vault?.save || !vault?.load || !providers) throw Error('Browser adapters are required.');
    if (!Number.isFinite(pollMs) || pollMs < 1 || !Number.isFinite(humanTimeoutMs) || humanTimeoutMs < 1 || humanTimeoutMs > 86400000) throw Error('Invalid browser deadlines.');
    Object.assign(this, {stateDir: resolve(stateDir), authorize, vault, providers, launch, notifier, inbox, now, pollMs, humanTimeoutMs});
    this.jobs = new Map();
  }
  async allowed(account, action = 'account:manage') {
    if (await this.authorize(scope(account), action) !== true) throw Error('Browser account access denied.');
  }
  key(account) { return digest(JSON.stringify(scope(account))); }
  path(account) { return join(this.stateDir, this.key(account)); }
  async read(account) {
    try { return JSON.parse(await readFile(join(this.path(account), 'operation.json'), 'utf8')); }
    catch (e) { if (e.code === 'ENOENT') return undefined; throw Error('Browser progress unreadable; reconcile before retrying.'); }
  }
  async persist(job) { await writePrivate(join(this.path(job.account), 'operation.json'), job.state); }
  receipt(state, token) {
    return {version: 1, flowId: state.flowId, action: state.action, origin: state.origin,
      accountRef: state.accountRef, status: state.status, step: state.step,
      ...(state.reason ? {reason: state.reason} : {}),
      ...(state.humanRequest ? {humanRequest: state.humanRequest} : {}),
      ...(token ? {resumeToken: token} : {}),
      ...(state.lastVerifiedAt ? {lastVerifiedAt: state.lastVerifiedAt} : {})};
  }
  async status(account) {
    await this.allowed(account, 'account:use');
    const state = await this.read(account);
    return state ? this.receipt(state) : {status: 'pending', step: 'not_started'};
  }
  async start({account, action, url, flowId = randomUUID()}) {
    await this.allowed(account);
    if (!['signup', 'login'].includes(action)) throw Error('Invalid browser action.');
    const current = this.jobs.get(this.key(account));
    if (current?.flight) await current.flight;
    if (current && this.jobs.has(this.key(account))) return this.receipt(current.state);
    const target = targetUrl(url), provider = this.providers[account.platform];
    if (!provider || !provider.origins.includes(target.origin)) throw Error('Unsupported browser target.');
    await mkdir(this.stateDir, {recursive: true, mode: 0o700});

    await mkdir(this.path(account), {recursive: true, mode: 0o700});
    await chmod(this.path(account), 0o700);
    const lock = await this.lock(account);
    let job;
    try {
      const previous = await this.read(account);
      // Never repeat uncertain signup/submit operations, including after a crash.
      if (previous && (previous.flowId === flowId || !['complete', 'revoked'].includes(previous.status))) {
        await this.unlock(account, lock);
        return this.receipt(previous);
      }
      if (previous?.status === 'revoked') throw Error('Account revoked; reconnect through account management.');
      const state = {version: 1, ...scope(account), flowId, action, origin: target.origin,
        url: target.href, status: 'step', step: 'inspect_form', acted: [], notified: [], createdAt: new Date(this.now()).toISOString()};
      job = {account: {...account}, provider, state, lock};
      await this.persist(job);
      await this.open(job);
      this.jobs.set(this.key(account), job);
      const result = await this.tick(job);
      this.schedule(job);
      return result;
    } catch {
      if (job) { job.state.status = 'failed'; job.state.reason = 'browser_failed'; await this.persist(job); await this.close(job); }
      else await this.unlock(account, lock);
      throw Error('Browser could not start; inspect saved progress before retrying.');
    }
  }
  async lock(account) {
    try { return await open(join(this.path(account), 'runner.lock'), 'wx', 0o600); }
    catch { throw Error('Browser operation locked; reconcile the existing runner before retrying.'); }
  }
  async unlock(account, lock) {
    if (!lock) return;
    await lock.close();
    await unlink(join(this.path(account), 'runner.lock'));
  }
  async open(job) {
    await rm(join(this.path(job.account),'profile'),{recursive:true,force:true});
    const profile = await mkdtemp(join(tmpdir(),'actas-browser-'));
    job.profile = profile;
    await chmod(profile, 0o700);
    const launch = this.launch || (async path => {
      const {chromium} = await import('playwright');
      const browser=await chromium.launch({headless:false,chromiumSandbox:true,ignoreDefaultArgs:['--use-mock-keychain']});
      const context=await browser.newContext({acceptDownloads:false});
      const close=context.close.bind(context);context.close=async()=>{try{await close();}finally{await browser.close();}};
      return context;
    });
    job.context = await launch(profile);
    const saved = await this.vault.load(scope(job.account));
    // Vault restore is only for a fresh operation, never overwrites a human's
    // in-progress profile when continuing a challenge.
    if (saved && job.state.step === 'inspect_form') await job.context.setStorageState(saved);
    job.page = job.context.pages()[0] || await job.context.newPage();
    let url = job.state.url;
    if (job.state.humanRequest && this.vault.loadProgress) {
      const progress = await this.vault.loadProgress(scope(job.account));
      if (progress?.flowId === job.state.flowId && job.provider.origins.includes(new URL(progress.url).origin)) {
        await job.context.setStorageState(progress.storage); url = progress.url;
      }
    }
    await job.page.goto(url);
    await job.page.bringToFront();
  }
  schedule(job) {
    if (!this.jobs.has(this.key(job.account)) || job.timer || ['complete', 'failed', 'revoked'].includes(job.state.status)) return;
    if (job.state.humanRequest && this.now() >= Date.parse(job.state.humanRequest.expiresAt)) return;
    job.timer = setTimeout(async () => {
      job.timer = undefined;
      try { await this.tick(job); }
      catch { job.state.status = 'failed'; job.state.reason = 'browser_failed'; await this.persist(job).catch(() => {}); await this.close(job); }
      this.schedule(job);
    }, this.pollMs);
    job.timer.unref?.();
  }
  async tick(job) {
    // Single flight prevents a timer and explicit resume from submitting twice.
    if (job.flight) return job.flight;
    job.flight = this.advance(job);
    try { return await job.flight; } finally { job.flight = undefined; }
  }
  async advance(job) {
    await this.allowed(job.account);
    const s = job.state;
    if (s.humanRequest && this.now() >= Date.parse(s.humanRequest.expiresAt)) return this.receipt(s);
    const observation = await job.provider.observe(job.page, job.account, s.action);
    if (observation.kind === 'authenticated') {
      // A provider verifier must establish the expected account at an allowed
      // origin. Disappearing CAPTCHA or changed URL alone is never completion.
      if (!job.provider.origins.includes(new URL(job.page.url()).origin) ||
        await job.provider.verify(job.page, job.account) !== true) throw Error('Unverified browser account.');
      await this.allowed(job.account);
      await this.vault.save(scope(job.account), await job.context.storageState({indexedDB: true}));
      s.status = 'complete'; s.step = 'verify_session'; s.lastVerifiedAt = new Date(this.now()).toISOString();
      delete s.reason; delete s.humanRequest; delete s.resumeDigest;
      await this.persist(job);
      await this.close(job);
      return this.receipt(s);
    }
    if (observation.kind === 'human') {
      const reason = reasons.has(observation.reason) ? observation.reason : 'provider_policy';
      const id = `${reason}:${observation.id || reason}`;
      if (s.humanId !== id) {
        s.humanId = id; delete s.humanRequest; delete s.resumeDigest;
      }
      if (!s.humanRequest) {
        const token = randomBytes(32).toString('base64url');
        const [instruction, why] = instructions[reason];
        s.status = 'needs_human'; s.step = 'human'; s.reason = reason;
        s.resumeDigest = digest(token);
        const requestedAt=this.now();
        s.humanRequest = {text: `In the ActAs browser window at ${s.origin}, ${instruction}. This service ${why}.`,
          openedUrl: s.origin, createdAt: new Date(requestedAt).toISOString(), expiresAt: new Date(requestedAt + this.humanTimeoutMs).toISOString()};
        // Persist deduplication BEFORE delivery. Uncertain delivery is never retried.
        const notify = !s.notified.includes(id);
        if (notify) s.notified.push(id);
        if (this.vault.saveProgress) await this.vault.saveProgress(scope(job.account), {flowId: s.flowId, url: job.page.url(), storage: await job.context.storageState({indexedDB: true})});
        await this.persist(job);
        await job.page.bringToFront();
        if (notify) { try { await this.notifier(this.receipt(s)); } catch { /* Caller receives the same request. */ } }
        return this.receipt(s, token);
      }
      return this.receipt(s);
    }
    delete s.humanRequest; delete s.reason; delete s.resumeDigest; delete s.humanId;
    s.status = 'step'; if (s.step === 'human') s.step = 'inspect_form';
    if (observation.kind === 'email') {
      if (!this.inbox || !job.provider.verifyEmail) throw Error('Product inbox adapter required.');
      const id = `email:${observation.id}`;
      if (!s.acted.includes(id)) {
        s.status = 'step'; s.step = 'verify_email'; await this.persist(job);
        // The inbox adapter validates product scope, sender, subject and since;
        // the message/code stays entirely inside tool code, never a receipt.
        await this.allowed(job.account);
        const message = await this.inbox.waitFor(scope(job.account), observation.match);
        if (message === undefined) return this.receipt(s);
        await this.allowed(job.account);
        s.acted.push(id); await this.persist(job);
        await job.provider.verifyEmail(job.page, message, job.account);
      }
    } else if (observation.kind === 'step' && typeof observation.id === 'string') {
      if (!s.acted.includes(observation.id)) {
        s.acted.push(observation.id); s.status = 'step'; s.step = observation.id;
        await this.persist(job); // Write-ahead: no automatic submission retry on crash.
        await job.provider.advance(job.page, observation.id, job.account, s.action);
      }
    } else if (observation.kind !== 'waiting') throw Error('Unknown browser observation.');
    await this.persist(job);
    return this.receipt(s);
  }
  async resume({account, flowId, resumeToken}) {
    await this.allowed(account);
    let job = this.jobs.get(this.key(account));
    const s = job?.state || await this.read(account);
    if (!s || s.flowId !== flowId || typeof resumeToken !== 'string' || s.resumeDigest !== digest(resumeToken) ||
      !s.humanRequest || this.now() >= Date.parse(s.humanRequest.expiresAt)) throw Error('Invalid or expired browser continuation.');
    // Consume before any awaited browser work, including concurrent resumes.
    delete s.resumeDigest;
    if (!job) {
      const lock = await this.lock(account);
      job = {account: {...account}, provider: this.providers[account.platform], state: s, lock};
      await this.persist(job);
      try { await this.open(job); } catch { await this.close(job); throw Error('Browser continuation could not open.'); }
      this.jobs.set(this.key(account), job);
    } else await this.persist(job);
    const result = await this.tick(job); this.schedule(job); return result;
  }
  // Only the trusted core calls this after its server-side resume token check.
  async continueTrusted({account, flowId}) {
    await this.allowed(account);
    let job = this.jobs.get(this.key(account));
    const state = job?.state || await this.read(account);
    if (!state || state.flowId !== flowId) throw Error('Browser flow mismatch.');
    if (['complete', 'failed', 'revoked'].includes(state.status)) return this.receipt(state);
    if (!job) {
      const lock = await this.lock(account);
      job = {account: {...account}, provider: this.providers[account.platform], state, lock};
      try { await this.open(job); } catch { await this.close(job); throw Error('Browser continuation could not open.'); }
      this.jobs.set(this.key(account), job);
    }
    const result = await this.tick(job); this.schedule(job); return result;
  }
  async close(job) {
    clearTimeout(job.timer); job.timer = undefined;
    try { await job.context?.close(); } finally {
      const lock = job.lock; job.lock = undefined;
      await rm(job.profile || join(this.path(job.account),'profile'),{recursive:true,force:true});
      await this.unlock(job.account, lock); this.jobs.delete(this.key(job.account));
    }
  }
  async revoke(account) {
    const job=this.jobs.get(this.key(account));if(job){if(job.flight)await job.flight.catch(()=>{});await this.close(job);}
    await rm(this.path(account),{recursive:true,force:true});
  }
  async shutdown() {
    for (const job of [...this.jobs.values()]) { if (job.flight) await job.flight.catch(() => {}); await this.close(job); }
  }
}
