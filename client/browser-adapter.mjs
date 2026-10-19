import {homedir} from 'node:os';
import {join} from 'node:path';
import {BrowserHandoffRunner} from './browser/runner.mjs';
import {createBrowserProviders} from './browser/providers.mjs';

/** Accounts MCP v1 boundary. All API bodies are scoped by trusted core options. */
export function createBrowserAdapter(options) {
  const {request, scope, waitForInbox, consumePrivateValue, saveReport} = options;
  if (!request || !scope?.ownerId || typeof saveReport !== 'function') throw Error('Scoped browser API connection required.');
  const body = data => ({...data, ownerId: scope.ownerId, productId: scope.productId ?? null});
  const path = (account, suffix) => `/accounts_browser/${account.accountRef}_${suffix}`;
  async function load(account, suffix) {
    try {
      const result = await request('/account-tools/flow/store', 'POST', body({accountRef:account.accountRef,flowId:activeFlows.get(account.accountRef)?.flowId,...(activeFlows.get(account.accountRef)?.resumeToken?{resumeToken:activeFlows.get(account.accountRef).resumeToken}:{}),store:suffix}));
      return JSON.parse(result.value);
    } catch { return undefined; } // Missing state requires verification, never success.
  }
  async function save(account, suffix, value) {
    await request('/account-tools/flow/store', 'POST', body({accountRef:account.accountRef,flowId:activeFlows.get(account.accountRef)?.flowId,...(activeFlows.get(account.accountRef)?.resumeToken?{resumeToken:activeFlows.get(account.accountRef).resumeToken}:{}),store:suffix,value:JSON.stringify(value)}));
    return path(account, suffix);
  }
  const reports = new Map();
  const activeFlows = new Map();
  const toReport = state => {
    const account = reports.get(state.flowId)?.account;
    return {flowId: state.flowId, accountRef: state.accountRef, origin: state.origin,
      step: state.status === 'complete' ? 'complete' : state.step === 'human' || state.step.startsWith('enter_credentials') ? 'enter_credentials' : state.step.startsWith('submit') ? 'submit' : state.step,
      ...(state.humanRequest ? {handoff: state.reason === 'phone' ? 'mfa' : state.reason, humanRequest: state.humanRequest} : {}),
      ...(state.status === 'complete' ? {authenticated: true, principal: account.handle, observedUrl: state.origin,
        observedAt: state.lastVerifiedAt, browserState: path(account, 'state')} : {})};
  };
  async function persistReport(report) {
    const metadata = reports.get(report.flowId);
    if (JSON.stringify(metadata.report) === JSON.stringify(report)) return;
    if (metadata.uncertain) throw Error('Browser report delivery uncertain; reconcile before retrying.');
    metadata.uncertain = true; // Never repeat a possibly accepted core mutation.
    const result=await saveReport(report);
    metadata.resumeToken=result?.resumeToken;
    metadata.report = report; delete metadata.uncertain;
  }
  const runner = new BrowserHandoffRunner({
    stateDir: options.stateDir || join(homedir(), '.local', 'state', 'actas', 'browser'),
    launch: options.launch, pollMs: options.pollMs,
    providers: options.providers || createBrowserProviders({emailRules: options.emailRules, async credentials(account) {
      const ref = account.secretRefs?.password;
      if (typeof ref !== 'string' || !/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(ref)) throw Error('Invalid credential reference.');
      const result = await request('/vault/read', 'POST', body({path: ref, action: 'reveal'}));
      return {password: result.value};
    }}),
    async authorize(account, action) {
      if (account.workspace !== scope.ownerId || account.product !== (scope.productId ?? null)) return false;
      const current = await request('/account-tools/status', 'POST', body({accountRef: account.accountRef}));
      const record = current.account || current;
      if (record.status === 'revoked' || record.workspace !== account.workspace || record.product !== account.product) return false;
      if (action === 'account:manage') {
        const metadata = activeFlows.get(account.accountRef);
        if (!metadata) return false;
        await request('/account-tools/flow/check', 'POST', body({accountRef: account.accountRef, flowId: metadata.flowId}));
      }
      return true;
    },
    vault: {load: a => load(a, 'state'), save: (a, value) => save(a, 'state', value),
      loadProgress: a => load(a, 'progress'), saveProgress: (a, value) => save(a, 'progress', value)},
    notifier: async state => {
      const report = toReport(state);
      await persistReport(report);
      await options.notifier?.(report);
    },
    inbox: waitForInbox && consumePrivateValue ? {async waitFor(account, match) {
      const result = await waitForInbox(match);
      if (result.status === 'pending') return undefined;
      if (result.status !== 'matched' || !result.valueHandle) throw Error('Invalid verification email result.');
      return consumePrivateValue(result.valueHandle);
    }} : undefined,
  });
  // Background completion must reach the server without another MCP invocation.
  const advance = runner.advance.bind(runner);
  runner.advance = async job => {
    const result = await advance(job), report = toReport(result);
    const metadata = reports.get(result.flowId);
    if (metadata && JSON.stringify(metadata.report) !== JSON.stringify(report)) {
      await persistReport(report);
    }
    return result;
  };
  return {
    async run(input) {
      if (input.version !== 1 || !/^[A-Za-z0-9_-]{1,80}$/.test(input.account?.accountRef) ||
        input.account.workspace !== scope.ownerId || input.account.product !== (scope.productId ?? null) ||
        typeof input.flowId !== 'string' || !input.flowId) throw Error('Invalid scoped browser request.');
      const provider = runner.providers[input.account.platform];
      if (!provider?.origins.includes(input.origin)) throw Error('Unsupported browser origin.');
      const metadata = {account: input.account, flowId: input.flowId, report: undefined};
      reports.set(input.flowId, metadata); activeFlows.set(input.account.accountRef, metadata);
      const state = await runner.read(input.account);
      if (state && state.flowId !== input.flowId && !['complete','revoked'].includes(state.status)) throw Error('Existing browser flow requires reconciliation.');
      if (state?.status === 'failed') throw Error('Browser flow failed; reconcile saved progress before continuing.');
      const result = state?.flowId === input.flowId
        ? await runner.continueTrusted({account: input.account, flowId: input.flowId})
        : await runner.start({account: input.account, action: input.action, flowId: input.flowId, url: provider.entry[input.action]});
      const report = toReport(result);
      await persistReport(report); // Every dispatched invocation must settle core dispatch, even unchanged resume.
      return report;
    },
    async revoke(account){if(account.workspace!==scope.ownerId||account.product!==(scope.productId??null))throw Error('Browser account scope denied.');await runner.revoke(account);activeFlows.delete(account.accountRef);},
    close: () => runner.shutdown(),
  };
}
