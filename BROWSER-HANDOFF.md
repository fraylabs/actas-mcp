# Headed browser fallback

`client/browser-adapter.mjs` exports the Accounts MCP v1 boundary owned by Worker
B. The core must persist its flow before `run`, validate/consume continuation
tokens server-side and retain the adapter instance while the browser is waiting.
The runner monitors the page without another model turn, then sends its verified
terminal report through the required `saveReport(report)` callback. Closing the adapter closes
its browser; the private profile and journal remain for explicit continuation.

## Trusted configuration

```js
const adapter = createBrowserAdapter({
  request, // existing authenticated API transport: (route, method, body)
  scope: {ownerId, productId},
  waitForInbox, consumePrivateValue,
  saveReport, // core owns atomic dispatch/resume capability; persists every changed report
  notifier: async report => { /* deliver one humanRequest through caller */ },
});
```

`saveReport` is the sole persistence channel, including the initial report before
notification. Each dispatched `run` settles one report, including unchanged
continuations; background ticks deduplicate unchanged reports. The core must not
persist the `run` return a second time.
`/account-tools/flow/check` rechecks current manage authority and revocation on
every monitor iteration without changing flow state.

The optional `stateDir` defaults outside the repository to
`~/.local/state/actas/browser`. Each workspace/product/platform/account gets a
hashed directory (0700), its own headed Chromium profile, a private journal
(0600), and an exclusive runner lock. Profiles contain sensitive browser data:
use the owning user's protected Mac and never upload profiles, journals or
screenshots of real account pages. No tracing, browser console or network logs
are enabled. Chromium sandboxing stays enabled. There are no stealth flags or
CAPTCHA services.

Secrets referenced by `account.secretRefs.password` can be filled during login
on the exact assigned origin; no secret values are accepted in MCP arguments.
Signup remains a visible human form for provider-specific names, birthday,
consent and unsupported steps. CAPTCHA, MFA, phone and policy steps are only
observed. Account registration is never inferred from submitting a form.
The X verifier requires the assigned handle's own `AppTabBar_Profile_Link`.
Instagram requires the assigned handle's profile link inside navigation. Both
are conservative DOM observations that still require live dogfood; missing or
changed markup leaves a human request, never assumed success.

Optional `emailRules` are trusted operator configuration indexed by accountRef:

```js
emailRules: {
  fixture: {
    selector: 'input[name="email_code"]',
    submitSelector: 'button[data-step="verify_email"]',
    match: {emailId, sender, subject, after, codePattern, timeoutMs: 30000},
  },
}
```

Configure an exact product inbox, expected sender, subject, request timestamp and
bounded code pattern through the core inbox bridge. No generic scraping or
cross-origin verification links are enabled. A pending inbox response waits;
matched values are consumed inside trusted runtime code and filled once. Never
configure an email rule for a CAPTCHA, MFA, phone or policy control.

## Human requests and continuation

The request identifies the browser origin, the literal action, and why the site
requires it. It contains an origin only, never a query/token-bearing page URL.
Progress storage (including exact current URL and browser state) is saved to the
product vault under `/accounts_browser/<accountRef>_progress`; authenticated
storage is `/accounts_browser/<accountRef>_state`. Core reports contain only
secret paths. These paths require the existing scoped vault grants. Existing
vault secrets are limited to 64 KiB; oversized browser storage fails without
marking the account active. Larger vault blobs require an explicit later contract.

One request is persisted before notification per observed human step. Delivery
failures are not retried because delivery may have succeeded; the same request
is returned to the calling agent. An optional notifier routes later human steps
without polling. With no notifier, the caller must poll account status. A direct
Turnless Needs-you route awaits the owners' integration; this adapter does not
send messages as the account owner.

A 24-hour expiry retains `needs_human`, with no retry or new signup. Reopening an
unexpired flow restores its private vault checkpoint at the saved step. Browser
profile or vault loss, site session expiry and platform rechecks can require a
human again; permanent exemption from platform checks is not promised.
Interrupted submission is recorded before the action and is never retried
automatically. A stale lock is not deleted automatically: verify the owning
runner has stopped before an operator reconciles it. Revocation prevents new
work and closes the monitored browser on its next authorization check. Existing
platform sessions must be revoked at the platform separately.

## Proof

```sh
npx tsx --test tests/browser-handoff.test.ts
node scripts/browser-handoff-demo.mjs
npm run check
npm test
npm run build
```

The demo opens a real headed browser against an ephemeral loopback server.
Its approval button is a synthetic fixture, not a CAPTCHA. The demo clicks only
that synthetic button, proves one notification, automatic authenticated resume,
private saved storage and a second login without another human request.
`artifacts/browser-handoff-demo/receipt.json` and before/after screenshots are
shareable synthetic evidence. No real signup or deployed success is claimed.
