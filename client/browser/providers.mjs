// First-party browser fallback. Challenge fields and policy buttons are observed
// only. Trusted credential references may be filled on the exact assigned origin.
const visible = async (page, selector) => page.locator(selector).first().isVisible().catch(() => false);
export async function detectHumanStep(page) {
  for (const frame of page.frames()) {
    if (/recaptcha|hcaptcha|challenges\.cloudflare|arkoselabs|funcaptcha/.test(frame.url())) {
      const element = await frame.frameElement().catch(() => undefined);
      if (element && await element.isVisible()) return 'captcha';
    }
  }
  if (await visible(page, 'input[autocomplete="one-time-code"], input[name="verificationCode"], input[name="challenge_response"]')) return 'mfa';
  if (await visible(page, 'input[type="tel"], input[name="phone_number"]')) return 'phone';
  return undefined;
}
export function createBrowserProviders({credentials, emailRules = {}} = {}) {
  function provider(origins, entry, profileSelector, username, password, next, submit) {
    const verify = async (page, account) => {
      const handle = account.handle?.replace(/^@/, '');
      if (!origins.includes(new URL(page.url()).origin) || !/^[A-Za-z0-9_.]{1,80}$/.test(handle)) return false;
      return visible(page, profileSelector(handle));
    };
    return {origins, entry, verify,
      async observe(page, account, action) {
        if (!origins.includes(new URL(page.url()).origin)) return {kind:'human',reason:'provider_policy',id:'unexpected_origin'};
        const reason = await detectHumanStep(page);
        if (reason === 'captcha' || reason === 'phone') return {kind:'human',reason};
        if (reason) return {kind:'human',reason};
        if (await verify(page, account)) return {kind:'authenticated'};
        const hasUsername=await visible(page,username), hasPassword=await visible(page,password);
        // Signup has provider-specific policy/age/name requirements; do not
        // silently consent or invent a person's details.
        if (hasUsername || hasPassword) return {kind:'human',reason:'human_credential_entry'};
        // Let client-rendered form/navigation arrive before asking a person to
        // review an unknown page. Waiting is observation, never a login retry.
        try { await page.locator(`${username}, ${password}, ${profileSelector(account.handle?.replace(/^@/,'') || '')}`).first().waitFor({state:'visible',timeout:3000}); return {kind:'waiting'}; }
        catch { return {kind:'human',reason:'provider_policy'}; }
      },
      async verifyEmail() { throw Error('Browser verification requires a human; automated entry is blocked.'); },
      async advance() { throw Error('Browser credential entry requires a human; automated entry is blocked.'); },
    };
  }
  return {
    x: provider(['https://x.com'], {login:'https://x.com/i/flow/login',signup:'https://x.com/i/flow/signup'},
      handle=>`a[data-testid="AppTabBar_Profile_Link"][href="/${handle}"]`,
      'input[autocomplete="username"]','input[name="password"]','button:has-text("Next"), div[role="button"]:has-text("Next")','[data-testid="LoginForm_Login_Button"]'),
    instagram: provider(['https://www.instagram.com'], {login:'https://www.instagram.com/accounts/login/',signup:'https://www.instagram.com/accounts/emailsignup/'},
      handle=>`nav a[href="/${handle}/"] img[alt*="profile picture"], [role="navigation"] a[href="/${handle}/"] img[alt*="profile picture"]`,
      'input[name="username"]','input[name="password"]','button[type="submit"]','button[type="submit"]'),
  };
}
export const browserProviders = createBrowserProviders();
