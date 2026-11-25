# ActAs MCP

For the agent that stops at each verification email and two-factor prompt.
ActAs gives it an identity: an email inbox on your domain, the logins you save
for it, and a token that reaches only what you granted. With this server it can:

- read the code out of a verification email sent to its own inbox
- get the username and password of a login you saved for it
- get that login's current two-factor code (the code, never the seed)

Start at https://actas.dev/sign-up?ref=readme

## Before you install

ActAs Pro: US$12/month or US$120/year plus applicable tax, as of this release. Current price and any free trial: https://actas.dev/pricing

1. Sign up at https://actas.dev/sign-up?ref=readme and create an agent in your
   workspace.
2. Give it an inbox and access to only what it needs. Its address is on your
   own domain, which you add and verify in the workspace first.
3. In the agent's Connection tab, click Connect CLI, choose the permissions,
   and download the connection file. Keep it outside your repository, readable
   only by you.

The connection file holds a bearer token. Never put its contents in a prompt, a
URL, a log or git. To cut an agent off, click Revoke access in its Connection
tab: later requests with that token are refused.

## Local: stdio

Needs Node.js 22 or newer. Add this to your MCP client's configuration, with
the absolute path to your connection file:

```json
{
  "mcpServers": {
    "actas": {
      "command": "npx",
      "args": ["-y", "actas@0.9.2", "mcp"],
      "env": {"ACTAS_CONNECTION_FILE": "/absolute/path/to/actas-identity.json"}
    }
  }
}
```

Or install it once:

```sh
npm install -g actas@0.9.2
actas mcp
```

Then set the client's command to `actas` with the argument `mcp` and the same
`ACTAS_CONNECTION_FILE`. A stdio server waits for input, so an idle terminal is
not a failure.

## Remote: no install

In an MCP client that supports Streamable HTTP with bearer headers, add
`https://actas.dev/mcp` and send the `token` value from your connection file in
the Authorization bearer header, saved in the client's protected credential
settings. Do not put the token in the endpoint URL, a prompt or source control.
OAuth is not offered.

Every call is checked against the connection's permissions as they stand at
that moment, so a revoked token stops here too. `actas_inbox_wait_for` and
`actas_account_use` are not listed remotely.

Two headers change what a remote connection may do. Both are off until you set
them:

- `ActAs-MCP-Secret-Output: allow` lets `actas_vault_login` and
  `actas_totp_code` return passwords and two-factor codes to a remote client.
  Without it they return no secret. Your grants still apply.
- `ActAs-MCP-Management: allow` is required before a workspace management
  token is accepted. Prefer a connection scoped to one identity.

## Secrets and permissions

A value a tool returns goes to your client, and whether it stays in chat
history is up to that client. `actas_vault_login` and `actas_totp_code` return
passwords and two-factor codes, and `actas_inbox_wait_for_code` returns the
code, so grant an agent only what it should see.

Tools that create identities or set up mail domains need a separate management
connection. An identity connection cannot reach them by choosing a tool.

## What still needs a person

ActAs does not solve CAPTCHAs, provide phone numbers or pass ID checks. When a
website asks for one of these, that is a job for a person. Whether a signup or
login goes through depends on the website and its policies.

## More

- Docs: https://actas.dev/docs?ref=readme
- Quickstart in plain text: https://actas.dev/mcp.md?ref=readme
- API reference: https://actas.dev/openapi.json
- Source, MIT licensed: https://github.com/fraylabs/actas-mcp
- Support: support@actas.dev
