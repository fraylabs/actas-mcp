# ActAs MCP

Give an AI agent its own identity, email, saved accounts and scoped credentials.
ActAs Pro: US$12/month or US$120/year plus applicable tax, after a 7-day free trial (card required, one per workspace). Current price and trial: https://actas.dev/pricing

The MCP server is available remotely over Streamable HTTP or locally over stdio.

## Remote: no install

Add `https://actas.dev/mcp` in an MCP client that supports bearer headers. Use
the token from your scoped ActAs connection in the Authorization bearer header,
saved through your client's protected credential settings. Do not put the token
in the endpoint URL, a prompt, or source control. OAuth is not offered.

The remote endpoint shares the stdio tool schemas and applies the same API
permissions and revocation checks on every call. Browser flows still need a
local browser adapter. Private verification handles (`actas_inbox_wait_for`) and
registered executable consumers (`actas_account_use`) are not listed remotely;
use the local client below.

Stored passwords and TOTP codes are withheld by default. To return them remotely,
explicitly configure `ActAs-MCP-Secret-Output: allow` as an additional header.
Existing reveal scopes and vault grants still apply. A hosted client may retain
secret tool results in chat history. These two tools return the value to your
client in both remote and local mode. To keep a secret out of the conversation
entirely, use the local client's browser sign-in steps and `actas_inbox_wait_for`,
which pass private handles instead of values.
Inbox sign-in codes also enter the client's results. Workspace management tokens
require `ActAs-MCP-Management: allow`; prefer scoped identity connections.

## Install

Requires Node.js 22 or newer and an ActAs subscription at https://actas.dev.
Download https://actas.dev/actas-mcp.tgz and run:

```sh
npm install -g ./actas-mcp.tgz
actas-accounts-mcp --help
```

`actas mcp` starts the same server.

Create an identity in your workspace, give it an inbox and grant only the
resources and actions it needs. In the agent's Connection tab, click Connect CLI
and download its private connection. Store it outside your source repository with owner-only file permissions.

Add this configuration to a stdio MCP client (replace the example file path):

```json
{
  "mcpServers": {
    "actas": {
      "command": "actas-accounts-mcp",
      "env": {
        "ACTAS_CONNECTION_FILE": "/absolute/path/to/actas-identity.json"
      }
    }
  }
}
```

The connection file contains a bearer token. Never put its contents in prompts,
URLs, logs or git. Revoke the connection in the agent's Connection tab (Revoke access) to stop its
future requests.

## Tools and permissions

The server lists saved accounts, runs scoped account actions, retrieves granted
login credentials and current TOTP codes, and waits for verification mail. Some
tools return sensitive credentials or codes to the authorized agent: grant only
what that agent should see. Management tools for identity creation and domain
setup require a separate management connection; ordinary identity connections
cannot gain management access by choosing a tool.

The optional browser adapter needs a locally installed Playwright Chromium
browser (`npx playwright install chromium`). Website signup and login depend on
the website and its policies. Phone, ID checks and CAPTCHAs require a human
handoff; saving an account record is not proof of external registration.

Documentation: https://actas.dev/docs

Plain-text quickstart: https://actas.dev/mcp.md

API reference: https://actas.dev/openapi.json

Support: support@actas.dev
