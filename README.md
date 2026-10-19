# ActAs MCP

[ActAs](https://actas.dev/?utm_source=github&utm_medium=directory&utm_campaign=launch) · [Setup guide](https://actas.dev/docs)

Give an AI agent its own identity, email, saved accounts and scoped credentials.
ActAs Pro costs US$12/month or US$120/year; there is no free tier. The MCP server
runs locally over stdio, connecting to your ActAs workspace over HTTPS.

## Install

Requires Node.js 22 or newer and an ActAs subscription at https://actas.dev.
Download https://actas.dev/actas-mcp.tgz and run:

```sh
npm install -g ./actas-mcp.tgz
actas-accounts-mcp --help
```

Create an identity in your workspace, give it an inbox and grant only the
resources and actions it needs. Download its private connection from the Access
tab. Store it outside your source repository with owner-only file permissions.

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
URLs, logs or git. Revoke the connection in ActAs to stop its future requests.

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

API reference: https://actas.dev/openapi.json

Support: support@actas.dev
