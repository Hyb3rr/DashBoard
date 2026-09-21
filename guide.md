# Codex with ChatGPT — Local Usage Guide

This guide documents the current local setup for connecting ChatGPT to the
`ip-intelligence` workspace through the read-only C2C bridge.

## Locations

### Main project

```text
/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence
```

This is the project that Codex can edit, test, and manage with Git.

### C2C checkout

```text
/private/tmp/codex-with-chatgpt
```

This contains the bridge and the `c2c` command-line tool. It is separate from
the main project.

### C2C local state

```text
/Users/ngaphan/Library/Application Support/codex-with-chatgpt
```

This stores local connection, pairing, and tunnel metadata. Project files and
secrets should not be stored here manually.

## Current connection

Workspace:

```text
ip-intelligence
```

MCP endpoint:

```text
https://c2c-ip-intelligence.baquan.click/mcp
```

The endpoint uses OAuth and a one-time pairing code. The bridge exposes
read-only workspace tools. It does not provide file-write, shell, delete, or
Git-commit tools to ChatGPT.

## Start and inspect the bridge

Run these commands from the C2C checkout:

```bash
cd /private/tmp/codex-with-chatgpt
node bin/c2c.js status -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence"
node bin/c2c.js doctor -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence" --json
```

The health check should report that Node, the workspace, bridge, MCP, OAuth,
and tunnel are healthy.

If the bridge is not running, start the existing setup with:

```bash
node bin/c2c.js setup -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence" --json
```

The named Cloudflare hostname is configured for this workspace, so restarting
the bridge should normally keep the same public address.

To stop the bridge:

```bash
node bin/c2c.js stop -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence"
```

## Reconnect or generate a pairing code

Generate a new one-time pairing code when ChatGPT asks for one:

```bash
node bin/c2c.js pair -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence" --json
```

Enter the returned code only on the C2C authorization page. Pairing codes
expire after a few minutes and are valid only once.

## Use the connector in ChatGPT

1. Open ChatGPT Web and start a normal text chat.
2. Open the `+` or tools menu near the message box.
3. Select the custom app/connector for `ip-intelligence`, or mention it with
   `@` if that option is available.
4. Ask ChatGPT to inspect the workspace.

Example verification prompt:

```text
Use the Codex with ChatGPT connector to inspect this workspace. Tell me the
workspace name and list the top-level files. Do not modify anything.
```

Example review prompt:

```text
Review the WebSocket collector replay logic and identify reliability risks.
Do not modify files yet.
```

Example implementation prompt:

```text
Use Codex with ChatGPT to implement [specific task]. Run the relevant tests
and report the results.
```

ChatGPT reads the workspace through the connector. Codex remains responsible
for editing files, running shell commands, running tests, and performing Git
operations locally.

## Cloudflare security requirements

Cloudflare Bot Fight Mode previously blocked ChatGPT's OAuth registration
request with a Managed Challenge. If connector creation fails with HTTP 403,
check **Cloudflare → Security → Events** for this hostname and the path
`/oauth/register`.

For Super Bot Fight Mode or Bot Management, any exception should be narrowly
limited to this dedicated hostname and the OAuth/MCP paths:

```text
/.well-known/*
/oauth/*
/mcp
```

Do not bypass protection for `/admin/*`. Keep the bridge's OAuth protection
enabled. Standard Bot Fight Mode does not support path-specific Skip rules.

## Important security rules

- Do not share pairing codes, OAuth tokens, cookies, or credentials.
- Do not place API keys or secrets in the project or commit them to Git.
- Do not open `/mcp` expecting a homepage; it is an authenticated API endpoint.
- A `401 Authentication required` response from `/mcp` without a token is
  expected.
- The C2C connector is read-only toward the workspace.
- The monitored Sentinel Hub server remains read-only; this setup does not
  block, configure, restart, remediate, or execute commands on that server.

## Troubleshooting checklist

Run:

```bash
cd /private/tmp/codex-with-chatgpt
node bin/c2c.js doctor -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence" --json
node bin/c2c.js logs -w "/Users/ngaphan/Desktop/01-Subject/Practice/4._Real_Web/ip-intelligence"
```

If the endpoint is reachable but `/` shows `Cannot GET /`, that is normal.
Use the connector endpoint and OAuth flow instead of the root URL.

If Cloudflare records a Bot Fight Mode challenge, adjust Cloudflare protection
for the dedicated hostname or temporarily use a Quick Tunnel for testing.

If ChatGPT cannot see the app, check that the app is enabled in ChatGPT
settings and that the current chat is a supported text conversation.
