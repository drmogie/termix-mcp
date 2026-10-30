# Termix MCP

![Version](https://img.shields.io/badge/version-2026.10.22.01-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small tool that lets Claude read and change a
[Termix](https://github.com/Termix-SSH/Termix) server through its API.

It runs on your own computer. Your API key stays on your computer.

## What Claude can do with it

- Check that Termix is up and the key works (termix_health).
- List, read, add, change, and delete hosts (termix_hosts).
- Add many hosts at once (termix_add_many_hosts).
- List stored credentials, with secrets hidden (termix_credentials).
- Manage roles: make roles, put users in them, share hosts or folders with a role (termix_roles).
- Call any other Termix API route (termix_call).

## Safety

- **Read** calls run right away.
- **Add and change** calls do not run until Claude asks you and sets `confirm`.
- **Delete** calls also need the exact phrase typed back, like
  `DELETE /host/db/host/3`.
- Passwords and keys are hidden in everything Claude sees.
- Creating credentials, logins, and key making are blocked.
  Do those in the Termix web page yourself.
- The API key is never printed. It is removed from error messages.

## Set up

### 1. Make an API key

1. Open Termix.
2. Look in your user profile or admin settings for API keys.
   Menu names can differ a little by version.
3. Best: make a separate key just for Claude, so you can delete it on its own later.

**Do not paste the key in a chat.** Put it only in the config file below.
If it ever lands in a chat, delete that key and make a new one.

### 2. Add the tool to Claude

Open the Claude desktop app settings and find the MCP servers config file.
Add the block from `claude_desktop_config.example.json`. Change the key.

- `TERMIX_URL`: your server, like `http://192.168.1.142:8081`
- `TERMIX_API_KEY`: your key
- `TERMIX_VERIFY_TLS`: set to `false` only for a self-signed https address

That file now holds a secret. Do not share it. Do not put it on GitHub.

If you do not have `uvx`, use Python instead:

```
pip install git+https://github.com/drmogie/termix-mcp
```

Then use `"command": "termix-mcp"` and no args.

Restart the Claude desktop app.

### 3. Try it

Ask Claude: "Check Termix." Then: "List my Termix hosts."

## Host field names

The Termix docs do not list the host fields. To see the exact names for your version:

1. Add one host by hand in the Termix web page.
2. Ask Claude to list hosts.
3. Claude copies those field names when adding more.

## Tests

```
pip install mcp
python -m unittest discover tests
```

The tests use a fake Termix server. They do not touch your real one.

## Docs

Termix API: https://docs.termix.site/api/
