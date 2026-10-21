# Termix MCP - project notes

- Repo: drmogie/termix-mcp (public). No ha- prefix, since it is not for Home Assistant.
- What: local MCP server (Python) so Claude can manage a Termix server through its API.
- Termix runs at http://172.16.20.42:8081 (Docker, next to Apache Guacamole).
- Run with uvx straight from GitHub. No local copy needed.
- Version format: YYYY.MM.DD.## (two digit counter). Keep in lockstep:
  pyproject.toml, termix_mcp/server.py (__version__), README badge, CHANGELOG, GitHub Release.
- API key lives only in the Claude desktop config. Never commit it.

## History

- 2026.10.19.01 - first version (local only).
- 2026.10.20.01 - git URL install in Claude config (local only).
- 2026.10.20.02 - repo created on GitHub and first release pushed.
