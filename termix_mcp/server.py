"""Termix MCP tool.

Lets Claude read and change a Termix server (web SSH, RDP, VNC, Telnet host
manager) through its HTTP API.

Settings come from environment variables only. The API key is never written
to disk, never printed, and never sent anywhere except the Termix server.

  TERMIX_URL         Example: http://192.168.1.142:8081   (required)
  TERMIX_API_KEY     API key from the Termix web page (starts with tmx_)  (required)
  TERMIX_VERIFY_TLS  "false" to skip TLS checks for a self-signed https URL
"""

from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mcp.server.fastmcp import FastMCP

__version__ = "2026.10.22.01"

mcp = FastMCP("termix")

HOSTS_PATH = "/host/db/host"
CREDENTIALS_PATH = "/credentials"
RBAC_PATH = "/rbac"

# Field names whose values are hidden in everything this tool prints.
SECRET_RE = re.compile(
    r"(pass(word|phrase)?|secret|private_?key|^key$|token|totp|api_?key)", re.I
)
# Paths that would move passwords or keys through the chat.
BLOCKED_PREFIXES = (
    "/users/login", "/users/create", "/users/password", "/users/oidc",
    "/credentials/generate", "/credentials/deploy",
)
HIDDEN = "***hidden***"


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------
# read         runs right away
# change       needs confirm=true (Claude must ask the user first)
# destructive  needs confirm=true AND confirm_phrase equal to "METHOD /path"


def classify(method: str, path: str) -> str:
    method = method.upper()
    if method in ("GET", "HEAD"):
        return "read"
    if method == "DELETE":
        return "destructive"
    return "change"


def phrase_for(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def blocked_reason(method: str, path: str) -> str:
    low = path.lower()
    for p in BLOCKED_PREFIXES:
        if low.startswith(p):
            return (f"{path} is blocked. It would put a password or key in the chat. "
                    "Do this step in the Termix web page yourself.")
    if low.startswith(CREDENTIALS_PATH) and method.upper() != "GET":
        return ("Creating or changing credentials is blocked. It would put a "
                "password or key in the chat. Add credentials in the Termix web page, "
                "then link them to hosts here with a credential id.")
    return ""


def scrub(value: Any) -> Any:
    """Hide secret fields anywhere in a JSON-like value."""
    if isinstance(value, dict):
        return {
            k: (HIDDEN if SECRET_RE.search(str(k)) and v not in (None, "", False)
                else scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _config() -> tuple[str, str]:
    url = os.environ.get("TERMIX_URL", "").strip().rstrip("/")
    key = os.environ.get("TERMIX_API_KEY", "").strip()
    if not url or not key:
        raise RuntimeError(
            "Set TERMIX_URL and TERMIX_API_KEY in this tool's environment "
            "(see the README). The key is not stored anywhere else."
        )
    return url, key


def _context(url: str) -> ssl.SSLContext | None:
    if not url.lower().startswith("https"):
        return None
    if os.environ.get("TERMIX_VERIFY_TLS", "true").strip().lower() in ("0", "false", "no"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def _request(method: str, path: str, query: dict[str, Any] | None = None,
             body: Any = None) -> dict[str, Any]:
    """Call the API. Returns a dict with ok, status, and data or error."""
    key = ""
    try:
        base, key = _config()
        if not path.startswith("/"):
            path = "/" + path
        url = base + path
        if query:
            q = {k: ("true" if v is True else "false" if v is False else str(v))
                 for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q)
        data = None
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30, context=_context(url)) as resp:
                raw = resp.read().decode("utf-8", "replace")
                status = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            status = e.code
        try:
            parsed: Any = json.loads(raw) if raw.strip() else None
        except ValueError:
            parsed = raw
        ok = 200 <= status < 300
        out: dict[str, Any] = {"ok": ok, "status": status}
        out["data" if ok else "error"] = scrub(parsed)
        return out
    except Exception as e:  # noqa: BLE001
        msg = str(e).replace(key, "***") if key else str(e)
        return {"ok": False, "error": msg}


def _gate(method: str, path: str, confirm: bool, confirm_phrase: str) -> dict[str, Any] | None:
    """Return an error/needs-confirm dict, or None when the call may run."""
    why = blocked_reason(method, path)
    if why:
        return {"ok": False, "error": why}
    level = classify(method, path)
    if level == "read":
        return None
    if not confirm:
        return {
            "ok": False, "needs_confirm": True, "level": level,
            "message": (f"This is a {level} call: {method.upper()} {path}. "
                        "Ask the user, then call again with confirm=true"
                        + (f' and confirm_phrase="{phrase_for(method, path)}".'
                           if level == "destructive" else ".")),
        }
    if level == "destructive" and confirm_phrase.strip() != phrase_for(method, path):
        return {
            "ok": False, "needs_confirm": True, "level": level,
            "message": f'Type the exact phrase back: confirm_phrase="{phrase_for(method, path)}".',
        }
    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def termix_health() -> dict[str, Any]:
    """Check that the Termix server is up and the API key works.

    Calls the health check, then lists hosts to test the key.
    """
    health = _request("GET", "/health")
    keycheck = _request("GET", HOSTS_PATH)
    return {
        "server_up": health.get("ok", False),
        "api_key_works": keycheck.get("ok", False),
        "host_count": len(keycheck["data"]) if keycheck.get("ok") and isinstance(keycheck.get("data"), list) else None,
        "detail": None if keycheck.get("ok") else keycheck.get("error"),
    }


@mcp.tool()
def termix_hosts(action: str = "list", host_id: int | str | None = None,
                 data: dict[str, Any] | None = None, confirm: bool = False,
                 confirm_phrase: str = "") -> dict[str, Any]:
    """List, read, add, change, or delete Termix hosts.

    action: list | get | add | update | delete
    host_id: needed for get, update, delete
    data: the host fields for add and update (see the README for the field names;
          run action=list once to see the exact fields your Termix version uses)
    add and update need confirm=true. delete also needs
    confirm_phrase="DELETE /host/db/host/<id>".
    Passwords and keys are hidden in all output. Enter those in the Termix web page.
    """
    action = (action or "list").lower()
    if action == "list":
        return _request("GET", HOSTS_PATH)
    if action in ("get", "update", "delete") and host_id in (None, ""):
        return {"ok": False, "error": "host_id is required for this action."}
    if action == "get":
        return _request("GET", f"{HOSTS_PATH}/{host_id}")
    if action == "add":
        if not data:
            return {"ok": False, "error": "data is required for add."}
        gate = _gate("POST", HOSTS_PATH, confirm, confirm_phrase)
        return gate or _request("POST", HOSTS_PATH, body=data)
    if action == "update":
        if not data:
            return {"ok": False, "error": "data is required for update."}
        path = f"{HOSTS_PATH}/{host_id}"
        gate = _gate("PUT", path, confirm, confirm_phrase)
        return gate or _request("PUT", path, body=data)
    if action == "delete":
        path = f"{HOSTS_PATH}/{host_id}"
        gate = _gate("DELETE", path, confirm, confirm_phrase)
        return gate or _request("DELETE", path)
    return {"ok": False, "error": "action must be list, get, add, update, or delete."}


@mcp.tool()
def termix_add_many_hosts(hosts: list[dict[str, Any]], confirm: bool = False) -> dict[str, Any]:
    """Add several hosts in one go. Each item is the same data you would give to
    termix_hosts add. Needs confirm=true. Reports each result on its own,
    so one bad row does not stop the rest."""
    if not hosts:
        return {"ok": False, "error": "hosts is empty."}
    gate = _gate("POST", HOSTS_PATH, confirm, "")
    if gate:
        gate["message"] = (gate.get("message", "") +
                           f" This will add {len(hosts)} hosts.")
        return gate
    results = []
    for h in hosts:
        r = _request("POST", HOSTS_PATH, body=h)
        results.append({"name": h.get("name") or h.get("ip") or h.get("host"),
                        "ok": r.get("ok"), "status": r.get("status"),
                        "error": r.get("error")})
    return {"ok": all(r["ok"] for r in results), "added": sum(1 for r in results if r["ok"]),
            "total": len(results), "results": results}


@mcp.tool()
def termix_credentials(action: str = "list", credential_id: int | str | None = None) -> dict[str, Any]:
    """List or read stored credentials. Read-only. Secrets are hidden.

    action: list | get
    Use the credential id inside a host's data to link a host to a credential.
    """
    if (action or "list").lower() == "get":
        if credential_id in (None, ""):
            return {"ok": False, "error": "credential_id is required for get."}
        return _request("GET", f"{CREDENTIALS_PATH}/{credential_id}")
    return _request("GET", CREDENTIALS_PATH)


@mcp.tool()
def termix_roles(action: str = "list", role_id: int | str | None = None,
                 user_id: int | str | None = None, host_id: int | str | None = None,
                 access_id: int | str | None = None, folder: str | None = None,
                 name: str | None = None, display_name: str | None = None,
                 description: str | None = None, role_ids: list[int] | None = None,
                 user_ids: list[int] | None = None, permission_level: str = "connect",
                 duration_hours: int | None = None, confirm: bool = False,
                 confirm_phrase: str = "") -> dict[str, Any]:
    """Manage Termix roles, who is in them, and which hosts they can reach.

    Read actions (run right away):
      list            all roles
      members         users in a role (needs role_id)
      user_roles      roles of one user (needs user_id)
      users           all users, to find a user_id
      host_access     who a host is shared with (needs host_id)
      folder_access   standing share rules for a folder (needs folder)
    Change actions (need confirm=true, so ask the user first):
      create          needs name (lowercase, digits, _ or -) and display_name
      update          needs role_id, and display_name and/or description
      assign          needs role_id and user_id
      share_host      needs host_id, and role_ids and/or user_ids
      share_folder    needs folder, and role_ids and/or user_ids (also covers
                      hosts added to that folder later)
      update_access   needs host_id, access_id, permission_level and/or duration_hours
    Destructive actions (need confirm=true and confirm_phrase="METHOD /path"):
      delete          delete a role (needs role_id)
      unassign        take a role off a user (needs role_id and user_id)
      revoke_access   remove a host share (needs host_id and access_id)
      delete_folder_rule  remove a folder share rule (needs access_id)
    Sharing uses the host's saved credential. No passwords pass through here.
    """
    a = (action or "list").lower()
    R = RBAC_PATH

    def need(**kw: Any) -> str:
        miss = [k for k, v in kw.items() if v in (None, "", [])]
        return ("Missing: " + ", ".join(miss) + ".") if miss else ""

    def targets() -> list[dict[str, Any]]:
        return ([{"type": "role", "id": r} for r in (role_ids or [])] +
                [{"type": "user", "id": u} for u in (user_ids or [])])

    def run(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        gate = _gate(method, path, confirm, confirm_phrase)
        return gate or _request(method, path, body=body)

    if a == "list":
        return _request("GET", f"{R}/roles")
    if a == "members":
        e = need(role_id=role_id)
        return {"ok": False, "error": e} if e else _request("GET", f"{R}/roles/{role_id}/members")
    if a == "user_roles":
        e = need(user_id=user_id)
        return {"ok": False, "error": e} if e else _request("GET", f"{R}/users/{user_id}/roles")
    if a == "users":
        return _request("GET", "/users/list")
    if a == "host_access":
        e = need(host_id=host_id)
        return {"ok": False, "error": e} if e else _request("GET", f"{R}/host/{host_id}/access")
    if a == "folder_access":
        e = need(folder=folder)
        if e:
            return {"ok": False, "error": e}
        r = _request("GET", f"{R}/folder/access", query={"folder": folder})
        return r
    if a == "create":
        e = need(name=name, display_name=display_name)
        if e:
            return {"ok": False, "error": e}
        body = {"name": name, "displayName": display_name}
        if description:
            body["description"] = description
        return run("POST", f"{R}/roles", body)
    if a == "update":
        e = need(role_id=role_id)
        if e or not (display_name or description):
            return {"ok": False, "error": e or "Give display_name and/or description."}
        body = {}
        if display_name:
            body["displayName"] = display_name
        if description:
            body["description"] = description
        return run("PUT", f"{R}/roles/{role_id}", body)
    if a == "delete":
        e = need(role_id=role_id)
        return {"ok": False, "error": e} if e else run("DELETE", f"{R}/roles/{role_id}")
    if a == "assign":
        e = need(role_id=role_id, user_id=user_id)
        if e:
            return {"ok": False, "error": e}
        try:
            rid = int(role_id)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return {"ok": False, "error": "role_id must be a number."}
        return run("POST", f"{R}/users/{user_id}/roles", {"roleId": rid})
    if a == "unassign":
        e = need(role_id=role_id, user_id=user_id)
        return {"ok": False, "error": e} if e else run("DELETE", f"{R}/users/{user_id}/roles/{role_id}")
    if a in ("share_host", "share_folder"):
        e = need(host_id=host_id) if a == "share_host" else need(folder=folder)
        if e or not targets():
            return {"ok": False, "error": e or "Give role_ids and/or user_ids."}
        body: dict[str, Any] = {"targets": targets(), "permissionLevel": permission_level}
        if duration_hours is not None:
            body["durationHours"] = duration_hours
        if a == "share_host":
            return run("POST", f"{R}/host/{host_id}/share", body)
        body["folder"] = folder
        return run("POST", f"{R}/folder/share", body)
    if a == "update_access":
        e = need(host_id=host_id, access_id=access_id)
        if e:
            return {"ok": False, "error": e}
        body = {"permissionLevel": permission_level}
        if duration_hours is not None:
            body["durationHours"] = duration_hours
        return run("PATCH", f"{R}/host/{host_id}/access/{access_id}", body)
    if a == "revoke_access":
        e = need(host_id=host_id, access_id=access_id)
        return {"ok": False, "error": e} if e else run("DELETE", f"{R}/host/{host_id}/access/{access_id}")
    if a == "delete_folder_rule":
        e = need(access_id=access_id)
        return {"ok": False, "error": e} if e else run("DELETE", f"{R}/folder/access/{access_id}")
    return {"ok": False, "error": "Unknown action. See the tool description for the list."}


@mcp.tool()
def termix_call(method: str, path: str, query: dict[str, Any] | None = None,
                body: dict[str, Any] | None = None, confirm: bool = False,
                confirm_phrase: str = "") -> dict[str, Any]:
    """Call any other Termix API route. Docs: https://docs.termix.site/api/

    method: GET, POST, PUT, PATCH, or DELETE
    path: like /host/db/host or /health
    GET runs right away. POST, PUT, PATCH need confirm=true.
    DELETE needs confirm=true and confirm_phrase="DELETE <path>".
    Password and key routes are blocked. Secrets in answers are hidden.
    """
    method = (method or "").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        return {"ok": False, "error": "method must be GET, POST, PUT, PATCH, or DELETE."}
    gate = _gate(method, path, confirm, confirm_phrase)
    return gate or _request(method, path, query=query, body=body)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
