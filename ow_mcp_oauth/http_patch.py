"""Extend MCP HTTP routing patch for OAuth endpoints.

Adds OAuth 2.1 endpoints that require application/json:
- /ow_mcp/oauth/register (Dynamic Client Registration, RFC 7591)
- /ow_mcp/oauth/token (Token endpoint, RFC 6749)
- /ow_mcp/oauth/revoke (Token revocation, RFC 7009)
"""
from odoo.addons.ow_mcp_server.http_patch import JSON_AS_HTTP_PATHS

# Add OAuth endpoints to the JSON-as-HTTP allowlist
JSON_AS_HTTP_PATHS.update({
    '/ow_mcp/oauth/register',
    '/ow_mcp/oauth/token',
    '/ow_mcp/oauth/revoke',
})
