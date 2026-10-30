"""Patch Odoo 14's HTTP routing to allow JSON requests on type='http' routes.

In Odoo 14, Root.get_request() automatically converts any request with
Content-Type: application/json to a JsonRequest. Routes declared as type='http'
then fail with "BadRequest: Function declared as capable of handling request
of type 'http' but called with a request of type 'json'".

This behavior was changed in Odoo 16+, but in v14 we must monkey-patch
Root.get_request() to force HttpRequest for specific paths. This follows
the same approach as OCA's base_rest in v14.

MCP clients (Claude, Cursor, ChatGPT) all POST with application/json,
and OAuth 2.1 Dynamic Client Registration (RFC 7591) requires it.
"""
from odoo import http

# Paths that should be treated as HttpRequest even with application/json
JSON_AS_HTTP_PATHS = {'/mcp'}

_original_get_request = http.Root.get_request


def patched_get_request(self, httprequest):
    """Force HttpRequest for MCP endpoints even with application/json."""
    if httprequest.path in JSON_AS_HTTP_PATHS:
        return http.HttpRequest(httprequest)
    return _original_get_request(self, httprequest)


http.Root.get_request = patched_get_request
