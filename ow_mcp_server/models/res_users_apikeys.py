"""Override res.users.apikeys to enforce strict scope matching for 'mcp'.

In Odoo 14, the base _check_credentials() method uses WHERE (scope IS NULL OR
scope = %s), meaning any global API key (scope=NULL) would match scope='mcp'.
This is a security vulnerability: a key created for another integration (Zapier,
RPC scripts, etc.) would grant MCP access.

This override enforces strict equality: only keys with scope='mcp' are accepted
when _check_credentials(scope='mcp') is called.
"""
from odoo import api, models


class ResUsersApikeys(models.Model):
    _inherit = 'res.users.apikeys'

    @api.model
    def _check_credentials(self, scope, key):
        """Override to enforce strict scope matching for 'mcp'.

        In Odoo 14, the default implementation accepts NULL scopes, which is
        insecure for MCP. We require exact scope='mcp' match.
        """
        if scope == 'mcp':
            # Strict match: reject NULL scopes for MCP
            # Note: Odoo 14 API keys don't have expiry_date field
            query = """
                SELECT id, user_id
                FROM res_users_apikeys
                WHERE key = %s
                  AND scope = 'mcp'
            """
            self.env.cr.execute(query, (key,))
            row = self.env.cr.fetchone()
            if row:
                return row[1]  # user_id
            return None
        # For other scopes, use the default behavior
        return super()._check_credentials(scope, key)
