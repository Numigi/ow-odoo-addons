"""Override res.users.apikeys to enforce strict scope matching for 'mcp'.

In Odoo 14, the base _check_credentials() method uses WHERE (scope IS NULL OR
scope = %s), meaning any global API key (scope=NULL) would match scope='mcp'.
This is a security vulnerability: a key created for another integration (Zapier,
RPC scripts, etc.) would grant MCP access.

This override enforces strict equality: only keys with scope='mcp' are accepted
when _check_credentials(scope='mcp') is called.
"""
from odoo import api, models
from odoo.addons.base.models.res_users import INDEX_SIZE, KEY_CRYPT_CONTEXT


class ResUsersApikeys(models.Model):
    _inherit = 'res.users.apikeys'

    @api.model
    def _check_credentials(self, scope, key):
        """Override to enforce strict scope matching for 'mcp'.

        In Odoo 14, the default implementation accepts NULL scopes, which is
        insecure for MCP. We require exact scope='mcp' match.

        Uses the same hashing mechanism as base (PBKDF2) but enforces
        strict scope equality instead of (scope IS NULL OR scope = %s).
        """
        if scope == 'mcp':
            # Strict match: reject NULL scopes for MCP
            # Use index (first 8 chars) for lookup, then verify hash
            index = key[:INDEX_SIZE]
            self.env.cr.execute('''
                SELECT user_id, key
                FROM res_users_apikeys INNER JOIN res_users u ON (u.id = user_id)
                WHERE u.active AND index = %s AND scope = 'mcp'
            ''', [index])
            for user_id, current_key in self.env.cr.fetchall():
                if KEY_CRYPT_CONTEXT.verify(key, current_key):
                    return user_id
            return None
        # For other scopes, use the default behavior
        return super()._check_credentials(scope, key)
