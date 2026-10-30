"""Override res.users.apikeys to allow both explicit 'mcp' scope and global keys.

In Odoo 14, the "New API Key" wizard creates global keys (scope=NULL). We accept
both scope='mcp' and scope=NULL for MCP authentication, matching Odoo 18 behavior.

This is less strict than rejecting NULL scopes, but it allows users to create
working MCP keys through the standard Odoo interface. The security tradeoff:
a global API key created for another purpose will also work for MCP. This is
the same behavior as Odoo 18's ow_mcp_server.

For stricter security in production, create keys with an explicit 'mcp' scope
using the shell or extend res.users.apikeys.description to add a scope field
to the wizard.
"""
from odoo import api, models
from odoo.addons.base.models.res_users import INDEX_SIZE, KEY_CRYPT_CONTEXT


class ResUsersApikeys(models.Model):
    _inherit = 'res.users.apikeys'

    @api.model
    def _check_credentials(self, *, scope, key):
        """Check credentials with Odoo 14 keyword-only signature.

        Accepts both scope='mcp' and scope=NULL (global keys) for MCP
        authentication, matching Odoo 18 behavior.
        """
        if scope == 'mcp':
            # Accept both explicit 'mcp' scope and global keys (NULL)
            # Use index (first 8 chars) for lookup, then verify hash
            index = key[:INDEX_SIZE]
            self.env.cr.execute('''
                SELECT user_id, key
                FROM res_users_apikeys INNER JOIN res_users u ON (u.id = user_id)
                WHERE u.active AND index = %s AND (scope IS NULL OR scope = 'mcp')
            ''', [index])
            for user_id, current_key in self.env.cr.fetchall():
                if KEY_CRYPT_CONTEXT.verify(key, current_key):
                    return user_id
            return None
        # For other scopes, use the default behavior with named arguments
        return super()._check_credentials(scope=scope, key=key)
