import base64
import json

from odoo.tests import HttpCase, tagged

from odoo.addons.ow_mcp_server.protocol import authfail


@tagged('post_install', '-at_install')
class TestMcpController(HttpCase):
    def setUp(self):
        super().setUp()
        authfail.reset()
        self.user = self.env['res.users'].create({
            'login': 'mcpuser',
            'name': 'MCP User',
            'password': 'mcppass',
            'groups_id': [
                (4, self.env.ref('ow_mcp_server.group_mcp_user').id),
                (4, self.env.ref('base.group_user').id),
            ],
        })
        self.key = (
            self.env['res.users.apikeys'].with_user(self.user)
            ._generate('mcp', 'test')
        )
        partner = self.env.ref('base.model_res_partner').id
        self.env['ow.mcp.model.access'].sudo().search(
            [('model_id', '=', partner)]
        ).unlink()
        self.env['ow.mcp.model.access'].create({
            'model_id': partner,
            'allow_read': True,
        })

    # ---- helpers ----

    def _post(self, body, auth_header=None):
        headers = {'Content-Type': 'application/json'}
        if auth_header:
            headers['Authorization'] = auth_header
        return self.url_open(
            '/mcp', data=json.dumps(body).encode(), headers=headers,
        )

    # ---- auth ----

    def test_missing_auth_returns_401(self):
        r = self._post({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'})
        self.assertEqual(r.status_code, 401)
        self.assertIn('Bearer', r.headers.get('WWW-Authenticate', ''))

    def test_basic_auth_rejected(self):
        creds = base64.b64encode(b'mcpuser:mcppass').decode()
        r = self._post(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
            f'Basic {creds}',
        )
        self.assertEqual(
            r.status_code, 401,
            'Basic auth must be rejected — API keys only.',
        )

    def test_wrong_scope_rejected(self):
        other = (
            self.env['res.users.apikeys'].with_user(self.user)
            ._generate('rpc', 'other')
        )
        r = self._post(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
            f'Bearer {other}',
        )
        self.assertEqual(r.status_code, 401)

    def test_null_scope_key_rejected(self):
        """API keys with scope=NULL (created via v14 UI) must be rejected.

        In Odoo 14, the Preferences → Security interface doesn't offer
        scope selection, so keys are created with scope=NULL. The MCP
        controller requires scope='mcp', so NULL-scope keys must fail auth.
        """
        # Create a key with empty/NULL scope by directly using sudo to bypass
        # the _generate method which sets a scope.
        null_scope_key = self.env['res.users.apikeys'].sudo().create({
            'user_id': self.user.id,
            'name': 'null_scope_test',
            'scope': False,  # NULL scope
        })
        self.env['res.users.apikeys'].flush()

        # Try to use this key for MCP access
        r = self._post(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
            f'Bearer {null_scope_key.key}',
        )
        # Should be rejected because scope is NULL, not 'mcp'
        self.assertEqual(
            r.status_code, 401,
            'NULL-scope keys (created via v14 UI) must be rejected by MCP',
        )

    def test_wrong_key_rejected(self):
        r = self._post(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
            'Bearer not-a-real-key',
        )
        self.assertEqual(r.status_code, 401)

    # ---- happy path ----

    def test_bearer_initialize(self):
        r = self._post(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
            f'Bearer {self.key}',
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data['id'], 1)
        self.assertEqual(data['result']['protocolVersion'], '2025-06-18')

    def test_tools_list(self):
        r = self._post(
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            f'Bearer {self.key}',
        )
        self.assertEqual(r.status_code, 200)
        names = {t['name'] for t in r.json()['result']['tools']}
        self.assertEqual(len(names), 6)

    def test_tools_call_list_models_end_to_end(self):
        r = self._post({
            'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
            'params': {'name': 'list_models', 'arguments': {}},
        }, f'Bearer {self.key}')
        self.assertEqual(r.status_code, 200)
        structured = r.json()['result']['structuredContent']
        self.assertIn('res.partner', {m['model'] for m in structured['models']})

    def test_batch_request_rejected(self):
        # MCP 2025-06-18 removed JSON-RPC
        # batching; a batch used to count as ONE call for the rate limit.
        r = self._post([
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
        ], f'Bearer {self.key}')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['error']['code'], -32600)

    def test_parse_error_returns_400(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.key}',
        }
        r = self.url_open('/mcp', data=b'{not json', headers=headers)
        self.assertEqual(r.status_code, 400)

    # ---- multi-db ----

    def test_matching_db_query_param_accepted(self):
        """?db=<current> should pass through transparently."""
        current_db = self.env.cr.dbname
        r = self.url_open(
            f'/mcp?db={current_db}',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}).encode(),
            headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {self.key}'},
        )
        self.assertEqual(r.status_code, 200)

    def test_mismatched_db_query_param_returns_404(self):
        r = self.url_open(
            '/mcp?db=nonexistent_db',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}).encode(),
            headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {self.key}'},
        )
        self.assertEqual(r.status_code, 404)
        body = r.json()
        self.assertEqual(body['error']['code'], -32003)
        self.assertIn('nonexistent_db', body['error']['message'])

    def test_mismatched_db_header_returns_404(self):
        r = self.url_open(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}).encode(),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.key}',
                'X-Odoo-Database': 'nonexistent_db',
            },
        )
        self.assertEqual(r.status_code, 404)
