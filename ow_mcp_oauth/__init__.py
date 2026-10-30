from . import http_patch  # Must be first to extend routing patch
from . import models
from . import controllers
from . import protocol  # installs OAuth scope guards on ow_mcp_server TOOL_HANDLERS
