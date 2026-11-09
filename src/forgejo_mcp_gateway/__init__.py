"""A multi-user MCP gateway for Forgejo."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("forgejo-mcp-gateway")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0"

__all__ = ["__version__"]
