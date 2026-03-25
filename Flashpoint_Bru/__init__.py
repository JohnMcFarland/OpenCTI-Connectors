# =============================================================================
# flashpoint_connector/__init__.py
# =============================================================================
# Package entry point for the Flashpoint Ignite OpenCTI connector.
#
# Exposes FlashpointConnector as the single public symbol so that main.py
# can import cleanly without needing to know the internal module structure:
#
#   from flashpoint_connector import FlashpointConnector
#
# This is the standard pattern used across all custom connectors in this
# instance. Do not import individual modules directly from outside the package.
# =============================================================================

from .connector import FlashpointConnector

__all__ = ["FlashpointConnector"]
