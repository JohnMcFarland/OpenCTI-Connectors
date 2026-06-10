"""
main.py
Entry point for the IC Reports OpenCTI connector.
"""

import logging
import sys
import traceback

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

try:
    from connector import ICReportsConnector
    connector = ICReportsConnector()
    connector.run()
except SystemExit:
    raise
except Exception as e:
    print("FATAL UNHANDLED EXCEPTION:", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
