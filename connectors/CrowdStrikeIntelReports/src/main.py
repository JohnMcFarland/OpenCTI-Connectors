"""CrowdStrike Intel Reports connector entrypoint."""

import sys
import time

from crowdstrike_intel_reports import CrowdStrikeIntelReportsConnector

if __name__ == "__main__":
    try:
        connector = CrowdStrikeIntelReportsConnector()
        connector.start()
    except Exception as e:
        print(f"[CrowdStrikeIntelReports] Fatal startup error: {e}", file=sys.stderr)
        time.sleep(60)
        sys.exit(1)
