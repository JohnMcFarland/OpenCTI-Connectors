# =============================================================================
# main.py — Flashpoint Ignite Connector entry point
# =============================================================================
# This is the script that Docker runs via the Dockerfile ENTRYPOINT.
# It instantiates FlashpointConnector and calls run(), which blocks
# indefinitely via the schedule_iso loop until the container is stopped.
#
# ERROR HANDLING:
# Any exception that escapes FlashpointConnector.__init__() or run()
# (i.e. a fatal startup error rather than a per-dataset runtime error)
# is caught here, printed with full traceback to stderr, and the process
# exits with code 1. Exit code 1 signals to Docker that the container
# failed, enabling Docker restart policies to apply.
#
# NORMAL SHUTDOWN:
# KeyboardInterrupt and SystemExit are caught inside process_data() in
# connector.py and result in a clean sys.exit(0). They propagate through
# run() and main() without triggering the traceback/exit(1) path.
#
# USAGE:
#   docker run ... connector-flashpoint
#   python main.py  (for local development)
# =============================================================================

import traceback

from flashpoint_connector import FlashpointConnector


if __name__ == "__main__":
    try:
        connector = FlashpointConnector()
        connector.run()
    except Exception:
        # Print the full traceback to stderr so it is captured by Docker logs.
        # This covers fatal errors like missing required config, failed author
        # identity creation, or any other startup failure.
        traceback.print_exc()
        exit(1)
