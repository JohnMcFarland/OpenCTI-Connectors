#!/usr/bin/env python3
"""
main.py

"""


import sys
from cis_pdf import CISPdfConnector


def main() -> int:
    connector = CISPdfConnector()
    connector.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

