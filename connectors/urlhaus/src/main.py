"""Entry point for the URLHaus OpenCTI connector."""

from connector import URLHausConnector

if __name__ == "__main__":
    connector = URLHausConnector()
    connector.run()
