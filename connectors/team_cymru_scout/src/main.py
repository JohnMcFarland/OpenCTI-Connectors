import sys
import time

from team_cymru_scout import TeamCymruScoutConnector

if __name__ == "__main__":
    try:
        connector = TeamCymruScoutConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(1)
