import json
import os
import boto3


class OpenPhishClient:
    """OpenPhishClient used to interact with OpenPhish"""

    LOCAL_FEED_JSON = "openphish_feed.json"

    def __init__(self, access_key_id, access_key_secret, feed_name) -> None:
        """
        Instantiates the connector from information.

        Args:
            access_key_id (_str_) - The Access Key ID to use to get the Phishing Feed Information
            access_key_secret (_str_) - The Access Key Secret to use to get the Phishing Feed Information
            feed_name (_str_) - The feed name/path to get

        Returns:
            None
        """
        self.aws_client = boto3.client(
            "s3",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=access_key_secret,
        )

        self.feed_name = feed_name

    def get_latest_feed_information(self) -> []:
        """
        This method gets the latest OpenPhish feed information.

        Returns:
            A list of Phishing URLs and associated information in the feed at the time.
        """
        with open(OpenPhishClient.LOCAL_FEED_JSON, "wb") as local_feed:
            self.aws_client.download_fileobj("opfeeds", self.feed_name, local_feed)

        with open(OpenPhishClient.LOCAL_FEED_JSON, "r") as f:
            op_feed_data = json.load(f)

        if os.path.exists(OpenPhishClient.LOCAL_FEED_JSON):
            os.remove(OpenPhishClient.LOCAL_FEED_JSON)

        return op_feed_data
